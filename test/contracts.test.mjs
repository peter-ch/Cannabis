import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { Contract, ContractFactory, Interface, parseEther, keccak256 } from 'ethers';
import { generateProof, verifyProof } from '@semaphore-protocol/proof';
import { compile } from '../scripts/compile.mjs';
import { startNode, deployLocal, deploy, localSources, localProof, localIdentity, localGroup, closeProver, end24Months } from '../scripts/lib.mjs';
import { createServer } from '../scripts/server.mjs';
import { prepareClaim } from '../scripts/prepare-claim.mjs';
import { claimScope } from '../claims/identity.mjs';
import { downloadMembershipSnapshot } from '../claims/snapshot.mjs';
let artifacts, node, provider, token, vest, enrollment, semaphore, start, end, founder, registrar, recipient, address, initial, proof, otherProof;
const zero = '0x0000000000000000000000000000000000000000';
async function freePort() { return new Promise(resolve => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); }); }
async function timestamp(time) { await provider.send('evm_setNextBlockTimestamp', [time]); await provider.send('evm_mine', []); }
async function claim() { return (await token.connect(recipient).claim(address, proof)).wait(); }
before(async () => {
  artifacts = compile({ ...localSources,
    'ExhaustionHarness.sol': { content: '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.30;\nimport {Cannabis} from "Cannabis.sol";\ncontract ExhaustionHarness is Cannabis { constructor(address f,uint64 s,uint64 e,address sem,address r) Cannabis(f,s,e,sem,r) { communityIssued = COMMUNITY_ALLOCATION - CLAIM_AMOUNT; _mint(f,communityIssued); } }' },
    'EnrollmentCapacityHarness.sol': { content: '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.30;\nimport {CannabisEnrollment} from "Cannabis.sol";\ncontract EnrollmentCapacityHarness is CannabisEnrollment { constructor(address s,address r) CannabisEnrollment(s,r) { enrolledCount = MAX_MEMBERS - 1; } }' }
  });
  node = await startNode(await freePort(), 'test-node.log'); provider = node.provider;
  ({ token, start, end, founder, registrar, enrollment, semaphore } = await deployLocal(provider, artifacts, { delay: 1000 }));
  recipient = await provider.getSigner(1); address = await recipient.getAddress();
  vest = new Contract(await token.founderVesting(), artifacts.FounderVesting.abi, recipient);
  proof = await localProof(provider, token, address);
  otherProof = await localProof(provider, token, await (await provider.getSigner(3)).getAddress());
  initial = await provider.send('evm_snapshot', []);
});
after(async () => { provider?.destroy(); node?.child.kill(); await closeProver(); });
async function reset() { await provider.send('evm_revert', [initial]); initial = await provider.send('evm_snapshot', []); }
async function membershipOptions() {
  const names = { token: await token.getAddress(), enrollment: await enrollment.getAddress(), semaphore: await semaphore.getAddress() };
  const release = { chainId: '31337', ...names, fromBlock: (await token.deploymentTransaction().wait()).blockNumber };
  for (const [name, target] of Object.entries(names)) release[name + 'CodeHash'] = keccak256(await provider.getCode(target));
  return { rpc: node.rpc, release, pageSize: 2 };
}
async function rpcProxy(mutate) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks)); requests.push(body);
      const upstream = await fetch(node.rpc, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const result = await upstream.json(); await mutate(body, result);
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(result));
    } catch { res.writeHead(500); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { requests, rpc: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}
test('exact name, fixed allocations and no proof-of-work entrypoint', async () => {
  await reset(); assert.equal(await token.name(), 'Cannabis');
  assert.equal(await token.CAP(), parseEther('420000000')); assert.equal(await token.COMMUNITY_ALLOCATION(), parseEther('415800000'));
  assert.equal(await token.MAX_CLAIMANTS(), 990000n); assert.equal(await token.totalSupply(), parseEther('4200000'));
  assert.equal(await token.balanceOf(founder), 0n); assert.equal(await token.balanceOf(await vest.getAddress()), parseEther('4200000'));
  assert.equal(await token.FOUNDER_ALLOCATION() * 100n, await token.CAP());
  assert.equal(await token.COMMUNITY_ALLOCATION() * 100n, await token.CAP() * 99n);
  assert.equal(await token.MAX_CLAIMANTS(), await enrollment.MAX_MEMBERS());
  assert.equal(await token.MAX_CLAIMANTS() * await token.CLAIM_AMOUNT(), await token.COMMUNITY_ALLOCATION());
  assert.equal(token.interface.getFunction('mine'), null);
  assert.equal(claimScope('31337', await token.getAddress()), (await token.claimScope()).toString());
});
test('whole-group downloader checks actual finalized state and replays paged batch events', async () => {
  await reset(); const options = await membershipOptions();
  const proxy = await rpcProxy((_request, response) => { if (Array.isArray(response.result)) response.result.reverse(); });
  try {
    const result = await downloadMembershipSnapshot({ ...options, rpc: proxy.rpc });
    assert.deepEqual(result.snapshot.commitments, Array.from({ length: 128 }, (_, i) => localIdentity(i).commitment.toString()));
    assert.equal(result.context.root, localGroup(128).root.toString());
    assert.equal(result.context.memberCount, 128); assert.equal(result.sent, false);
    assert.equal(result.evidence.eventCount, 4); assert.ok(result.evidence.pages >= 2);
    assert.equal(result.evidence.anchor.tag, 'finalized');
    assert.match(result.evidence.rpcTrust, /no independent/);
    for (const request of proxy.requests) {
      assert.ok(['eth_chainId','eth_getBlockByNumber','eth_getCode','eth_call','eth_getLogs'].includes(request.method));
      if (['eth_call','eth_getCode'].includes(request.method)) {
        assert.equal(request.params[1].requireCanonical, true);
        assert.match(request.params[1].blockHash, /^0x[0-9a-f]{64}$/);
      }
      if (request.method === 'eth_getLogs') assert.equal(request.params[0].topics.length, 2);
    }
    assert.equal(JSON.stringify(proxy.requests).includes(localIdentity(1).commitment.toString()), false);
  } finally { await proxy.close(); }
});
test('membership downloader rejects incomplete, repeated, wrong-group and altered event history', async () => {
  await reset(); const options = await membershipOptions();
  const eventABI = new Interface(['event MembersAdded(uint256 indexed groupId,uint256 startIndex,uint256[] identityCommitments,uint256 merkleTreeRoot)', 'event MemberRemoved(uint256 indexed groupId,uint256 index,uint256 identityCommitment,uint256 merkleTreeRoot)']);
  for (const mode of ['omit','duplicate','wrong-group','alter','remove']) {
    let changed = false;
    const proxy = await rpcProxy((request, response) => {
      if (changed || request.method !== 'eth_getLogs' || !response.result?.length) return;
      changed = true;
      if (mode === 'omit') response.result.shift();
      else if (mode === 'duplicate') response.result.push(structuredClone(response.result[0]));
      else if (mode === 'wrong-group') response.result[0].topics[1] = '0x' + 'ff'.repeat(32);
      else {
        const item = response.result[0], decoded = eventABI.parseLog(item);
        const members = Array.from(decoded.args[2]); members[0] = localIdentity(999).commitment;
        const changedEvent = mode === 'remove' ? eventABI.encodeEventLog(eventABI.getEvent('MemberRemoved'), [decoded.args[0],decoded.args[1],decoded.args[2][0],decoded.args[3]])
          : eventABI.encodeEventLog(eventABI.getEvent('MembersAdded'), [decoded.args[0],decoded.args[1],members,decoded.args[3]]);
        item.data = changedEvent.data; item.topics = changedEvent.topics;
      }
    });
    try {
      await assert.rejects(downloadMembershipSnapshot({ ...options, rpc: proxy.rpc }), /membership additions|Repeated membership|event envelope|event root|Non-append/);
      assert.equal(changed, true);
    } finally { await proxy.close(); }
  }
});
test('membership downloader rejects code substitution, anchor changes, stale heads and newer membership', async () => {
  await reset(); const options = await membershipOptions();
  const rootSelector = new Interface(['function getMerkleTreeRoot(uint256) view returns (uint256)']).getFunction('getMerkleTreeRoot').selector;
  for (const mode of ['code','anchor','stale','new-members']) {
    let rootReads = 0, changed = false;
    const proxy = await rpcProxy((request, response) => {
      if (mode === 'code' && request.method === 'eth_getCode') { response.result = '0x6000'; changed = true; }
      if (mode === 'anchor' && request.method === 'eth_getBlockByNumber' && request.params[0].startsWith('0x')) { response.result.hash = '0x' + 'ab'.repeat(32); changed = true; }
      if (mode === 'stale' && request.method === 'eth_getBlockByNumber' && request.params[0] === 'latest') { response.result.timestamp = '0x1'; changed = true; }
      if (mode === 'new-members' && request.method === 'eth_call' && request.params[0].data.startsWith(rootSelector) && ++rootReads > 1) { response.result = '0x' + '01'.repeat(32); changed = true; }
    });
    try {
      await assert.rejects(downloadMembershipSnapshot({ ...options, rpc: proxy.rpc }), /Runtime-code hash|anchor changed|stale or inconsistent|Membership changed/);
      assert.equal(changed, true);
    } finally { await proxy.close(); }
  }
});
test('membership downloader enforces release chain, page budget and read-only transport', async () => {
  await reset(); const options = await membershipOptions();
  await assert.rejects(downloadMembershipSnapshot({ ...options, release: { ...options.release, chainId: '1' } }), /chain does not match/);
  await assert.rejects(downloadMembershipSnapshot({ ...options, pageSize: 1, maxPages: 1 }), /page budget/);
  await assert.rejects(downloadMembershipSnapshot({ ...options, rpc: 'http://example.invalid' }), /HTTPS RPC/);
  await assert.rejects(downloadMembershipSnapshot({ ...options, rpc: 'https://user:password@example.invalid' }), /HTTPS RPC/);
  const proxy = await rpcProxy((_request, response) => { response.id = 'wrong-request'; });
  try { await assert.rejects(downloadMembershipSnapshot({ ...options, rpc: proxy.rpc }), /RPC read failed/); }
  finally { await proxy.close(); }
});
test('24 calendar months clamps leap-day schedules', () => {
  assert.equal(new Date(end24Months(Date.parse('2028-02-29T12:00:00Z') / 1000) * 1000).toISOString(), '2030-02-28T12:00:00.000Z');
});
test('real Semaphore proof claims only after the common opening', async t => {
  await reset(); assert.equal(await verifyProof(proof), true);
  await assert.rejects(token.claim.staticCall(address, proof), /ClaimsNotOpen/);
  await timestamp(start); const receipt = await claim();
  assert.equal(await token.balanceOf(address), parseEther('420')); assert.equal(await token.communityIssued(), parseEther('420'));
  assert.ok(receipt.gasUsed < 600000n);
  t.diagnostic('Actual local EVM gas for real ZK claim: ' + receipt.gasUsed + '; not an energy or fee quote.');
});
test('recipient substitution, forged inputs, malformed proofs and wrong scopes are rejected', async () => {
  await reset(); await timestamp(start); const attacker = await (await provider.getSigner(3)).getAddress();
  await assert.rejects(token.claim.staticCall(attacker, proof), /InvalidProof/);
  await assert.rejects(token.claim.staticCall(attacker, { ...proof, message: BigInt(attacker).toString() }));
  await assert.rejects(token.claim.staticCall(address, { ...proof, points: Array(8).fill('0') }));
  await assert.rejects(token.claim.staticCall(address, { ...proof, scope: (BigInt(proof.scope) + 1n).toString() }), /InvalidProof/);
  await assert.rejects(token.claim.staticCall(zero, { ...proof, message: '0' }), /InvalidProof/);
});
test('same identity cannot claim again even using a fresh receiving wallet', async () => {
  await reset(); await timestamp(start); await claim();
  await assert.rejects(token.claim.staticCall(address, proof), /AlreadyClaimed/);
  assert.equal(otherProof.nullifier, proof.nullifier); assert.equal(await verifyProof(otherProof), true);
  await assert.rejects(token.claim.staticCall(await (await provider.getSigner(3)).getAddress(), otherProof), /AlreadyClaimed/);
});
test('public claim preparation checks the chain and code and never sends the claim', async () => {
  await reset(); await timestamp(start);
  const options = { rpc: node.rpc, chainId: 31337, token: await token.getAddress(), recipient: address,
    codeHash: keccak256(await provider.getCode(await token.getAddress())), proof };
  const result = await prepareClaim(options);
  assert.equal(result.sent, false); assert.equal(await token.balanceOf(address), 0n);
  await (await recipient.sendTransaction(result.transaction)).wait();
  assert.equal(await token.balanceOf(address), parseEther('420'));
  await assert.rejects(prepareClaim({ ...options, chainId: 8453 }), /chain ID does not match/);
  await assert.rejects(prepareClaim({ ...options, codeHash: '0x' + '00'.repeat(32) }), /code does not match/);
});
test('relayers cannot divert rewards and external nullifier burning cannot block a claim', async () => {
  await reset(); await timestamp(start); const stranger = await provider.getSigner(4);
  await (await semaphore.connect(stranger).validateProof(await token.groupId(), proof)).wait();
  await (await token.connect(stranger).claim(address, proof)).wait();
  assert.equal(await token.balanceOf(address), parseEther('420')); assert.equal(await token.balanceOf(await stranger.getAddress()), 0n);
});
test('only registrar can enroll; duplicate members and group-control takeover fail', async () => {
  await reset();
  await assert.rejects(enrollment.connect(recipient).addVerifiedMembers.staticCall([localIdentity(128).commitment]), /Unauthorized/);
  await assert.rejects(semaphore.connect(await provider.getSigner(2)).updateGroupAdmin.staticCall(await token.groupId(), registrar));
  await assert.rejects(enrollment.addVerifiedMembers.staticCall([localIdentity(1).commitment]));
  assert.equal(enrollment.interface.getFunction('removeMember'), null);
  assert.equal(enrollment.interface.getFunction('updateGroupAdmin'), null);
});
test('enrollment admits the final eligible member and rejects excess capacity atomically', async () => {
  await reset();
  const signer = await provider.getSigner(2);
  const registry = await new ContractFactory(artifacts.EnrollmentCapacityHarness.abi, artifacts.EnrollmentCapacityHarness.bytecode, signer).deploy(await semaphore.getAddress(), registrar);
  await registry.waitForDeployment();
  assert.equal(await registry.enrolledCount(), 989999n);
  await assert.rejects(registry.addVerifiedMembers.staticCall([localIdentity(0).commitment, localIdentity(1).commitment]), /InvalidEnrollment/);
  assert.equal(await registry.enrolledCount(), 989999n);
  await (await registry.addVerifiedMembers([localIdentity(0).commitment])).wait();
  assert.equal(await registry.enrolledCount(), 990000n);
  await assert.rejects(registry.addVerifiedMembers.staticCall([localIdentity(1).commitment]), /InvalidEnrollment/);
});
test('small groups and stale roots cannot bypass the anonymity threshold', async () => {
  await reset(); const other = await deploy(provider, artifacts.Cannabis, { semaphoreAddress: await semaphore.getAddress(), delay: 100 });
  await timestamp(Math.max(start, other.start));
  await assert.rejects(other.token.claim.staticCall(address, { ...proof, scope: (await other.token.claimScope()).toString() }), /AnonymitySetTooSmall/);
  await (await enrollment.addVerifiedMembers([localIdentity(128).commitment])).wait();
  await assert.rejects(token.claim.staticCall(address, proof), /MembershipRootChanged/);
  const refreshed = await generateProof(localIdentity(1), localGroup(129), BigInt(address), await token.claimScope());
  await (await token.claim(address, refreshed)).wait(); assert.equal(await token.balanceOf(address), parseEther('420'));
});
test('vesting pays only founder linearly over exact schedule', async () => {
  await reset(); const amount = await token.FOUNDER_ALLOCATION();
  assert.equal(await vest.vestedAt(start), 0n); assert.equal(await vest.vestedAt(start + (end - start) / 2), amount / 2n);
  assert.equal(await vest.vestedAt(end + 1), amount); await assert.rejects(vest.release.staticCall());
  await timestamp(end); await (await vest.release()).wait();
  assert.equal(await token.balanceOf(founder), amount); assert.equal(await token.balanceOf(address), 0n);
  await assert.rejects(vest.release.staticCall());
});
test('ordinary transfers have no taxes or privileged restrictions', async () => {
  await reset(); await timestamp(start); await claim();
  await (await token.connect(recipient).transfer(registrar, parseEther('100'))).wait();
  assert.equal(await token.balanceOf(registrar), parseEther('100'));
  await assert.rejects(token.connect(recipient).transfer.staticCall(registrar, parseEther('1000')));
});
test('final claim reaches cap exactly; further issuance fails', async () => {
  await reset();
  const last = await new ContractFactory(artifacts.ExhaustionHarness.abi, artifacts.ExhaustionHarness.bytecode, recipient).deploy(founder, start, end, await semaphore.getAddress(), registrar);
  await last.waitForDeployment();
  const registry = new Contract(await last.enrollment(), artifacts.CannabisEnrollment.abi, await provider.getSigner(2));
  const members = Array.from({ length: 128 }, (_, i) => localIdentity(i).commitment);
  for (let i = 0; i < members.length; i += 32) await (await registry.addVerifiedMembers(members.slice(i, i + 32))).wait();
  const lastProof = await localProof(provider, last, address); await timestamp(start);
  await (await last.claim(address, lastProof)).wait(); assert.equal(await last.totalSupply(), await last.CAP());
  const other = await (await provider.getSigner(3)).getAddress();
  await assert.rejects(last.claim.staticCall(other, { ...lastProof, nullifier: '1', message: BigInt(other).toString() }), /CommunityExhausted/);
});
test('invalid deployment configuration is rejected', async () => {
  await reset(); const factory = new ContractFactory(artifacts.Cannabis.abi, artifacts.Cannabis.bytecode, recipient); const sem = await semaphore.getAddress();
  for (const args of [[zero,start,end,sem,registrar], [founder,1,end,sem,registrar], [founder,start,start,sem,registrar], [founder,start,end,zero,registrar], [founder,start,end,sem,zero]]) await assert.rejects(factory.deploy(...args));
});
test('local API restricts origins, rejects repeat claims, and never serves private files', async () => {
  await reset(); const port = await freePort();
  const server = createServer({ provider, token, state: { address: await token.getAddress(), vesting: await vest.getAddress(), start, end, founder }, vestingAbi: artifacts.FounderVesting.abi, port });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve)); const url = 'http://127.0.0.1:' + port;
  try {
    const status = await fetch(url + '/api/status');
    assert.equal(status.status, 200);
    assert.equal((await status.json()).founderAllocation, '4200000.0');
    assert.equal((await fetch(url + '/api/claim', { method: 'POST' })).status, 403);
    const spoofed = await new Promise((resolve, reject) => { http.get(url + '/api/status', { headers: { Host: 'evil.example' } }, res => { res.resume(); resolve(res.statusCode); }).on('error', reject); }); assert.equal(spoofed, 403);
    for (const name of ['/.env', '/.runtime/deployment.json', '/private/wallets/founder-wallet.dpapi.json']) assert.equal((await fetch(url + name)).status, 404);
    const options = { method: 'POST', headers: { Origin: url, 'Content-Type': 'application/json' }, body: '{}' };
    const res = await fetch(url + '/api/claim', options); assert.equal(res.status, 200); assert.equal((await res.json()).reward, '420');
    assert.equal((await fetch(url + '/api/claim', options)).status, 409);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
