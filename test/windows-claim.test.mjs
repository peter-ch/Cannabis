import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { keccak256, parseEther } from 'ethers';
import { compile } from '../scripts/compile.mjs';
import { startNode, deployLocal, localSources, localIdentity } from '../scripts/lib.mjs';
import { downloadMembershipSnapshot } from '../claims/snapshot.mjs';
import { createParticipant, participantClaimBinding, proveParticipantClaim } from '../participant/windows-custody.mjs';
import { selectParticipantClaimConfiguration, reviewParticipantClaim, prepareParticipantClaim } from '../participant/claim-flow.mjs';

const windows = process.platform === 'win32', digest = bytes => createHash('sha256').update(bytes).digest('hex');
let directory, custody, originalRecord, originalRecovery, config, configFile, node, provider, token, enrollment, initial, recipient, server;
const requests = [];
const freePort = () => new Promise(resolve => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const port = s.address().port; s.close(() => resolve(port)); }); });
const approval = review => Object.fromEntries(['reviewId','releaseDigest','token','recipient'].map(name => [name, review[name]]));
const review = () => reviewParticipantClaim(selectParticipantClaimConfiguration(configFile), recipient, custody);
before(async () => {
  if (!windows) return;
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-guided-claim-'));
  custody = { directory: path.join(directory, 'custody'), age: process.env.CANNABIS_AGE };
  assert.ok(custody.age && path.isAbsolute(custody.age)); custody.ageKeygen = path.join(path.dirname(custody.age), 'age-keygen.exe');
  const created = await createParticipant(custody);
  originalRecord = fs.readFileSync(path.join(custody.directory, 'participant.json'));
  // Explicit fixture marker: this is not an owner-operated portable-restore test.
  originalRecovery = Buffer.from(JSON.stringify({ schema: 'cannabis.participant-recovery-check.v1', checkedAt: new Date().toISOString(),
    commitment: created.commitment, vaultSHA256: JSON.parse(originalRecord).vaultSHA256, backupSHA256: '0'.repeat(64), portableRecoveryVerified: true, enrolled: false }));
  fs.writeFileSync(path.join(custody.directory, 'recovery-check.json'), originalRecovery);
  const artifacts = compile(localSources);
  node = await startNode(await freePort(), 'guided-claim-fixture.log'); provider = node.provider;
  assert.equal((await provider.getNetwork()).chainId, 31337n);
  const deployed = await deployLocal(provider, artifacts, { memberCount: 0, delay: 10 }); token = deployed.token; enrollment = deployed.enrollment;
  await (await enrollment.addVerifiedMembers([created.commitment, localIdentity(0).commitment])).wait();
  await provider.send('evm_setNextBlockTimestamp', [deployed.start+1]); await provider.send('evm_mine', []);
  recipient = await (await provider.getSigner(1)).getAddress();
  const release = { chainId: '31337', token: await token.getAddress(), enrollment: await token.enrollment(), semaphore: await token.semaphore(), fromBlock: (await token.deploymentTransaction().wait()).blockNumber };
  for (const name of ['token','enrollment','semaphore']) release[name+'CodeHash'] = keccak256(await provider.getCode(release[name]));
  server = http.createServer(async (req, res) => {
    try {
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > 1024*1024) throw Error('Fixture request bound'); chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks)); requests.push(...(Array.isArray(body) ? body : [body]));
      const upstream = await fetch(node.rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(await upstream.text());
    } catch { res.writeHead(500); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const proving = { depth: 1 };
  for (const name of ['wasm','zkey']) {
    const response = await fetch('https://snark-artifacts.pse.dev/semaphore/4.13.0/semaphore-1.'+name); assert.ok(response.ok);
    const bytes = Buffer.from(await response.arrayBuffer()); assert.ok(bytes.length < 128*1024*1024);
    const file = path.join(directory, 'semaphore-1.'+name); fs.writeFileSync(file, bytes);
    proving[name] = { path: file, bytes: bytes.length, sha256: digest(bytes) };
  }
  config = { schema: 'cannabis.participant-claim-config.v1', rpc: 'http://127.0.0.1:'+server.address().port, release, artifacts: proving };
  configFile = path.join(directory, 'claim-config.json'); initial = await provider.send('evm_snapshot', []);
});
beforeEach(async () => {
  if (!windows) return;
  await provider.send('evm_revert', [initial]); initial = await provider.send('evm_snapshot', []);
  fs.writeFileSync(configFile, JSON.stringify(config)); fs.writeFileSync(path.join(custody.directory, 'participant.json'), originalRecord);
  fs.writeFileSync(path.join(custody.directory, 'recovery-check.json'), originalRecovery); requests.length = 0;
});
after(async () => {
  if (server) await new Promise(resolve => { server.closeAllConnections(); server.close(resolve); });
  provider?.destroy(); node?.child.kill(); await globalThis.curve_bn128?.terminate();
  if (directory) {
    const resolved = fs.realpathSync(directory);
    if (path.dirname(resolved) !== fs.realpathSync(os.tmpdir()) || !path.basename(resolved).startsWith('cannabis-guided-claim-')) throw Error('Unexpected fixture cleanup target');
    fs.rmSync(resolved, { recursive: true });
  }
});
test('guided Windows claim joins actual DPAPI, downloaded membership and a valid unsigned transaction without broadcasting', { skip: !windows }, async () => {
  const selected = await review(); assert.equal(selected.memberCount, 2); assert.equal(selected.minimumClaimMembers, 1);
  assert.equal(selected.open, true); assert.equal(selected.claimAmount, '420'); assert.equal(selected.canonicalReleaseAuthenticated, false);
  assert.equal(Object.hasOwn(selected, 'commitment'), false);
  const output = path.join(directory, 'unsigned.json'), raced = path.join(directory, 'raced.json');
  const attempts = await Promise.allSettled([prepareParticipantClaim(selected, approval(selected), output), prepareParticipantClaim(selected, approval(selected), raced)]);
  assert.equal(attempts[0].status, 'fulfilled', String(attempts[0].reason)); assert.equal(attempts[1].status, 'rejected'); assert.equal(fs.existsSync(raced), false);
  const saved = JSON.parse(fs.readFileSync(output)); assert.equal(saved.sent, false); assert.equal(saved.signingRequired, true);
  assert.equal(saved.transaction.from, recipient); assert.equal(saved.transaction.to, await token.getAddress()); assert.equal(saved.transaction.value, '0x0');
  assert.equal(await token.walletClaimed(recipient), false); assert.equal(await token.balanceOf(recipient), 0n);
  const commitment = JSON.parse(originalRecord).commitment;
  assert.equal(JSON.stringify(saved).includes(commitment), false); assert.equal(JSON.stringify(requests).includes(commitment), false);
  assert.equal(JSON.stringify(requests).includes('AGE-SECRET-KEY'), false);
  assert.ok(requests.every(request => ['eth_chainId','eth_blockNumber','eth_getBlockByNumber','eth_getCode','eth_call','eth_getLogs'].includes(request.method)));
  assert.deepEqual(fs.readFileSync(path.join(custody.directory, 'participant.json')), originalRecord);
  // Only this disposable loopback-chain fixture signs, using a known local key.
  await (await (await provider.getSigner(1)).sendTransaction(saved.transaction)).wait();
  assert.equal(await token.balanceOf(recipient), parseEther('420'));
});
test('guided claim refuses forged review and changed recipient, recovery, configuration or custody', { skip: !windows }, async () => {
  const selected = await review(), output = path.join(directory, 'refused.json');
  await assert.rejects(prepareParticipantClaim({ ...selected }, approval(selected), output), /current process/);
  await assert.rejects(prepareParticipantClaim(selected, { ...approval(selected), recipient: await token.getAddress() }, output), /displayed claim/);
  fs.appendFileSync(configFile, '\n'); await assert.rejects(prepareParticipantClaim(selected, approval(selected), output), /configuration changed/);
  fs.writeFileSync(configFile, JSON.stringify(config));
  const next = await review(); fs.appendFileSync(path.join(custody.directory, 'recovery-check.json'), '\n');
  await assert.rejects(prepareParticipantClaim(next, approval(next), output), /custody or recovery changed/);
  fs.writeFileSync(path.join(custody.directory, 'recovery-check.json'), originalRecovery);
  const last = await review(); fs.appendFileSync(path.join(custody.directory, 'participant.json'), '\n');
  await assert.rejects(prepareParticipantClaim(last, approval(last), output), /custody or recovery changed/); assert.equal(fs.existsSync(output), false);
});
test('guided claim refuses stale membership or policy and consumes the approved attempt', { skip: !windows }, async () => {
  const selected = await review(), output = path.join(directory, 'stale.json'); await (await token.increaseMinimumClaimMembers(2)).wait();
  await assert.rejects(prepareParticipantClaim(selected, approval(selected), output), /conditions changed/);
  await assert.rejects(prepareParticipantClaim(selected, approval(selected), output), /current process/);
  const next = await review(); await (await enrollment.addVerifiedMembers([localIdentity(1).commitment])).wait();
  await assert.rejects(prepareParticipantClaim(next, approval(next), output), /conditions changed/); assert.equal(fs.existsSync(output), false);
});
test('guided claim requires portable recovery and checks artifacts before opening custody', { skip: !windows }, async () => {
  fs.unlinkSync(path.join(custody.directory, 'recovery-check.json')); await assert.rejects(review()); assert.equal(requests.length, 0);
  fs.writeFileSync(path.join(custody.directory, 'recovery-check.json'), originalRecovery);
  const membership = await downloadMembershipSnapshot({ rpc: config.rpc, release: config.release });
  const broken = structuredClone(config.artifacts); broken.wasm.sha256 = '0'.repeat(64);
  await assert.rejects(proveParticipantClaim({ directory: path.join(directory, 'absent'), age: custody.age, ageKeygen: custody.ageKeygen,
    binding: participantClaimBinding(custody), snapshot: membership.snapshot, context: membership.context, recipient, artifacts: broken }), /artifact does not match/);
  fs.writeFileSync(configFile, JSON.stringify({ ...config, artifacts: broken })); requests.length = 0;
  await assert.rejects(review(), /reviewed pin/); assert.equal(requests.length, 0);
});
test('guided claim refuses expired approval without network reads', { skip: !windows }, async () => {
  const selected = await review(), output = path.join(directory, 'expired.json'), now = Date.now; requests.length = 0;
  Date.now = () => now()+300001;
  try { await assert.rejects(prepareParticipantClaim(selected, approval(selected), output), /expired/); } finally { Date.now = now; }
  assert.equal(requests.length, 0); assert.equal(fs.existsSync(output), false);
});
