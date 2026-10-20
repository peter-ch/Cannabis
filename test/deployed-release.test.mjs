import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Contract, Wallet, keccak256, parseEther, toQuantity } from 'ethers';
import { compile, root } from '../scripts/compile.mjs';
import { startNode, deployLocal, localSources } from '../scripts/lib.mjs';
import { buildRelease, releaseArtifacts } from '../launch/release.mjs';
import { readReleasePackage } from '../launch/release-package.mjs';
import { compileReleaseRuntime, matchReleaseRuntime } from '../launch/release-runtime.mjs';
import { checkFinalityProgress, deploymentBlock, inspectDeployedRelease } from '../launch/release-inspection.mjs';
import { verifyDeployedRelease } from '../launch/deployed-release.mjs';
import { quoteNetworkRelease } from '../launch/release-fees.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
let node, provider, temporary, artifacts, compilerInput, plan, ownedPlan, runtimes, hashes, anchor, options;
function writePackage(name, selectedPlan) {
  const folder = path.join(temporary, name);
  fs.mkdirSync(folder); fs.mkdirSync(path.join(folder, 'artifacts'));
  const bytes = { 'compiler-input.json': Buffer.from(JSON.stringify(compilerInput)) };
  for (const name of releaseArtifacts) bytes[`artifacts/${name}.json`] = Buffer.from(JSON.stringify(artifacts[name]));
  const files = Object.fromEntries(Object.entries(bytes).map(([name, data]) => {
    fs.writeFileSync(path.join(folder, name), data); return [name, sha(data)];
  }));
  const packageSHA256 = sha(JSON.stringify({ plan: selectedPlan, files })), manifestFile = path.join(folder, 'network-release.json');
  fs.writeFileSync(manifestFile, JSON.stringify({ ...selectedPlan, files, packageSHA256 }));
  return { manifestFile, expectedPackageSHA256: packageSHA256 };
}
before(async () => {
  temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-deployed-release-'));
  const extra = compile(localSources);
  artifacts = compile(); compilerInput = JSON.parse(fs.readFileSync(path.join(root, 'artifacts/compiler-input.json')));
  const port = await new Promise(resolve => {
    const server = net.createServer(); server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); });
  });
  node = await startNode(port, 'deployed-release-node.log'); provider = node.provider;
  assert.equal((await provider.getNetwork()).chainId, 31337n);
  const local = await deployLocal(provider, extra, { memberCount: 0 });
  const wallet = Wallet.createRandom().connect(provider);
  await provider.send('hardhat_setBalance', [wallet.address, toQuantity(parseEther('100'))]);
  await provider.send('hardhat_setNonce', [wallet.address, '0x5']);
  const configuration = { schema: 'cannabis.release-configuration.v1', chainId: '1', deployer: wallet.address, founder: wallet.address,
    firstNonce: '5', launch: new Date(Date.now() + 14 * 86400000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    minimumClaimMembers: 1, registryReviewers: ['55', '66', '77'].map(pair => '0x' + pair.repeat(20)), registryQuorum: 2 };
  const dependencies = { schema: 'cannabis.semaphore-dependencies.v1', chainId: '1', poseidonLinkOffsets: [1] };
  for (const [name, address] of [['semaphore', await local.semaphore.getAddress()],
    ['verifier', await local.verifier.getAddress()], ['poseidon', '0x' + '44'.repeat(20)]])
    dependencies[name] = { address, codeHash: keccak256('0x00') };
  plan = await buildRelease(configuration, dependencies, artifacts);
  options = { rpc: node.rpc, ...writePackage('complete', plan), transactionHashes: [] };
  runtimes = compileReleaseRuntime({ compilerInput, artifacts, plan });
  // The low-level inspector is exercised with real owned chain31337 receipts.
  // Production entry points still accept only strictly reconstructed chain1 packages.
  ownedPlan = structuredClone(plan); ownedPlan.configuration.chainId = '31337';
  for (const entry of ownedPlan.transactions) entry.transaction.chainId = '0x7a69';
  hashes = [];
  for (const entry of ownedPlan.transactions) {
    const receipt = await (await wallet.sendTransaction(entry.transaction)).wait();
    assert.equal(receipt.status, 1); assert.equal(receipt.contractAddress, entry.expectedAddress);
    hashes.push(receipt.hash);
  }
  options.transactionHashes = hashes;
  anchor = deploymentBlock(await provider.send('eth_getBlockByNumber', ['latest', false]));
});
after(() => {
  provider?.destroy(); node?.child.kill();
  if (temporary) {
    const target = fs.realpathSync(temporary);
    assert.equal(path.dirname(target), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(target).startsWith('cannabis-deployed-release-'));
    fs.rmSync(target, { recursive: true });
  }
});
const inspect = rpc => inspectDeployedRelease({ plan: ownedPlan, runtimes, transactionHashes: hashes, anchor,
  rpc: rpc ?? ((method, params) => provider.send(method, params)) });

test('complete inspector verifies actual owned creation receipts, all seven runtimes and immutable links', async () => {
  const result = await inspect();
  assert.equal(result.receipts.length, 5); assert.equal(Object.keys(result.code).length, 7);
  assert.equal(result.founderMintToVestingVerified, true); assert.ok(result.immutableChecks > 30);
  assert.ok(BigInt(result.totalDeploymentNetworkFeeWei) > 0n);
  for (const [role, value] of Object.entries(result.code)) {
    assert.equal(value.address, plan.addresses[role]); assert.ok(value.bytes > 0);
    assert.equal(value.runtimeKeccak256, keccak256(await provider.getCode(value.address)));
  }
});

test('runtime matching refuses changed instructions, empty code and conflicting repeated immutable values', async () => {
  const code = await provider.getCode(plan.addresses.registrar), template = runtimes.CommunityRegistrar;
  assert.throws(() => matchReleaseRuntime('0x', template), /runtime/);
  const changed = '0x' + (code.slice(2, 4) === '00' ? '01' : '00') + code.slice(4);
  assert.throws(() => matchReleaseRuntime(changed, template), /outside compiler/);
  const repeated = Object.values(template.immutableReferences).find(ranges => ranges.length > 1);
  assert.ok(repeated);
  const bytes = Buffer.from(code.slice(2), 'hex'); bytes[repeated[0].start + 31] ^= 1;
  assert.throws(() => matchReleaseRuntime('0x' + bytes.toString('hex'), template), /Repeated immutable/);
  assert.throws(() => compileReleaseRuntime({ compilerInput, artifacts, plan: { ...plan, compiler: 'unreviewed compiler' } }), /exact release compiler/);
});

test('receipt inspector refuses missing, failed, reordered, changed, unfinalized and incorrectly linked deployments', async () => {
  const modes = ['missing', 'status', 'nonce', 'data', 'address', 'fee', 'gas', 'mint', 'block-member', 'runtime', 'link', 'reorg'];
  for (const mode of modes) {
    let reached = false, blockReads = 0;
    const rpc = async (method, params) => {
      const value = structuredClone(await provider.send(method, params));
      if (method === 'eth_getTransactionReceipt' && params[0] === hashes[0]) {
        if (mode === 'missing') { reached = true; return null; }
        if (mode === 'status') { value.status = '0x0'; reached = true; }
        if (mode === 'address') { value.contractAddress = plan.addresses.token; reached = true; }
        if (mode === 'fee') { value.effectiveGasPrice = '0x0'; reached = true; }
        if (mode === 'gas') { value.gasUsed = toQuantity(53000); reached = true; }
      }
      if (method === 'eth_getTransactionByHash' && params[0] === hashes[0]) {
        if (mode === 'nonce') { value.nonce = '0x0'; reached = true; }
        if (mode === 'data') { value.input = '0x00'; reached = true; }
      }
      if (mode === 'mint' && method === 'eth_getTransactionReceipt' && params[0] === hashes[1]) {
        value.logs = []; reached = true;
      }
      if (method === 'eth_getBlockByNumber') {
        ++blockReads;
        if (mode === 'block-member') { value.transactions = []; reached = true; }
        if (mode === 'reorg' && blockReads > 5) { value.hash = '0x' + 'aa'.repeat(32); reached = true; }
      }
      if (mode === 'runtime' && method === 'eth_getCode') { reached = true; return '0x00'; }
      if (mode === 'link' && method === 'eth_call') { reached = true; return '0x' + '00'.repeat(32); }
      return value;
    };
    await assert.rejects(inspect(rpc), undefined, mode); assert.equal(reached, true, mode);
  }
  await assert.rejects(inspectDeployedRelease({ plan: ownedPlan, runtimes, transactionHashes: [...hashes].reverse(), anchor,
    rpc: (method, params) => provider.send(method, params) }), /does not match/);
  await assert.rejects(inspectDeployedRelease({ plan: ownedPlan, runtimes, transactionHashes: hashes,
    anchor: { ...anchor, number: anchor.number - 1n }, rpc: (method, params) => provider.send(method, params) }), /unfinalized/);
});

test('finality progress refuses stale, regressing and conflicting same-height canonical views', () => {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const first = { ...anchor, number: 100n, timestamp: now - 60n, hash: '0x' + 'aa'.repeat(32) };
  const finalized = { ...first, number: 101n, timestamp: now - 30n, hash: '0x' + 'bb'.repeat(32) };
  const head = { ...first, number: 102n, timestamp: now, hash: '0x' + 'cc'.repeat(32) };
  assert.doesNotThrow(() => checkFinalityProgress(first, finalized, head, now));
  assert.doesNotThrow(() => checkFinalityProgress(first, first, first, now));
  for (const [changedFinal, changedHead] of [
    [{ ...finalized, number: 99n }, head], [{ ...finalized, number: first.number }, head],
    [finalized, { ...head, number: finalized.number }], [finalized, { ...head, timestamp: now + 31n }],
    [{ ...finalized, timestamp: now - 7201n }, head], [finalized, { ...head, timestamp: now - 121n }]
  ]) assert.throws(() => checkFinalityProgress(first, changedFinal, changedHead, now), /finality/);
});

test('historical reconstruction is explicit while current fee and preparation notice checks remain strict', async () => {
  const launch = new Date(Date.now() - 86400000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const historical = await buildRelease({ ...plan.configuration, launch }, plan.dependencies, artifacts, Date.parse(launch) - 8 * 86400000);
  const selected = writePackage('historical', historical);
  await assert.rejects(readReleasePackage(selected.manifestFile, selected.expectedPackageSHA256), /seven days/);
  const read = await readReleasePackage(selected.manifestFile, selected.expectedPackageSHA256, { deployed: true });
  assert.deepEqual(read.plan, historical); assert.deepEqual(read.compilerInput, compilerInput);
  await assert.rejects(quoteNetworkRelease({ rpc: node.rpc, ...selected, deployed: true }), /options/);
  await assert.rejects(verifyDeployedRelease(options), /chain does not match/);
});

test('later vesting release does not invalidate creation provenance and fixed contract links', async () => {
  const vesting = new Contract(plan.addresses.founderVesting, artifacts.FounderVesting.abi, await provider.getSigner(0));
  await provider.send('evm_setNextBlockTimestamp', [Date.parse(plan.claimsOpen) / 1000 + 86400]);
  await (await vesting.release()).wait();
  assert.ok(await vesting.released() > 0n);
  anchor = deploymentBlock(await provider.send('eth_getBlockByNumber', ['latest', false]));
  assert.equal((await inspect()).founderMintToVestingVerified, true);
});

test('deployment verification CLI refuses private malformed input without publishing a result', () => {
  const config = path.join(temporary, 'private-config.json'), out = path.join(temporary, 'absent.json');
  fs.writeFileSync(config, JSON.stringify({ ...options, rpc: 'https://rpc.invalid/?token=private-verification-marker', unexpected: true }));
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/verify-network-release.mjs', import.meta.url)),
    '--config', config, '--out', out], { encoding: 'utf8', windowsHide: true });
  assert.equal(result.status, 1); assert.equal(result.stdout, '');
  assert.equal(result.stderr.includes('private-verification-marker'), false); assert.equal(result.stderr.includes(config), false);
  assert.equal(fs.existsSync(out), false);
});
