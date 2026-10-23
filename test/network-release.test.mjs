import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import solc from 'solc';
import { Contract, ContractFactory, ZeroAddress, Wallet, keccak256, parseEther, toQuantity } from 'ethers';
import { compile } from '../scripts/compile.mjs';
import { startNode, deployLocal, localSources } from '../scripts/lib.mjs';
import { buildRelease, releaseArtifacts, validateRelease } from '../launch/release.mjs';
import { verifyLaunchDependencies } from '../launch/dependencies.mjs';
import { observeReleaseState } from '../launch/release-state.mjs';
import { prepareNetworkRelease } from '../scripts/prepare-network-release.mjs';
import { dependencyRPC } from './fixtures/dependency-rpc.mjs';

const configuration = () => ({ schema: 'cannabis.release-configuration.v1', chainId: '1',
  deployer: '0x' + '11'.repeat(20), founder: '0x' + '11'.repeat(20), firstNonce: '5',
  launch: new Date(Date.now() + 14 * 86400000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  minimumClaimMembers: 1, registryReviewers: ['55', '66', '77'].map(pair => '0x' + pair.repeat(20)), registryQuorum: 2 });
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
let artifacts;
before(() => { artifacts = compile(); });
const temporary = [];
after(() => {
  const parent = fs.realpathSync(os.tmpdir());
  for (const dir of temporary) {
    const target = fs.realpathSync(dir);
    assert.equal(path.dirname(target), parent);
    assert.ok(path.basename(target).startsWith('cannabis-network-release-'));
    fs.rmSync(target, { recursive: true });
  }
});
function temp() { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-network-release-')); temporary.push(dir); return dir; }
async function fixture(mutator = () => {}) {
  const config = configuration();
  return dependencyRPC(async (request, response, context) => {
    if (request.method === 'eth_getTransactionCount' && request.params[0].toLowerCase() === config.deployer.toLowerCase())
      response.result = toQuantity(config.firstNonce);
    await mutator(request, response, context);
  }, '1');
}

test('complete plan binds all five transactions, child addresses, dates, assets and fees', async () => {
  const rpc = await fixture();
  try {
    const config = configuration(), plan = await buildRelease(config, rpc.config.dependencies, artifacts);
    assert.deepEqual(plan.transactions.map(tx => tx.role), ['registrar', 'token', 'nativeEscrow', 'cannabisEscrow', 'market']);
    assert.deepEqual(plan.transactions.map(tx => tx.transaction.nonce), ['0x5', '0x6', '0x7', '0x8', '0x9']);
    assert.equal(new Set(Object.values(plan.addresses)).size, 7);
    assert.equal(plan.transactions[0].constructorArguments[0], plan.addresses.enrollment);
    assert.equal(plan.transactions[1].constructorArguments[4], plan.addresses.registrar);
    assert.equal(plan.transactions[1].constructorArguments[5], 1);
    assert.equal(plan.expected.escrowFeeRecipient, config.founder);
    assert.equal(plan.expected.nativeEscrowAsset, ZeroAddress);
    assert.equal(plan.expected.cannabisEscrowAsset, plan.addresses.token);
    assert.equal(plan.expected.feeBps, 100);
    assert.equal(plan.status, 'UNSIGNED_DRAFT'); assert.equal(plan.sent, false); assert.equal(plan.signingAuthorized, false);
    for (const entry of plan.transactions) {
      assert.equal(keccak256(entry.transaction.data), entry.deploymentDataKeccak256);
      assert.equal(entry.transaction.chainId, '0x1'); assert.equal(entry.transaction.from, config.deployer);
      assert.equal(entry.transaction.value, '0x0');
      assert.equal(Object.hasOwn(entry.transaction, 'to'), false);
    }
    for (const minimumClaimMembers of [1, 4, 8, 990000])
      assert.equal(validateRelease({ ...config, minimumClaimMembers }, rpc.config.dependencies).configuration.minimumClaimMembers, minimumClaimMembers);
  } finally { await rpc.close(); }
});

test('configuration refuses ambiguous networks, nonces, dates, quorums and unsafe identities', async () => {
  const rpc = await fixture();
  try {
    const config = configuration(), pins = rpc.config.dependencies;
    for (const change of [{ chainId: '8453' }, { chainId: 1 }, { extra: true }, { firstNonce: '05' }, { firstNonce: 5 },
      { firstNonce: '-1' }, { firstNonce: '9007199254740991' }, { deployer: ZeroAddress },
      { founder: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' }, { launch: '2026-10-18' },
      { minimumClaimMembers: 0 }, { minimumClaimMembers: undefined }, { registryQuorum: 1 }, { registryQuorum: 4 },
      { registryReviewers: [...config.registryReviewers].reverse() },
      { registryReviewers: Array(3).fill(config.registryReviewers[0]) }])
      assert.throws(() => validateRelease({ ...config, ...change }, pins));
    await assert.rejects(buildRelease(config, pins, { ...artifacts, ComputeEscrow: undefined }));
    await assert.rejects(buildRelease(config, pins, { ...artifacts, ComputeMarket: { ...artifacts.ComputeMarket, compiler: 'changed' } }));
  } finally { await rpc.close(); }
});

test('canonical state refuses pending nonce, delegated sender, occupied targets and reorganization', async () => {
  let mode = '', observed = false;
  const rpc = await fixture((request, response) => {
    if (!observed) return;
    const isSender = request.params[0]?.toLowerCase?.() === configuration().deployer.toLowerCase();
    if (mode === 'pending' && request.method === 'eth_getTransactionCount' && request.params[1] === 'pending') response.result = '0x6';
    if (mode === 'sender-nonce' && request.method === 'eth_getTransactionCount' && isSender) response.result = '0x4';
    if (mode === 'delegated' && request.method === 'eth_getCode' && isSender) response.result = '0xef0100' + '88'.repeat(20);
    if (mode === 'occupied-code' && request.method === 'eth_getCode' && !isSender) response.result = '0x00';
    if (mode === 'occupied-nonce' && request.method === 'eth_getTransactionCount' && !isSender) response.result = '0x1';
    if (mode === 'reorg' && request.method === 'eth_getBlockByNumber') response.result.hash = '0x' + 'cc'.repeat(32);
    if (mode === 'wrong-chain' && request.method === 'eth_chainId') response.result = '0x7a69';
    if (mode === 'head-advanced' && request.method === 'eth_getBlockByNumber' && request.params[0] === 'latest') response.result.hash = '0x' + 'dd'.repeat(32);
  });
  try {
    const config = configuration(), dependencies = await verifyLaunchDependencies(rpc.config); observed = true;
    const result = await observeReleaseState(config, rpc.config, dependencies);
    assert.equal(result.targetsUnoccupied, true); assert.equal(result.pendingNonceMatched, true); assert.equal(result.sent, false);
    for (mode of ['pending', 'sender-nonce', 'delegated', 'occupied-code', 'occupied-nonce', 'reorg', 'wrong-chain', 'head-advanced'])
      await assert.rejects(observeReleaseState(config, rpc.config, dependencies), undefined, mode);
    mode = '';
    await assert.rejects(observeReleaseState(config, rpc.config, { ...dependencies, runtimeAndLinksMatched: false }));
    await assert.rejects(observeReleaseState(config, rpc.config, { ...dependencies, checkedHead: { ...dependencies.checkedHead, timestamp: 1 } }));
    assert.ok(rpc.requests.every(r => ['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call', 'eth_getTransactionCount'].includes(r.method)));
  } finally { await rpc.close(); }
});

test('exported complete compiler input reproduces every creation transaction and package commitment', async () => {
  let refuse = false, mutateCaller;
  const rpc = await fixture((request, response) => {
    if (mutateCaller) { const mutate = mutateCaller; mutateCaller = undefined; mutate(); }
    if (refuse && request.method === 'eth_getTransactionCount' && request.params[1] === 'pending') response.result = '0x6';
  });
  try {
    const parent = temp(), out = path.join(parent, 'review');
    const options = { configuration: configuration(), dependencyConfig: structuredClone(rpc.config), out };
    const expectedConfiguration = structuredClone(options.configuration);
    mutateCaller = () => {
      options.configuration.firstNonce = '9';
      options.configuration.registryReviewers.reverse();
      options.dependencyConfig.rpc = 'http://127.0.0.1:1';
    };
    const result = await prepareNetworkRelease(options);
    assert.equal(result.transactions, 5); assert.equal(result.sent, false);
    const raw = fs.readFileSync(result.manifestPath), manifest = JSON.parse(raw);
    assert.deepEqual(manifest.configuration, expectedConfiguration);
    assert.equal(manifest.stateObservation.firstNonce, expectedConfiguration.firstNonce);
    options.configuration = expectedConfiguration;
    options.dependencyConfig = rpc.config;
    assert.equal(raw.includes(rpc.config.rpc), false);
    for (const [name, digest] of Object.entries(manifest.files)) assert.equal(sha(fs.readFileSync(path.join(out, name))), digest);
    const { preparedAt, files, packageSHA256, dependencyObservation, stateObservation, ...plan } = manifest;
    assert.equal(sha(JSON.stringify({ plan, files })), packageSHA256);
    const output = JSON.parse(solc.compile(fs.readFileSync(path.join(out, 'compiler-input.json'), 'utf8')));
    assert.deepEqual((output.errors ?? []).filter(e => e.severity === 'error'), []);
    for (const entry of manifest.transactions) {
      const contract = Object.values(output.contracts).find(source => source[entry.contract])?.[entry.contract];
      const { data } = await new ContractFactory(contract.abi, '0x' + contract.evm.bytecode.object).getDeployTransaction(...entry.constructorArguments);
      assert.equal(data, entry.transaction.data);
    }
    assert.equal(releaseArtifacts.length, 6);
    await assert.rejects(prepareNetworkRelease(options), /unused review/);
    refuse = true;
    const refusedOut = path.join(parent, 'refused');
    await assert.rejects(prepareNetworkRelease({ ...options, out: refusedOut }), /Pending transactions/);
    assert.equal(fs.existsSync(refusedOut), false);
    assert.deepEqual(fs.readFileSync(result.manifestPath), raw);
  } finally { await rpc.close(); }
});

test('emitted creation data deploys the complete linked network at a nonzero nonce on the isolated chain', async () => {
  const extra = compile(localSources), port = await new Promise(resolve => {
    const server = net.createServer(); server.listen(0, '127.0.0.1', () => { const value = server.address().port; server.close(() => resolve(value)); });
  });
  const node = await startNode(port, 'network-release-test-node.log'), provider = node.provider;
  try {
    assert.equal((await provider.getNetwork()).chainId, 31337n);
    const deps = await deployLocal(provider, extra, { memberCount: 0 });
    const deployer = Wallet.createRandom().connect(provider), config = configuration();
    await provider.send('hardhat_setBalance', [deployer.address, toQuantity(parseEther('100'))]);
    await provider.send('hardhat_setNonce', [deployer.address, '0x5']);
    config.deployer = config.founder = deployer.address;
    const pins = { schema: 'cannabis.semaphore-dependencies.v1', chainId: '1', poseidonLinkOffsets: [1] };
    for (const [name, address] of [['semaphore', await deps.semaphore.getAddress()], ['verifier', await deps.verifier.getAddress()],
      ['poseidon', '0x' + '44'.repeat(20)]]) pins[name] = { address, codeHash: keccak256('0x00') };
    const plan = await buildRelease(config, pins, artifacts);
    for (const entry of plan.transactions) {
      // Only the chain ID is changed for this explicitly isolated fixture. All
      // creation data, nonces, sender and address predictions remain identical.
      const receipt = await (await deployer.sendTransaction({ ...entry.transaction, chainId: 31337 })).wait();
      assert.equal(receipt.status, 1);
      assert.equal(receipt.contractAddress, entry.expectedAddress);
    }
    const at = (role, name) => new Contract(plan.addresses[role], artifacts[name].abi, provider);
    const token = at('token', 'Cannabis'), registrar = at('registrar', 'CommunityRegistrar');
    const enrollment = at('enrollment', 'CannabisEnrollment'), vesting = at('founderVesting', 'FounderVesting');
    assert.equal(await token.enrollment(), plan.addresses.enrollment); assert.equal(await token.founderVesting(), plan.addresses.founderVesting);
    assert.equal(await token.semaphore(), pins.semaphore.address); assert.equal(await enrollment.semaphore(), pins.semaphore.address);
    assert.equal(await token.CAP(), parseEther('420000000')); assert.equal(await token.totalSupply(), parseEther('4200000'));
    assert.equal(await token.balanceOf(plan.addresses.founderVesting), parseEther('4200000'));
    assert.equal(await token.balanceOf(config.founder), 0n); assert.equal(await token.communityIssued(), 0n);
    assert.equal(await token.minimumClaimMembers(), 1n); assert.equal(await token.claimPolicyAuthority(), config.founder);
    assert.equal(await enrollment.registrar(), plan.addresses.registrar); assert.equal(await enrollment.enrolledCount(), 0n);
    assert.equal(await registrar.enrollment(), plan.addresses.enrollment); assert.equal(await registrar.registryQuorum(), 2n);
    for (let i = 0; i < config.registryReviewers.length; ++i) assert.equal(await registrar.registryReviewers(i), config.registryReviewers[i]);
    assert.equal(await vesting.token(), plan.addresses.token); assert.equal(await vesting.beneficiary(), config.founder);
    assert.equal(Number(await vesting.start()), Date.parse(plan.claimsOpen) / 1000);
    assert.equal(Number(await vesting.end()), Date.parse(plan.founderVestingEnds) / 1000);
    for (const [role, asset] of [['nativeEscrow', ZeroAddress], ['cannabisEscrow', plan.addresses.token]]) {
      const escrow = at(role, 'ComputeEscrow');
      assert.equal(await escrow.token(), asset); assert.equal(await escrow.founderRecipient(), config.founder);
      assert.equal(await escrow.FEE_BPS(), 100n); assert.equal(await escrow.totalLiability(), 0n);
    }
    const market = at('market', 'ComputeMarket');
    assert.equal(await market.nativeEscrow(), plan.addresses.nativeEscrow);
    assert.equal(await market.cannabisEscrow(), plan.addresses.cannabisEscrow);
  } finally { provider.destroy(); node.child.kill(); }
});

test('release CLI errors do not disclose private RPC configuration', () => {
  const parent = temp(), config = path.join(parent, 'private.json'), marker = 'private-release-rpc-credential';
  fs.writeFileSync(config, 'https://rpc.invalid/?key=' + marker);
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/prepare-network-release.mjs', import.meta.url)),
    '--config', config, '--dependency-config', config, '--out', path.join(parent, 'out')], { encoding: 'utf8', windowsHide: true });
  assert.equal(result.status, 1); assert.equal(result.stdout, '');
  assert.equal(result.stderr.includes(marker), false); assert.equal(result.stderr.includes(config), false);
  assert.equal(fs.existsSync(path.join(parent, 'out')), false);
});
