import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Interface, keccak256, parseEther, toQuantity } from 'ethers';
import { compile, root } from '../scripts/compile.mjs';
import { buildRelease, releaseArtifacts } from '../launch/release.mjs';
import { readReleasePackage } from '../launch/release-package.mjs';
import { releaseGetters } from '../launch/release-getters.mjs';
import { quoteNetworkRelease } from '../launch/release-fees.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const hash = n => '0x' + n.toString(16).padStart(64, '0');
const address = n => '0x' + n.repeat(20);
const codes = { semaphore: '0x73' + address('44').slice(2) + '600056', verifier: '0x600160005260206000f3', poseidon: '0x600260005260206000f3' };
const dependencies = { schema: 'cannabis.semaphore-dependencies.v1', chainId: '1', poseidonLinkOffsets: [1] };
for (const [name, pair] of [['semaphore', '22'], ['verifier', '33'], ['poseidon', '44']])
  dependencies[name] = { address: address(pair), codeHash: keccak256(codes[name]) };
const configuration = { schema: 'cannabis.release-configuration.v1', chainId: '1',
  deployer: address('11'), founder: address('11'), firstNonce: '5',
  launch: new Date(Date.now() + 14 * 86400000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  minimumClaimMembers: 1, registryReviewers: ['55', '66', '77'].map(address), registryQuorum: 2 };
let temporary, manifestFile, packageSHA256, plan;
before(async () => {
  const artifacts = compile();
  plan = await buildRelease(configuration, dependencies, artifacts);
  temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-release-fees-'));
  fs.mkdirSync(path.join(temporary, 'artifacts'));
  const bytes = { 'compiler-input.json': fs.readFileSync(path.join(root, 'artifacts/compiler-input.json')) };
  for (const name of releaseArtifacts) bytes[`artifacts/${name}.json`] = Buffer.from(JSON.stringify(artifacts[name]));
  const files = Object.fromEntries(Object.entries(bytes).map(([name, data]) => {
    fs.writeFileSync(path.join(temporary, name), data); return [name, sha(data)];
  }));
  packageSHA256 = sha(JSON.stringify({ plan, files }));
  manifestFile = path.join(temporary, 'network-release.json');
  fs.writeFileSync(manifestFile, JSON.stringify({ ...plan, files, packageSHA256, preparedAt: new Date().toISOString() }));
});
after(() => {
  if (!temporary) return;
  const resolved = fs.realpathSync(temporary);
  assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir()));
  assert.ok(path.basename(resolved).startsWith('cannabis-release-fees-'));
  fs.rmSync(resolved, { recursive: true });
});

// Deliberately canned protocol replies; the separate retained real RPC run
// establishes execution-engine compatibility, not this fixture.
async function fixture(mutate = () => {}) {
  const requests = [], now = Math.floor(Date.now() / 1000), abi = new Interface(['function verifier() view returns (address)']);
  const head = { number: '0x65', timestamp: toQuantity(now), hash: hash(101), baseFeePerGas: '0x3b9aca00', gasLimit: '0x3938700' };
  const finalized = { ...head, number: '0x64', timestamp: toQuantity(now - 30), hash: hash(100) };
  const server = http.createServer(async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const request = JSON.parse(Buffer.concat(chunks)); requests.push(request);
      const { method, params } = request; let result;
      if (method === 'eth_chainId') result = '0x1';
      else if (method === 'eth_getBlockByNumber') result = structuredClone(['0x64', 'finalized'].includes(params[0]) ? finalized : head);
      else if (method === 'eth_getCode') result = codes[Object.keys(dependencies).find(k => dependencies[k]?.address === params[0])] ?? '0x';
      else if (method === 'eth_getTransactionCount') result = params[0] === configuration.deployer ? '0x5' : '0x0';
      else if (method === 'eth_getBalance') result = toQuantity(parseEther('1'));
      else if (method === 'eth_gasPrice') result = toQuantity(1100000000n);
      else if (method === 'eth_maxPriorityFeePerGas') result = toQuantity(100000000n);
      else if (method === 'eth_call') result = abi.encodeFunctionResult('verifier', [dependencies.verifier.address]);
      else if (method === 'eth_simulateV1') {
        assert.deepEqual(Object.keys(params[0]).sort(), ['blockStateCalls', 'returnFullTransactions', 'traceTransfers', 'validation']);
        assert.equal(params[1], head.hash);
        let parent = head.hash;
        const getters = releaseGetters(plan);
        result = params[0].blockStateCalls.map((entry, index) => {
          assert.deepEqual(Object.keys(entry), ['calls']); // no state/block overrides
          const calls = entry.calls.map((call, i) => ({
            status: '0x1', returnData: index < 5 ? '0x60006000' : getters[i].expected ?? hash(42),
            gasUsed: toQuantity(index < 5 ? 2000000 : 30000), maxUsedGas: toQuantity(index < 5 ? 2100000 : 30000), logs: []
          }));
          const block = { ...head, number: toQuantity(102 + index), timestamp: toQuantity(now + 12 * (index + 1)),
            hash: hash(200 + index), parentHash: parent, baseFeePerGas: params[0].validation ? head.baseFeePerGas : '0x0',
            gasUsed: toQuantity(calls.reduce((sum, call) => sum + BigInt(call.gasUsed), 0n)), calls,
            transactions: entry.calls.map(({ data, ...call }) => ({ ...call, to: call.to ?? null, input: data, accessList: [] })) };
          parent = block.hash; return block;
        });
      } else throw Error('Unexpected read-only RPC method');
      const response = { jsonrpc: '2.0', id: request.id, result };
      await mutate(request, response, requests);
      res.writeHead(200, { 'content-type': 'application/json', connection: 'close' }); res.end(JSON.stringify(response));
    } catch { res.writeHead(500); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { options: { rpc: `http://127.0.0.1:${server.address().port}`, manifestFile, expectedPackageSHA256: packageSHA256 }, requests,
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}

test('complete release fee quote binds all five creations, postconditions and actual aggregate budget', async () => {
  let mutateOptions;
  const server = await fixture(() => { if (mutateOptions) { mutateOptions(); mutateOptions = null; } });
  try {
    const expected = structuredClone(server.options);
    mutateOptions = () => { server.options.expectedPackageSHA256 = '0'.repeat(64); server.options.gasBufferBps = 10000; server.options.rpc = 'http://127.0.0.1:1'; };
    const quote = await quoteNetworkRelease(server.options);
    assert.equal(quote.packageSHA256, expected.expectedPackageSHA256);
    assert.equal(quote.transactions.length, 5); assert.equal(quote.postconditionsChecked, releaseGetters(plan).length);
    assert.equal(quote.gasBufferBps, 2000);
    assert.deepEqual(quote.transactions.map(tx => tx.role), plan.transactions.map(tx => tx.role));
    assert.equal(quote.estimatedNetworkFeeWei, '11000000000000000');
    assert.equal(quote.planningBudgetWei, '26460000000000000');
    assert.equal(quote.nativeBalanceWei, parseEther('1').toString());
    assert.equal(quote.simulationValidationPassed, true); assert.equal(quote.spendAuthorized, false); assert.equal(quote.sent, false);
    assert.equal(quote.stateOverridesUsed, false); assert.equal(quote.blockOverridesUsed, false);
    const simulations = server.requests.filter(r => r.method === 'eth_simulateV1');
    assert.deepEqual(simulations.map(r => r.params[0].validation), [false, true]);
    assert.deepEqual(simulations.map(r => r.params[0].blockStateCalls.length), [6, 5]);
    for (const entry of simulations[1].params[0].blockStateCalls) assert.equal(entry.calls[0].gas, toQuantity(2520000));
    assert.ok(server.requests.every(r => !/send|sign|set|impersonate/i.test(r.method)));
  } finally { await server.close(); }
});

test('release package refuses altered files, incomplete or forged plans and mismatched independent digests', async () => {
  assert.deepEqual((await readReleasePackage(manifestFile, packageSHA256)).plan, plan);
  await assert.rejects(readReleasePackage(manifestFile, '0'.repeat(64)), /commitment/);
  const target = path.join(temporary, 'artifacts/ComputeMarket.json'), saved = fs.readFileSync(target);
  try { fs.writeFileSync(target, '{}'); await assert.rejects(readReleasePackage(manifestFile, packageSHA256), /artifact/); }
  finally { fs.writeFileSync(target, saved); }
  const original = fs.readFileSync(manifestFile);
  try {
    const incomplete = JSON.parse(original);
    delete incomplete.files['artifacts/ComputeEscrow.json'];
    const { files: partialFiles, preparedAt: partialDate, packageSHA256: partialHash, ...partialPlan } = incomplete;
    incomplete.packageSHA256 = sha(JSON.stringify({ plan: partialPlan, files: partialFiles }));
    fs.writeFileSync(manifestFile, JSON.stringify(incomplete));
    await assert.rejects(readReleasePackage(manifestFile, incomplete.packageSHA256), /Incomplete release files/);
    const manifest = JSON.parse(original);
    manifest.transactions[4].transaction.nonce = '0x2';
    const { files, preparedAt, packageSHA256: old, ...changedPlan } = manifest;
    manifest.packageSHA256 = sha(JSON.stringify({ plan: changedPlan, files }));
    fs.writeFileSync(manifestFile, JSON.stringify(manifest));
    await assert.rejects(readReleasePackage(manifestFile, manifest.packageSHA256), /does not reproduce/);
  } finally { fs.writeFileSync(manifestFile, original); }
});

test('complete quote refuses failed, partial, reordered, changed, excessive and incorrectly linked simulations', async () => {
  let mode, reached;
  const server = await fixture((request, response) => {
    if (request.method !== 'eth_simulateV1') return;
    const blocks = response.result, first = blocks[0], validated = request.params[0].validation;
    if (!mode.startsWith('validation-') || validated) reached = true;
    if (mode === 'failed') first.calls[0].status = '0x0';
    if (mode === 'error') first.calls[0].error = { code: 3 };
    if (mode === 'missing-block') blocks.pop();
    if (mode === 'extra-call') first.calls.push(first.calls[0]);
    if (mode === 'nonce') first.transactions[0].nonce = '0x6';
    if (mode === 'data') first.transactions[0].input = '0x00';
    if (mode === 'gas') first.calls[0].maxUsedGas = toQuantity(16777216);
    if (mode === 'refund') first.calls[0].maxUsedGas = '0x1';
    if (mode === 'parent') first.parentHash = hash(9);
    if (mode === 'time') first.timestamp = '0x1';
    if (mode === 'block-gas') first.gasUsed = '0x1';
    if (mode === 'postcondition' && !validated) blocks[5].calls[0].returnData = hash(1);
    if (mode === 'group' && !validated) blocks[5].calls[releaseGetters(plan).findIndex(g => g.relation)].returnData = hash(1);
    if (mode === 'validation-runtime' && validated) first.calls[0].returnData = '0x6001';
    if (mode === 'validation-fee' && validated) first.baseFeePerGas = toQuantity(100000000000n);
    if (mode === 'rpc-error') response.error = { code: -32000, message: 'owned refusal' };
  });
  try {
    for (mode of ['failed', 'error', 'missing-block', 'extra-call', 'nonce', 'data', 'gas', 'refund', 'parent',
      'time', 'block-gas', 'postcondition', 'group', 'validation-runtime', 'validation-fee', 'rpc-error'])
    {
      reached = false;
      await assert.rejects(quoteNetworkRelease(server.options), undefined, mode);
      assert.equal(reached, true, 'Must reach the intended simulated failure: ' + mode);
    }
  } finally { await server.close(); }
});

test('complete quote refuses changed custody prerequisites, funding, dependencies and canonical state', async () => {
  let mode;
  const server = await fixture((request, response, requests) => {
    const { method, params } = request, sender = params[0] === configuration.deployer;
    if (mode === 'pending' && method === 'eth_getTransactionCount' && params[1] === 'pending') response.result = '0x6';
    if (mode === 'delegated' && method === 'eth_getCode' && sender) response.result = '0xef0100' + address('88').slice(2);
    if (mode === 'occupied' && method === 'eth_getTransactionCount' && !sender) response.result = '0x1';
    if (mode === 'balance' && method === 'eth_getBalance') response.result = '0x0';
    if (mode === 'dependency' && method === 'eth_getCode' && params[0] === dependencies.semaphore.address) response.result = '0x00';
    if (mode === 'reorg' && method === 'eth_getBlockByNumber' && requests.some(r => r.method === 'eth_simulateV1')) response.result.hash = hash(9);
    if (mode === 'stale' && method === 'eth_getBlockByNumber') response.result.timestamp = '0x1';
    if (mode === 'wrong-chain' && method === 'eth_chainId') response.result = '0x7a69';
  });
  try {
    for (mode of ['pending', 'delegated', 'occupied', 'balance', 'dependency', 'reorg', 'stale', 'wrong-chain']) {
      server.requests.length = 0;
      await assert.rejects(quoteNetworkRelease(server.options), error => {
        const expected = { pending: /sender, nonce/, delegated: /sender, nonce/, occupied: /target is occupied/,
          balance: /Native balance/, dependency: /runtime-code mismatch/, reorg: /Canonical fee anchor/,
          stale: /stale/, 'wrong-chain': /does not match/ };
        assert.match(error.message, expected[mode]);
        if (mode === 'balance') {
          assert.equal(error.funding.status, 'UNVALIDATED_FUNDING_SHORTFALL');
          assert.equal(error.funding.shortfallWei, error.funding.planningBudgetWei);
          assert.equal(error.funding.simulationValidationPassed, false);
          assert.equal(error.funding.sent, false);
        }
        return true;
      }, mode);
    }
    await assert.rejects(quoteNetworkRelease({ ...server.options, stateOverrides: {} }), /options/);
    await assert.rejects(quoteNetworkRelease({ ...server.options, gasBufferBps: -1 }), /buffer/);
  } finally { await server.close(); }
});

test('complete quote CLI keeps failed configurations private and does not write output', () => {
  const config = path.join(temporary, 'private-config.json'), out = path.join(temporary, 'not-created.json');
  fs.writeFileSync(config, JSON.stringify({ rpc: 'https://rpc.invalid/?token=private-marker', manifestFile, expectedPackageSHA256: '0'.repeat(64) }));
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/quote-network-release.mjs', import.meta.url)),
    '--config', config, '--out', out], { encoding: 'utf8', windowsHide: true });
  assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.equal(result.stderr.includes('private-marker'), false);
  assert.equal(result.stderr.includes(config), false); assert.equal(fs.existsSync(out), false);
});
