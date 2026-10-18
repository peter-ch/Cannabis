import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Interface, keccak256, Transaction, toQuantity } from 'ethers';
import { quoteDeploymentFee } from '../launch/fees.mjs';

const abi = new Interface(['function getL1Fee(bytes) view returns (uint256)', 'function getL1FeeUpperBound(uint256) view returns (uint256)',
  'function getOperatorFee(uint256) view returns (uint256)', 'function version() view returns (string)',
  'function isFjord() view returns (bool)', 'function isIsthmus() view returns (bool)', 'function isJovian() view returns (bool)']);
const from = '0x1111111111111111111111111111111111111111', data = '0x60006000';
async function fixture(chainId = 1, mutate = () => {}) {
  const requests = [], block = { number: '0x64', hash: '0x' + 'aa'.repeat(32), timestamp: toQuantity(Math.floor(Date.now() / 1000)), baseFeePerGas: '0x2', gasLimit: '0x1c9c380' };
  const server = http.createServer(async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const request = JSON.parse(Buffer.concat(chunks)); requests.push(request);
      let result;
      switch (request.method) {
        case 'eth_chainId': result = toQuantity(chainId); break;
        case 'eth_getBlockByNumber': result = { ...block }; break;
        case 'eth_estimateGas': result = toQuantity(chainId === 42161 ? 112000 : 100000); break;
        case 'eth_gasPrice': result = '0x3'; break;
        case 'eth_maxPriorityFeePerGas': result = '0x1'; break;
        case 'eth_getBalance': result = toQuantity(1000000); break;
        case 'eth_getTransactionCount': result = '0x7'; break;
        case 'eth_getCode': result = '0x60016000'; break;
        case 'eth_call': {
          const call = abi.parseTransaction(request.params[0]);
          if (call.name === 'version') result = abi.encodeFunctionResult(call.name, ['1.6.0']);
          else if (call.name.startsWith('is')) result = abi.encodeFunctionResult(call.name, [true]);
          else if (call.name === 'getL1Fee') result = abi.encodeFunctionResult(call.name, [100]);
          else if (call.name === 'getL1FeeUpperBound') result = abi.encodeFunctionResult(call.name, [200]);
          else if (call.name === 'getOperatorFee') result = abi.encodeFunctionResult(call.name, [call.args[0] * 2n]);
          else throw Error('Unexpected oracle call');
          break;
        }
        default: throw Error('Unexpected RPC method');
      }
      const response = { jsonrpc: '2.0', id: request.id, result };
      const override = await mutate(request, response, requests);
      res.writeHead(override?.status ?? 200, override?.headers ?? { 'content-type': 'application/json' });
      res.end(override?.raw ?? JSON.stringify(response));
    } catch { res.writeHead(500); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { options: { rpc: `http://127.0.0.1:${server.address().port}`, transaction: { chainId: toQuantity(chainId), from, data, value: '0x0' }, expectedDataHash: keccak256(data) },
    requests, block, close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}

test('Ethereum deployment quote binds exact creation data and computes a buffered fee budget', async () => {
  const f = await fixture();
  try {
    const q = await quoteDeploymentFee(f.options);
    assert.equal(q.chainId, '1'); assert.equal(q.model, 'ethereum-eip1559');
    assert.equal(q.estimatedNetworkFeeWei, '300000'); assert.equal(q.planningBudgetWei, '600000');
    assert.equal(q.gasLimit, '120000'); assert.equal(q.proposedMaxFeePerGasWei, '5');
    assert.equal(q.nonce, '7'); assert.equal(q.planningShortfallWei, '0'); assert.equal(q.oracle, null);
    assert.equal(q.spendAuthorized, false); assert.equal(q.sent, false);
    const estimate = f.requests.find(r => r.method === 'eth_estimateGas');
    assert.deepEqual(estimate.params, [f.options.transaction, '0x64']);
    for (const r of f.requests.filter(r => ['eth_getBalance', 'eth_getTransactionCount'].includes(r.method))) assert.deepEqual(r.params[1], { blockHash: f.block.hash, requireCanonical: true });
    assert.equal(f.requests.some(r => /send|sign|personal/i.test(r.method)), false);
  } finally { await f.close(); }
});

test('Base quote adds L1 and operator fees and queries serialized unsigned bytes with all fee fields', async () => {
  const f = await fixture(8453);
  try {
    const q = await quoteDeploymentFee(f.options);
    assert.equal(q.estimatedNetworkFeeWei, '500100'); assert.equal(q.planningBudgetWei, '840400');
    assert.equal(q.l1DataFeeWei, '100'); assert.equal(q.l1DataSizeBoundWei, '200'); assert.equal(q.operatorFeeWei, '200000');
    assert.equal(q.bufferedOperatorFeeWei, '240000'); assert.equal(q.oracle.isJovian, true);
    const calls = f.requests.filter(r => r.method === 'eth_call');
    assert.ok(calls.every(r => r.params[1].blockHash === f.block.hash && r.params[1].requireCanonical));
    const l1 = calls.map(r => abi.parseTransaction(r.params[0])).find(r => r.name === 'getL1Fee');
    const tx = Transaction.from(l1.args[0]);
    assert.equal(tx.type, 2); assert.equal(tx.signature, null); assert.equal(tx.chainId, 8453n);
    assert.equal(tx.to, null); assert.equal(tx.value, 0n); assert.equal(tx.nonce, 7); assert.equal(tx.gasLimit, 120000n);
    assert.equal(tx.maxFeePerGas, 5n); assert.equal(tx.maxPriorityFeePerGas, 1n); assert.equal(tx.data, data);
    const bound = calls.map(r => abi.parseTransaction(r.params[0])).find(r => r.name === 'getL1FeeUpperBound');
    assert.equal(bound.args[0], BigInt((l1.args[0].length - 2) / 2));
  } finally { await f.close(); }
});

test('Arbitrum includes its L1 component once and reports funding shortfall', async () => {
  const f = await fixture(42161, (r, s) => { if (r.method === 'eth_getBalance') s.result = '0x0'; });
  try {
    const q = await quoteDeploymentFee(f.options);
    assert.equal(q.estimatedNetworkFeeWei, '336000'); assert.equal(q.planningBudgetWei, '672000');
    assert.equal(q.planningShortfallWei, '672000'); assert.equal(q.l1FeeIncludedInGasEstimate, true);
    assert.equal(q.l1DataFeeWei, null); assert.equal(f.requests.some(r => r.method === 'eth_call'), false);
  } finally { await f.close(); }
});

test('quote uses the higher current price when the suggested priority fee exceeds the gas-price quote', async () => {
  const f = await fixture(1, (r, s) => { if (r.method === 'eth_maxPriorityFeePerGas') s.result = '0xa'; });
  try { const q = await quoteDeploymentFee(f.options); assert.equal(q.feePriceForEstimateWei, '12'); assert.equal(q.estimatedNetworkFeeWei, '1200000'); assert.equal(q.proposedMaxFeePerGasWei, '14'); }
  finally { await f.close(); }
});

test('quote rejects value transfers, data substitution, unsupported chains and insecure endpoints before RPC', async () => {
  const f = await fixture();
  try {
    for (const change of [{ expectedDataHash: '0x' + 'bb'.repeat(32) }, { transaction: { ...f.options.transaction, value: '0x1' } },
      { transaction: { ...f.options.transaction, to: from } }, { transaction: { ...f.options.transaction, chainId: '0x89' } },
      { transaction: { ...f.options.transaction, data: '0x' } }, { transaction: { ...f.options.transaction, from: '0x' + '00'.repeat(20) } },
      { gasBufferBps: 10001 }, { rpc: 'http://example.invalid' }, { rpc: 'https://user:secret@example.invalid' }, { rpc: 'https://example.invalid/#secret' }]) {
      await assert.rejects(quoteDeploymentFee({ ...f.options, ...change }));
    }
    assert.equal(f.requests.length, 0);
  } finally { await f.close(); }
});

test('stale anchors, inconsistent estimates, changed canonical blocks and chain drift reject the quote', async () => {
  const mutations = [
    (r, s) => { if (r.method === 'eth_getBlockByNumber') s.result.timestamp = toQuantity(Math.floor(Date.now() / 1000) - 121); },
    (r, s) => { if (r.method === 'eth_getBlockByNumber') s.result.timestamp = toQuantity(Math.floor(Date.now() / 1000) + 31); },
    (r, s) => { if (r.method === 'eth_gasPrice') s.result = '0x1'; },
    (r, s) => { if (r.method === 'eth_estimateGas') s.result = toQuantity(21000); },
    (r, s) => { if (r.method === 'eth_estimateGas') s.result = toQuantity(16777216); },
    (r, s) => { if (r.method === 'eth_getBlockByNumber' && r.params[0] !== 'latest') s.result.hash = '0x' + 'bb'.repeat(32); },
    (r, s, all) => { if (r.method === 'eth_chainId' && all.length > 1) s.result = '0x2'; },
    (r, s) => { if (r.method === 'eth_getBalance') s.result = '0x00'; },
    (r, s) => { s.id = 999; },
    (r, s) => { if (r.method === 'eth_estimateGas') { delete s.result; s.error = { code: -32000, message: 'private account details' }; } }
  ];
  for (const mutation of mutations) {
    const f = await fixture(1, mutation);
    try { await assert.rejects(quoteDeploymentFee(f.options), e => !e.message.includes('private account details')); }
    finally { await f.close(); }
  }
});

test('Base oracle errors, missing components and unreviewed versions never produce a partial fee total', async () => {
  const mutations = [
    (r, s) => { if (r.method === 'eth_getCode') s.result = '0x'; },
    (r, s) => { if (r.method === 'eth_call' && abi.parseTransaction(r.params[0]).name === 'getOperatorFee') { delete s.result; s.error = { message: 'Unavailable' }; } },
    (r, s) => { if (r.method === 'eth_call' && abi.parseTransaction(r.params[0]).name === 'version') s.result = abi.encodeFunctionResult('version', ['2.0.0']); },
    (r, s) => { if (r.method === 'eth_call' && abi.parseTransaction(r.params[0]).name === 'isJovian') s.result = abi.encodeFunctionResult('isJovian', [false]); },
    (r, s) => { if (r.method === 'eth_call' && abi.parseTransaction(r.params[0]).name === 'getL1FeeUpperBound') s.result = abi.encodeFunctionResult('getL1FeeUpperBound', [99]); }
  ];
  for (const mutation of mutations) { const f = await fixture(8453, mutation); try { await assert.rejects(quoteDeploymentFee(f.options)); } finally { await f.close(); } }
});

test('quote reader rejects redirects, oversized bodies and malformed text without disclosing response contents', async () => {
  for (const override of [{ status: 302, headers: { location: 'https://example.invalid/private' } }, { raw: 'x'.repeat(256 * 1024 + 1) }, { raw: 'private-malformed-json' }, { raw: Buffer.from([0xff]) }]) {
    const f = await fixture(1, () => override);
    try { await assert.rejects(quoteDeploymentFee(f.options), e => e.message === 'Fee-estimation RPC failed; no incomplete fee total is returned'); }
    finally { await f.close(); }
  }
});

test('quote CLI binds an unsigned manifest, protects existing outputs and suppresses private error content', async () => {
  const f = await fixture(), dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-fee-'));
  const cli = fileURLToPath(new URL('../scripts/quote-launch.mjs', import.meta.url));
  const run = args => new Promise(resolve => {
    const child = spawn(process.execPath, [cli, ...args], { windowsHide: true }); let stdout = '', stderr = '';
    child.stdout.on('data', x => stdout += x); child.stderr.on('data', x => stderr += x);
    child.on('exit', code => resolve({ code, stdout, stderr }));
  });
  try {
    const manifestFile = path.join(dir, 'manifest.json'), config = path.join(dir, 'config.json'), out = path.join(dir, 'quote.json');
    fs.writeFileSync(manifestFile, JSON.stringify({ name: 'Cannabis', status: 'UNSIGNED_DRAFT', deploymentDataKeccak256: f.options.expectedDataHash,
      chain: { chainId: 1 }, founderBeneficiary: from, transaction: f.options.transaction }));
    fs.writeFileSync(config, JSON.stringify({ manifestFile, rpc: f.options.rpc, expectedDataHash: f.options.expectedDataHash }));
    assert.equal((await run(['--config', config, '--out', out])).code, 0);
    const original = fs.readFileSync(out); assert.equal(JSON.parse(original).estimatedNetworkFeeWei, '300000');
    assert.equal((await run(['--config', config, '--out', out])).code, 1); assert.deepEqual(fs.readFileSync(out), original);
    fs.writeFileSync(config, '{"secret":"do-not-print-wallet-information"');
    const failed = await run(['--config', config, '--out', path.join(dir, 'failed.json')]);
    assert.equal(failed.code, 1); assert.equal(failed.stderr.includes('do-not-print-wallet-information'), false);
  } finally {
    await f.close();
    const resolved = fs.realpathSync(dir);
    if (path.dirname(resolved) !== fs.realpathSync(os.tmpdir()) || !path.basename(resolved).startsWith('cannabis-fee-')) throw Error('Unexpected cleanup target');
    fs.rmSync(resolved, { recursive: true, force: true });
  }
});
