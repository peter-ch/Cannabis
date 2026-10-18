import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { validateDependencies, verifyLaunchDependencies } from '../launch/dependencies.mjs';
import { dependencyRPC } from './fixtures/dependency-rpc.mjs';

test('dependency check binds finalized and fresh canonical state without signing or exposing the RPC URL', async () => {
  const fixture = await dependencyRPC();
  try {
    const result = await verifyLaunchDependencies({ ...fixture.config, rpc: fixture.config.rpc + '/?key=not-for-reporting' });
    assert.equal(result.runtimeAndLinksMatched, true); assert.equal(result.sent, false);
    assert.equal(result.anchor.number, 100); assert.equal(result.anchor.tag, 'finalized');
    assert.equal(result.checkedHead.number, 101);
    assert.equal(JSON.stringify(result).includes('not-for-reporting'), false);
    assert.equal(fixture.requests.filter(r => r.method === 'eth_getCode').length, 6);
    for (const request of fixture.requests) {
      assert.ok(['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call'].includes(request.method));
      if (['eth_getCode', 'eth_call'].includes(request.method)) {
        assert.equal(request.params[1].requireCanonical, true);
        assert.match(request.params[1].blockHash, /^0x[0-9a-f]{64}$/);
      }
    }
  } finally { await fixture.close(); }
});

test('dependency checker rejects wrong chains, code and verifier at both observed blocks', async () => {
  for (const mode of ['chain', 'code-finalized', 'code-current', 'empty', 'verifier']) {
    const fixture = await dependencyRPC((request, response, state) => {
      if (mode === 'chain' && request.method === 'eth_chainId') response.result = '0x1';
      if (request.method === 'eth_getCode' && (mode === 'empty' || (mode === 'code-finalized' && request.params[1].blockHash === state.anchor.hash) || (mode === 'code-current' && request.params[1].blockHash === state.head.hash))) response.result = mode === 'empty' ? '0x' : '0x6000';
      if (mode === 'verifier' && request.method === 'eth_call') response.result = '0x' + '00'.repeat(12) + '11'.repeat(20);
    });
    try { await assert.rejects(verifyLaunchDependencies(fixture.config), /chain|runtime-code|verifier/); }
    finally { await fixture.close(); }
  }
});

test('dependency checker rejects stale, future, inconsistent and reorganized anchors', async () => {
  for (const mode of ['stale-finalized', 'stale-head', 'future', 'earlier-head', 'reorg-finalized', 'reorg-head', 'changed-chain']) {
    const fixture = await dependencyRPC((request, response, state) => {
      if (mode === 'changed-chain' && request.method === 'eth_chainId' && state.requests.length > 1) response.result = '0x1';
      if (request.method !== 'eth_getBlockByNumber') return;
      const tag = request.params[0];
      if ((mode === 'stale-finalized' && tag === 'finalized') || (mode === 'stale-head' && tag === 'latest')) response.result.timestamp = '0x1';
      if (mode === 'future') response.result.timestamp = '0x' + (Math.floor(Date.now()/1000) + 1000).toString(16);
      if (mode === 'earlier-head' && tag === 'latest') response.result.number = '0x63';
      if ((mode === 'reorg-finalized' && tag === '0x64') || (mode === 'reorg-head' && tag === '0x65')) response.result.hash = '0x' + 'cc'.repeat(32);
    });
    try { await assert.rejects(verifyLaunchDependencies(fixture.config), /stale|future|inconsistent|changed|chain/); }
    finally { await fixture.close(); }
  }
});

test('missing EIP-1898 state and malformed RPC envelopes fail without weaker fallback', async () => {
  for (const mode of ['missing-history', 'wrong-id', 'oversize']) {
    const fixture = await dependencyRPC((request, response) => {
      if (mode === 'missing-history' && request.method === 'eth_getCode') { delete response.result; response.error = { code: -32000, message: 'historical state unavailable' }; }
      if (mode === 'wrong-id') response.id++;
      if (mode === 'oversize') response.result = 'x'.repeat(300000);
    });
    try {
      await assert.rejects(verifyLaunchDependencies(fixture.config), /RPC read failed/);
      for (const request of fixture.requests.filter(r => r.method === 'eth_getCode')) assert.equal(typeof request.params[1], 'object');
    } finally { await fixture.close(); }
  }
});

test('reviewed library references are checked separately from the runtime hashes', async () => {
  const fixture = await dependencyRPC();
  try {
    const dependencies = structuredClone(fixture.config.dependencies); dependencies.poseidonLinkOffsets = [2];
    await assert.rejects(verifyLaunchDependencies({ ...fixture.config, dependencies }), /library link/);
    for (const changes of [{ schema: 'unknown' }, { chainId: '08453' }, { poseidonLinkOffsets: [] }, { poseidonLinkOffsets: [1, 2] }, { extra: true }]) assert.throws(() => validateDependencies({ ...fixture.config.dependencies, ...changes }));
    const duplicate = structuredClone(fixture.config.dependencies); duplicate.verifier = duplicate.semaphore;
    assert.throws(() => validateDependencies(duplicate), /distinct/);
    await assert.rejects(verifyLaunchDependencies({ ...fixture.config, rpc: 'http://example.com' }), /HTTPS/);
    await assert.rejects(verifyLaunchDependencies({ ...fixture.config, maxHeadAgeSeconds: 0 }), /bound/);
  } finally { await fixture.close(); }
});

test('dependency CLI produces an observation and refuses to replace an existing report', async () => {
  const fixture = await dependencyRPC(), directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-dependencies-'));
  const config = path.join(directory, 'config.json'), output = path.join(directory, 'report.json');
  try {
    fs.writeFileSync(config, JSON.stringify(fixture.config));
    const args = [fileURLToPath(new URL('../scripts/check-dependencies.mjs', import.meta.url)), '--config', config, '--out', output];
    const result = await promisify(execFile)(process.execPath, args, { windowsHide: true });
    assert.equal(JSON.parse(result.stdout).sent, false);
    assert.equal(JSON.parse(fs.readFileSync(output)).runtimeAndLinksMatched, true);
    const before = fs.readFileSync(output);
    await assert.rejects(promisify(execFile)(process.execPath, args, { windowsHide: true }), error => error.code === 1 && !error.stderr.includes(config));
    assert.deepEqual(fs.readFileSync(output), before);
  } finally {
    await fixture.close();
    for (const name of ['config.json', 'report.json']) fs.rmSync(path.join(directory, name), { force: true });
    fs.rmdirSync(directory);
  }
});
