import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { normalizeBrightIDPolicy, brightIDApplicationUserId, verifyBrightIDRecord, checkBrightIDProvider, BrightIDIntakeLedger } from '../claims/brightid.mjs';

const keys = generateKeyPairSync('ed25519');
const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
const commitment = '123456789123456789';
const base = { schema: 'cannabis.brightid-policy.v1', nodeUrl: 'https://provider.example/brightid/v6/', nodeVersion: '6.18.0', app: 'cannabis', verification: 'ReviewedHuman', publicKey,
  chainId: '8453', enrollment: '0x1111111111111111111111111111111111111111', maxAgeSeconds: 120, clockSkewSeconds: 5 };
const sha = text => createHash('sha256').update(text).digest('hex');
const now = () => Math.floor(Date.now() / 1000);
function credential(policy = base, member = commitment, time = now()) {
  const record = { unique: true, app: policy.app, appUserId: brightIDApplicationUserId(policy, member), verification: policy.verification,
    verificationHash: sha(policy.verification), timestamp: time, publicKey: policy.publicKey };
  record.sig = sign(null, Buffer.from(`${record.app},${record.appUserId},${record.verificationHash},${record.timestamp}`, 'ascii'), keys.privateKey).toString('base64');
  return record;
}
async function providerFixture(mutate = () => {}) {
  let p; const requests = []; let configReads = 0;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1'); requests.push({ method: req.method, url });
    let body;
    if (url.pathname.endsWith('/state')) {
      body = { data: { development: false, version: p.nodeVersion, naclSigningKey: p.publicKey } }; configReads++;
    } else if (url.pathname.endsWith(`/apps/${p.app}`)) {
      body = { data: { id: p.app, testing: false, idsAsHex: false, usingBlindSig: true, verificationExpirationLength: 0, verifications: [p.verification] } };
    } else if (url.pathname.includes('/verifications/')) body = { data: [credential(p)] };
    else { res.writeHead(404); res.end(); return; }
    const override = await mutate({ url, body, configReads, policy: p });
    if (override?.status) res.writeHead(override.status, override.headers ?? {});
    else res.writeHead(200, { 'content-type': 'application/json' });
    res.end(override?.raw ?? JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  p = { ...base, nodeUrl: `http://127.0.0.1:${server.address().port}/brightid/v6/` };
  return { policy: p, requests, close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}
const run = args => new Promise(resolve => {
  const child = spawn(process.execPath, args, { windowsHide: true }); let stdout = '', stderr = '';
  child.stdout.on('data', data => stdout += data); child.stderr.on('data', data => stderr += data);
  child.on('exit', code => resolve({ code, stdout, stderr }));
});

test('BrightID signed record binds exact app, verification, deployment and Semaphore commitment', () => {
  const time = now(), record = credential(base, commitment, time);
  const expected = sha(`Cannabis BrightID enrollment v1\0${base.chainId}\0${base.enrollment}\0${commitment}`);
  assert.equal(record.appUserId, expected);
  const checked = verifyBrightIDRecord(record, base, commitment, time);
  assert.equal(checked.eligibilitySignatureVerified, true);
  assert.equal(checked.enrollmentAuthorized, false); assert.equal(checked.lifetimeUniquenessEstablished, false);
  assert.throws(() => verifyBrightIDRecord(record, base, '123', time));
  for (const policy of [{ ...base, chainId: '1' }, { ...base, enrollment: '0x2222222222222222222222222222222222222222' }, { ...base, app: 'another' }, { ...base, verification: 'AnotherPolicy' }]) {
    assert.throws(() => verifyBrightIDRecord(record, policy, commitment, time));
  }
});

test('signature, trusted key, hash, timestamp and exact response fields are all mandatory', () => {
  const time = now(), good = credential(base, commitment, time);
  const mutations = [
    r => r.unique = false, r => r.sig = '', r => r.sig = Buffer.alloc(64).toString('base64'),
    r => r.publicKey = Buffer.alloc(32).toString('base64'), r => r.verificationHash = '0'.repeat(64),
    r => delete r.verificationHash, r => delete r.timestamp, r => r.timestamp = String(time),
    r => r.timestamp++, r => r.sig = r.sig.replace(/=+$/, ''), r => r.unexpected = 'secret'
  ];
  for (const mutate of mutations) { const r = structuredClone(good); mutate(r); assert.throws(() => verifyBrightIDRecord(r, base, commitment, time)); }
  const forged = generateKeyPairSync('ed25519');
  const r = { ...good, publicKey: forged.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64') };
  r.sig = sign(null, Buffer.from(`${r.app},${r.appUserId},${r.verificationHash},${r.timestamp}`), forged.privateKey).toString('base64');
  assert.throws(() => verifyBrightIDRecord(r, base, commitment, time));
  assert.throws(() => verifyBrightIDRecord(credential(base, commitment, time - 121), base, commitment, time));
  assert.throws(() => verifyBrightIDRecord(credential(base, commitment, time + 6), base, commitment, time));
});

test('policy rejects delimiter ambiguity, unreviewed versions and insecure endpoint/configuration forms', () => {
  for (const replacement of [
    { app: 'bad,app' }, { verification: '\u00e9' }, { nodeVersion: '6.17.1' }, { maxAgeSeconds: 301 }, { clockSkewSeconds: 31 },
    { chainId: '08453' }, { enrollment: '0x0000000000000000000000000000000000000000' }, { publicKey: publicKey.slice(0, -1) },
    { nodeUrl: 'http://provider.example/brightid/v6/' }, { nodeUrl: 'http://localhost/brightid/v6/' },
    { nodeUrl: 'https://user:password@provider.example/brightid/v6/' }, { nodeUrl: 'https://provider.example/brightid/v6/?token=secret' }
  ]) assert.throws(() => normalizeBrightIDPolicy({ ...base, ...replacement }));
  for (const member of ['0', '001', '-1', '21888242871839275222246405745257275088548364400416034343698204186575808495617']) assert.throws(() => brightIDApplicationUserId(base, member));
  assert.deepEqual(normalizeBrightIDPolicy(Object.fromEntries(Object.entries(base).reverse())), normalizeBrightIDPolicy(base));
});

test('source-compared provider versions require explicit policy selection', async () => {
  const p = { ...base, nodeVersion: '6.17.2' };
  const checked = verifyBrightIDRecord(credential(p), p, commitment);
  assert.equal(checked.eligibilitySignatureVerified, true);
  assert.notEqual(checked.policySHA256, verifyBrightIDRecord(credential(base), base, commitment).policySHA256);
  assert.throws(() => normalizeBrightIDPolicy({ ...base, nodeVersion: '6.19.0' }));
  const f = await providerFixture(); f.policy.nodeVersion = '6.17.2';
  try { assert.equal((await checkBrightIDProvider({ policy: f.policy, commitment })).result.eligibilitySignatureVerified, true); }
  finally { await f.close(); }
});

test('provider adapter checks live app/node configuration twice and only requests the bound signed record', async () => {
  const f = await providerFixture();
  try {
    const checked = await checkBrightIDProvider({ policy: f.policy, commitment });
    assert.equal(checked.result.eligibilitySignatureVerified, true);
    assert.equal(f.requests.length, 5); assert.ok(f.requests.every(r => r.method === 'GET'));
    const request = f.requests.find(r => r.url.pathname.includes('/verifications/'));
    assert.equal(request.url.pathname, `/brightid/v6/verifications/cannabis/${brightIDApplicationUserId(f.policy, commitment)}`);
    assert.equal(request.url.searchParams.get('signed'), 'nacl'); assert.equal(request.url.searchParams.get('includeHash'), 'true');
    assert.equal(request.url.searchParams.get('timestamp'), 'seconds'); assert.equal(request.url.searchParams.has('pseudoVerification'), false);
  } finally { await f.close(); }
});

test('provider adapter rejects development, policy renewal, extra verification classes and changed node configuration', async () => {
  const mutations = [
    ({ url, body }) => { if (url.pathname.endsWith('/state')) body.data.development = true; },
    ({ url, body }) => { if (url.pathname.endsWith('/state')) body.data.version = '6.17.2'; },
    ({ url, body }) => { if (url.pathname.includes('/apps/')) body.data.verificationExpirationLength = 3600000; },
    ({ url, body }) => { if (url.pathname.includes('/apps/')) body.data.verifications.push('Other'); },
    ({ url, body }) => { if (url.pathname.includes('/apps/')) body.data.testing = true; },
    ({ url, body }) => { if (url.pathname.includes('/apps/')) body.data.usingBlindSig = false; },
    ({ url, body }) => { if (url.pathname.includes('/apps/')) body.data.idsAsHex = true; },
    ({ url, body, configReads }) => { if (url.pathname.endsWith('/state') && configReads > 1) body.data.naclSigningKey = Buffer.alloc(32).toString('base64'); },
    ({ url, body }) => { if (url.pathname.includes('/verifications/')) body.data.push({ ...body.data[0] }); }
  ];
  for (const mutation of mutations) {
    const f = await providerFixture(mutation);
    try { await assert.rejects(checkBrightIDProvider({ policy: f.policy, commitment })); } finally { await f.close(); }
  }
});

test('provider adapter bounds responses, rejects redirects and hides response/URL details from errors', async () => {
  for (const override of [{ status: 302, headers: { location: 'https://example.invalid/private' } }, { raw: 'x'.repeat(65537) }, { raw: '{private-content' }, { raw: Buffer.from([0xff]) }]) {
    const f = await providerFixture(() => override);
    try { await assert.rejects(checkBrightIDProvider({ policy: f.policy, commitment }), e => e.message === 'Provider request failed'); }
    finally { await f.close(); }
  }
});

test('intake persists idempotent records across connections and refuses policy resets', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'cannabis-intake-')), file = path.join(dir, 'intake.sqlite');
  const p = structuredClone(base), time = now(); let a, b;
  try {
    a = new BrightIDIntakeLedger(file, p, () => time); b = new BrightIDIntakeLedger(file, base, () => time);
    p.app = 'changed'; // Caller mutations cannot alter the retained trust policy.
    const first = a.record(credential(base, commitment, time), commitment);
    assert.equal(first.alreadyRecorded, false);
    assert.equal(b.record(credential(base, commitment, time), commitment).alreadyRecorded, true);
    assert.throws(() => b.record(credential(base, commitment, time), '123'));
    assert.throws(() => new BrightIDIntakeLedger(file, { ...base, app: 'changed' }));
    assert.throws(() => new BrightIDIntakeLedger(file, { ...base, publicKey: Buffer.alloc(32, 1).toString('base64') }));
    const db = new DatabaseSync(file); assert.equal(db.prepare('SELECT COUNT(*) AS n FROM brightid_intake').get().n, 1); db.close();
    a.close(); a = null; b.close(); b = null;
    a = new BrightIDIntakeLedger(file, base, () => time + 1);
    assert.equal(a.record(credential(base, commitment, time + 1), commitment).alreadyRecorded, true);
  } finally { a?.close(); b?.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('current ceremony CLI refuses retired provider configurations without contacting a provider', async () => {
  const f = await providerFixture(), dir = mkdtempSync(path.join(os.tmpdir(), 'cannabis-intake-cli-'));
  const cli = fileURLToPath(new URL('../scripts/check-person-verification.mjs', import.meta.url));
  try {
    const config = path.join(dir, 'config.json'), dbFile = path.join(dir, 'intake.sqlite');
    writeFileSync(config, JSON.stringify({ policy: f.policy, commitment, ledger: dbFile }));
    const outputs = [path.join(dir, 'one.json'), path.join(dir, 'two.json')];
    const runs = await Promise.all(outputs.map(out => run([cli, '--config', config, '--out', out])));
    assert.deepEqual(runs.map(r => r.code), [1, 1]);
    assert.equal(f.requests.length, 0);
    for (const r of runs) { assert.equal(r.stdout.includes(commitment), false); assert.equal(r.stdout.includes(f.policy.publicKey), false); }
    writeFileSync(config, '{"private":"do-not-print-this"');
    const bad = await run([cli, '--config', config, '--out', path.join(dir, 'bad.json')]);
    assert.equal(bad.code, 1); assert.equal(bad.stderr.includes('do-not-print-this'), false);
  } finally { await f.close(); rmSync(dir, { recursive: true, force: true }); }
});
