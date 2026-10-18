import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { AttestationLedger, attestWithTrustee, requestTrusteeResult, trusteeEvidenceRequest, trusteeRuntimeData, validateAttestationPolicy, verifyTrusteeResult } from '../compute/attestation.mjs';

// Synthetic signed EAR fixtures exercise the result consumer, not vendor evidence
// verification. No fixture is operational hardware evidence or a launch claim.
const h = n => n.toString(16).padStart(64, '0');
const keys = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const signer = keys(), otherSigner = keys(), guest = keys();
const jwk = k => k.publicKey.export({ format: 'jwk' });
const channel = jwk(guest), baseTime = 1800000000;
function sorted(v) {
  if (Array.isArray(v)) return v.map(sorted);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map(k => [k, sorted(v[k])]));
  return v;
}
function setup(tee = 'snp', file = ':memory:') {
  const policy = { schema: 'cannabis.attestation.trustee-policy.v1', issuer: 'CoCo-Attestation-Service', signingJwk: jwk(signer),
    verifierBuild: 'attestation-service fixture', appraisalPolicyId: 'reviewed-cpu-profile', maxTokenAgeSeconds: 60, maxTokenLifetimeSeconds: 300,
    challengeTTLSeconds: 90, tee, measurements: tee === 'snp'
      ? { launch: '11'.repeat(48), initData: '22'.repeat(32), minimumTCB: { bootloader: 1, tee: 2, snp: 3, microcode: 4 } }
      : { launch: '11'.repeat(48), initData: '22'.repeat(48), rtmr0: '33'.repeat(48), rtmr1: '44'.repeat(48), rtmr2: '55'.repeat(48), rtmr3: '00'.repeat(48) } };
  let time = baseTime;
  const ledger = new AttestationLedger(file, policy, () => time);
  const binding = { chainId: 31337, escrow: '0x' + '12'.repeat(20), orderId: '0x' + h(1), leaseDigest: '0x' + h(2), reservationId: '0x' + h(3),
    packageSHA256: h(4), policySHA256: h(5), runtimeSHA256: h(6), taskSHA256: h(7), attempt: 1, rank: 0, worldSize: 1, acceleratorClass: 'cpu' };
  const challenge = ledger.challenge(binding);
  return { ledger, policy, binding, challenge, setTime: t => { time = t; } };
}
function claims(s, key = channel) {
  const runtime = trusteeRuntimeData(s.challenge, key), m = s.policy.measurements;
  const report = createHash('sha384').update(JSON.stringify(sorted(runtime))).digest('hex') + '00'.repeat(16);
  const cpu = s.policy.tee === 'snp'
    ? { measurement: m.launch, policy_debug_allowed: false, policy_migrate_ma: false, reported_tcb_bootloader: 1, reported_tcb_tee: 2, reported_tcb_snp: 3, reported_tcb_microcode: 4 }
    : { td_attributes: { debug: false }, tcb_status: 'UpToDate', collateral_expiration_status: '0', quote: { body: { mr_td: m.launch, rtmr_0: m.rtmr0, rtmr_1: m.rtmr1, rtmr_2: m.rtmr2, rtmr_3: m.rtmr3 } } };
  return { iss: s.policy.issuer, iat: baseTime, exp: baseTime + 300, eat_profile: 'tag:github.com,2024:confidential-containers/Trustee',
    'ear.verifier-id': { developer: 'https://confidentialcontainers.org', build: s.policy.verifierBuild },
    submods: { cpu0: { 'ear.status': 'affirming', 'ear.appraisal-policy-id': s.policy.appraisalPolicyId,
      'ear.trustworthiness-vector': { 'instance-identity': 0, configuration: 2, executables: 3, 'file-system': 0, hardware: 2, 'runtime-opaque': 0, 'storage-opaque': 0, 'sourced-data': 0 },
      'ear.veraison.annotated-evidence': { [s.policy.tee]: cpu, report_data: report, init_data: m.initData, runtime_data_claims: runtime, init_data_claims: null } } } };
}
function token(payload, signing = signer, extra = {}) {
  const header = { typ: 'JWT', alg: 'ES256', jwk: jwk(signing), ...extra };
  const data = [header, payload].map(x => Buffer.from(JSON.stringify(x)).toString('base64url')).join('.');
  return data + '.' + sign('sha256', Buffer.from(data), { key: signing.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
}
const evidence = p => p.submods.cpu0['ear.veraison.annotated-evidence'];

for (const tee of ['snp', 'tdx']) test(`${tee} EAR accepts approved CPU evidence and consumes the nonce without releasing a key`, async () => {
  const s = setup(tee);
  try {
    const result = await s.ledger.verify(s.challenge.nonce, token(claims(s)), channel);
    assert.equal(result.attestationVerified, true); assert.equal(result.challengeConsumed, true);
    assert.equal(result.executionAuthorized, false); assert.equal(result.keyReleaseAuthorized, false);
    assert.equal(result.fundingRecheckRequired, true); assert.deepEqual(result.binding, s.binding);
    assert.equal(result.expiresAt, baseTime + 60);
    await assert.rejects(s.ledger.verify(s.challenge.nonce, token(claims(s)), channel), /consumed/);
  } finally { s.ledger.close(); }
});

test('embedded attacker keys, algorithm substitution and remote key URLs never establish trust', async () => {
  const s = setup();
  try {
    await assert.rejects(s.ledger.verify(s.challenge.nonce, token(claims(s), otherSigner), channel));
    await assert.rejects(s.ledger.verify(s.challenge.nonce, token(claims(s), signer, { alg: 'HS256' }), channel));
    await assert.rejects(s.ledger.verify(s.challenge.nonce, token(claims(s), signer, { jku: 'https://attacker.invalid/keys' }), channel), /Remote/);
    assert.equal((await s.ledger.verify(s.challenge.nonce, token(claims(s)), channel)).attestationVerified, true);
  } finally { s.ledger.close(); }
});

test('freshness rejects pre-challenge, future, expired and excessive-lifetime signed results', async () => {
  const s = setup();
  try {
    for (const changes of [{ iat: baseTime - 1 }, { iat: baseTime + 1 }, { exp: baseTime }, { exp: baseTime + 301 }]) {
      await assert.rejects(s.ledger.verify(s.challenge.nonce, token({ ...claims(s), ...changes }), channel));
    }
    s.setTime(baseTime + 61);
    await assert.rejects(s.ledger.verify(s.challenge.nonce, token(claims(s)), channel));
    s.setTime(baseTime + 90);
    await assert.rejects(s.ledger.verify(s.challenge.nonce, token(claims(s)), channel), /expired/);
  } finally { s.ledger.close(); }
});

test('wrong signer identity, policy and unapproved trust vectors are rejected', async () => {
  const mutations = [p => { p.iss = 'other'; }, p => { p.eat_profile = 'other'; }, p => { p['ear.verifier-id'].build = 'other'; },
    p => { p.submods.cpu0['ear.appraisal-policy-id'] = 'default'; }, p => { p.submods.cpu0['ear.status'] = 'contraindicated'; },
    ...['hardware', 'executables', 'configuration'].map(k => p => { p.submods.cpu0['ear.trustworthiness-vector'][k] = 0; }),
    p => { p.submods.cpu0['ear.trustworthiness-vector'].configuration = 36; },
    p => { delete p.submods.cpu0['ear.trustworthiness-vector']['storage-opaque']; },
    p => { const v = p.submods.cpu0['ear.trustworthiness-vector']; delete v.configuration; delete v.executables; v['configuration,executables'] = 0; }];
  const s = setup();
  try { for (const mutate of mutations) { const p = claims(s); mutate(p); await assert.rejects(s.ledger.verify(s.challenge.nonce, token(p), channel)); } }
  finally { s.ledger.close(); }
});

test('SNP debug, migration, old TCB, boot and init-data substitutions fail closed', async () => {
  const s = setup();
  try {
    for (const change of [{ policy_debug_allowed: true }, { policy_migrate_ma: true }, { reported_tcb_microcode: 3 }, { reported_tcb_tee: '2' }, { measurement: 'aa'.repeat(48) }]) {
      const p = claims(s); Object.assign(evidence(p).snp, change); await assert.rejects(s.ledger.verify(s.challenge.nonce, token(p), channel));
    }
    const p = claims(s); evidence(p).init_data = 'aa'.repeat(32); await assert.rejects(s.ledger.verify(s.challenge.nonce, token(p), channel), /init data/);
  } finally { s.ledger.close(); }
});

test('TDX requires debug disabled, current collateral and every pinned runtime measurement', async () => {
  const s = setup('tdx');
  try {
    for (const change of [{ td_attributes: { debug: true } }, { tcb_status: 'OutOfDate' }, { tcb_status_current: 'OutOfDate' }, { collateral_expiration_status: '1' }]) {
      const p = claims(s); Object.assign(evidence(p).tdx, change); await assert.rejects(s.ledger.verify(s.challenge.nonce, token(p), channel));
    }
    for (let i = 0; i < 4; i++) {
      const p = claims(s); evidence(p).tdx.quote.body['rtmr_' + i] = 'ff'.repeat(48); await assert.rejects(s.ledger.verify(s.challenge.nonce, token(p), channel), /measurement/);
    }
  } finally { s.ledger.close(); }
});

test('challenge, encrypted package, lease, rank and key substitution are all bound to report data', async () => {
  const s = setup();
  try {
    for (const field of ['packageSHA256', 'leaseDigest', 'policySHA256', 'runtimeSHA256', 'taskSHA256', 'reservationId', 'orderId', 'rank', 'attempt', 'worldSize', 'chainId', 'escrow']) {
      const p = claims(s), b = evidence(p).runtime_data_claims.cannabis.binding; b[field] = typeof b[field] === 'number' ? b[field] + 1 : b[field] + '0';
      await assert.rejects(s.ledger.verify(s.challenge.nonce, token(p), channel), /binding/);
    }
    const p = claims(s); evidence(p).runtime_data_claims.nonce = h(999); await assert.rejects(s.ledger.verify(s.challenge.nonce, token(p), channel), /binding/);
    await assert.rejects(s.ledger.verify(s.challenge.nonce, token(claims(s)), jwk(otherSigner)), /binding/);
    const badReport = claims(s); evidence(badReport).report_data = 'ff'.repeat(64); await assert.rejects(s.ledger.verify(s.challenge.nonce, token(badReport), channel), /report data/);
  } finally { s.ledger.close(); }
});

test('CPU appraisal cannot authorize accelerators or a different device roster', async () => {
  const s = setup();
  try {
    assert.throws(() => s.ledger.challenge({ ...s.binding, acceleratorClass: 'cuda' }), /no CPU-only fallback/);
    for (const extra of ['gpu0', 'ppcie0', 'cpu1']) { const p = claims(s); p.submods[extra] = structuredClone(p.submods.cpu0); await assert.rejects(s.ledger.verify(s.challenge.nonce, token(p), channel)); }
    const p = claims(s); evidence(p).sample = { debug: false }; await assert.rejects(s.ledger.verify(s.challenge.nonce, token(p), channel));
    const wrong = structuredClone(s.policy); wrong.tee = 'sample'; assert.throws(() => validateAttestationPolicy(wrong), /Unsupported/);
  } finally { s.ledger.close(); }
});

test('private, malformed and off-curve channel keys are rejected', async () => {
  const s = setup();
  try {
    for (const key of [{ ...channel, d: 'private' }, { ...channel, x: channel.x + '=' }, { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'A'.repeat(43) }]) {
      await assert.rejects(s.ledger.verify(s.challenge.nonce, token(claims(s)), key));
    }
    await assert.rejects(s.ledger.verify(s.challenge.nonce, 'a'.repeat(256 * 1024 + 1), channel), /oversized/);
  } finally { s.ledger.close(); }
});

test('concurrent verification consumes a challenge only once across database connections', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-attestation-')), file = path.join(dir, 'challenges.sqlite');
  const s = setup('snp', file); let second;
  try {
    second = new AttestationLedger(file, s.policy, () => baseTime);
    const results = await Promise.allSettled([s.ledger.verify(s.challenge.nonce, token(claims(s)), channel), second.verify(s.challenge.nonce, token(claims(s)), channel)]);
    assert.equal(results.filter(x => x.status === 'fulfilled').length, 1);
    assert.match(results.find(x => x.status === 'rejected').reason.message, /consumed/);
    const rotated = structuredClone(s.policy); rotated.signingJwk = jwk(otherSigner);
    assert.throws(() => new AttestationLedger(file, rotated), /cannot change/);
  } finally { second?.close(); s.ledger.close(); for (const name of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, name)); fs.rmdirSync(dir); }
});

test('cancellation and expiry during asynchronous verification prevent consumption', async () => {
  const s = setup();
  try {
    const pending = s.ledger.verify(s.challenge.nonce, token(claims(s)), channel); s.ledger.cancel(s.challenge.nonce);
    await assert.rejects(pending, /consumed/);
    s.challenge = s.ledger.challenge(s.binding);
    const expired = s.ledger.verify(s.challenge.nonce, token(claims(s)), channel); s.setTime(baseTime + 90);
    await assert.rejects(expired, /expired/);
  } finally { s.ledger.close(); }
});

test('pure result inspection does not claim nonce consumption', async () => {
  const s = setup();
  try { const r = await verifyTrusteeResult(token(claims(s)), s.policy, s.challenge, channel, baseTime); assert.equal(r.challengeConsumed, undefined); }
  finally { s.ledger.close(); }
});

test('REST request binds exact structured runtime data and raw measured init digest', async () => {
  const s = setup(), encoded = Buffer.from('synthetic hardware evidence').toString('base64url');
  let captured;
  const server = http.createServer(async (req, res) => {
    let data = ''; for await (const part of req) data += part;
    captured = JSON.parse(data); res.end(token(claims(s)));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const r = await attestWithTrustee(s.ledger, `http://127.0.0.1:${server.address().port}/attestation`, s.challenge.nonce, channel, encoded);
    assert.equal(r.challengeConsumed, true);
    assert.deepEqual(captured, trusteeEvidenceRequest(s.policy, s.challenge, channel, encoded, baseTime));
    assert.equal(captured.verification_requests[0].runtime_data_hash_algorithm, 'sha384');
    assert.equal(captured.verification_requests[0].init_data.init_data_digest, Buffer.from(s.policy.measurements.initData, 'hex').toString('base64url'));
    assert.deepEqual(captured.policy_ids, [s.policy.appraisalPolicyId]);
  } finally { s.ledger.close(); await new Promise(resolve => server.close(resolve)); }
});

test('transport rejects insecure remote hosts, credentials, redirects and oversized responses', async () => {
  const s = setup(), encoded = Buffer.from('fixture').toString('base64url'); let mode = 'redirect';
  const server = http.createServer((req, res) => { req.resume(); if (mode === 'redirect') { res.writeHead(302, { Location: '/other' }); res.end(); } else res.end('x'.repeat(256 * 1024 + 1)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    for (const url of ['http://example.com/attestation', 'https://user:pass@example.com/attestation', 'https://example.com/attestation?token=secret', 'https://example.com/other']) {
      await assert.rejects(attestWithTrustee(s.ledger, url, s.challenge.nonce, channel, encoded), /Require HTTPS/);
    }
    const endpoint = `http://127.0.0.1:${server.address().port}/attestation`;
    await assert.rejects(attestWithTrustee(s.ledger, endpoint, s.challenge.nonce, channel, encoded)); mode = 'oversized';
    await assert.rejects(attestWithTrustee(s.ledger, endpoint, s.challenge.nonce, channel, encoded), /Oversized/);
    assert.equal(s.ledger.pending(s.challenge.nonce).nonce, s.challenge.nonce);
  } finally { s.ledger.close(); await new Promise(resolve => server.close(resolve)); }
});

test('appraisal fetch verifies the EAR without consuming a challenge needed by key delivery', async () => {
  const s = setup(); let cancel = false;
  const server = http.createServer((req, res) => { req.resume(); if (cancel) s.ledger.cancel(s.challenge.nonce); res.end(token(claims(s))); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}/attestation`, evidence = Buffer.from('protocol fixture').toString('base64url');
    const result = await requestTrusteeResult(s.ledger, url, s.challenge.nonce, channel, evidence);
    assert.equal(result.challengeConsumed, false); assert.equal(result.appraisal.attestationVerified, true);
    assert.equal(result.executionAuthorized, false); assert.equal(s.ledger.pending(s.challenge.nonce).nonce, s.challenge.nonce);
    assert.equal((await verifyTrusteeResult(result.token, s.policy, s.challenge, channel, baseTime)).attestationVerified, true);
    cancel = true;
    await assert.rejects(requestTrusteeResult(s.ledger, url, s.challenge.nonce, channel, evidence), /consumed/);
  } finally { s.ledger.close(); await new Promise(resolve => server.close(resolve)); }
});
