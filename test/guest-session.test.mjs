import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import { AttestationLedger, trusteeEvidenceRequest, trusteeRuntimeData } from '../compute/attestation.mjs';
import { GuestEvidenceSession, probeGuestAgent, GUEST_COMPONENTS_REVISION, GUEST_AGENT_VERSION } from '../compute/guest_session.mjs';
import { guestAgentFixture } from './helpers/guest_agent_fixture.mjs';

const signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const hex = n => n.toString(16).padStart(64, '0'), time = 1800000000;
test('guest service build pins agree with the admitted CPU wire profile', () => {
  const build = JSON.parse(fs.readFileSync(new URL('../compute/guest-service-build.json', import.meta.url), 'utf8'));
  assert.equal(build.source.revision, GUEST_COMPONENTS_REVISION);
  assert.equal('Guest Components Version: ' + build.source.tag, GUEST_AGENT_VERSION);
  assert.equal(build.bridgeFeature, 'attestation');
  assert.deepEqual(build.agentFeatures, ['bin', 'ttrpc', 'rust-crypto', 'snp-attester', 'tdx-attester']);
  assert.deepEqual(build.binaries, ['ttrpc-aa', 'api-server-rest']);
});
function setup(tee = 'snp') {
  const policy = { schema: 'cannabis.attestation.trustee-policy.v1', issuer: 'Fixture AS', signingJwk: signer.publicKey.export({ format: 'jwk' }),
    verifierBuild: 'Protocol fixture', appraisalPolicyId: 'fixture-cpu', maxTokenAgeSeconds: 60, maxTokenLifetimeSeconds: 300, challengeTTLSeconds: 90, tee,
    measurements: tee === 'snp' ? { launch: '11'.repeat(48), initData: '22'.repeat(32), minimumTCB: { bootloader: 1, tee: 1, snp: 1, microcode: 1 } }
      : { launch: '11'.repeat(48), initData: '22'.repeat(48), rtmr0: '33'.repeat(48), rtmr1: '44'.repeat(48), rtmr2: '55'.repeat(48), rtmr3: '00'.repeat(48) } };
  const binding = { chainId: 31337, escrow: '0x' + '12'.repeat(20), orderId: '0x' + hex(1), leaseDigest: '0x' + hex(2), reservationId: '0x' + hex(3),
    packageSHA256: hex(4), policySHA256: hex(5), runtimeSHA256: hex(6), taskSHA256: hex(7), attempt: 1, rank: 0, worldSize: 1, acceleratorClass: 'cpu' };
  const ledger = new AttestationLedger(':memory:', policy, () => time), challenge = ledger.challenge(binding); ledger.close();
  return { policy, challenge, expectedBinding: binding, requester: '0x' + '13'.repeat(20), jobId: 'opaque-job' };
}
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, sorted(value[k])]));
  return value;
}

for (const tee of ['snp', 'tdx']) test(`${tee} guest collects the exact 64 report bytes bound to its own channel key`, async () => {
  const s = setup(tee), agent = await guestAgentFixture({ tee }); let session;
  try {
    session = await GuestEvidenceSession.create({ ...s, agentUrl: agent.url }, { clock: () => time });
    const result = await session.evidence();
    const expected = Buffer.concat([createHash('sha384').update(JSON.stringify(sorted(trusteeRuntimeData(s.challenge, result.channelJwk)))).digest(), Buffer.alloc(16)]);
    assert.deepEqual(agent.calls, ['/info', '/aa/evidence']); assert.equal(agent.reports[0].encoding, 'base64');
    assert.equal(agent.reports[0].bytes.length, 64); assert.deepEqual(agent.reports[0].bytes, expected);
    assert.equal(result.hardwareVerified, false); assert.equal(result.executionAuthorized, false);
    assert.equal(JSON.stringify(session), '{}'); assert.deepEqual(Object.keys(session.channelJwk).sort(), ['crv', 'kty', 'x', 'y']);
    const copy = session.channelJwk; copy.x = 'changed'; assert.notEqual(session.channelJwk.x, copy.x);
    const request = trusteeEvidenceRequest(s.policy, s.challenge, result.channelJwk, result.evidence, time);
    assert.deepEqual(JSON.parse(Buffer.from(request.verification_requests[0].evidence, 'base64url')), JSON.parse(Buffer.from(result.evidence, 'base64url')));
    assert.deepEqual(await session.evidence(), result); assert.equal(agent.reports.length, 1);
  } finally { session?.close(); await agent.close(); }
});

test('untrusted or unsupported guest agent profiles never request evidence', async () => {
  for (const info of [{ tee: 'sample' }, { tee: 'az-snp-vtpm' }, { version: 'other' }, { feature: 'all' }, { additional_tees: ['nvidia'] }]) {
    const agent = await guestAgentFixture({ info }); let session;
    try {
      session = await GuestEvidenceSession.create({ ...setup(), agentUrl: agent.url }, { clock: () => time });
      await assert.rejects(session.evidence(), /profile mismatch/); assert.equal(session.status.state, 'closed'); assert.equal(agent.reports.length, 0);
    } finally { session?.close(); await agent.close(); }
  }
});

test('guest API rejects external origins, credentials and redirects without following them', async () => {
  for (const agentUrl of ['https://127.0.0.1:8006', 'http://localhost:8006', 'http://example.com', 'http://127.0.0.1/path', 'http://user:pass@127.0.0.1', 'http://127.0.0.1/?x=1']) {
    await assert.rejects(probeGuestAgent({ agentUrl, tee: 'snp' }), /loopback/);
  }
  const target = await guestAgentFixture(), redirect = await guestAgentFixture({ redirect: target.url });
  try { await assert.rejects(probeGuestAgent({ agentUrl: redirect.url, tee: 'snp' }), /response rejected/); assert.equal(target.calls.length, 0); }
  finally { await redirect.close(); await target.close(); }
});

test('empty, malformed and oversized evidence fails without exposing agent diagnostics', async () => {
  for (const raw of ['{}', '{private diagnostic', '[]', JSON.stringify({ huge: 'a'.repeat(3 * 1024 * 1024) })]) {
    const agent = await guestAgentFixture({ raw }); let session;
    try {
      session = await GuestEvidenceSession.create({ ...setup(), agentUrl: agent.url }, { clock: () => time });
      await assert.rejects(session.evidence(), error => !error.message.includes('private diagnostic'));
      assert.equal(session.status.state, 'closed');
    } finally { session?.close(); await agent.close(); }
  }
});

test('expiry after hardware collection and cancellation while waiting retire the guest key', async () => {
  let current = time;
  const agent = await guestAgentFixture({ onEvidence: () => { current = time + 90; } }); let session;
  try {
    session = await GuestEvidenceSession.create({ ...setup(), agentUrl: agent.url }, { clock: () => current });
    await assert.rejects(session.evidence(), /expired/); assert.equal(session.status.state, 'closed');
  } finally { session?.close(); await agent.close(); }
  const slow = await guestAgentFixture({ hang: true }); let waiting;
  try {
    waiting = await GuestEvidenceSession.create({ ...setup(), agentUrl: slow.url }, { clock: () => time });
    const pending = waiting.evidence(); const rejected = assert.rejects(pending, /cancelled|failed/);
    await new Promise(resolve => setTimeout(resolve, 25)); waiting.close(); await rejected;
    await assert.rejects(waiting.evidence(), /closed/);
  } finally { waiting?.close(); await slow.close(); }
});

test('a stalled local agent is bounded and concurrent collection cannot fork a session', async () => {
  const agent = await guestAgentFixture({ hang: true }); let session;
  try {
    session = await GuestEvidenceSession.create({ ...setup(), agentUrl: agent.url }, { clock: () => time });
    const pending = session.evidence({ timeoutMs: 100 }); const rejected = assert.rejects(pending, /cancelled|failed/);
    await assert.rejects(session.evidence(), /in progress/); await rejected;
    assert.equal(session.status.state, 'closed');
  } finally { session?.close(); await agent.close(); }
});

test('the guest retains its assignment and refuses host-supplied changes before opening', async () => {
  const s = setup(), agent = await guestAgentFixture(); let session;
  try {
    await assert.rejects(GuestEvidenceSession.create({ ...s, expectedBinding: { ...s.expectedBinding, rank: 1 }, agentUrl: agent.url }, { clock: () => time }), /approved guest assignment/);
    session = await GuestEvidenceSession.create({ ...s, agentUrl: agent.url }, { clock: () => time });
    s.challenge.binding.rank = 9; // External mutation does not change the retained assignment.
    const evidence = await session.evidence();
    assert.equal(JSON.parse(Buffer.from(evidence.evidence, 'base64url')).protocolFixtureOnly, true);
    await assert.rejects(session.open('not-a-jwe', { requester: '0x' + '14'.repeat(20), value: {}, domain: {} }), /retained guest assignment/);
    assert.equal(session.status.state, 'closed');
  } finally { session?.close(); await agent.close(); }
});
