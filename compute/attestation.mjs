// Requester-side appraisal of Trustee v0.22.0 EAR results. No secrets or key release.
import { createHash, randomBytes } from 'node:crypto';
import { openDurableDatabase } from './sqlite_runtime.mjs';
import { importJWK, jwtVerify } from 'jose';
import { getAddress } from 'ethers';
import { inspectLease } from './leases.mjs';
import { verifyMarketLeaseProof } from './market_lease.mjs';

export const TRUSTEE_REVISION = '512fed65642015b849f38fb13bfdec7806639987';
const PROFILE = 'tag:github.com,2024:confidential-containers/Trustee';
const VECTOR = ['instance-identity', 'configuration', 'executables', 'file-system', 'hardware', 'runtime-opaque', 'storage-opaque', 'sourced-data'];
const MAX_TOKEN = 256 * 1024;
const seconds = () => Math.floor(Date.now() / 1000);
const sha256 = data => createHash('sha256').update(data).digest('hex');
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
function exact(v, keys) {
  if (!object(v) || Object.keys(v).length !== keys.length || keys.some(k => !Object.hasOwn(v, k))) throw Error('Unexpected or missing attestation fields');
}
function integer(v, min, max) {
  if (!Number.isSafeInteger(v) || v < min || v > max) throw Error('Invalid attestation integer');
}
function hex(v, bytes) {
  if (typeof v !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(v) || /^0+$/.test(v)) throw Error('Invalid attestation digest');
}
function bytes32(v) { if (typeof v !== 'string' || !v.startsWith('0x')) throw Error('Invalid binding'); hex(v.slice(2), 32); }
function label(v) { if (typeof v !== 'string' || !/^[\x20-\x7e]{1,160}$/.test(v) || v.trim() !== v) throw Error('Invalid attestation label'); }
function address(v) { if (getAddress(v) === '0x0000000000000000000000000000000000000000') throw Error('Invalid binding address'); }

// Only fixed ASCII field names/strings and safe integers enter our hashed objects.
// This restricted subset has the same encoding as Trustee's RFC 8785 canonicalizer.
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (object(v)) return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
function publicKey(key) {
  exact(key, ['kty', 'crv', 'x', 'y']);
  if (key.kty !== 'EC' || key.crv !== 'P-256') throw Error('Require a public P-256 JWK');
  for (const value of [key.x, key.y]) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value) || Buffer.from(value, 'base64url').toString('base64url') !== value) throw Error('Invalid public-key coordinate');
  }
}

export function validateAttestationPolicy(policy) {
  exact(policy, ['schema', 'issuer', 'signingJwk', 'verifierBuild', 'appraisalPolicyId', 'maxTokenAgeSeconds', 'maxTokenLifetimeSeconds', 'challengeTTLSeconds', 'tee', 'measurements']);
  if (policy.schema !== 'cannabis.attestation.trustee-policy.v1') throw Error('Unknown attestation policy');
  for (const k of ['issuer', 'verifierBuild', 'appraisalPolicyId']) label(policy[k]);
  publicKey(policy.signingJwk);
  integer(policy.maxTokenAgeSeconds, 1, 300); integer(policy.maxTokenLifetimeSeconds, 1, 300); integer(policy.challengeTTLSeconds, 1, 120);
  const m = policy.measurements;
  if (policy.tee === 'snp') {
    exact(m, ['launch', 'initData', 'minimumTCB']); hex(m.launch, 48); hex(m.initData, 32);
    exact(m.minimumTCB, ['bootloader', 'tee', 'snp', 'microcode']);
    for (const v of Object.values(m.minimumTCB)) integer(v, 0, 255);
  } else if (policy.tee === 'tdx') {
    exact(m, ['launch', 'initData', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3']);
    for (const [k, v] of Object.entries(m)) {
      // An unused runtime register may legitimately be all zeroes.
      if (/^rtmr/.test(k) && v === '0'.repeat(96)) continue;
      hex(v, 48);
    }
  } else throw Error('Unsupported attestation profile; require SNP or TDX CPU evidence');
  return sha256(canonical(policy));
}

export function validateAttestationBinding(b) {
  const configured=Object.hasOwn(b??{},'configurationSHA256');
  exact(b, ['chainId', 'escrow', 'orderId', 'leaseDigest', 'reservationId', 'packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256', 'attempt', 'rank', 'worldSize', 'acceleratorClass',...(configured?['configurationSHA256']:[])]);
  if(configured)bytes32(b.configurationSHA256);
  integer(b.chainId, 1, Number.MAX_SAFE_INTEGER); address(b.escrow);
  for (const k of ['orderId', 'leaseDigest', 'reservationId']) bytes32(b[k]);
  for (const k of ['packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256']) hex(b[k], 32);
  integer(b.attempt, 1, 1000000); integer(b.worldSize, 1, 100000); integer(b.rank, 0, b.worldSize - 1);
  if (b.acceleratorClass !== 'cpu') throw Error('Accelerator and interconnect attestation profiles are not integrated; no CPU-only fallback');
}

// Derive financial bindings from the provider's trusted local funded-lease ledger.
// This historical record is not a fresh funding check or runtime authorization.
export function leaseAttestationBinding(ledger, leaseId, reservationId, run, now = seconds()) {
  exact(run, ['runtimeSHA256', 'taskSHA256', 'attempt', 'rank', 'worldSize', 'acceleratorClass']);
  const record = inspectLease(ledger, leaseId);
  const reservation = record.reservations.find(r => r.id === reservationId);
  if (!reservation || reservation.end <= now) throw Error('Unknown or elapsed lease reservation');
  const job = record.agreement.request.job;
  const binding = { chainId: ledger.context.chainId, escrow: record.escrow, orderId: record.orderId,
    leaseDigest: record.digest, reservationId, packageSHA256: job.packageSHA256, policySHA256: job.policySHA256, ...run };
  validateAttestationBinding(binding); return binding;
}

// The complete group digest commits the market and booking digests; each booking
// commits its immutable offer/resource, requester, price and settlement terms.
// No saved observation is a fresh chain check or permission to release keys.
export function marketAttestationBinding(proof, context, bookingId, run, now = seconds()) {
  exact(run, ['runtimeSHA256', 'taskSHA256', 'attempt', 'rank', 'worldSize', 'acceleratorClass']);
  const lease = verifyMarketLeaseProof(proof, context), reservation = lease.reservations.find(r => r.reservationId === bookingId);
  if (!reservation || !Number.isSafeInteger(now) || reservation.end <= now) throw Error('Unknown or elapsed market booking');
  if(lease.executionPlan) {
    const planned=lease.assignments.find(a=>a.reservationId===bookingId);
    if(!planned||canonical(planned.run)!==canonical(run))throw Error('Run differs from the complete booked execution plan');
  } else if(run.worldSize!==1||run.rank!==0)throw Error('A coordinated group requires a complete committed execution plan');
  const binding = { chainId: context.chainId, escrow: lease.escrow, orderId: lease.orderId,
    leaseDigest: lease.digest, reservationId: bookingId, packageSHA256: lease.job.packageSHA256, policySHA256: lease.job.policySHA256, ...run };
  validateAttestationBinding(binding); return binding;
}

// The caller supplies the hash of its independently reviewed configuration.
// Requester key approval later recomputes it from that full local configuration.
export function configuredMarketAttestationBinding(proof,context,bookingId,run,configurationSHA256,now=seconds()) {
  bytes32(configurationSHA256);
  const binding={...marketAttestationBinding(proof,context,bookingId,run,now),configurationSHA256};
  validateAttestationBinding(binding);return binding;
}

function validateChallenge(c, policyDigest, policy, now) {
  exact(c, ['schema', 'nonce', 'issuedAt', 'expiresAt', 'attestationPolicySHA256', 'binding']);
  if (c.schema !== 'cannabis.attestation.challenge.v1' || c.attestationPolicySHA256 !== policyDigest) throw Error('Challenge policy mismatch');
  hex(c.nonce, 32); integer(now, 1, Number.MAX_SAFE_INTEGER); integer(c.issuedAt, 1, now);
  integer(c.expiresAt, c.issuedAt + 1, c.issuedAt + policy.challengeTTLSeconds);
  if (c.expiresAt <= now) throw Error('Attestation challenge expired');
  validateAttestationBinding(c.binding);
}

// The protected guest generates the channel key. Its private half never leaves it.
// This custom structured runtime data is for Trustee AS, not the KBS RCAR wire format.
export function trusteeRuntimeData(challenge, channelJwk) {
  publicKey(channelJwk);
  return structuredClone({ nonce: challenge.nonce, 'cannabis-channel-key': channelJwk,
    cannabis: { schema: challenge.schema, issuedAt: challenge.issuedAt, expiresAt: challenge.expiresAt,
      attestationPolicySHA256: challenge.attestationPolicySHA256, binding: challenge.binding } });
}

// Bytes passed directly to the guest attester, not the un-hashed JSON or its
// printable hex representation. SNP/TDX report_data is exactly 64 bytes.
export function trusteeReportData(policy, challenge, channelJwk, now = seconds()) {
  const digest = validateAttestationPolicy(policy);
  validateChallenge(challenge, digest, policy, now);
  return Buffer.concat([createHash('sha384').update(canonical(trusteeRuntimeData(challenge, channelJwk))).digest(), Buffer.alloc(16)]);
}

export function trusteeEvidenceRequest(policy, challenge, channelJwk, evidence, now = seconds()) {
  const digest = validateAttestationPolicy(policy); validateChallenge(challenge, digest, policy, now); publicKey(channelJwk);
  if (typeof evidence !== 'string' || evidence.length > 4 * 1024 * 1024 || !/^[A-Za-z0-9_-]+$/.test(evidence) ||
    Buffer.from(evidence, 'base64url').toString('base64url') !== evidence) throw Error('Require bounded base64url hardware evidence');
  return { verification_requests: [{ tee: policy.tee, evidence,
    runtime_data: { structured: trusteeRuntimeData(challenge, channelJwk) }, runtime_data_hash_algorithm: 'sha384',
    init_data: { init_data_digest: Buffer.from(policy.measurements.initData, 'hex').toString('base64url') } }],
    policy_ids: [policy.appraisalPolicyId] };
}

// Send hardware evidence to the owner's configured AS. It checks vendor roots and
// revocation; our independent pinned-key/result checks still run on its response.
async function fetchTrusteeToken(policy, challenge, endpoint, channelJwk, evidence, now) {
  const url = new URL(endpoint);
  if (url.username || url.password || url.hash || url.search || url.pathname !== '/attestation' ||
    (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)))) throw Error('Require HTTPS Trustee /attestation endpoint or explicit loopback');
  const request = trusteeEvidenceRequest(policy, challenge, channelJwk, evidence, now);
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'text/plain' },
    body: JSON.stringify(request), redirect: 'error', signal: AbortSignal.timeout(15000) });
  if (!response.ok || !response.body) { await response.body?.cancel(); throw Error('Trustee attestation request failed'); }
  const reader = response.body.getReader(); let size = 0; const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.length; if (size > MAX_TOKEN) throw Error('Oversized Trustee response'); chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return Buffer.concat(chunks).toString('utf8').trim();
}

export async function attestWithTrustee(ledger, endpoint, nonce, channelJwk, evidence) {
  channelJwk = structuredClone(channelJwk);
  const token = await fetchTrusteeToken(ledger.policy, ledger.pending(nonce), endpoint, channelJwk, evidence, ledger.clock());
  return ledger.verify(nonce, token, channelJwk);
}

// Requester-side appraisal for the later atomic key-delivery transaction. This
// verifies the EAR but deliberately keeps its challenge pending for seal().
export async function requestTrusteeResult(ledger, endpoint, nonce, channelJwk, evidence) {
  channelJwk = structuredClone(channelJwk);
  const challenge = ledger.pending(nonce);
  const token = await fetchTrusteeToken(ledger.policy, challenge, endpoint, channelJwk, evidence, ledger.clock());
  const appraisal = await verifyTrusteeResult(token, ledger.policy, challenge, channelJwk, ledger.clock());
  if (canonical(ledger.pending(nonce)) !== canonical(challenge)) throw Error('Challenge changed during Trustee appraisal');
  return { token, appraisal, challengeConsumed: false, executionAuthorized: false, keyReleaseAuthorized: false };
}

function checkCpu(appraisal, policy, runtime) {
  if (!object(appraisal) || appraisal['ear.status'] !== 'affirming' || appraisal['ear.appraisal-policy-id'] !== policy.appraisalPolicyId) throw Error('CPU appraisal is not approved by the pinned policy');
  const vector = appraisal['ear.trustworthiness-vector']; exact(vector, VECTOR);
  for (const [key, value] of Object.entries(vector)) {
    const allowed = key === 'hardware' ? [2] : key === 'executables' ? [3, 4] : key === 'configuration' ? [2, 3] : [0];
    if (!allowed.includes(value)) throw Error('Unsupported or non-affirming CPU trust vector');
  }
  const evidence = appraisal['ear.veraison.annotated-evidence'];
  exact(evidence, [policy.tee, 'report_data', 'init_data', 'runtime_data_claims', 'init_data_claims']);
  if (canonical(evidence.runtime_data_claims) !== canonical(runtime)) throw Error('Attestation runtime binding mismatch');
  const reportData = createHash('sha384').update(canonical(runtime)).digest('hex') + '0'.repeat(32);
  if (evidence.report_data !== reportData || evidence.init_data !== policy.measurements.initData) throw Error('Measured report data or init data mismatch');
  const claims = evidence[policy.tee], m = policy.measurements;
  if (!object(claims)) throw Error('Missing CPU claims');
  if (policy.tee === 'snp') {
    if (claims.measurement !== m.launch || claims.policy_debug_allowed !== false || claims.policy_migrate_ma !== false) throw Error('SNP boot, debug or migration policy mismatch');
    for (const [part, minimum] of Object.entries(m.minimumTCB)) {
      const actual = claims['reported_tcb_' + part]; integer(actual, minimum, 255);
    }
  } else {
    if (claims.td_attributes?.debug !== false || claims.tcb_status !== 'UpToDate' || claims.collateral_expiration_status !== '0' ||
      (claims.tcb_status_current !== undefined && claims.tcb_status_current !== 'UpToDate')) throw Error('TDX debug, TCB or collateral policy mismatch');
    const body = claims.quote?.body;
    if (!object(body) || body.mr_td !== m.launch) throw Error('TDX launch measurement mismatch');
    for (let i = 0; i < 4; i++) if (body['rtmr_' + i] !== m['rtmr' + i]) throw Error('TDX runtime measurement mismatch');
  }
}

// Verifies one signed result. Use AttestationLedger.verify to also consume its nonce.
export async function verifyTrusteeResult(token, policy, challenge, channelJwk, now = seconds()) {
  policy = structuredClone(policy); challenge = structuredClone(challenge); channelJwk = structuredClone(channelJwk);
  const policyDigest = validateAttestationPolicy(policy); validateChallenge(challenge, policyDigest, policy, now); publicKey(channelJwk);
  if (typeof token !== 'string' || token.length > MAX_TOKEN || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw Error('Invalid or oversized EAR token');
  // Use only requester-provisioned trust. Embedded jwk/x5c/jku are never trust anchors.
  const key = await importJWK(policy.signingJwk, 'ES256');
  await importJWK(channelJwk, 'ECDH-ES'); // Reject off-curve channel keys, even if a token is signed.
  const { payload, protectedHeader } = await jwtVerify(token, key, {
    algorithms: ['ES256'], typ: 'JWT', issuer: policy.issuer, currentDate: new Date(now * 1000),
    requiredClaims: ['iat', 'exp', 'iss', 'eat_profile', 'ear.verifier-id', 'submods'],
    maxTokenAge: policy.maxTokenAgeSeconds, clockTolerance: 0
  });
  if (protectedHeader.jku !== undefined || protectedHeader.x5u !== undefined) throw Error('Remote signing-key references are not accepted');
  integer(payload.iat, challenge.issuedAt, now); integer(payload.exp, now + 1, payload.iat + policy.maxTokenLifetimeSeconds);
  if (payload.eat_profile !== PROFILE || payload['ear.verifier-id']?.developer !== 'https://confidentialcontainers.org' || payload['ear.verifier-id']?.build !== policy.verifierBuild) throw Error('Unexpected Trustee profile or verifier identity');
  exact(payload.submods, ['cpu0']); // Additional or missing devices require a separately integrated profile.
  checkCpu(payload.submods.cpu0, policy, trusteeRuntimeData(challenge, channelJwk));
  return { schema: 'cannabis.attestation.result.v1', attestationVerified: true,
    tokenSHA256: sha256(token), attestationPolicySHA256: policyDigest, channelJwk,
    binding: challenge.binding, verifiedAt: now, expiresAt: Math.min(payload.exp, challenge.expiresAt, payload.iat + policy.maxTokenAgeSeconds),
    executionAuthorized: false, keyReleaseAuthorized: false, fundingRecheckRequired: true,
    note: 'CPU attestation result checked. Protected runtime, per-job key delivery, peer admission and fresh funded-lease authorization remain separate requirements.' };
}

export class AttestationLedger {
  constructor(file, policy, clock = seconds) {
    this.policy = structuredClone(policy); this.policyDigest = validateAttestationPolicy(this.policy); this.clock = clock;
    this.db = openDurableDatabase(file, { timeout: 5000 });
    this.db.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS attestation_settings (id INTEGER PRIMARY KEY CHECK(id=1), policyDigest TEXT NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS attestation_challenges (nonce TEXT PRIMARY KEY, body TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, tokenSHA256 TEXT) STRICT;`);
    try { this.transaction(() => {
      const saved = this.db.prepare('SELECT policyDigest FROM attestation_settings WHERE id=1').get();
      if (saved && saved.policyDigest !== this.policyDigest) throw Error('Attestation ledger policy cannot change; rotate trust explicitly');
      if (!saved) this.db.prepare('INSERT INTO attestation_settings VALUES (1,?)').run(this.policyDigest);
    }); } catch (error) { this.db.close(); throw error; }
  }
  transaction(fn) { this.db.exec('BEGIN IMMEDIATE'); try { const r = fn(); this.db.exec('COMMIT'); return r; } catch (e) { this.db.exec('ROLLBACK'); throw e; } }
  close() { this.db.close(); }
  challenge(binding) {
    binding = structuredClone(binding); validateAttestationBinding(binding);
    const now = this.clock(); integer(now, 1, Number.MAX_SAFE_INTEGER - 120);
    const challenge = { schema: 'cannabis.attestation.challenge.v1', nonce: randomBytes(32).toString('hex'), issuedAt: now,
      expiresAt: now + this.policy.challengeTTLSeconds, attestationPolicySHA256: this.policyDigest, binding };
    this.db.prepare('INSERT INTO attestation_challenges (nonce,body) VALUES (?,?)').run(challenge.nonce, JSON.stringify(challenge));
    return challenge;
  }
  pending(nonce) {
    hex(nonce, 32);
    const row = this.db.prepare('SELECT body,consumed FROM attestation_challenges WHERE nonce=?').get(nonce);
    if (!row || row.consumed) throw Error('Unknown or consumed attestation challenge');
    const c = JSON.parse(row.body); validateChallenge(c, this.policyDigest, this.policy, this.clock()); return c;
  }
  cancel(nonce) {
    hex(nonce, 32);
    return { cancelled: this.db.prepare('UPDATE attestation_challenges SET consumed=1 WHERE nonce=? AND consumed=0').run(nonce).changes === 1 };
  }
  async verify(nonce, token, channelJwk) {
    const challenge = this.pending(nonce);
    const result = await verifyTrusteeResult(token, this.policy, challenge, channelJwk, this.clock());
    return this.transaction(() => {
      const current = this.pending(nonce), now = this.clock();
      if (canonical(current) !== canonical(challenge) || now < result.verifiedAt || result.expiresAt <= now) throw Error('Challenge changed or expired during verification');
      this.db.prepare('UPDATE attestation_challenges SET consumed=1,tokenSHA256=? WHERE nonce=?').run(result.tokenSHA256, nonce);
      return { ...result, challengeConsumed: true, verifiedAt: now };
    });
  }
}
