// Requester-authorized, attestation-bound encrypted job-key delivery.
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CompactEncrypt, compactDecrypt, importJWK, calculateJwkThumbprint } from 'jose';
import { TypedDataEncoder, getAddress, verifyTypedData } from 'ethers';
import { inspectLease } from './leases.mjs';
import { leaseAttestationBinding, trusteeRuntimeData, verifyTrusteeResult } from './attestation.mjs';
import { readCurrentEscrow, readFinalizedEscrow } from './finality.mjs';

const hash = data => createHash('sha256').update(data).digest('hex');
const nowSeconds = () => Math.floor(Date.now() / 1000);
const recipient = value => typeof value === 'string' && /^age1[0-9a-z]{58}$/.test(value);

// Source paths/executables are trusted local requester configuration, never worker
// protocol fields. The owner identity is decrypted only in this local child.
export async function recoverRequesterJobKey(source, expected) {
  source = structuredClone(source); expected = structuredClone(expected);
  exact(source, ['python', 'age', 'identity', 'capsule', 'descriptor']);
  for (const value of Object.values(source)) if (typeof value !== 'string' || !value || value.includes('\0')) throw Error('Invalid requester custody path');
  const script = fileURLToPath(new URL('../scripts/compute-key-capsule-pipe.py', import.meta.url));
  const { python, ...local } = source;
  return new Promise((resolve, reject) => {
    const child = spawn(python, [script], { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true, shell: false });
    let size = 0, failed = false; const chunks = [];
    const fail = () => { if (!failed) { failed = true; clearTimeout(timer); for (const chunk of chunks) chunk.fill(0); child.kill(); reject(Error('Local job-key recovery failed')); } };
    const timer = setTimeout(fail, 30000);
    child.on('error', fail); child.stdin.on('error', fail);
    child.stdout.on('data', data => { size += data.length; if (size > 16384) fail(); else chunks.push(data); });
    child.on('close', code => {
      clearTimeout(timer);
      if (failed) return;
      if (code !== 0) { fail(); return; }
      const raw = Buffer.concat(chunks);
      try { resolve(JSON.parse(raw.toString('utf8'))); } catch { fail(); }
      finally { raw.fill(0); for (const chunk of chunks) chunk.fill(0); }
    });
    child.stdin.end(JSON.stringify({ protocol: 'cannabis.local-job-key.v1', source: local, expected }));
  });
}
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) throw Error('Unexpected key-delivery fields');
}
function bytes32(value) { if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/.test(value) || /^0x0+$/.test(value)) throw Error('Invalid key-delivery commitment'); }
function integer(value, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) throw Error('Invalid key-delivery time or rank'); }
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
function domain(binding) { return { name: 'Cannabis confidential key delivery', version: '1', chainId: binding.chainId, verifyingContract: getAddress(binding.escrow) }; }
export const deliveryTypes = { JobKeyDelivery: [
  ['releaseId', 'bytes32'], ['leaseDigest', 'bytes32'], ['orderId', 'bytes32'], ['reservationId', 'bytes32'],
  ['packageSHA256', 'bytes32'], ['policySHA256', 'bytes32'], ['attestationPolicySHA256', 'bytes32'],
  ['runtimeSHA256', 'bytes32'], ['taskSHA256', 'bytes32'], ['capsuleSHA256', 'bytes32'],
  ['inputRecipient', 'string'], ['channelKeySHA256', 'bytes32'], ['nonce', 'bytes32'],
  ['attempt', 'uint32'], ['rank', 'uint32'], ['worldSize', 'uint32'], ['notBefore', 'uint64'], ['expiresAt', 'uint64']
].map(([name, type]) => ({ name, type })) };

function custody(descriptor, job) {
  if (!descriptor || descriptor.schema !== 'cannabis.package.v2' || descriptor.id !== job.id || descriptor.ciphertextSHA256 !== job.packageSHA256 || descriptor.policySHA256 !== job.policySHA256 || !recipient(descriptor.recipient)) throw Error('Key descriptor differs from the funded workload');
  const c = descriptor.keyCustody;
  exact(c, ['schema', 'format', 'ciphertextSHA256', 'ciphertextBytes']);
  if (c.schema !== 'cannabis.job-key.custody.v1' || c.format !== 'age-v1+json') throw Error('Unsupported job-key custody');
  bytes32('0x' + c.ciphertextSHA256); integer(c.ciphertextBytes, 1, 16384);
  return c;
}

// A wallet-review payload. No signing, key recovery, RPC or key delivery occurs here.
export function keyDeliveryPayload(capacity, attestations, request, now = nowSeconds()) {
  exact(request, ['releaseId', 'leaseId', 'nonce', 'channelJwk', 'descriptor', 'notBefore', 'expiresAt']);
  bytes32(request.releaseId); bytes32(request.leaseId);
  const challenge = attestations.pending(request.nonce), b = challenge.binding;
  const lease = inspectLease(capacity, request.leaseId);
  const reservation = lease.reservations.find(r => r.id === b.reservationId);
  if (!reservation) throw Error('Challenge does not reference this funded reservation');
  const run = Object.fromEntries(['runtimeSHA256', 'taskSHA256', 'attempt', 'rank', 'worldSize', 'acceleratorClass'].map(k => [k, b[k]]));
  const expected = leaseAttestationBinding(capacity, request.leaseId, b.reservationId, run, now);
  if (canonical(expected) !== canonical(b)) throw Error('Challenge and funded lease differ');
  const c = custody(request.descriptor, lease.agreement.request.job);
  trusteeRuntimeData(challenge, request.channelJwk); // Strict public-key schema; no private key accepted.
  integer(request.notBefore, Math.max(reservation.start, challenge.issuedAt), reservation.end - 1);
  integer(request.expiresAt, Math.max(request.notBefore, now) + 1, Math.min(reservation.end, challenge.expiresAt));
  const value = {
    releaseId: request.releaseId, leaseDigest: b.leaseDigest, orderId: b.orderId, reservationId: b.reservationId,
    packageSHA256: '0x' + b.packageSHA256, policySHA256: '0x' + b.policySHA256,
    attestationPolicySHA256: '0x' + challenge.attestationPolicySHA256, runtimeSHA256: '0x' + b.runtimeSHA256,
    taskSHA256: '0x' + b.taskSHA256, capsuleSHA256: '0x' + c.ciphertextSHA256,
    inputRecipient: request.descriptor.recipient, channelKeySHA256: '0x' + hash(canonical(request.channelJwk)),
    nonce: '0x' + challenge.nonce, attempt: b.attempt, rank: b.rank, worldSize: b.worldSize,
    notBefore: request.notBefore, expiresAt: request.expiresAt
  };
  const d = domain(b);
  return { domain: d, types: deliveryTypes, value, digest: TypedDataEncoder.hash(d, deliveryTypes, value),
    requester: getAddress(lease.agreement.request.job.requester), provider: reservation.provider,
    jobId: lease.agreement.request.job.id, leaseId: lease.leaseId,
    executionAuthorized: false, keyReleaseAuthorized: false };
}

function checkWindow(payload, now) {
  integer(now, payload.value.notBefore, payload.value.expiresAt - 1);
}

function activeSnapshot(snapshot, lease, network) {
  const original = lease.finalityEvidence;
  if (snapshot.termsDigest !== original.termsDigest || snapshot.requester !== original.requester ||
    getAddress(snapshot.escrow) !== getAddress(lease.escrow) || getAddress(snapshot.token) !== getAddress(original.token) ||
    snapshot.genesisHash !== original.genesisHash || snapshot.runtimeCodeHashes.escrow.toLowerCase() !== original.runtimeCodeHashes.escrow.toLowerCase() ||
    snapshot.runtimeCodeHashes.token.toLowerCase() !== original.runtimeCodeHashes.token.toLowerCase() || BigInt(snapshot.chainId) !== BigInt(network.chainId)) throw Error('Funding or network differs from the signed lease');
  if (snapshot.state !== 2 || snapshot.acceptedCount !== snapshot.accounts.length || BigInt(snapshot.acceptedBitmap) !== (1n << BigInt(snapshot.accounts.length)) - 1n) throw Error('The fully accepted funded order must still be active');
}

function deriveInputRecipient(identity, ageKeygen) {
  if (typeof identity !== 'string' || !/^AGE-SECRET-KEY-1[A-Z0-9]{58}\n$/.test(identity)) throw Error('Require exactly one per-job input identity');
  const executable = ageKeygen || (process.env.CANNABIS_AGE ? path.join(path.dirname(process.env.CANNABIS_AGE), process.platform === 'win32' ? 'age-keygen.exe' : 'age-keygen') : 'age-keygen');
  const result = spawnSync(executable, ['-y'], { input: identity, encoding: 'utf8', timeout: 10000, maxBuffer: 1024, windowsHide: true, shell: false });
  if (result.error || result.status !== 0 || !recipient(result.stdout.trim())) throw Error('Local per-job key verification failed');
  return result.stdout.trim(); // Never include parser output/errors in diagnostics.
}

function initializeJournal(attestations) {
  attestations.db.exec(`CREATE TABLE IF NOT EXISTS key_deliveries (
    releaseId TEXT PRIMARY KEY, approvalDigest TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE,
    leaseDigest TEXT NOT NULL, taskSHA256 TEXT NOT NULL, attempt INTEGER NOT NULL, rank INTEGER NOT NULL,
    body TEXT NOT NULL, UNIQUE(leaseDigest,taskSHA256,attempt,rank)
  ) STRICT;`);
}

// loadJobKey is a trusted requester-side callback. It must recover the capsule
// against the approved descriptor/commitments, never accept a worker-supplied key.
export async function sealJobKeyDelivery(capacity, attestations, signed, token, network, loadJobKey, { clock = nowSeconds, ageKeygen } = {}) {
  signed = structuredClone(signed); network = structuredClone(network);
  exact(signed, ['request', 'requesterSignature']);
  initializeJournal(attestations);
  const request = signed.request, payload = keyDeliveryPayload(capacity, attestations, request, clock());
  if (verifyTypedData(payload.domain, payload.types, payload.value, signed.requesterSignature) !== payload.requester) throw Error('Requester key-delivery approval signature mismatch');
  checkWindow(payload, clock());
  if (attestations.db.prepare('SELECT 1 FROM key_deliveries WHERE releaseId=? OR (leaseDigest=? AND taskSHA256=? AND attempt=? AND rank=?)').get(payload.value.releaseId, payload.value.leaseDigest, payload.value.taskSHA256, payload.value.attempt, payload.value.rank)) throw Error('A key delivery already exists for this release or rank attempt');
  const challenge = attestations.pending(request.nonce), lease = inspectLease(capacity, request.leaseId);
  if (BigInt(network.chainId) !== BigInt(payload.domain.chainId) || getAddress(network.escrow) !== getAddress(payload.domain.verifyingContract)) throw Error('Key-delivery network mismatch');
  const appraisal = await verifyTrusteeResult(token, attestations.policy, challenge, request.channelJwk, clock());
  const finalized = await readFinalizedEscrow({ ...network, orderId: payload.value.orderId }, clock);
  activeSnapshot(finalized, lease, network);
  const head = await readCurrentEscrow({ ...network, orderId: payload.value.orderId, finalizedAnchor: finalized.finalizedBlock }, clock);
  activeSnapshot(head, lease, network);
  if (head.headBlock.number < finalized.finalizedBlock.number || head.headBlock.timestamp >= request.expiresAt) throw Error('Funding head is behind finality or outside the delivery window');
  checkWindow(payload, clock());
  if (clock() >= appraisal.expiresAt) throw Error('Attestation expired before job-key recovery');
  if (canonical(attestations.pending(request.nonce)) !== canonical(challenge)) throw Error('Challenge changed before job-key recovery');
  // The callback is reached only after signature, attestation, finality and head checks.
  const recovered = await loadJobKey(structuredClone({ jobId: payload.jobId, packageSHA256: challenge.binding.packageSHA256,
    policySHA256: challenge.binding.policySHA256, capsuleSHA256: request.descriptor.keyCustody.ciphertextSHA256,
    inputRecipient: request.descriptor.recipient }));
  exact(recovered, ['identity', 'jobId', 'packageSHA256', 'policySHA256', 'inputRecipient', 'resultRecipient']);
  if (recovered.jobId !== payload.jobId || recovered.packageSHA256 !== challenge.binding.packageSHA256 || recovered.policySHA256 !== challenge.binding.policySHA256 ||
    recovered.inputRecipient !== payload.value.inputRecipient || !recipient(recovered.resultRecipient) || recovered.resultRecipient === recovered.inputRecipient ||
    deriveInputRecipient(recovered.identity, ageKeygen) !== payload.value.inputRecipient) throw Error('Recovered key does not belong to this approved job');
  const publicKey = await importJWK(request.channelJwk, 'ECDH-ES+A256KW');
  const keyId = await calculateJwkThumbprint(request.channelJwk);
  const cleartext = Buffer.from(JSON.stringify({ schema: 'cannabis.job-key.delivery.v1',
    notAfter: Math.min(request.expiresAt, appraisal.expiresAt),
    approval: { domain: payload.domain, value: payload.value, requester: payload.requester, signature: signed.requesterSignature },
    job: recovered }));
  let envelope;
  try {
    envelope = await new CompactEncrypt(cleartext).setProtectedHeader({ alg: 'ECDH-ES+A256KW', enc: 'A256GCM',
      typ: 'cannabis-job-key+jwe', kid: keyId, 'cannabis-approval': payload.digest }).encrypt(publicKey);
  } finally { cleartext.fill(0); } // Best effort only; JS strings/crypto internals may retain copies.
  // Reobserve after local key recovery/wrapping; neither a saved lease nor an
  // earlier active snapshot authorizes a later delivery after state changes.
  const finalHead = await readCurrentEscrow({ ...network, orderId: payload.value.orderId, finalizedAnchor: finalized.finalizedBlock }, clock);
  activeSnapshot(finalHead, lease, network);
  if (finalHead.headBlock.number < head.headBlock.number || finalHead.headBlock.timestamp >= request.expiresAt) throw Error('Latest funding view regressed or delivery window ended');
  return attestations.transaction(() => {
    checkWindow(payload, clock());
    if (clock() >= appraisal.expiresAt) throw Error('Attestation expired during key wrapping');
    const current = keyDeliveryPayload(capacity, attestations, request, clock());
    if (current.digest !== payload.digest || inspectLease(capacity, request.leaseId).digest !== lease.digest) throw Error('Delivery approval or lease changed during wrapping');
    const record = { schema: 'cannabis.key-delivery.record.v1', releaseId: request.releaseId, approvalDigest: payload.digest,
      nonce: request.nonce, issuedAt: clock(), expiresAt: Math.min(request.expiresAt, appraisal.expiresAt),
      envelope, envelopeSHA256: hash(envelope), attestationTokenSHA256: appraisal.tokenSHA256,
      finalizedBlock: finalized.finalizedBlock, observedHead: finalHead.headBlock,
      keyWrapped: true, transmitted: false, executionAuthorized: false };
    attestations.db.prepare('INSERT INTO key_deliveries VALUES (?,?,?,?,?,?,?,?)').run(request.releaseId, payload.digest, request.nonce,
      payload.value.leaseDigest, payload.value.taskSHA256, payload.value.attempt, payload.value.rank, JSON.stringify(record));
    const consumed = attestations.db.prepare('UPDATE attestation_challenges SET consumed=1,tokenSHA256=? WHERE nonce=? AND consumed=0').run(appraisal.tokenSHA256, request.nonce);
    if (consumed.changes !== 1) throw Error('Key-delivery challenge was already consumed');
    return record;
  });
}

export function inspectKeyDelivery(attestations, releaseId) {
  bytes32(releaseId); initializeJournal(attestations);
  const row = attestations.db.prepare('SELECT body FROM key_deliveries WHERE releaseId=?').get(releaseId);
  if (!row) throw Error('Unknown encrypted key delivery');
  return JSON.parse(row.body);
}

// Call only INSIDE the approved guest with its own channel private key and its
// locally retained expected ticket. Decryption alone never authorizes execution.
export async function openJobKeyDelivery(envelope, channelPrivateKey, expected, { clock = nowSeconds, ageKeygen } = {}) {
  if (typeof envelope !== 'string' || envelope.length > 32768) throw Error('Invalid key-delivery envelope');
  const { plaintext, protectedHeader } = await compactDecrypt(envelope, channelPrivateKey, {
    keyManagementAlgorithms: ['ECDH-ES+A256KW'], contentEncryptionAlgorithms: ['A256GCM']
  });
  let decoded;
  try { decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)); }
  catch { throw Error('Malformed protected job-key delivery'); }
  finally { plaintext.fill(0); }
  exact(decoded, ['schema', 'notAfter', 'approval', 'job']);
  const a = decoded.approval;
  exact(a, ['domain', 'value', 'requester', 'signature']);
  if (decoded.schema !== 'cannabis.job-key.delivery.v1' || protectedHeader.typ !== 'cannabis-job-key+jwe' ||
    protectedHeader.kid !== Buffer.from(expected.value.channelKeySHA256.slice(2), 'hex').toString('base64url') ||
    canonical(a.domain) !== canonical(expected.domain) || canonical(a.value) !== canonical(expected.value) || a.requester !== expected.requester) throw Error('Guest key delivery differs from its expected approval');
  const digest = TypedDataEncoder.hash(a.domain, deliveryTypes, a.value);
  if (digest !== expected.digest || protectedHeader['cannabis-approval'] !== digest || verifyTypedData(a.domain, deliveryTypes, a.value, a.signature) !== getAddress(expected.requester)) throw Error('Guest requester approval signature mismatch');
  checkWindow({ value: a.value }, clock());
  integer(decoded.notAfter, clock() + 1, a.value.expiresAt);
  const j = decoded.job;
  exact(j, ['identity', 'jobId', 'packageSHA256', 'policySHA256', 'inputRecipient', 'resultRecipient']);
  if (j.jobId !== expected.jobId || j.packageSHA256 !== a.value.packageSHA256.slice(2) || j.policySHA256 !== a.value.policySHA256.slice(2) || j.inputRecipient !== a.value.inputRecipient ||
    !recipient(j.resultRecipient) || j.resultRecipient === j.inputRecipient || deriveInputRecipient(j.identity, ageKeygen) !== j.inputRecipient) throw Error('Guest job-key binding mismatch');
  const { identity, ...metadata } = j;
  // Avoid accidental disclosure through ordinary JSON/object inspection. Explicit
  // identity access is still sensitive and must stay inside the protected guest.
  return Object.defineProperty(metadata, 'identity', { value: identity, enumerable: false });
}
