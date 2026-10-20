// Requester-authorized, attestation-bound encrypted job-key delivery.
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CompactEncrypt, compactDecrypt, importJWK, calculateJwkThumbprint } from 'jose';
import { TypedDataEncoder, getAddress, verifyTypedData, ZeroAddress } from 'ethers';
import { inspectLease } from './leases.mjs';
import { leaseAttestationBinding, marketAttestationBinding, configuredMarketAttestationBinding, trusteeRuntimeData, verifyTrusteeResult } from './attestation.mjs';
import { verifyMarketLeaseProof, readMarketLeaseState } from './market_lease.mjs';
import { readCurrentEscrow, readFinalizedEscrow } from './finality.mjs';
import { resultKeyCommitment } from './result_keys.mjs';
import { validateGuestConfiguration } from './guest_configuration.mjs';
import { guestInitialization } from './guest_initialization.mjs';
import { nativeServiceCommitment } from './guest_execution.mjs';
import { inspectLaunchConsent } from './guest_consent.mjs';
import { inspectGuestDependency } from './guest_dependency.mjs';

const hash = data => createHash('sha256').update(data).digest('hex');
const nowSeconds = () => Math.floor(Date.now() / 1000);
const recipient = value => typeof value === 'string' && /^age1[0-9a-z]{58}$/.test(value);
const marketSource=source=>['cannabis.market-requester.v1','cannabis.market-requester.v2','cannabis.market-requester.v3'].includes(source?.schema);
function agreement(source, leaseId) {
  if (!marketSource(source)) return inspectLease(source, leaseId);
  // Saved approvals/results remain readable without issuing new keys from an
  // obsolete configuration-only source. Never silently drop consent on downgrade.
  if(source.schema==='cannabis.market-requester.v2')throw Error('Configured key delivery requires bilateral launch consent (market-requester.v3)');
  const configured=source.schema==='cannabis.market-requester.v3';
  exact(source, ['schema', 'context', 'proof',...(configured?['configuration','consent']:[])]);
  const checked=configured?validateGuestConfiguration(source.configuration):{};
  if(configured&&(checked.configuration.schema!=='cannabis.guest-launch-configuration.v3'||
    canonical(checked.configuration.context)!==canonical(source.context)))throw Error('Require a locally reviewed market launch configuration');
  if(configured&&canonical(source.consent?.configuration)!==canonical(checked.configuration))
    throw Error('Launch consent differs from the independently reviewed configuration');
  const lease = verifyMarketLeaseProof(source.proof, source.context);
  if (lease.digest !== leaseId) throw Error('Requester market group differs from approval');
  return { ...lease, ...checked, leaseId: lease.digest, agreement: { request: { job: lease.job } },
    reservations: lease.reservations.map(r => ({ ...r, id: r.reservationId })) };
}

function consentApprovals(source, lease, binding, now) {
  if(!lease.configuration)return undefined; // Explicit historical unconfigured helpers only.
  const initialization={schema:'cannabis.guest-initialization.v2',tee:lease.configuration.attestationPolicyTemplate.tee,
    requester:lease.requester,jobId:lease.job.id,binding};
  return inspectLaunchConsent(source.consent,initialization,lease.proof,now).approvals;
}

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
function domain(binding,version='1') { return { name: 'Cannabis confidential key delivery', version, chainId: binding.chainId, verifyingContract: getAddress(binding.escrow) }; }
export const deliveryTypes = { JobKeyDelivery: [
  ['releaseId', 'bytes32'], ['leaseDigest', 'bytes32'], ['orderId', 'bytes32'], ['reservationId', 'bytes32'],
  ['packageSHA256', 'bytes32'], ['policySHA256', 'bytes32'], ['attestationPolicySHA256', 'bytes32'],
  ['runtimeSHA256', 'bytes32'], ['taskSHA256', 'bytes32'], ['capsuleSHA256', 'bytes32'],
  ['inputRecipient', 'string'], ['channelKeySHA256', 'bytes32'], ['nonce', 'bytes32'],
  ['attempt', 'uint32'], ['rank', 'uint32'], ['worldSize', 'uint32'], ['notBefore', 'uint64'], ['expiresAt', 'uint64']
].map(([name, type]) => ({ name, type })) };
export const deliveryTypesV2={JobKeyDelivery:[...deliveryTypes.JobKeyDelivery,{name:'resultKeySHA256',type:'bytes32'}]};
export const deliveryTypesV3={JobKeyDelivery:[...deliveryTypesV2.JobKeyDelivery,{name:'configurationSHA256',type:'bytes32'}]};
export const deliveryTypesV4={JobKeyDelivery:[...deliveryTypesV3.JobKeyDelivery,{name:'dependencyApprovalDigest',type:'bytes32'}]};
export function deliveryApprovalTypes(version) {
  if(version==='1')return deliveryTypes;if(version==='2')return deliveryTypesV2;if(version==='3')return deliveryTypesV3;
  if(version==='4')return deliveryTypesV4;
  throw Error('Unsupported key-delivery approval version');
}

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
  const withResult=Object.hasOwn(request??{},'resultKeySHA256');
  const withDependency=Object.hasOwn(request??{},'dependency');
  exact(request, ['releaseId', 'leaseId', 'nonce', 'channelJwk', 'descriptor', 'notBefore', 'expiresAt',...(withResult?['resultKeySHA256']:[]),...(withDependency?['dependency']:[])]);
  if(withResult)bytes32(request.resultKeySHA256);
  bytes32(request.releaseId); bytes32(request.leaseId);
  const challenge = attestations.pending(request.nonce), b = challenge.binding;
  const lease = agreement(capacity, request.leaseId);
  const reservation = lease.reservations.find(r => r.id === b.reservationId);
  if (!reservation) throw Error('Challenge does not reference this funded reservation');
  const run = Object.fromEntries(['runtimeSHA256', 'taskSHA256', 'attempt', 'rank', 'worldSize', 'acceleratorClass'].map(k => [k, b[k]]));
  const configured=!!lease.configuration;
  if(configured!==Object.hasOwn(b,'configurationSHA256')||configured&&!withResult)
    throw Error('Configuration-bound delivery requires its reviewed configuration and result channel');
  const expected = configured
    ? configuredMarketAttestationBinding(capacity.proof,capacity.context,b.reservationId,run,lease.configurationSHA256,now)
    : marketSource(capacity)?marketAttestationBinding(capacity.proof,capacity.context,b.reservationId,run,now)
    : leaseAttestationBinding(capacity,request.leaseId,b.reservationId,run,now);
  if(configured) {
    const configuration=lease.configuration,service=nativeServiceCommitment(configuration.execution);
    if(getAddress(configuration.provider)!==reservation.provider||configuration.resourceId!==reservation.resourceId||
      service.serviceSHA256!==reservation.serviceSHA256||service.units!==reservation.units||
      configuration.execution.profile.runtime.digestSHA256!==b.runtimeSHA256||
      getAddress(configuration.network.escrow)!==lease.escrow||configuration.validFrom>reservation.start||
      configuration.validUntil<reservation.end||now<configuration.validFrom||now>=configuration.validUntil)
      throw Error('Reviewed launch configuration differs from the booked execution');
    const initialization={schema:'cannabis.guest-initialization.v2',tee:configuration.attestationPolicyTemplate.tee,
      requester:lease.requester,jobId:lease.job.id,binding:expected};
    const policy=structuredClone(configuration.attestationPolicyTemplate);
    policy.measurements.initData=guestInitialization(initialization).digest;
    if(canonical(policy)!==canonical(attestations.policy))throw Error('Requester appraisal policy differs from reviewed configuration and assignment');
  }
  if (canonical(expected) !== canonical(b)) throw Error('Challenge and funded lease differ');
  if(withDependency&&!configured)throw Error('Dependency delivery requires the approved operating configuration');
  const dependency=configured?inspectGuestDependency({proof:capacity.proof,network:lease.configuration.network,binding:b,
    execution:lease.configuration.execution,dependency:withDependency?{descriptor:request.descriptor,signed:request.dependency}:undefined,now}):null;
  consentApprovals(capacity,lease,b,now); // Offline party/assignment checks; no chain authorization.
  const c = custody(request.descriptor, lease.agreement.request.job);
  trusteeRuntimeData(challenge, request.channelJwk); // Strict public-key schema; no private key accepted.
  integer(request.notBefore, Math.max(reservation.start, challenge.issuedAt), reservation.end - 1);
  integer(request.expiresAt, Math.max(request.notBefore, now) + 1, Math.min(reservation.end, challenge.expiresAt));
  if(dependency&&(request.notBefore<dependency.signed.window.notBefore||request.expiresAt>dependency.signed.window.expiresAt))
    throw Error('Key delivery exceeds the approved dependency input window');
  const value = {
    releaseId: request.releaseId, leaseDigest: b.leaseDigest, orderId: b.orderId, reservationId: b.reservationId,
    packageSHA256: '0x' + b.packageSHA256, policySHA256: '0x' + b.policySHA256,
    attestationPolicySHA256: '0x' + challenge.attestationPolicySHA256, runtimeSHA256: '0x' + b.runtimeSHA256,
    taskSHA256: '0x' + b.taskSHA256, capsuleSHA256: '0x' + c.ciphertextSHA256,
    inputRecipient: request.descriptor.recipient, channelKeySHA256: '0x' + hash(canonical(request.channelJwk)),
    nonce: '0x' + challenge.nonce, attempt: b.attempt, rank: b.rank, worldSize: b.worldSize,
    notBefore: request.notBefore, expiresAt: request.expiresAt,
    ...(withResult?{resultKeySHA256:request.resultKeySHA256}:{}),
    ...(configured?{configurationSHA256:lease.configurationSHA256}:{}),
    ...(dependency?{dependencyApprovalDigest:dependency.approvalDigest}:{})
  };
  const d=domain(b,dependency?'4':configured?'3':withResult?'2':'1'),types=deliveryApprovalTypes(d.version);
  return { domain: d, types, value, digest: TypedDataEncoder.hash(d, types, value),
    requester: getAddress(lease.agreement.request.job.requester), provider: reservation.provider,
    jobId: lease.agreement.request.job.id, leaseId: lease.leaseId,
    executionAuthorized: false, keyReleaseAuthorized: false };
}

function checkWindow(payload, now) {
  integer(now, payload.value.notBefore, payload.value.expiresAt - 1);
}

function activeSnapshot(snapshot, lease, network) {
  const original = lease.finalityEvidence;
  const tokenCodeMatches = getAddress(snapshot.token) === ZeroAddress
    ? snapshot.runtimeCodeHashes.token === null && original.runtimeCodeHashes.token === null
    : typeof snapshot.runtimeCodeHashes.token === 'string' && typeof original.runtimeCodeHashes.token === 'string' &&
      snapshot.runtimeCodeHashes.token.toLowerCase() === original.runtimeCodeHashes.token.toLowerCase();
  if (snapshot.termsDigest !== original.termsDigest || snapshot.requester !== original.requester ||
    getAddress(snapshot.escrow) !== getAddress(lease.escrow) || getAddress(snapshot.token) !== getAddress(original.token) ||
    snapshot.genesisHash !== original.genesisHash || snapshot.runtimeCodeHashes.escrow.toLowerCase() !== original.runtimeCodeHashes.escrow.toLowerCase() ||
    !tokenCodeMatches || BigInt(snapshot.chainId) !== BigInt(network.chainId)) throw Error('Funding or network differs from the signed lease');
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
export async function sealJobKeyDelivery(capacity, attestations, signed, token, network, loadJobKey, { clock = nowSeconds, ageKeygen, loadResultKey } = {}) {
  signed = structuredClone(signed); network = structuredClone(network);
  if(marketSource(capacity))capacity=structuredClone(capacity);
  exact(signed, ['request', 'requesterSignature']);
  initializeJournal(attestations);
  const request = signed.request, payload = keyDeliveryPayload(capacity, attestations, request, clock());
  if (verifyTypedData(payload.domain, payload.types, payload.value, signed.requesterSignature) !== payload.requester) throw Error('Requester key-delivery approval signature mismatch');
  checkWindow(payload, clock());
  if (attestations.db.prepare('SELECT 1 FROM key_deliveries WHERE releaseId=? OR (leaseDigest=? AND taskSHA256=? AND attempt=? AND rank=?)').get(payload.value.releaseId, payload.value.leaseDigest, payload.value.taskSHA256, payload.value.attempt, payload.value.rank)) throw Error('A key delivery already exists for this release or rank attempt');
  const challenge = attestations.pending(request.nonce), lease = agreement(capacity, request.leaseId);
  if (BigInt(network.chainId) !== BigInt(payload.domain.chainId) || getAddress(network.escrow) !== getAddress(payload.domain.verifyingContract)) throw Error('Key-delivery network mismatch');
  if(lease.configuration&&canonical(network)!==canonical(lease.configuration.network))throw Error('Funding network differs from requester-reviewed launch configuration');
  const approvals=consentApprovals(capacity,lease,challenge.binding,clock());
  const observationOptions=approvals?{launchApprovals:approvals}:{};
  const appraisal = await verifyTrusteeResult(token, attestations.policy, challenge, request.channelJwk, clock());
  const marketBased=marketSource(capacity);
  const finalized = marketBased ? await readMarketLeaseState(lease.proof, network, clock, observationOptions)
    : await readFinalizedEscrow({ ...network, orderId: payload.value.orderId }, clock);
  if (!marketBased) activeSnapshot(finalized, lease, network);
  const head = marketBased ? finalized : await readCurrentEscrow({ ...network, orderId: payload.value.orderId, finalizedAnchor: finalized.finalizedBlock }, clock);
  if (!marketBased) activeSnapshot(head, lease, network);
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
  let envelope,resultKey,cleartext;
  try {
    if(['2','3','4'].includes(payload.domain.version)) {
      if(typeof loadResultKey!=='function')throw Error('Require requester-held result-key custody');
      resultKey=await loadResultKey({releaseId:request.releaseId,recipient:recovered.resultRecipient,resultKeySHA256:payload.value.resultKeySHA256});
      if(resultKeyCommitment(resultKey)!==payload.value.resultKeySHA256)throw Error('Result key differs from signed approval');
    }
    const publicKey = await importJWK(request.channelJwk, 'ECDH-ES+A256KW');
    const keyId = await calculateJwkThumbprint(request.channelJwk);
    cleartext = Buffer.from(JSON.stringify({ schema: 'cannabis.job-key.delivery.v'+payload.domain.version,
      notAfter: Math.min(request.expiresAt, appraisal.expiresAt),
      approval: { domain: payload.domain, value: payload.value, requester: payload.requester, signature: signed.requesterSignature },
      job: recovered,...(resultKey?{resultKey:Buffer.from(resultKey).toString('base64url')}:{}) }));
    envelope = await new CompactEncrypt(cleartext).setProtectedHeader({ alg: 'ECDH-ES+A256KW', enc: 'A256GCM',
      typ: 'cannabis-job-key+jwe', kid: keyId, 'cannabis-approval': payload.digest }).encrypt(publicKey);
  } finally { cleartext?.fill(0);resultKey?.fill(0); } // Best effort only; strings/crypto internals may retain copies.
  // Reobserve after local key recovery/wrapping; neither a saved lease nor an
  // earlier active snapshot authorizes a later delivery after state changes.
  const finalHead = marketBased ? await readMarketLeaseState(lease.proof, network, clock, observationOptions)
    : await readCurrentEscrow({ ...network, orderId: payload.value.orderId, finalizedAnchor: finalized.finalizedBlock }, clock);
  if (!marketBased) activeSnapshot(finalHead, lease, network);
  if (finalHead.headBlock.number < head.headBlock.number || finalHead.headBlock.timestamp >= request.expiresAt) throw Error('Latest funding view regressed or delivery window ended');
  return attestations.transaction(() => {
    checkWindow(payload, clock());
    if (clock() >= appraisal.expiresAt) throw Error('Attestation expired during key wrapping');
    const current = keyDeliveryPayload(capacity, attestations, request, clock());
    if (current.digest !== payload.digest || agreement(capacity, request.leaseId).digest !== lease.digest) throw Error('Delivery approval or lease changed during wrapping');
    const record = { schema: 'cannabis.key-delivery.record.v'+payload.domain.version, releaseId: request.releaseId, approvalDigest: payload.digest,
      nonce: request.nonce, issuedAt: clock(), expiresAt: Math.min(request.expiresAt, appraisal.expiresAt),
      envelope, envelopeSHA256: hash(envelope), attestationTokenSHA256: appraisal.tokenSHA256,
      finalizedBlock: finalized.finalizedBlock, observedHead: finalHead.headBlock,
      keyWrapped: true, transmitted: false, executionAuthorized: false,
      ...(['2','3','4'].includes(payload.domain.version)?{expectedApproval:{...structuredClone(payload),requesterSignature:signed.requesterSignature}}:{}) };
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
  const types=deliveryApprovalTypes(expected?.domain?.version),withResult=['2','3','4'].includes(expected.domain.version);
  exact(expected.value,types.JobKeyDelivery.map(f=>f.name));
  exact(decoded, ['schema', 'notAfter', 'approval', 'job',...(withResult?['resultKey']:[])]);
  const a = decoded.approval;
  exact(a, ['domain', 'value', 'requester', 'signature']);
  if (decoded.schema !== 'cannabis.job-key.delivery.v'+expected.domain.version || protectedHeader.typ !== 'cannabis-job-key+jwe' ||
    protectedHeader.kid !== Buffer.from(expected.value.channelKeySHA256.slice(2), 'hex').toString('base64url') ||
    canonical(a.domain) !== canonical(expected.domain) || canonical(a.value) !== canonical(expected.value) || a.requester !== expected.requester) throw Error('Guest key delivery differs from its expected approval');
  const digest = TypedDataEncoder.hash(a.domain, types, a.value);
  if (digest !== expected.digest || protectedHeader['cannabis-approval'] !== digest || verifyTypedData(a.domain, types, a.value, a.signature) !== getAddress(expected.requester)) throw Error('Guest requester approval signature mismatch');
  checkWindow({ value: a.value }, clock());
  integer(decoded.notAfter, clock() + 1, a.value.expiresAt);
  const j = decoded.job;
  exact(j, ['identity', 'jobId', 'packageSHA256', 'policySHA256', 'inputRecipient', 'resultRecipient']);
  if (j.jobId !== expected.jobId || j.packageSHA256 !== a.value.packageSHA256.slice(2) || j.policySHA256 !== a.value.policySHA256.slice(2) || j.inputRecipient !== a.value.inputRecipient ||
    !recipient(j.resultRecipient) || j.resultRecipient === j.inputRecipient || deriveInputRecipient(j.identity, ageKeygen) !== j.inputRecipient) throw Error('Guest job-key binding mismatch');
  const { identity, ...metadata } = j;
  checkWindow({ value: a.value }, clock());
  integer(decoded.notAfter, clock() + 1, a.value.expiresAt);
  // Avoid accidental disclosure through ordinary JSON/object inspection. Explicit
  // identity access is still sensitive and must stay inside the protected guest.
  let resultKey;
  if(withResult) {
    if(typeof decoded.resultKey!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(decoded.resultKey))throw Error('Invalid protected result key');
    resultKey=Buffer.from(decoded.resultKey,'base64url');
    if(resultKey.toString('base64url')!==decoded.resultKey||resultKeyCommitment(resultKey)!==a.value.resultKeySHA256){resultKey.fill(0);throw Error('Protected result key differs from approval');}
  }
  return Object.defineProperties(metadata, {
    identity: { value: identity, enumerable: false },
    deliveryExpiresAt: { value: decoded.notAfter, enumerable: false },
    ...(resultKey?{resultKey:{value:resultKey,enumerable:false}}:{})
  });
}
