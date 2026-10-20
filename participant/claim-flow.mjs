// Explicit local review -> same-identity proving -> unsigned transaction. Never signs or broadcasts.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { getAddress } from 'ethers';
import { readBounded, validateMembershipSnapshot } from '../claims/identity.mjs';
import { downloadMembershipSnapshot, readClaimConditions } from '../claims/snapshot.mjs';
import { prepareClaim } from '../scripts/prepare-claim.mjs';
import { participantClaimBinding, proveParticipantClaim } from './windows-custody.mjs';

const selections = new WeakMap(), reviews = new WeakMap();
const digest = data => createHash('sha256').update(data).digest('hex');
const exact = (value, fields) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== fields.slice().sort().join(',')) throw Error('Unexpected guided claim fields');
};
const freeze = value => { for (const entry of Object.values(value)) if (entry && typeof entry === 'object') freeze(entry); return Object.freeze(value); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function address(value) { const result = getAddress(value); if (BigInt(result) === 0n) throw Error('Require a nonzero address'); return result; }
function artifact(spec, maximum) {
  exact(spec, ['path', 'sha256', 'bytes']);
  if (!path.isAbsolute(spec.path) || !/^[0-9a-f]{64}$/.test(spec.sha256) || !Number.isSafeInteger(spec.bytes) || spec.bytes < 1 || spec.bytes > maximum) throw Error('Invalid proving artifact selection');
  return { path: spec.path, sha256: spec.sha256, bytes: spec.bytes };
}
function checkFiles(artifacts) {
  for (const name of ['wasm', 'zkey']) {
    const spec = artifacts[name], bytes = readBounded(spec.path, spec.bytes);
    if (bytes.length !== spec.bytes || digest(bytes) !== spec.sha256) throw Error('Proving file changed or does not match the reviewed pin');
  }
}
function unchangedSelection(state) {
  if (digest(readBounded(state.file, 16384)) !== state.fileDigest) throw Error('Claim configuration changed; select and review it again');
}
function matchingConditions(current, reviewed) {
  for (const name of ['chainId', 'token', 'root', 'memberCount', 'minimumClaimMembers', 'claimsStartAt', 'claimAmountBaseUnits']) {
    if (current[name] !== reviewed[name]) throw Error('Claim conditions changed; review fresh membership');
  }
  if (!current.open || current.walletAlreadyClaimed || BigInt(current.communityRemainingBaseUnits) < BigInt(current.claimAmountBaseUnits)) throw Error('Claim is not currently available');
}

export function selectParticipantClaimConfiguration(file) {
  const bytes = readBounded(file, 16384), config = JSON.parse(bytes.toString('utf8'));
  exact(config, ['schema', 'rpc', 'release', 'artifacts']);
  if (config.schema !== 'cannabis.participant-claim-config.v1') throw Error('Invalid claim configuration schema');
  exact(config.release, ['chainId', 'token', 'tokenCodeHash', 'enrollment', 'enrollmentCodeHash', 'semaphore', 'semaphoreCodeHash', 'fromBlock']);
  const release = { chainId: config.release.chainId };
  if (typeof release.chainId !== 'string' || !/^[1-9][0-9]{0,77}$/.test(release.chainId) || BigInt(release.chainId) >= (1n<<256n)) throw Error('Invalid selected chain');
  for (const name of ['token', 'enrollment', 'semaphore']) {
    release[name] = address(config.release[name]);
    const hash = config.release[name+'CodeHash'];
    if (typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash) || /^0x0+$/.test(hash)) throw Error('Pin all deployed code hashes');
    release[name+'CodeHash'] = hash.toLowerCase();
  }
  if (new Set([release.token, release.enrollment, release.semaphore]).size !== 3) throw Error('Deployment addresses must be distinct');
  release.fromBlock = config.release.fromBlock;
  if (!Number.isSafeInteger(release.fromBlock) || release.fromBlock < 0) throw Error('Invalid deployment start block');
  const rpc = new URL(config.rpc);
  if (rpc.username || rpc.password || rpc.hash || (rpc.protocol !== 'https:' && !(rpc.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(rpc.hostname)))) throw Error('Select HTTPS or literal loopback RPC');
  exact(config.artifacts, ['depth', 'wasm', 'zkey']);
  if (!Number.isSafeInteger(config.artifacts.depth) || config.artifacts.depth < 1 || config.artifacts.depth > 20) throw Error('Invalid proving depth');
  const artifacts = { depth: config.artifacts.depth, wasm: artifact(config.artifacts.wasm, 32*1024*1024), zkey: artifact(config.artifacts.zkey, 128*1024*1024) };
  const publicPins = { depth: artifacts.depth,
    wasm: { sha256: artifacts.wasm.sha256, bytes: artifacts.wasm.bytes },
    zkey: { sha256: artifacts.zkey.sha256, bytes: artifacts.zkey.bytes } };
  const releaseDigest = digest(JSON.stringify({ release, artifacts: publicPins }));
  const selection = freeze({ schema: 'cannabis.participant-claim-selection.v1', releaseDigest,
    chainId: release.chainId, token: release.token, tokenCodeHash: release.tokenCodeHash,
    enrollment: release.enrollment, enrollmentCodeHash: release.enrollmentCodeHash,
    semaphore: release.semaphore, semaphoreCodeHash: release.semaphoreCodeHash,
    fromBlock: release.fromBlock, rpcOrigin: rpc.origin, artifacts: publicPins,
    canonicalReleaseAuthenticated: false });
  selections.set(selection, { file, fileDigest: digest(bytes), source: { rpc: rpc.toString(), release }, artifacts });
  return selection;
}

export async function reviewParticipantClaim(selection, recipient, custody) {
  const state = selections.get(selection);
  if (!state) throw Error('Select a claim configuration in this process');
  unchangedSelection(state);
  recipient = address(recipient);
  const binding = participantClaimBinding(custody);
  checkFiles(state.artifacts);
  const membership = await downloadMembershipSnapshot(state.source);
  const group = validateMembershipSnapshot(membership.snapshot, membership.context);
  if (group.indexOf(BigInt(binding.commitment)) < 0) throw Error('The recovered identity is absent from finalized membership');
  if (Math.max(1, group.depth) !== state.artifacts.depth) throw Error('Proving files do not match finalized group depth');
  const conditions = await readClaimConditions(state.source);
  if (conditions.root !== membership.context.root || conditions.memberCount !== membership.context.memberCount || conditions.minimumClaimMembers !== membership.context.minimumClaimMembers) throw Error('Membership changed during review');
  unchangedSelection(state);
  if (!same(binding, participantClaimBinding(custody))) throw Error('Custody changed during review');
  const created = Date.now();
  const review = freeze({ schema: 'cannabis.participant-claim-review.v1', reviewId: randomUUID(),
    releaseDigest: selection.releaseDigest, chainId: selection.chainId, token: selection.token,
    tokenCodeHash: selection.tokenCodeHash, recipient, claimAmount: '420',
    memberCount: conditions.memberCount, minimumClaimMembers: conditions.minimumClaimMembers,
    claimsStartAt: conditions.claimsStartAt, open: conditions.open, rpcOrigin: selection.rpcOrigin,
    artifactDepth: state.artifacts.depth, expiresAt: new Date(created+300000).toISOString(),
    singletonPrivacy: conditions.memberCount === 1, canonicalReleaseAuthenticated: false,
    rpcTrust: membership.evidence.rpcTrust, sent: false });
  reviews.set(review, { state, binding, membership, conditions, created, custody: { ...custody } });
  return review;
}

export async function prepareParticipantClaim(review, approval, output) {
  const retained = reviews.get(review);
  if (!retained) throw Error('Review this claim in the current process before approving');
  exact(approval, ['reviewId', 'releaseDigest', 'token', 'recipient']);
  for (const name of ['reviewId', 'releaseDigest', 'token', 'recipient']) if (approval[name] !== review[name]) throw Error('Approval does not match the displayed claim');
  if (!path.isAbsolute(output) || fs.existsSync(output)) throw Error('Choose a new absolute unsigned-claim filename');
  // A reviewed attempt is consumed before asynchronous work. A failure requires fresh review.
  reviews.delete(review);
  const { state, binding, membership, conditions, created, custody } = retained;
  const timely = () => { if (Date.now() < created || Date.now()-created > 300000) throw Error('Claim review expired'); };
  timely();
  unchangedSelection(state);
  if (!same(binding, participantClaimBinding(custody))) throw Error('Participant custody or recovery changed after review');
  checkFiles(state.artifacts);
  matchingConditions(await readClaimConditions(state.source, review.recipient), conditions);
  const proof = await proveParticipantClaim({ ...custody, binding, snapshot: membership.snapshot,
    context: membership.context, recipient: review.recipient, artifacts: state.artifacts });
  unchangedSelection(state);
  if (!same(binding, participantClaimBinding(custody))) throw Error('Participant custody changed during proving');
  matchingConditions(await readClaimConditions(state.source, review.recipient), conditions);
  const result = await prepareClaim({ rpc: state.source.rpc, chainId: review.chainId,
    token: review.token, recipient: review.recipient, codeHash: review.tokenCodeHash, proof });
  matchingConditions(await readClaimConditions(state.source, review.recipient), conditions);
  if (result.minimumClaimMembers !== review.minimumClaimMembers) throw Error('Claim policy changed during simulation');
  unchangedSelection(state);
  timely();
  if (!same(binding, participantClaimBinding(custody))) throw Error('Participant custody changed before export');
  const exportRecord = { ...result, schema: 'cannabis.participant-unsigned-claim.v1',
    releaseDigest: review.releaseDigest, claimAmount: '420', memberCount: review.memberCount,
    claimsStartAt: review.claimsStartAt, canonicalReleaseAuthenticated: false,
    signingRequired: true, review: 'Compare this unsigned transaction with the canonical reviewed deployment and recipient in your wallet. Re-simulate immediately before signing; membership and chain state can change. Network fees apply. The selected RPC has seen the public proof and recipient. No identity secret or member index was sent.' };
  fs.writeFileSync(output, JSON.stringify(exportRecord, null, 2)+'\n', { flag: 'wx', mode: 0o600 });
  return { output: path.resolve(output), status: result.status, sent: false, signingRequired: true };
}
