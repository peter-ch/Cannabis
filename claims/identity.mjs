// Local participant custody and proving. No enrollment, RPC, wallet signing or broadcast.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { AbiCoder, getAddress, keccak256 } from 'ethers';
import { Identity } from '@semaphore-protocol/identity';
import { Group } from '@semaphore-protocol/group';
import { generateProof, verifyProof } from '@semaphore-protocol/proof';

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const sha256 = data => createHash('sha256').update(data).digest('hex');
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length || fields.some(k => !Object.hasOwn(value, k))) throw Error('Unexpected claim input fields');
}
function decimal(value, max = FIELD) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,77}$/.test(value) || BigInt(value) >= max) throw Error('Expected canonical positive integer');
  return BigInt(value);
}
function address(value) {
  const result = getAddress(value);
  if (BigInt(result) === 0n) throw Error('Address must be nonzero');
  return result;
}
function absolute(file) {
  if (typeof file !== 'string' || !path.isAbsolute(file) || file.includes('\0')) throw Error('Use trusted absolute local paths');
  return file;
}
export function readBounded(file, limit) {
  absolute(file);
  const before = fs.lstatSync(file);
  if (!before.isFile() || before.isSymbolicLink()) throw Error('Require a regular local file');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  let data;
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino || stat.size < 1 || stat.size > limit) throw Error('Local file exceeds bounds or changed');
    data = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < data.length) {
      const n = fs.readSync(fd, data, offset, data.length - offset, null);
      if (!n) throw Error('Local file changed');
      offset += n;
    }
    if (fs.readSync(fd, Buffer.alloc(1), 0, 1, null)) throw Error('Local file changed');
    return data;
  } catch (error) { data?.fill(0); throw error; }
  finally { fs.closeSync(fd); }
}
function ageRun(age, args, input, maxBuffer = 16384) {
  absolute(age);
  const result = spawnSync(age, args, { input, stdio: ['pipe', 'pipe', 'ignore'], shell: false, windowsHide: true, timeout: 30000, maxBuffer });
  if (result.error || result.status !== 0 || !result.stdout?.length || result.stdout.length > maxBuffer) {
    result.stdout?.fill(0); throw Error('Local identity encryption operation failed');
  }
  return result.stdout;
}
function wipeIdentity(identity) {
  // Buffers can be cleared; library BigInts/strings and engine copies cannot be guaranteed erased.
  if (identity?.privateKey instanceof Uint8Array) identity.privateKey.fill(0);
}
export function createEncryptedIdentity({ age, recipient, vault }) {
  absolute(vault);
  if (typeof recipient !== 'string' || !/^age1[0-9a-z]{58}$/.test(recipient)) throw Error('Use one native age X25519 backup recipient');
  if (fs.existsSync(vault)) throw Error('Identity vault already exists');
  const secret = randomBytes(32), identity = new Identity(secret);
  const commitment = identity.commitment.toString();
  const plaintext = Buffer.from(JSON.stringify({ schema: 'cannabis.claim-identity.v1', commitment, identity: identity.export() }));
  try {
    const ciphertext = ageRun(age, ['--encrypt', '--recipient', recipient], plaintext);
    fs.writeFileSync(vault, ciphertext, { flag: 'wx', mode: 0o600 });
    return { schema: 'cannabis.claim-identity.public.v1', commitment, ciphertextSHA256: sha256(ciphertext), ciphertextBytes: ciphertext.length, enrolled: false };
  } finally { plaintext.fill(0); secret.fill(0); wipeIdentity(identity); }
}
async function withIdentity({ age, vault, identityFile, identityKey, commitment }, operation) {
  decimal(commitment);
  const ciphertext = readBounded(vault, 16384);
  const suppliedKey = identityKey;
  if (suppliedKey !== undefined && (identityFile !== undefined || !Buffer.isBuffer(suppliedKey) || suppliedKey.length < 1 || suppliedKey.length > 4096)) throw Error('Use one bounded owner identity source');
  const ownerKey = suppliedKey === undefined ? readBounded(identityFile, 4096) : Buffer.from(suppliedKey);
  let plaintext, identity, staging;
  try {
    const lines = ownerKey.toString('ascii').split(/\r?\n/).filter(line => line && !line.startsWith('#'));
    if (lines.length !== 1 || !/^AGE-SECRET-KEY-1[0-9A-Z]{58}$/.test(lines[0])) throw Error('Use one native age X25519 identity');
    // The only temporary file is encrypted. Feed the owner key on stdin, never argv or disk.
    staging = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-claim-'));
    fs.chmodSync(staging, 0o700);
    const snapshot = path.join(staging, 'identity.age');
    fs.writeFileSync(snapshot, ciphertext, { flag: 'wx', mode: 0o600 });
    plaintext = ageRun(age, ['--decrypt', '--identity', '-', snapshot], ownerKey, 4096);
    let record;
    try { record = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)); }
    catch { throw Error('Invalid encrypted identity record'); }
    exact(record, ['schema', 'commitment', 'identity']);
    if (record.schema !== 'cannabis.claim-identity.v1' || record.commitment !== commitment || typeof record.identity !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(record.identity)) throw Error('Identity record does not match');
    identity = Identity.import(record.identity);
    if (identity.export() !== record.identity || identity.commitment.toString() !== commitment) throw Error('Identity record does not match');
    return await operation(identity);
  } finally {
    ownerKey.fill(0); plaintext?.fill(0); wipeIdentity(identity);
    if (staging) { fs.rmSync(path.join(staging, 'identity.age'), { force: true }); fs.rmdirSync(staging); }
  }
}
export function inspectEncryptedIdentity(options) {
  return withIdentity(options, identity => ({ commitment: identity.commitment.toString(), recoveryVerified: true, enrolled: false }));
}
export function claimScope(chainId, token) {
  decimal(chainId, 1n << 256n);
  return BigInt(keccak256(AbiCoder.defaultAbiCoder().encode(['string', 'uint256', 'address'], ['Cannabis community claim v1', chainId, address(token)]))).toString();
}
export function validateMembershipSnapshot(snapshot, context) {
  const contextFields = ['chainId', 'token', 'root', 'memberCount'];
  exact(context, Object.hasOwn(context ?? {}, 'minimumClaimMembers') ? [...contextFields, 'minimumClaimMembers'] : contextFields);
  if (Object.hasOwn(context, 'minimumClaimMembers') && (!Number.isSafeInteger(context.minimumClaimMembers) || context.minimumClaimMembers < 1 || context.minimumClaimMembers > 990000 || context.memberCount < context.minimumClaimMembers)) throw Error('Membership is below the selected claim minimum');
  exact(snapshot, ['schema', 'chainId', 'token', 'root', 'commitments']);
  claimScope(context.chainId, context.token); decimal(context.root);
  if (snapshot.schema !== 'cannabis.membership-snapshot.v1' || snapshot.chainId !== context.chainId || address(snapshot.token) !== address(context.token) || snapshot.root !== context.root) throw Error('Membership context mismatch');
  if (!Number.isSafeInteger(context.memberCount) || context.memberCount < 1 || context.memberCount > 990000 || !Array.isArray(snapshot.commitments) || snapshot.commitments.length !== context.memberCount) throw Error('Require the complete membership list and at least one enrolled member');
  const members = snapshot.commitments.map(member => decimal(member));
  if (new Set(snapshot.commitments).size !== members.length) throw Error('Duplicate membership commitment');
  const group = new Group(members);
  if (group.root.toString() !== context.root) throw Error('Membership root mismatch');
  return group;
}
function pinnedArtifact(spec, maxBytes) {
  exact(spec, ['path', 'sha256', 'bytes']);
  if (!Number.isSafeInteger(spec.bytes) || spec.bytes < 1 || spec.bytes > maxBytes || !/^[0-9a-f]{64}$/.test(spec.sha256)) throw Error('Require reviewed proving artifact size and SHA-256');
  const data = readBounded(spec.path, spec.bytes);
  if (data.length !== spec.bytes || sha256(data) !== spec.sha256) throw Error('Proving artifact does not match its pin');
  return data; // Prove from these checked bytes, without reopening an attacker-replaceable path.
}
// Retain checked public inputs before a caller opens its device-held custody.
export function createClaimProver(options) {
  const { snapshot, context, artifacts } = structuredClone({ snapshot: options.snapshot, context: options.context, artifacts: options.artifacts });
  const recipient = address(options.recipient), group = validateMembershipSnapshot(snapshot, context);
  exact(artifacts, ['depth', 'wasm', 'zkey']);
  // A singleton LeanIMT has depth zero. Semaphore supports it using its depth-one
  // circuit; no fabricated identity or additional group leaf is inserted.
  const proofDepth = Math.max(1, group.depth);
  if (artifacts.depth !== proofDepth || artifacts.depth < 1 || artifacts.depth > 20) throw Error('Proving artifacts must match the complete group depth (minimum circuit depth one)');
  const wasm = pinnedArtifact(artifacts.wasm, 32 * 1024 * 1024);
  const zkey = pinnedArtifact(artifacts.zkey, 128 * 1024 * 1024);
  return custody => withIdentity(custody, async identity => {
    if (group.indexOf(identity.commitment) < 0) throw Error('Identity is not in this membership snapshot');
    const proof = await generateProof(identity, group, BigInt(recipient), claimScope(context.chainId, context.token), proofDepth, { wasm, zkey });
    if (!await verifyProof(proof)) throw Error('Generated proof failed verification');
    // No commitment, member index, Merkle path or identity secret in the public output.
    return proof;
  });
}
export async function generateClaimProof(options) {
  return createClaimProver(options)(options);
}
