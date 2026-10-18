// Retired from the Cannabis release path; historical regression coverage only.
// BrightID v6 signed-record intake. This does not establish lifetime human uniqueness
// or authorize on-chain enrollment. See docs/person-verification.md.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { getAddress } from 'ethers';

export const BRIGHTID_SOURCE_REVISIONS = Object.freeze({
  '6.17.2': 'c8fa7006d30d39e926fc6e96bb08819de76906ba',
  '6.18.0': 'c699663519334b7a5149a4e4e8f5622984a23691'
});
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const seconds = () => Math.floor(Date.now() / 1000);
const sha256 = value => createHash('sha256').update(value).digest('hex');
const exact = (value, keys) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) throw Error('Unexpected verification fields');
};
function integer(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw Error('Invalid verification integer');
}
function decimal(value, max) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,77}$/.test(value) || BigInt(value) >= max) throw Error('Invalid verification integer');
}
function base64(value, bytes) {
  if (typeof value !== 'string' || value.length !== 4 * Math.ceil(bytes / 3)) throw Error('Invalid verification encoding');
  const data = Buffer.from(value, 'base64');
  if (data.length !== bytes || data.toString('base64') !== value) throw Error('Invalid verification encoding');
  return data;
}
function endpoint(value) {
  if (typeof value !== 'string' || value.length > 2048) throw Error('Invalid provider URL');
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || !/^\/[-a-zA-Z0-9_/]*$/.test(url.pathname) || url.pathname.includes('//') || !url.pathname.endsWith('/brightid/v6/')) throw Error('Invalid provider URL');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname))) throw Error('Require HTTPS or literal loopback');
  if (url.href !== value) throw Error('Use canonical provider URL');
  return url;
}

export function normalizeBrightIDPolicy(input) {
  exact(input, ['schema', 'nodeUrl', 'nodeVersion', 'app', 'verification', 'publicKey', 'chainId', 'enrollment', 'maxAgeSeconds', 'clockSkewSeconds']);
  if (input.schema !== 'cannabis.brightid-policy.v1') throw Error('Unknown verification policy');
  endpoint(input.nodeUrl);
  if (typeof input.nodeVersion !== 'string' || !Object.hasOwn(BRIGHTID_SOURCE_REVISIONS, input.nodeVersion)) throw Error('Require a source-reviewed node version');
  if (typeof input.app !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(input.app)) throw Error('Invalid application identifier');
  if (typeof input.verification !== 'string' || !/^[\x20-\x7e]{1,2048}$/.test(input.verification) || input.verification.trim() !== input.verification) throw Error('Invalid verification expression');
  base64(input.publicKey, 32); decimal(input.chainId, 1n << 256n);
  const enrollment = getAddress(input.enrollment);
  if (BigInt(enrollment) === 0n) throw Error('Invalid enrollment address');
  integer(input.maxAgeSeconds, 1, 300); integer(input.clockSkewSeconds, 0, 30);
  // Fixed field order gives the same digest regardless of input JSON key order.
  return { schema: input.schema, nodeUrl: input.nodeUrl, nodeVersion: input.nodeVersion, app: input.app,
    verification: input.verification, publicKey: input.publicKey, chainId: input.chainId, enrollment,
    maxAgeSeconds: input.maxAgeSeconds, clockSkewSeconds: input.clockSkewSeconds };
}

export function brightIDApplicationUserId(policy, commitment) {
  const p = normalizeBrightIDPolicy(policy); decimal(commitment, FIELD);
  return sha256(['Cannabis BrightID enrollment v1', p.chainId, p.enrollment.toLowerCase(), commitment].join('\0'));
}

export function verifyBrightIDRecord(record, policy, commitment, now = seconds()) {
  const p = normalizeBrightIDPolicy(policy), appUserId = brightIDApplicationUserId(p, commitment);
  integer(now, 1, Number.MAX_SAFE_INTEGER - 300);
  exact(record, ['unique', 'app', 'appUserId', 'verification', 'verificationHash', 'timestamp', 'sig', 'publicKey']);
  if (record.unique !== true || record.app !== p.app || record.appUserId !== appUserId || record.verification !== p.verification ||
      record.verificationHash !== sha256(p.verification) || record.publicKey !== p.publicKey) throw Error('Provider record does not match the enrollment request');
  integer(record.timestamp, 1, Number.MAX_SAFE_INTEGER - 300);
  if (record.timestamp > now + p.clockSkewSeconds || now - record.timestamp > p.maxAgeSeconds) throw Error('Provider record is stale or in the future');
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), base64(p.publicKey, 32)]), format: 'der', type: 'spki' });
  // Exact upstream NaCl message, with hash and seconds timestamp mandatory.
  const message = Buffer.from([p.app, appUserId, record.verificationHash, record.timestamp].join(','), 'ascii');
  if (!verify(null, message, key, base64(record.sig, 64))) throw Error('Invalid provider signature');
  return { schema: 'cannabis.brightid-check.v1', policySHA256: sha256(JSON.stringify(p)),
    requestSHA256: appUserId, commitment, credentialSHA256: sha256(Buffer.concat([message, base64(record.sig, 64)])),
    checkedAt: now, expiresAt: record.timestamp + p.maxAgeSeconds, eligibilitySignatureVerified: true,
    lifetimeUniquenessEstablished: false, enrollmentAuthorized: false, enrolled: false };
}

function providerConfiguration(state, app, p) {
  if (!state || state.development !== false || state.version !== p.nodeVersion || state.naclSigningKey !== p.publicKey) throw Error('Provider node configuration changed');
  if (!app || app.id !== p.app || app.testing !== false || app.idsAsHex !== false || app.usingBlindSig !== true ||
      app.verificationExpirationLength !== 0 || !Array.isArray(app.verifications) || app.verifications.length !== 1 || app.verifications[0] !== p.verification) throw Error('Require one nonexpiring blind verification policy');
}

async function jsonGet(url, deadline) {
  let response;
  try {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw Error('Expired');
    response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(Math.min(15000, remaining)), headers: { accept: 'application/json' } });
    if (!response.ok || !response.body) throw Error('HTTP failure');
    const chunks = []; let length = 0;
    for await (const chunk of response.body) {
      length += chunk.length;
      if (length > 65536) throw Error('Response too large');
      chunks.push(chunk);
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  } catch {
    if (response?.body && !response.body.locked) await response.body.cancel().catch(() => {});
    throw Error('Provider request failed'); // Never echo URLs, private IDs or server bodies.
  }
}

export async function checkBrightIDProvider({ policy, commitment }) {
  const p = normalizeBrightIDPolicy(structuredClone(policy));
  const appUserId = brightIDApplicationUserId(p, commitment), startedAt = seconds(), deadline = Date.now() + 60000;
  const stateUrl = new URL('state', p.nodeUrl), appUrl = new URL(`apps/${p.app}`, p.nodeUrl);
  const inspect = async () => {
    const [state, app] = await Promise.all([jsonGet(stateUrl, deadline), jsonGet(appUrl, deadline)]);
    providerConfiguration(state.data, app.data, p);
  };
  await inspect();
  const url = new URL(`verifications/${p.app}/${appUserId}`, p.nodeUrl);
  url.search = new URLSearchParams({ signed: 'nacl', includeHash: 'true', timestamp: 'seconds' }).toString();
  const body = await jsonGet(url, deadline);
  exact(body, ['data']);
  if (!Array.isArray(body.data) || body.data.length !== 1) throw Error('Unexpected provider records');
  await inspect();
  if (seconds() < startedAt || Date.now() > deadline) throw Error('Provider check exceeded its time bound');
  const result = verifyBrightIDRecord(body.data[0], p, commitment);
  return { result, record: body.data[0] };
}

// Operator-private intake only. Keep the database, WAL and backups on protected storage.
// A stable provider credential is still required to deduplicate people across aliases.
export class BrightIDIntakeLedger {
  #db; #policy; #digest; #clock;
  constructor(file, policy, clock = seconds) {
    this.#policy = normalizeBrightIDPolicy(structuredClone(policy));
    this.#digest = sha256(JSON.stringify(this.#policy)); this.#clock = clock;
    this.#db = new DatabaseSync(file, { timeout: 5000 });
    try {
      this.#db.exec(`PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS brightid_settings (id INTEGER PRIMARY KEY CHECK(id=1), policyDigest TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS brightid_intake (requestDigest TEXT PRIMARY KEY, commitment TEXT UNIQUE NOT NULL, result TEXT NOT NULL) STRICT;`);
      this.#transaction(() => {
        const saved = this.#db.prepare('SELECT policyDigest FROM brightid_settings WHERE id=1').get();
        if (saved && saved.policyDigest !== this.#digest) throw Error('Intake policy cannot change; review migration without resetting duplicates');
        if (!saved) this.#db.prepare('INSERT INTO brightid_settings VALUES (1,?)').run(this.#digest);
      });
    } catch (error) { this.#db.close(); throw error; }
  }
  #transaction(fn) {
    this.#db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); this.#db.exec('COMMIT'); return result; }
    catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  record(record, commitment) {
    return this.#transaction(() => {
      const checked = verifyBrightIDRecord(record, this.#policy, commitment, this.#clock());
      const existing = this.#db.prepare('SELECT result FROM brightid_intake WHERE requestDigest=?').get(checked.requestSHA256);
      if (existing) return { ...checked, firstCheckedAt: JSON.parse(existing.result).checkedAt, alreadyRecorded: true };
      const count = this.#db.prepare('SELECT COUNT(*) AS n FROM brightid_intake').get().n;
      if (count >= 990000) throw Error('Intake capacity reached');
      this.#db.prepare('INSERT INTO brightid_intake VALUES (?,?,?)').run(checked.requestSHA256, commitment, JSON.stringify(checked));
      return { ...checked, alreadyRecorded: false };
    });
  }
  close() { this.#db.close(); }
}
