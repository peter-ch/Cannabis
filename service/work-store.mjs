import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes } from 'node:crypto';
import { getAddress, verifyMessage } from 'ethers';

export const founderRecipient = '0xe02Ad92413aD0a3Aac8263eE3C2Bd9410955F89b';
export const digest = value => createHash('sha256').update(value).digest('hex');
const secret = () => randomBytes(32).toString('hex');
const tokenPattern = /^[0-9a-f]{64}$/;
export const idPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export class WorkError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, message) => { throw new WorkError(status, message); };
export function exact(value, names) {
  if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).sort().join() !== [...names].sort().join()) fail(400, 'Unexpected request fields');
}
export function amount(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,59})(\.\d{1,18})?$/.test(value)) fail(400, 'Use an exact decimal budget');
  const [whole, fraction = ''] = value.split('.');
  const atomic = BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, '0'));
  if (atomic <= 0n || atomic >= 2n ** 256n || atomic % 100n !== 0n) fail(400, 'Budget must be a positive multiple of 0.0000000000000001');
  return { totalAtomic: String(atomic), founderFeeAtomic: String(atomic / 100n), workerPoolAtomic: String(atomic - atomic / 100n) };
}
export function validateDraft(body) {
  exact(body, ['id', 'accessHash', 'asset', 'budget', 'account', 'commitments']);
  if (!idPattern.test(body.id) || !tokenPattern.test(body.accessHash) || /^0+$/.test(body.accessHash) || !['Cannabis', 'ETH'].includes(body.asset) || typeof body.account !== 'boolean') fail(400, 'Invalid order preparation');
  amount(body.budget);
  if (body.commitments !== null) {
    exact(body.commitments, ['id', 'requester', 'packageSHA256', 'policySHA256', 'acceptanceSHA256']);
    const c = body.commitments;
    if (typeof c.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(c.id) || !['packageSHA256', 'policySHA256', 'acceptanceSHA256'].every(k => tokenPattern.test(c[k]) && !/^0+$/.test(c[k]))) fail(400, 'Invalid encrypted workload commitments');
    try { if (getAddress(c.requester) === '0x0000000000000000000000000000000000000000') throw Error(); }
    catch { fail(400, 'Invalid requester address'); }
  }
  return body;
}

// This store records preparations, never payment/execution claims. A future paid
// order gateway must derive those states from verified settlement and admission.
export class WorkStore {
  constructor(file, origin, { now = Date.now, maxRecords = 5000 } = {}) {
    this.now = now; this.origin = origin; this.maxRecords = maxRecords;
    this.db = new DatabaseSync(file, { timeout: 2000 });
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS accounts (address TEXT PRIMARY KEY, created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, binding TEXT NOT NULL, address TEXT NOT NULL, message TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, address TEXT NOT NULL REFERENCES accounts(address), expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, access_hash TEXT NOT NULL, account TEXT REFERENCES accounts(address), payload TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS orders_account ON orders(account, created);`);
  }
  close() { this.db.close(); }
  cleanup() {
    for (const name of ['challenges', 'sessions', 'orders']) this.db.prepare(`DELETE FROM ${name} WHERE expires <= ?`).run(this.now());
  }
  capacity(table) {
    if (this.db.prepare(`SELECT count(*) AS n FROM ${table}`).get().n >= this.maxRecords) fail(503, 'Preparation capacity is full; retain your local recovery file');
  }
  challenge(address, chainId) {
    this.cleanup(); this.capacity('challenges');
    try { address = getAddress(address); } catch { fail(400, 'Invalid wallet address'); }
    if (address === '0x0000000000000000000000000000000000000000' || !Number.isSafeInteger(chainId) || chainId <= 0) fail(400, 'Invalid wallet network');
    const id = secret(), binding = secret(), expires = this.now() + 5 * 60_000;
    const message = `${new URL(this.origin).host} wants you to sign in with your Ethereum account:\n${address}\n\nSign in to your Cannabis work account. This does not authorize payments.\n\nURI: ${this.origin}/work.html\nVersion: 1\nChain ID: ${chainId}\nNonce: ${id}\nIssued At: ${new Date(this.now()).toISOString()}\nExpiration Time: ${new Date(expires).toISOString()}`;
    this.db.prepare('INSERT INTO challenges VALUES (?, ?, ?, ?, ?)').run(id, digest(binding), address, message, expires);
    return { id, binding, message };
  }
  signIn(id, binding, signature) {
    if (!tokenPattern.test(id) || !tokenPattern.test(binding) || typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(signature)) fail(401, 'Wallet sign-in could not be verified');
    this.cleanup();
    const c = this.db.prepare('SELECT * FROM challenges WHERE id = ? AND binding = ?').get(id, digest(binding));
    if (!c) fail(401, 'Wallet sign-in expired or belongs to another browser');
    // Single use, including a failed signature. Compare only our stored message.
    this.db.prepare('DELETE FROM challenges WHERE id = ?').run(id);
    let signer;
    try { signer = verifyMessage(c.message, signature); } catch { fail(401, 'Wallet signature did not verify'); }
    if (signer !== c.address) fail(401, 'Wallet signature did not verify');
    if (!this.db.prepare('SELECT 1 FROM accounts WHERE address = ?').get(signer)) this.capacity('accounts');
    this.capacity('sessions');
    const token = secret(), expires = this.now() + 12 * 3600_000;
    this.db.prepare('INSERT OR IGNORE INTO accounts VALUES (?, ?)').run(signer, this.now());
    this.db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(digest(token), signer, expires);
    return { token, address: signer, expires };
  }
  account(token) {
    return tokenPattern.test(token ?? '') ? this.db.prepare('SELECT address FROM sessions WHERE token = ? AND expires > ?').get(digest(token), this.now())?.address ?? null : null;
  }
  signOut(token) { if (tokenPattern.test(token ?? '')) this.db.prepare('DELETE FROM sessions WHERE token = ?').run(digest(token)); }
  create(body, account) {
    validateDraft(body); this.cleanup();
    if (body.account && !account) fail(401, 'Sign in or choose guest ordering');
    const owner = body.account ? account : null, payload = JSON.stringify({ asset: body.asset, budget: body.budget, commitments: body.commitments });
    const previous = this.db.prepare('SELECT * FROM orders WHERE id = ?').get(body.id);
    if (previous) {
      if (previous.access_hash !== body.accessHash || previous.account !== owner || previous.payload !== payload) fail(409, 'This order ID is already in use');
      return this.present(previous);
    }
    this.capacity('orders');
    if (owner && this.db.prepare('SELECT count(*) AS n FROM orders WHERE account = ?').get(owner).n >= 100) fail(429, 'Account preparation limit reached');
    const created = this.now(), expires = created + 30 * 86400_000;
    this.db.prepare('INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)').run(body.id, body.accessHash, owner, payload, created, expires);
    return this.get(body.id, null, owner, body.accessHash);
  }
  present(row) {
    const payload = JSON.parse(row.payload);
    return { id: row.id, ...payload, state: 'prepared', linkedToAccount: row.account !== null, created: row.created, expires: row.expires,
      payment: { ...amount(payload.budget), feeBasisPoints: 100, founderRecipient, networkFeesIncluded: false },
      funded: false, executionAuthorized: false, resultsAvailable: false };
  }
  get(id, token, account, verifiedHash = null) {
    if (!idPattern.test(id)) fail(404, 'Order not found');
    const row = this.db.prepare('SELECT * FROM orders WHERE id = ? AND expires > ?').get(id, this.now());
    const hash = verifiedHash ?? (tokenPattern.test(token ?? '') ? digest(token) : null);
    if (!row || !(hash && row.access_hash === hash || account && row.account === account)) fail(404, 'Order not found');
    return this.present(row);
  }
  list(account) {
    if (!account) fail(401, 'Sign in to view account orders');
    return this.db.prepare('SELECT * FROM orders WHERE account = ? AND expires > ? ORDER BY created DESC LIMIT 100').all(account, this.now()).map(row => this.present(row));
  }
  remove(id, token, account) {
    this.get(id, token, account);
    this.db.prepare('DELETE FROM orders WHERE id = ?').run(id);
  }
}
