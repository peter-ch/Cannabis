import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { randomBytes, randomUUID } from 'node:crypto';
import { Wallet } from 'ethers';
import { WorkStore, digest, amount } from '../service/work-store.mjs';
import { createWorkServer } from '../service/work-server.mjs';
const origin = 'http://127.0.0.1:4200';
const draft = (token, more = {}) => ({ id: randomUUID(), accessHash: digest(token), asset: 'ETH', budget: '0.0000000000000001', account: false, commitments: null, ...more });
const token = () => randomBytes(32).toString('hex');
test('guest recovery survives restart, is isolated, idempotent and expires', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-work-')), file = path.join(dir, 'work.sqlite'); let now = Date.now();
  let store = new WorkStore(file, origin, { now: () => now });
  try {
    const key = token(), body = draft(key), result = store.create(body, null);
    assert.equal(result.state, 'prepared'); assert.equal(result.payment.founderFeeAtomic, '1'); assert.equal(result.payment.workerPoolAtomic, '99');
    assert.equal(result.funded, false); assert.equal(JSON.stringify(result).includes(key), false);
    assert.deepEqual(store.create(body, null), result);
    assert.throws(() => store.create({ ...body, budget: '1' }, null), /already in use/);
    assert.throws(() => store.get(body.id, token(), null), /not found/);
    assert.throws(() => store.get(body.id, null, Wallet.createRandom().address), /not found/);
    store.close(); store = new WorkStore(file, origin, { now: () => now });
    assert.deepEqual(store.get(body.id, key, null), result);
    now += 31 * 86400_000; assert.throws(() => store.get(body.id, key, null), /not found/);
    store.cleanup(); assert.equal(store.db.prepare('SELECT count(*) AS n FROM orders').get().n, 0);
  } finally { store.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
test('wallet challenges bind browser, origin, network and expiry, cannot replay; guests stay separate', async () => {
  let now = Date.now(); const store = new WorkStore(':memory:', origin, { now: () => now });
  try {
    const wallet = Wallet.createRandom(), c = store.challenge(wallet.address, 1);
    assert.match(c.message, /127\.0\.0\.1:4200 wants you/); assert.match(c.message, /Chain ID: 1/);
    const signature = await wallet.signMessage(c.message);
    assert.throws(() => store.signIn(c.id, token(), signature), /another browser/);
    const session = store.signIn(c.id, c.binding, signature), owner = store.account(session.token);
    assert.equal(owner, wallet.address);
    assert.throws(() => store.signIn(c.id, c.binding, signature), /expired/);
    const guestKey = token(), guest = store.create(draft(guestKey), owner);
    assert.equal(guest.linkedToAccount, false); assert.equal(store.list(owner).length, 0);
    const linked = store.create(draft(token(), { account: true }), owner);
    assert.deepEqual(store.list(owner).map(x => x.id), [linked.id]);
    assert.throws(() => store.get(guest.id, null, owner), /not found/);
    assert.throws(() => store.create(draft(token(), { account: true }), null), /Sign in/);
    const changed = store.challenge(wallet.address, 1);
    assert.throws(() => store.signIn(changed.id, changed.binding, signature), /did not verify/);
    const expired = store.challenge(wallet.address, 1); now += 301_000;
    assert.throws(() => store.signIn(expired.id, expired.binding, signature), /expired/);
    store.signOut(session.token); assert.equal(store.account(session.token), null);
  } finally { store.close(); }
});
test('exact fees, strict preparation schema and bounded records prevent false payment states', () => {
  const store = new WorkStore(':memory:', origin, { maxRecords: 1 });
  try {
    for (const n of ['0', '0.000000000000000001', '-1', '1e3', 'NaN', 1]) assert.throws(() => amount(n));
    for (const patch of [{ asset: 'USDC' }, { paid: true }, { commitments: { code: 'private workload' } }, { accessHash: '0'.repeat(64) }]) assert.throws(() => store.create(draft(token(), patch), null));
    store.create(draft(token()), null); assert.throws(() => store.create(draft(token()), null), /capacity/);
  } finally { store.close(); }
});
test('HTTP rejects CSRF, query secrets, spoofed access and oversized bodies; no funding endpoint', async () => {
  const reservation = net.createServer(); await new Promise(r => reservation.listen(0, '127.0.0.1', r));
  const port = reservation.address().port; await new Promise(r => reservation.close(r));
  const origin = 'http://127.0.0.1:' + port;
  const { server } = createWorkServer({ file: ':memory:', origin });
  await new Promise(r => server.listen(port, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const request = (route, options = {}) => fetch(base + '/api/work/' + route, { ...options, headers: { Origin: origin, 'Content-Type': 'application/json', ...options.headers } });
  try {
    const key = token(), body = draft(key);
    assert.equal((await request('orders', { method: 'POST', body: JSON.stringify(body), headers: { Origin: 'https://evil.invalid' } })).status, 403);
    assert.equal((await request('orders', { method: 'POST', body: JSON.stringify({ ...body, extra: 'x'.repeat(9000) }) })).status, 413);
    assert.equal((await request('orders?key=' + key)).status, 400);
    assert.equal((await request('orders', { method: 'POST', body: JSON.stringify(body) })).status, 201);
    assert.equal((await request('orders/' + body.id)).status, 404);
    const read = await request('orders/' + body.id, { headers: { Authorization: 'Bearer ' + key } });
    assert.equal(read.status, 200); assert.equal(read.headers.get('cache-control'), 'no-store');
    const quote = await request(`orders/${body.id}/quote`, { method: 'POST', body: '{}', headers: { Authorization: 'Bearer ' + key } });
    assert.equal(quote.status, 503); assert.equal((await quote.json()).code, 'PAYMENT_NOT_OPEN');
    assert.equal((await request('fund', { method: 'POST', body: '{}' })).status, 404);
    assert.equal((await request('orders/' + body.id, { method: 'DELETE', headers: { Authorization: 'Bearer ' + key } })).status, 200);
    assert.equal((await request('orders/' + body.id, { headers: { Authorization: 'Bearer ' + key } })).status, 404);
  } finally { server.closeAllConnections(); await new Promise(r => server.close(r)); }
});
