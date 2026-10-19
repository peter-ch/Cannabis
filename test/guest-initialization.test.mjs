import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, webcrypto } from 'node:crypto';
import { guestInitialization, readGuestInitialization, matchGuestInitialization } from '../compute/guest_initialization.mjs';
import { GuestEvidenceSession } from '../compute/guest_session.mjs';

const hex = n => n.toString(16).padStart(64, '0');
function fixture(tee = 'snp') {
  return { schema: 'cannabis.guest-initialization.v1', tee, requester: '0x' + 'ab'.repeat(20), jobId: 'opaque-fixture', binding: {
    chainId: 31337, escrow: '0x' + 'cd'.repeat(20), orderId: '0x' + hex(1), leaseDigest: '0x' + hex(2), reservationId: '0x' + hex(3),
    packageSHA256: hex(4), policySHA256: hex(5), runtimeSHA256: hex(6), taskSHA256: hex(7), attempt: 1, rank: 0, worldSize: 2, acceleratorClass: 'cpu' } };
}
function expected(value) {
  const init = guestInitialization(value), a = init.assignment;
  return { policy: { tee: a.tee, measurements: { initData: init.digest } }, expectedBinding: a.binding, requester: a.requester, jobId: a.jobId };
}
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-init-check-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir;
}
test('initialization commits every assignment field with stable SNP/TDX bytes', () => {
  for (const tee of ['snp', 'tdx']) {
    const input = fixture(tee), result = guestInitialization(input);
    assert.equal(result.digest, createHash(tee === 'snp' ? 'sha256' : 'sha384').update(result.canonical).digest('hex'));
    assert.equal(Buffer.from(result.digestBase64, 'base64').toString('hex'), result.digest);
    const reordered = Object.fromEntries(Object.entries(result.assignment).reverse());
    reordered.binding = Object.fromEntries(Object.entries(reordered.binding).reverse());
    assert.equal(guestInitialization(reordered).digest, result.digest);
    assert.equal(matchGuestInitialization(input, expected(input)).digest, result.digest);
    for (const change of [v => v.requester = '0x' + '12'.repeat(20), v => v.jobId += '-changed',
      ...['chainId', 'attempt', 'rank'].map(k => v => v.binding[k]++), v => v.binding.worldSize++,
      v => v.binding.escrow = '0x' + '14'.repeat(20),
      ...['orderId', 'leaseDigest', 'reservationId'].map(k => v => v.binding[k] = '0x' + hex(99)),
      ...['packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256'].map(k => v => v.binding[k] = hex(99))]) {
      const altered = structuredClone(input); change(altered);
      assert.notEqual(guestInitialization(altered).digest, result.digest);
      assert.throws(() => matchGuestInitialization(altered, expected(input)), /approved guest assignment/);
    }
  }
});
test('changed or missing initialization refuses key generation and evidence intake', async t => {
  let keys = 0;
  t.mock.method(webcrypto.subtle, 'generateKey', () => { keys++; throw Error('unexpected key generation'); });
  for (const initialization of [undefined, fixture(), { ...fixture(), jobId: 'changed' }]) {
    const opts = expected(fixture()); opts.policy.measurements.initData = 'ff'.repeat(32);
    await assert.rejects(GuestEvidenceSession.create({ ...opts, initialization, challenge: { binding: opts.expectedBinding } }), /initialization|approved guest assignment/i);
  }
  for (const alter of [v => v.jobId = 'other', v => v.requester = '0x' + '12'.repeat(20),
    v => v.expectedBinding.rank = 1, v => v.challenge.binding.runtimeSHA256 = hex(99)]) {
    const opts = expected(fixture());
    opts.initialization = fixture(); opts.challenge = { binding: structuredClone(opts.expectedBinding) };
    alter(opts);
    await assert.rejects(GuestEvidenceSession.create(opts), /approved guest assignment/);
  }
  assert.equal(keys, 0);
});

test('configuration-bound initialization changes hardware commitments and refuses version downgrade',()=>{
  for(const tee of ['snp','tdx']) {
    const input=fixture(tee);input.schema='cannabis.guest-initialization.v2';input.binding.configurationSHA256='0x'+hex(91);
    const retained=guestInitialization(input),approved=expected(input);
    assert.equal(matchGuestInitialization(input,approved).digest,retained.digest);
    for(const alter of [v=>v.binding.configurationSHA256='0x'+hex(92),v=>{delete v.binding.configurationSHA256;v.schema='cannabis.guest-initialization.v1';}]) {
      const changed=structuredClone(input);alter(changed);
      assert.notEqual(guestInitialization(changed).digest,retained.digest);
      assert.throws(()=>matchGuestInitialization(changed,approved));
    }
    for(const alter of [v=>v.schema='cannabis.guest-initialization.v1',v=>delete v.binding.configurationSHA256,
      v=>v.binding.configurationSHA256='0x'+'00'.repeat(32),v=>v.binding.configurationSHA256=hex(91)]) {
      const changed=structuredClone(input);alter(changed);assert.throws(()=>guestInitialization(changed));
    }
  }
});
test('unknown fields, invalid placement and unsupported accelerators are rejected', () => {
  for (const mutate of [v => v.extra = true, v => v.tee = 'sample', v => v.jobId = '../path',
    v => v.requester = '0x' + '00'.repeat(20), v => v.binding.rank = 2,
    v => v.binding.acceleratorClass = 'cuda', v => v.binding.extra = true]) {
    const value = fixture(); mutate(value); assert.throws(() => guestInitialization(value));
  }
});
test('preparation writes canonical bounded input, refusing overwrite and ambiguous files', t => {
  const dir = temporary(t), source = path.join(dir, 'assignment.json'), out = path.join(dir, 'canonical.json');
  fs.writeFileSync(source, JSON.stringify(fixture(), null, 2));
  const args = ['scripts/prepare-guest-init.mjs', '--input', source, '--out', out];
  const result = JSON.parse(execFileSync(process.execPath, args, { encoding: 'utf8', windowsHide: true }));
  assert.equal(result.initData, readGuestInitialization(out).digest);
  assert.equal(result.executionAuthorized, false);
  assert.equal(spawnSync(process.execPath, args, { windowsHide: true }).status, 1);
  for (const bytes of [fs.readFileSync(out, 'utf8').trim(), '{"schema":"ignored",' + fs.readFileSync(out, 'utf8').slice(1),
    Buffer.from([0xff]), ' '.repeat(65537)]) {
    fs.writeFileSync(source, bytes); assert.throws(() => readGuestInitialization(source));
  }
  assert.throws(() => readGuestInitialization(dir));
});
test('Linux rejects symlinks and FIFOs before reading initialization', { skip: process.platform !== 'linux' }, t => {
  const dir = temporary(t), source = path.join(dir, 'source.json'), link = path.join(dir, 'link'), fifo = path.join(dir, 'fifo');
  fs.writeFileSync(source, guestInitialization(fixture()).canonical + '\n');
  fs.symlinkSync(source, link); execFileSync('mkfifo', [fifo]);
  assert.throws(() => readGuestInitialization(link));
  assert.throws(() => readGuestInitialization(fifo), /regular/);
});
