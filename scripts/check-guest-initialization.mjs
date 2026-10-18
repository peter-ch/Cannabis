// Negative acceptance inside the ordinary component-check VM. No customer data.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { InitializedGuestControlPlane } from '../compute/guest_bootstrap.mjs';
import { guestInitialization } from '../compute/guest_initialization.mjs';

if (process.platform !== 'linux' || path.resolve(fileURLToPath(new URL('..', import.meta.url))) !== '/opt/cannabis' ||
    !fs.existsSync('/opt/cannabis/image-files.json')) throw Error('Run only in the isolated component-check image');
const directory = fs.mkdtempSync('/run/cannabis-init-check-');
const input = path.join(directory, 'assignment.json');
const hex = n => n.toString(16).padStart(64, '0');
function services() {
  return fs.readdirSync('/proc').filter(pid => /^\d+$/.test(pid)).filter(pid => {
    try { return ['/usr/local/bin/ttrpc-aa', '/usr/local/bin/api-server-rest'].includes(fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0')[0]); }
    catch { return false; }
  }).sort();
}
function clean(before) {
  if (JSON.stringify(services()) !== JSON.stringify(before) || fs.readdirSync(directory).some(name => name !== 'assignment.json')) {
    throw Error('Initialization services or temporary socket survived rejection');
  }
}
const options = { initializationFile: input, runtimeDirectory: directory, port: 8007 };
async function rejected(expected, configuration = options, limits) {
  const before = services(); let plane, error;
  try { plane = await InitializedGuestControlPlane.start(configuration, limits); }
  catch (caught) { error = caught; }
  finally { await plane?.close(); }
  if (!error || !expected.test(error.message)) throw Error('Expected initialization refusal did not occur');
  clean(before);
}
try {
  const checks = [];
  for (const tee of ['snp', 'tdx']) {
    const fixture = guestInitialization({ schema: 'cannabis.guest-initialization.v1', tee,
      requester: '0x' + '13'.repeat(20), jobId: 'boot-check-fixture', binding: {
        chainId: 31337, escrow: '0x' + '12'.repeat(20), orderId: '0x' + hex(1), leaseDigest: '0x' + hex(2), reservationId: '0x' + hex(3),
        packageSHA256: hex(4), policySHA256: hex(5), runtimeSHA256: hex(6), taskSHA256: hex(7), attempt: 1, rank: 0, worldSize: 1, acceleratorClass: 'cpu' } });
    fs.writeFileSync(input, fixture.canonical + '\n', { mode: 0o600 });
    await rejected(/^Guest agent profile mismatch; no alternate TEE or accelerator fallback$/);
    checks.push({ profile: tee, unsupportedHardwareRejected: true, servicesStopped: true });
  }
  await rejected(/^Guest initialization cancelled$/, options, { signal: AbortSignal.abort() });
  const cancel = new AbortController();
  const timer = setTimeout(() => cancel.abort(), 1);
  try { await rejected(/^Guest evidence services stopped or initialization cancelled$/, options, { signal: cancel.signal }); }
  finally { clearTimeout(timer); }
  await rejected(/^Guest service binary differs from its build pin$/, { ...options, agentBinary: '/usr/local/bin/node' });
  // A pre-existing loopback responder must never impersonate the spawned bridge.
  let calls = 0;
  const occupied = http.createServer((_, response) => { calls++; response.end('{}'); });
  await new Promise(resolve => occupied.listen(8007, '127.0.0.1', resolve));
  try { await rejected(/^Guest evidence services stopped or initialization cancelled$/); }
  finally { await new Promise(resolve => occupied.close(resolve)); }
  if (calls) throw Error('An unowned loopback listener was queried');
  console.log(JSON.stringify({ schema: 'cannabis.guest-initialization-check.v1', profiles: checks,
    cancellationRejected: true, changedBinaryRejected: true, occupiedPortRejected: true,
    requestedEvidence: false, acceptedJobKeys: false, hardwareValidated: false }));
} finally { if (fs.existsSync(input)) fs.unlinkSync(input); fs.rmdirSync(directory); }
