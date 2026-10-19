// Protected control-plane transport, not a hardware attestation or public API.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';

const protocol = 'cannabis.guest-native.pipe.v1', maxResponse = 5 * 1024 * 1024;
const failure = () => Error('Protected native execution failed; retire the job');
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
const fields = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join() === keys.sort().join();
function frame(value) {
  const raw = Buffer.from(JSON.stringify(value));
  if (!raw.length || raw.length > 65536) { raw.fill(0); throw failure(); }
  const bytes = Buffer.alloc(raw.length + 4); bytes.writeUInt32BE(raw.length); raw.copy(bytes, 4); raw.fill(0); return bytes;
}

export function nativeServiceCommitment(execution) {
  execution = structuredClone(execution);
  if (!fields(execution, ['profile', 'source']) || !fields(execution.source, ['python', 'rootfs', 'age', 'ciphertext', 'destination']) ||
      Object.values(execution.source).some(p => typeof p !== 'string' || !path.isAbsolute(p) || p.includes('\0')) ||
      execution.profile?.schema !== 'cannabis.guest-native-service.v2' || execution.profile.units !== 1) throw failure();
  const bytes = Buffer.from(canonical(execution.profile));
  if (bytes.length > 32768) throw failure();
  return { serviceSHA256: '0x' + createHash('sha256').update(bytes).digest('hex'), units: execution.profile.units };
}

// A fixed measured helper is used by executeNative below. This lower-level
// transport accepts a trusted entry point so hostile-protocol fixtures can verify
// the lifecycle without manufacturing a production attestation bypass.
export async function runNativeGuestPipe(python, script, request, releaseKey, { timeoutMs, signal } = {}) {
  if (process.platform !== 'linux' || ![python, script].every(p => typeof p === 'string' && path.isAbsolute(p) && !p.includes('\0')) ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2147483647 || typeof releaseKey !== 'function' ||
      (signal !== undefined && !(signal instanceof AbortSignal)) || signal?.aborted) throw failure();
  const preparation = frame(request);
  return new Promise((resolve, reject) => {
    let child, state = 'preparing', pending = Buffer.alloc(0), result, nonce, settled = false, failed = false, cleanupTimer;
    const outbound = new Set([preparation]);
    try {
      // Inherit only the outer measured launcher's public containment descriptors.
      const env = { PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8' };
      for (const key of ['CANNABIS_JOB_CGROUP', 'CANNABIS_JOB_CONTROL', 'CANNABIS_JOB_DEADLINE', 'CANNABIS_JOB_TOTAL', 'CANNABIS_JOB_CONTROL_LIMITS']) {
        if (process.env[key] !== undefined) env[key] = process.env[key];
      }
      child = spawn(python, ['-I', '-B', script], { stdio: ['pipe', 'pipe', 'ignore'], shell: false, detached: true, env });
    } catch { preparation.fill(0); reject(failure()); return; }
    const wipe = () => { pending.fill(0); pending = Buffer.alloc(0); for (const bytes of outbound) bytes.fill(0); outbound.clear(); };
    const stop = () => { if (child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch (e) { if (e.code !== 'ESRCH') return false; } } return true; };
    const finish = ok => {
      if (settled) return;
      settled = true; clearTimeout(timer); clearTimeout(cleanupTimer); signal?.removeEventListener('abort', fail);
      wipe(); child.stdin.destroy(); child.stdout.destroy();
      if (ok) resolve(result); else reject(failure());
    };
    const fail = () => {
      if (failed || settled) return;
      failed = true; wipe(); child.stdin.destroy(); stop();
      cleanupTimer = setTimeout(() => finish(false), 5000);
    };
    const timer = setTimeout(fail, timeoutMs);
    const write = (bytes, end = false) => {
      outbound.add(bytes);
      const done = error => { bytes.fill(0); outbound.delete(bytes); if (error) fail(); };
      if (end) child.stdin.end(bytes, done); else child.stdin.write(bytes, done);
    };
    const accept = value => {
      if (state === 'preparing') {
        if (!fields(value, ['protocol', 'operation', 'nonce', 'serviceSHA256']) || value.protocol !== protocol || value.operation !== 'ready' ||
            typeof value.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(value.nonce) || value.serviceSHA256 !== request.serviceSHA256) throw failure();
        nonce = value.nonce; state = 'releasing';
        Promise.resolve().then(() => { if (failed || settled || signal?.aborted) throw failure(); return releaseKey(); }).then(job => {
          if (failed || settled || signal?.aborted) return;
          const bytes = frame({ protocol, operation: 'execute', nonce, job: { ...job, identity: job.identity } });
          state = 'executing'; write(bytes, true);
        }).catch(fail);
      } else if (state === 'executing') {
        if (!fields(value, ['protocol', 'operation', 'nonce', 'report', 'receipt']) || value.protocol !== protocol || value.operation !== 'complete' ||
            !fields(value.report,['schema','executionCompleted','resultEncrypted','runtimeCleanupVerified','hardwareAdmissionEstablished','paymentAccepted']) ||
            value.nonce !== nonce || value.report?.schema !== 'cannabis.guest-native-result.v1' || value.report.executionCompleted !== true ||
            value.report.resultEncrypted !== true || value.report.runtimeCleanupVerified !== true || value.report.hardwareAdmissionEstablished !== false ||
            value.report.paymentAccepted !== false || !value.receipt || typeof value.receipt !== 'object') throw failure();
        result = value; state = 'completed';
      } else throw failure();
    };
    child.stdout.on('data', chunk => {
      if (failed || settled) { chunk.fill(0); return; }
      try {
        if (pending.length + chunk.length > maxResponse + 4) throw failure();
        const combined = Buffer.concat([pending, chunk]); pending.fill(0); chunk.fill(0); pending = combined;
        while (pending.length >= 4) {
          const length = pending.readUInt32BE();
          if (!length || length > maxResponse || (state === 'preparing' && length > 4096)) throw failure();
          if (pending.length < length + 4) break;
          const bytes = pending.subarray(4, length + 4);
          const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
          const rest = Buffer.from(pending.subarray(length + 4)); pending.fill(0); pending = rest;
          accept(value);
        }
      } catch { fail(); }
    });
    signal?.addEventListener('abort', fail, { once: true });
    child.on('error', fail); child.stdin.on('error', fail); child.stdout.on('error', fail);
    child.on('exit', code => { if (code !== 0 || !stop()) fail(); });
    child.on('close', code => finish(!failed && code === 0 && state === 'completed' && pending.length === 0));
    if (signal?.aborted) fail(); else write(preparation);
  });
}

export async function executeNativeGuest(execution, binding, interval, releaseKey, options) {
  execution = structuredClone(execution); binding = structuredClone(binding); interval = structuredClone(interval);
  const commitment = nativeServiceCommitment(execution), { python, ...source } = execution.source;
  verifyPython(execution);
  const script = fileURLToPath(new URL('../scripts/compute-guest-native-pipe.py', import.meta.url));
  const response = await runNativeGuestPipe(python, script, { protocol, operation: 'prepare', profile: execution.profile,
    ...commitment, source, binding, interval }, releaseKey, options);
  // The private receipt is returned only through explicit protected-channel use.
  return Object.defineProperties(response.report, { receipt: { value: response.receipt, enumerable: false },
    ciphertext: { value: source.destination, enumerable: false } });
}

function verifyPython(execution) {
  const {python}=execution.source;
  const fd = fs.openSync(python, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const s = fs.fstatSync(fd);
    if (!s.isFile() || s.uid !== 0 || s.mode & 0o022 || s.size > 256 * 1024 * 1024 ||
        createHash('sha256').update(fs.readFileSync(fd)).digest('hex') !== execution.profile.tools?.pythonSHA256) throw failure();
  } finally { fs.closeSync(fd); }
}

export function inspectNativeGuest(execution,binding,interval,{timeoutMs}={}) {
  if(process.platform!=='linux'||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>60000)throw failure();
  const commitment=nativeServiceCommitment(execution),{python,...source}=execution.source;verifyPython(execution);
  const input=JSON.stringify({protocol,operation:'prepare',profile:execution.profile,...commitment,source,binding,interval});
  if(Buffer.byteLength(input)>65536)throw failure();
  const env={PATH:'/usr/local/bin:/usr/bin:/bin',LANG:'C.UTF-8'};
  for(const key of ['CANNABIS_JOB_CGROUP','CANNABIS_JOB_CONTROL','CANNABIS_JOB_DEADLINE','CANNABIS_JOB_TOTAL','CANNABIS_JOB_CONTROL_LIMITS'])
    if(process.env[key]!==undefined)env[key]=process.env[key];
  let result;
  try{result=JSON.parse(execFileSync(python,['-I','-B',fileURLToPath(new URL('../scripts/compute-guest-admission.py',import.meta.url))],
    {input,encoding:'utf8',timeout:timeoutMs,maxBuffer:4096,stdio:['pipe','pipe','ignore'],env}));}catch{throw failure();}
  if(!fields(result,['schema','serviceSHA256','controlContained','runtimeVerified','ciphertextVerified','ciphertextStorageVerified','hardwareValidated','executionAuthorized'])||
    result.schema!=='cannabis.guest-admission-check.v1'||result.serviceSHA256!==commitment.serviceSHA256||result.controlContained!==true||
    result.runtimeVerified!==true||result.ciphertextVerified!==true||result.ciphertextStorageVerified!==true||
    result.hardwareValidated!==false||result.executionAuthorized!==false)throw failure();
  return result;
}
