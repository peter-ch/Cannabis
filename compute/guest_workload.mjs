// Internal guest-control-plane transport. Does not establish a confidential VM.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export async function prepareGuestWorkload(source, job, binding, { maxBytes, timeoutMs = 600000 } = {}) {
  source = structuredClone(source); binding = structuredClone(binding);
  const fields = ['python', 'age', 'ciphertext', 'destination'];
  if (!source || Object.keys(source).length !== fields.length || fields.some(k => typeof source[k] !== 'string' || !path.isAbsolute(source[k]) || source[k].includes('\0'))) throw Error('Require trusted absolute guest paths');
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > 2 ** 40 || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3600000) throw Error('Require bounded guest extraction and deadline');
  const script = fileURLToPath(new URL('../scripts/compute-guest-workload-pipe.py', import.meta.url));
  const { python, ...local } = source;
  // identity is intentionally non-enumerable on GuestEvidenceSession.open().
  const privateJob = { ...job, identity: job.identity };
  const input = Buffer.from(JSON.stringify({ protocol: 'cannabis.guest-workload.pipe.v1', source: local, job: privateJob, binding, maxBytes }));
  if (input.length > 65536) { input.fill(0); throw Error('Guest pipe request exceeds bound'); }
  return new Promise((resolve, reject) => {
    const child = spawn(python, ['-I', script], { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true, shell: false });
    let size = 0, failed = false; const chunks = [];
    const fail = () => {
      if (failed) return;
      failed = true; clearTimeout(timer); input.fill(0); for (const part of chunks) part.fill(0);
      child.kill(); reject(Error('Protected guest workload preparation failed; discard its staging before retry'));
    };
    const timer = setTimeout(fail, timeoutMs);
    child.on('error', fail); child.stdin.on('error', fail);
    child.stdout.on('data', part => { if (failed) { part.fill(0); return; } size += part.length; if (size > 5 * 1024 * 1024) { part.fill(0); fail(); } else chunks.push(part); });
    child.on('close', code => {
      clearTimeout(timer); input.fill(0);
      if (failed) return;
      if (code !== 0) { fail(); return; }
      const raw = Buffer.concat(chunks);
      try {
        const decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
        if (decoded.report?.schema !== 'cannabis.guest-workload.v1' || decoded.report.executionAuthorized !== false || !decoded.workload) throw Error('Invalid guest response');
        resolve(Object.defineProperty(decoded.report, 'workload', { value: decoded.workload, enumerable: false }));
      } catch { fail(); }
      finally { raw.fill(0); for (const part of chunks) part.fill(0); }
    });
    child.stdin.end(input, () => input.fill(0));
  });
}
