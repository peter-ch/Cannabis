// Internal guest-control-plane transport. Does not establish a confidential VM.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runGuestPipe } from './guest_pipe.mjs';

export async function prepareGuestWorkload(source, job, binding, { maxBytes, timeoutMs = 600000, signal } = {}) {
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
  const raw = await runGuestPipe(python, script, input, { timeoutMs, maxResponseBytes: 5 * 1024 * 1024, signal });
  try {
    const decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    if (decoded.report?.schema !== 'cannabis.guest-workload.v1' || decoded.report.executionAuthorized !== false || !decoded.workload) throw Error('Invalid guest response');
    return Object.defineProperty(decoded.report, 'workload', { value: decoded.workload, enumerable: false });
  } catch { throw Error('Protected guest workload preparation failed; discard its staging before retry'); }
  finally { raw.fill(0); }
}
