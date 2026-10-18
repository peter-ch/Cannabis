// Anonymous transport for trusted guest helpers, never a customer-code launcher.
import { spawn } from 'node:child_process';
import path from 'node:path';

const failure = () => Error('Protected guest workload preparation failed; discard its staging before retry');

export async function runGuestPipe(python, script, input, { timeoutMs, maxResponseBytes, signal } = {}) {
  if (![python, script].every(p => typeof p === 'string' && path.isAbsolute(p) && !p.includes('\0'))
      || !Buffer.isBuffer(input) || input.length > 65536
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3600000
      || !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 5 * 1024 * 1024
      || (signal !== undefined && !(signal instanceof AbortSignal))) {
    if (Buffer.isBuffer(input)) input.fill(0);
    throw failure();
  }
  if (signal?.aborted) { input.fill(0); throw failure(); }
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(python, ['-I', script], {
        stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true, shell: false,
        // Keep the handle referenced. POSIX group membership is checked by Python.
        detached: process.platform !== 'win32'
      });
    } catch { input.fill(0); reject(failure()); return; }
    let size = 0, failed = false, settled = false, cleanupTimer, exited = false;
    const chunks = [];
    const wipe = () => { input.fill(0); for (const part of chunks) part.fill(0); };
    const stopTree = () => {
      if (!child.pid) return true;
      try {
        if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
        else if (!exited) child.kill('SIGKILL'); // Python owns a kill-on-close job.
      } catch (error) {
        if (error.code !== 'ESRCH') return false;
      }
      return true;
    };
    const settleFailure = () => {
      if (settled) return;
      settled = true; clearTimeout(deadline); clearTimeout(cleanupTimer);
      signal?.removeEventListener('abort', fail); wipe();
      child.stdin.destroy(); child.stdout.destroy(); reject(failure());
    };
    const fail = () => {
      if (settled || failed) return;
      failed = true; clearTimeout(deadline); wipe(); child.stdin.destroy(); stopTree();
      // Usually 'close' acknowledges termination. If the OS cannot close the
      // process/pipe, fail boundedly without claiming cleanup or returning files.
      cleanupTimer = setTimeout(settleFailure, 5000);
    };
    const deadline = setTimeout(fail, timeoutMs);
    signal?.addEventListener('abort', fail, { once: true });
    child.on('error', fail); child.stdin.on('error', fail); child.stdout.on('error', fail);
    child.stdout.on('data', part => {
      if (failed || settled) { part.fill(0); return; }
      size += part.length;
      if (size > maxResponseBytes) { part.fill(0); fail(); } else chunks.push(part);
    });
    child.on('exit', code => {
      exited = true;
      // An exited helper can leave descendants holding stdout open. Stop the
      // group at exit, before waiting for EOF/'close', including on success.
      if (code !== 0) fail();
      if (!stopTree()) fail();
    });
    child.on('close', code => {
      if (settled) return;
      if (failed || code !== 0) { settleFailure(); return; }
      settled = true; clearTimeout(deadline); clearTimeout(cleanupTimer);
      signal?.removeEventListener('abort', fail);
      const raw = Buffer.concat(chunks); wipe(); resolve(raw);
    });
    if (signal?.aborted) fail();
    else child.stdin.end(input, () => input.fill(0));
  });
}
