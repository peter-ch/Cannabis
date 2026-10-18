import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { runGuestPipe } from '../compute/guest_pipe.mjs';

const locate = spawnSync(process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3'),
  ['-I', '-c', 'import sys; print(sys.executable)'], { encoding: 'utf8', windowsHide: true });
assert.equal(locate.status, 0, 'Python is required for guest pipe verification');
const python = locate.stdout.trim(), script = fileURLToPath(new URL('./helpers/guest_process_fixture.py', import.meta.url));

function running(pid) {
  try {
    process.kill(pid, 0);
    // Linux can briefly retain a dead orphan as a zombie until init reaps it.
    if (process.platform === 'linux' && /\) Z /.test(fs.readFileSync(`/proc/${pid}/stat`, 'utf8'))) return false;
    return true;
  } catch (error) {
    if (['ESRCH', 'ENOENT'].includes(error.code)) return false;
    throw error;
  }
}
function pids(directory) {
  return ['helper', 'child', 'grandchild'].filter(name => fs.existsSync(path.join(directory, name)))
    .map(name => Number(fs.readFileSync(path.join(directory, name), 'utf8')));
}
async function until(check) {
  const deadline = Date.now() + 5000;
  while (!check()) { assert.ok(Date.now() < deadline, 'Fixture condition did not complete'); await delay(20); }
}

for (const mode of ['ok', 'timeout', 'cancel', 'error', 'oversized', 'ok-orphan']) {
  test(`guest pipe contains its descendants on ${mode}`, { timeout: 15000 }, async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-guest-tree-'));
    const sentinel = spawn(python, ['-I', '-c', 'import time; time.sleep(30)'], { stdio: 'ignore', windowsHide: true });
    const controller = new AbortController();
    const input = Buffer.from(JSON.stringify({ directory, mode }));
    try {
      const promise = runGuestPipe(python, script, input, {
        timeoutMs: mode === 'timeout' ? 1500 : 10000, maxResponseBytes: 4096, signal: controller.signal
      });
      // Attach the rejection handler immediately; fast faults must not produce an
      // unhandled rejection while the fixture's readiness is being observed.
      const result = promise.then(value => ({ value }), error => ({ error }));
      if (mode === 'cancel') {
        await until(() => pids(directory).length === 3);
        controller.abort();
      }
      const outcome = await result;
      if (mode === 'ok' || mode === 'ok-orphan') {
        assert.deepEqual(JSON.parse(outcome.value.toString()), { complete: true });
        outcome.value.fill(0);
      } else {
        assert.match(outcome.error?.message || '', /preparation failed; discard/);
        assert.equal(outcome.error.message.includes('private fixture diagnostic'), false);
      }
      const processes = pids(directory);
      assert.equal(processes.length, mode === 'ok' ? 1 : 3, 'Exercise the actual descendant tree');
      await until(() => processes.every(pid => !running(pid)));
      assert.ok(running(sentinel.pid), 'Other processes must remain untouched');
      assert.ok(input.every(byte => byte === 0), 'Clear the consumed request buffer');
    } finally {
      controller.abort();
      for (const pid of pids(directory)) if (Number.isSafeInteger(pid) && pid > 0 && running(pid)) process.kill(pid, 'SIGKILL');
      sentinel.kill('SIGKILL');
      await until(() => !running(sentinel.pid));
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
}

test('cancelled and invalid guest requests never start a helper', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-guest-unstarted-'));
  try {
    const controller = new AbortController(); controller.abort();
    for (const options of [{ signal: controller.signal }, { timeoutMs: 0 }, { maxResponseBytes: 0 }]) {
      const input = Buffer.from(JSON.stringify({ directory, mode: 'ok' }));
      await assert.rejects(runGuestPipe(python, script, input, { timeoutMs: 1000, maxResponseBytes: 4096, ...options }), /preparation failed/);
      assert.ok(input.every(byte => byte === 0));
      assert.deepEqual(fs.readdirSync(directory), []);
    }
    await assert.rejects(runGuestPipe(path.join(directory, 'missing-python'), script, Buffer.from('{}'),
      { timeoutMs: 1000, maxResponseBytes: 4096 }), /preparation failed/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
