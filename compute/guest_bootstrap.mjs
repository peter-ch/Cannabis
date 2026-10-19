// Start the pinned CPU evidence services inside a dedicated measured guest.
// This gate authorizes an evidence session, never customer-code execution.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { readGuestInitialization, guestInitialization } from './guest_initialization.mjs';
import { GuestEvidenceSession, probeGuestAgent } from './guest_session.mjs';

const construction = Symbol('initialized-guest');
const servicePins = JSON.parse(fs.readFileSync(new URL('./guest-image/inputs.json', import.meta.url))).guestServices;

function verifyBinary(file, hash) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) throw Error('Require an absolute guest service path');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || !(stat.mode & 0o111) || stat.size > 256 * 1024 * 1024 ||
        createHash('sha256').update(fs.readFileSync(fd)).digest('hex') !== hash) throw Error('Guest service binary differs from its build pin');
  } finally { fs.closeSync(fd); }
}

function ownsListener(pid, port) {
  const endpoint = '0100007F:' + port.toString(16).toUpperCase().padStart(4, '0');
  const listeners = new Set(fs.readFileSync('/proc/net/tcp', 'utf8').trim().split('\n').slice(1)
    .map(line => line.trim().split(/\s+/)).filter(row => row[1] === endpoint && row[3] === '0A').map(row => row[9]));
  try {
    return fs.readdirSync(`/proc/${pid}/fd`).some(name => {
      try { const link = fs.readlinkSync(`/proc/${pid}/fd/${name}`); return listeners.has(/^socket:\[(\d+)\]$/.exec(link)?.[1]); }
      catch { return false; }
    });
  } catch { return false; }
}

export class InitializedGuestControlPlane {
  #initialization; #directory; #socket; #children = []; #session; #issued = false; #state = 'starting'; #origin; #signal; #onAbort; #closing;
  constructor(guard, initialization, directory, port, signal) {
    if (guard !== construction) throw Error('Use InitializedGuestControlPlane.start');
    this.#initialization = initialization; this.#directory = directory;
    this.#socket = path.join(directory, 'agent.sock'); this.#origin = `http://127.0.0.1:${port}`;
    this.#signal = signal; this.#onAbort = () => { this.#stop(); };
    signal?.addEventListener('abort', this.#onAbort, { once: true });
  }
  static async start({ initializationFile, assignment, agentBinary = '/usr/local/bin/ttrpc-aa', bridgeBinary = '/usr/local/bin/api-server-rest', runtimeDirectory = '/run', port = 8006 }, { timeoutMs = 20000, signal } = {}) {
    if (process.platform !== 'linux' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000 ||
        !Number.isSafeInteger(port) || port < 1024 || port > 65535 || !path.isAbsolute(runtimeDirectory) || (signal && !(signal instanceof AbortSignal))) {
      throw Error('Require a dedicated Linux guest and bounded startup configuration');
    }
    if (signal?.aborted) throw Error('Guest initialization cancelled');
    if((initializationFile===undefined)===(assignment===undefined))throw Error('Retain exactly one guest initialization source');
    const initialization = assignment===undefined?readGuestInitialization(initializationFile):guestInitialization(assignment);
    verifyBinary(agentBinary, servicePins['ttrpc-aa']); verifyBinary(bridgeBinary, servicePins['api-server-rest']);
    const directory = fs.mkdtempSync(path.join(runtimeDirectory, 'cannabis-init-'));
    fs.chmodSync(directory, 0o700);
    const guest = new InitializedGuestControlPlane(construction, initialization, directory, port, signal);
    try {
      if (Buffer.byteLength(guest.#socket) > 100) throw Error('Guest socket path exceeds its bound');
      const deadline = Date.now() + timeoutMs;
      // The upstream CLI checks this digest against HOST_DATA/MRCONFIGID before
      // binding its RPC socket. Do not pass a TOML override or inherit an env.
      guest.#launch(agentBinary, ['--attestation_sock', 'unix://' + guest.#socket, '--initdata-digest', initialization.digestBase64]);
      while (!fs.existsSync(guest.#socket)) { guest.#alive(); if (Date.now() >= deadline) throw Error('Guest initialization startup expired'); await delay(25); }
      if (!fs.lstatSync(guest.#socket).isSocket()) throw Error('Guest agent did not create its socket');
      const bridge = guest.#launch(bridgeBinary, ['--features', 'attestation', '--aa_addr', 'unix://' + guest.#socket, '--bind', `127.0.0.1:${port}`]);
      while (!ownsListener(bridge.pid, port)) { guest.#alive(); if (Date.now() >= deadline) throw Error('Guest bridge startup expired'); await delay(25); }
      guest.#alive();
      // Upstream permits Unsupported init-data binding on sample hardware. That
      // branch is never admitted here, even if the RPC socket became available.
      await probeGuestAgent({ agentUrl: guest.#origin, tee: initialization.assignment.tee }, { timeoutMs: Math.max(1, deadline - Date.now()), signal });
      guest.#alive(); guest.#state = 'ready'; return guest;
    } catch (error) { await guest.close(); throw error; }
  }
  #launch(binary, args) {
    this.#alive();
    const child = spawn(binary, args, { detached: true, shell: false, stdio: 'ignore', cwd: this.#directory,
      env: { PATH: '/usr/bin:/bin', HOME: this.#directory, LANG: 'C.UTF-8', RUST_LOG: 'error' } });
    const record = { child, stopped: false, closed: null };
    record.closed = new Promise(resolve => {
      child.once('close', () => { record.stopped = true; resolve(); this.#stop(); });
      child.once('error', () => { record.stopped = true; this.#stop(); });
      child.once('exit', () => { record.stopped = true; this.#stop(); });
    });
    this.#children.push(record); return child;
  }
  #alive() {
    if (this.#signal?.aborted || this.#closing || this.#children.some(record => record.stopped)) throw Error('Guest evidence services stopped or initialization cancelled');
  }
  // Event handlers observe cleanup without creating an unhandled rejection.
  // Explicit close/start callers still receive the same cleanup promise/error.
  #stop() { this.close().catch(() => {}); }
  get status() { return { state: this.#state, tee: this.#initialization.assignment.tee, initData: this.#initialization.digest, assignmentRetained: true, hardwareValidated: false, executionAuthorized: false }; }
  async createSession({ policy, challenge, funding, execution }) {
    this.#alive();
    if (this.#state !== 'ready' || this.#issued) throw Error('Guest permits one evidence session for its retained assignment');
    this.#issued = true;
    const init = this.#initialization.assignment;
    try {
      if (!funding || !execution) throw Error('Initialized guest sessions require approved funding and execution configurations');
      const session = await GuestEvidenceSession.create({ initialization: init, policy, challenge, funding, execution,
        expectedBinding: init.binding, requester: init.requester, jobId: init.jobId, agentUrl: this.#origin });
      try { this.#alive(); } catch (error) { session.close(); throw error; }
      this.#session = session; return session;
    } catch (error) { await this.close(); throw error; }
  }
  close() {
    if (!this.#closing) {
      this.#state = 'closing'; this.#signal?.removeEventListener('abort', this.#onAbort); this.#session?.close();
      this.#closing = this.#cleanup().then(() => { this.#state = 'closed'; }, error => { this.#state = 'cleanup-failed'; throw error; });
    }
    return this.#closing;
  }
  async #cleanup() {
    let failed = false;
    for (const { child } of this.#children) {
      if (!child.pid) continue;
      try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') failed = true; }
    }
    let timer;
    try {
      await Promise.race([Promise.all(this.#children.map(record => record.closed)), new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error('Guest service cleanup timed out')), 5000);
      })]);
    } finally { clearTimeout(timer); }
    if (failed) throw Error('Guest service cleanup failed');
    // Only remove the socket and fresh directory reserved by this invocation.
    if (fs.existsSync(this.#socket)) fs.unlinkSync(this.#socket);
    fs.rmdirSync(this.#directory);
  }
}
