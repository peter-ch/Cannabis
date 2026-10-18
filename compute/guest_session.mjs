// Run inside the approved guest control plane. This module is not a TEE or launcher.
import http from 'node:http';
import { createHash, webcrypto } from 'node:crypto';
import { exportJWK } from 'jose';
import { getAddress, ZeroAddress } from 'ethers';
import { trusteeReportData } from './attestation.mjs';
import { openJobKeyDelivery } from './key_delivery.mjs';
import { prepareGuestWorkload } from './guest_workload.mjs';

export const GUEST_COMPONENTS_REVISION = 'eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a';
export const GUEST_AGENT_VERSION = 'Guest Components Version: v0.22.0';
const nowSeconds = () => Math.floor(Date.now() / 1000);
const construction = Symbol('guest-session-construction');
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
function endpoint(value) {
  const url = new URL(value);
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) ||
      url.username || url.password || url.search || url.hash || url.pathname !== '/') throw Error('Guest agent must use a literal loopback HTTP origin');
  return url.origin;
}
function timeout(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 60000) throw Error('Guest agent timeout must be 1..60000 milliseconds');
  return value;
}
function localRead(url, limit, timeoutMs, signal) {
  // Direct HTTP avoids DNS, proxy environment variables and redirect following.
  return new Promise((resolve, reject) => {
    const stop = AbortSignal.any([AbortSignal.timeout(timeout(timeoutMs)), ...(signal ? [signal] : [])]);
    const req = http.get(url, { signal: stop, agent: false, headers: { Accept: 'application/json, application/octet-stream' } }, res => {
      if (res.statusCode !== 200 || (res.headers['content-length'] && (!/^\d+$/.test(res.headers['content-length']) || Number(res.headers['content-length']) > limit))) {
        res.destroy(); reject(Error('Guest agent response rejected')); return;
      }
      let size = 0; const chunks = [];
      res.on('data', chunk => { size += chunk.length; if (size > limit) res.destroy(Error('Guest agent response exceeded its bound')); else chunks.push(chunk); });
      res.on('error', () => reject(Error('Guest agent response failed')));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('error', () => reject(Error('Guest agent unavailable or request cancelled')));
  });
}
function json(raw) {
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)); }
  catch { throw Error('Guest agent returned malformed JSON'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Guest agent returned an invalid object');
  return value;
}

export async function probeGuestAgent({ agentUrl = 'http://127.0.0.1:8006', agentVersion = GUEST_AGENT_VERSION, tee }, { timeoutMs = 15000, signal } = {}) {
  if (!['snp', 'tdx'].includes(tee) || agentVersion !== GUEST_AGENT_VERSION) throw Error('Require the pinned SNP/TDX guest-agent profile');
  const origin = endpoint(agentUrl);
  const info = json(await localRead(origin + '/info', 4096, timeoutMs, signal));
  if (info.version !== agentVersion || info.tee !== tee || info.feature !== 'attestation' ||
      (info.additional_tees !== undefined && (!Array.isArray(info.additional_tees) || info.additional_tees.length))) throw Error('Guest agent profile mismatch; no alternate TEE or accelerator fallback');
  return { version: info.version, tee, protocolRevision: GUEST_COMPONENTS_REVISION, hardwareVerified: false };
}

export class GuestEvidenceSession {
  #policy; #challenge; #requester; #jobId; #key; #publicKey; #clock; #agent; #timer;
  #abort = new AbortController(); #state = 'ready'; #evidence; #preparationAbort;
  constructor(guard, options, key, publicKey) {
    if (guard !== construction) throw Error('Use GuestEvidenceSession.create');
    this.#policy = options.policy; this.#challenge = options.challenge;
    this.#requester = options.requester; this.#jobId = options.jobId;
    this.#agent = { agentUrl: endpoint(options.agentUrl), agentVersion: GUEST_AGENT_VERSION, tee: options.policy.tee };
    this.#clock = options.clock; this.#key = key; this.#publicKey = publicKey;
    this.#timer = setTimeout(() => this.close(), Math.max(1, options.challenge.expiresAt - this.#clock()) * 1000);
    this.#timer.unref();
  }
  static async create({ policy, challenge, expectedBinding, requester, jobId, agentUrl = 'http://127.0.0.1:8006' }, { clock = nowSeconds } = {}) {
    policy = structuredClone(policy); challenge = structuredClone(challenge); expectedBinding = structuredClone(expectedBinding);
    endpoint(agentUrl);
    requester = getAddress(requester);
    if (requester === ZeroAddress || typeof jobId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(jobId) ||
        canonical(challenge.binding) !== canonical(expectedBinding)) throw Error('Challenge differs from the approved guest assignment');
    // The caller cannot supply a channel key. The private key is non-extractable
    // and held only in this session; no file, environment or serialization path.
    const pair = await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const publicKey = await exportJWK(pair.publicKey);
    trusteeReportData(policy, challenge, publicKey, clock());
    return new GuestEvidenceSession(construction, { policy, challenge, requester, jobId, agentUrl, clock }, pair.privateKey, publicKey);
  }
  get channelJwk() { return structuredClone(this.#publicKey); }
  get status() { return { state: this.#state, nonce: this.#challenge.nonce, expiresAt: this.#challenge.expiresAt, executionAuthorized: false }; }
  #fresh() {
    const now = this.#clock();
    if (!Number.isSafeInteger(now) || now < this.#challenge.issuedAt || now >= this.#challenge.expiresAt || ['closed', 'consumed'].includes(this.#state)) {
      this.close(); throw Error('Guest evidence session is closed or expired');
    }
  }
  async evidence({ timeoutMs = 15000 } = {}) {
    this.#fresh();
    if (this.#state === 'quoted') return structuredClone(this.#evidence);
    if (this.#state !== 'ready') throw Error('Guest evidence collection already in progress');
    this.#state = 'collecting';
    try {
      const agent = await probeGuestAgent(this.#agent, { timeoutMs, signal: this.#abort.signal });
      this.#fresh();
      const report = trusteeReportData(this.#policy, this.#challenge, this.#publicKey, this.#clock());
      const query = new URLSearchParams({ runtime_data: report.toString('base64url'), encoding: 'base64' });
      const raw = await localRead(this.#agent.agentUrl + '/aa/evidence?' + query, 3 * 1024 * 1024, timeoutMs, this.#abort.signal);
      if (!Object.keys(json(raw)).length) throw Error('Guest agent returned empty evidence');
      this.#fresh();
      this.#evidence = { schema: 'cannabis.guest-evidence.v1', nonce: this.#challenge.nonce,
        channelJwk: this.channelJwk, evidence: raw.toString('base64url'), agent,
        evidenceSHA256: createHash('sha256').update(raw).digest('hex'), hardwareVerified: false, executionAuthorized: false };
      this.#state = 'quoted'; return structuredClone(this.#evidence);
    } catch (error) { this.close(); throw error; }
  }
  #match(expected) {
    const b = this.#challenge.binding, v = expected?.value, d = expected?.domain;
    if (!v || !d || expected.requester !== this.#requester || expected.jobId !== this.#jobId ||
        d.name !== 'Cannabis confidential key delivery' || d.version !== '1' || BigInt(d.chainId) !== BigInt(b.chainId) ||
        getAddress(d.verifyingContract) !== getAddress(b.escrow)) throw Error('Delivery differs from retained guest assignment');
    const fields = { leaseDigest: b.leaseDigest, orderId: b.orderId, reservationId: b.reservationId,
      nonce: '0x' + this.#challenge.nonce, attestationPolicySHA256: '0x' + this.#challenge.attestationPolicySHA256,
      channelKeySHA256: '0x' + createHash('sha256').update(canonical(this.#publicKey)).digest('hex'),
      attempt: b.attempt, rank: b.rank, worldSize: b.worldSize };
    for (const k of ['packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256']) fields[k] = '0x' + b[k];
    if (Object.entries(fields).some(([k, value]) => v[k] !== value) ||
        !Number.isSafeInteger(v.notBefore) || !Number.isSafeInteger(v.expiresAt) ||
        v.notBefore < this.#challenge.issuedAt || v.expiresAt > this.#challenge.expiresAt || v.expiresAt <= v.notBefore) throw Error('Delivery binding differs from retained guest assignment');
  }
  async open(envelope, expected, { ageKeygen } = {}) {
    this.#fresh();
    if (this.#state !== 'quoted') throw Error('Guest session has no completed evidence or is already opening');
    this.#state = 'opening';
    try {
      expected = structuredClone(expected); this.#match(expected);
      const job = await openJobKeyDelivery(envelope, this.#key, expected, { clock: this.#clock, ageKeygen });
      this.#fresh(); this.#dispose('consumed'); return job;
    } catch (error) { this.close(); throw error; }
  }
  async prepare(envelope, expected, source, options = {}) {
    expected = structuredClone(expected); source = structuredClone(source); options = structuredClone(options);
    if (this.#preparationAbort) throw Error('Guest workload preparation already in progress');
    const preparation = new AbortController(); this.#preparationAbort = preparation;
    try {
      const key = await this.open(envelope, expected, options);
      const binding = Object.fromEntries(['packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256'].map(k => [k, expected.value[k].slice(2)]));
      for (const k of ['attempt', 'rank', 'worldSize']) binding[k] = expected.value[k];
      binding.acceleratorClass = this.#challenge.binding.acceleratorClass;
      return await prepareGuestWorkload(source, key, binding, { ...options, signal: preparation.signal });
    } finally { this.#preparationAbort = undefined; }
  }
  #dispose(state) {
    clearTimeout(this.#timer); this.#abort.abort(); this.#key = undefined; this.#evidence = undefined; this.#state = state;
  }
  close() { this.#preparationAbort?.abort(); this.#dispose(this.#state === 'consumed' ? 'consumed' : 'closed'); }
}
