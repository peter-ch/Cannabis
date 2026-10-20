// Run inside the approved guest control plane. This module is not a TEE or launcher.
import http from 'node:http';
import path from 'node:path';
import { createHash, webcrypto } from 'node:crypto';
import { exportJWK } from 'jose';
import { getAddress, ZeroAddress } from 'ethers';
import { trusteeReportData } from './attestation.mjs';
import { openJobKeyDelivery } from './key_delivery.mjs';
import { prepareGuestWorkload } from './guest_workload.mjs';
import { matchGuestInitialization } from './guest_initialization.mjs';
import { GuestFunding } from './guest_funding.mjs';
import { nativeServiceCommitment, executeNativeGuest } from './guest_execution.mjs';
import { sealResultDelivery } from './result_delivery.mjs';
import { inspectGuestDependency } from './guest_dependency.mjs';

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
  #abort = new AbortController(); #state = 'ready'; #evidence; #preparationAbort; #funding; #execution; #dependency;
  constructor(guard, options, key, publicKey) {
    if (guard !== construction) throw Error('Use GuestEvidenceSession.create');
    this.#policy = options.policy; this.#challenge = options.challenge;
    this.#requester = options.requester; this.#jobId = options.jobId;
    this.#agent = { agentUrl: endpoint(options.agentUrl), agentVersion: GUEST_AGENT_VERSION, tee: options.policy.tee };
    this.#clock = options.clock; this.#key = key; this.#publicKey = publicKey;
    this.#funding = options.funding;
    this.#execution = options.execution;
    this.#dependency = options.dependency;
    this.#timer = setTimeout(() => this.close(), Math.max(1, options.challenge.expiresAt - this.#clock()) * 1000);
    this.#timer.unref();
  }
  static async create({ initialization, policy, challenge, expectedBinding, requester, jobId, funding, execution, dependency, agentUrl = 'http://127.0.0.1:8006' }, { clock = nowSeconds } = {}) {
    policy = structuredClone(policy); challenge = structuredClone(challenge); expectedBinding = structuredClone(expectedBinding);
    endpoint(agentUrl);
    requester = getAddress(requester);
    matchGuestInitialization(initialization, { policy, expectedBinding, requester, jobId });
    if (requester === ZeroAddress || typeof jobId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(jobId) ||
        canonical(challenge.binding) !== canonical(expectedBinding)) throw Error('Challenge differs from the approved guest assignment');
    const retainedFunding = funding === undefined ? undefined : new GuestFunding(funding, initialization, { clock });
    if (execution !== undefined) {
      execution = structuredClone(execution);
      if (!retainedFunding) throw Error('Native execution requires a signed funding configuration');
      retainedFunding.assertService(nativeServiceCommitment(execution));
    }
    const retainedDependency=funding?inspectGuestDependency({proof:funding.proof,network:funding.network,binding:expectedBinding,execution,
      dependency:dependency?{descriptor:dependency.descriptor,signed:dependency.signed}:undefined,now:clock()}):null;
    if(dependency&&!funding)throw Error('Dependency inputs require retained funding');
    // The caller cannot supply a channel key. The private key is non-extractable
    // and held only in this session; no file, environment or serialization path.
    const pair = await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const publicKey = await exportJWK(pair.publicKey);
    trusteeReportData(policy, challenge, publicKey, clock());
    return new GuestEvidenceSession(construction, { policy, challenge, requester, jobId, agentUrl, clock, funding: retainedFunding, execution, dependency:retainedDependency }, pair.privateKey, publicKey);
  }
  get channelJwk() { return structuredClone(this.#publicKey); }
  get status() { return { state: this.#state, nonce: this.#challenge.nonce, expiresAt: this.#challenge.expiresAt, fundingRequired: !!this.#funding, executionAuthorized: false }; }
  get serviceInterval() { return this.#funding?.interval; }
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
        d.name !== 'Cannabis confidential key delivery' || !['1','2','3','4'].includes(d.version) || BigInt(d.chainId) !== BigInt(b.chainId) ||
        getAddress(d.verifyingContract) !== getAddress(b.escrow)) throw Error('Delivery differs from retained guest assignment');
    if((['3','4'].includes(d.version))!==Object.hasOwn(b,'configurationSHA256'))throw Error('Delivery configuration version differs from retained assignment');
    if((d.version==='4')!==!!this.#dependency||this.#dependency&&(v.dependencyApprovalDigest!==this.#dependency.approvalDigest||
      this.#clock()<this.#dependency.signed.window.notBefore||this.#clock()>=this.#dependency.signed.window.expiresAt||
      v.notBefore<this.#dependency.signed.window.notBefore||v.expiresAt>this.#dependency.signed.window.expiresAt))
      throw Error('Key delivery differs from the retained dependency approval');
    const fields = { ...(['3','4'].includes(d.version)?{configurationSHA256:b.configurationSHA256}:{}),leaseDigest: b.leaseDigest, orderId: b.orderId, reservationId: b.reservationId,
      nonce: '0x' + this.#challenge.nonce, attestationPolicySHA256: '0x' + this.#challenge.attestationPolicySHA256,
      channelKeySHA256: '0x' + createHash('sha256').update(canonical(this.#publicKey)).digest('hex'),
      attempt: b.attempt, rank: b.rank, worldSize: b.worldSize };
    for (const k of ['packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256']) fields[k] = '0x' + b[k];
    if (Object.entries(fields).some(([k, value]) => v[k] !== value) ||
        !Number.isSafeInteger(v.notBefore) || !Number.isSafeInteger(v.expiresAt) ||
        v.notBefore < this.#challenge.issuedAt || v.expiresAt > this.#challenge.expiresAt || v.expiresAt <= v.notBefore) throw Error('Delivery binding differs from retained guest assignment');
  }
  async open(envelope, expected, { ageKeygen } = {}) {
    if (this.#preparationAbort) throw Error('Guest execution or preparation already in progress');
    if (this.#execution) throw Error('Bound native sessions release keys only through execution readiness');
    return this.#open(envelope, expected, { ageKeygen });
  }
  async #open(envelope, expected, { ageKeygen } = {}) {
    this.#fresh();
    if (this.#state !== 'quoted') throw Error('Guest session has no completed evidence or is already opening');
    this.#state = 'opening';
    let job;
    try {
      expected = structuredClone(expected); this.#match(expected);
      if (this.#funding) {
        const interval = this.#funding.interval;
        if (expected.value.notBefore < interval.start || expected.value.expiresAt > interval.end) throw Error('Key-delivery window exceeds the signed service interval');
        await this.#funding.refresh(); this.#fresh();
      }
      job = await openJobKeyDelivery(envelope, this.#key, expected, { clock: this.#clock, ageKeygen });
      if (this.#funding) await this.#funding.refresh();
      this.#fresh();
      if (this.#clock() >= job.deliveryExpiresAt) throw Error('Job-key release expired during guest funding inspection');
      this.#dispose('consumed'); return job;
    } catch (error) { job?.resultKey?.fill(0);this.close(); throw error; }
  }
  async prepare(envelope, expected, source, options = {}) {
    if (this.#execution) throw Error('Bound native sessions release keys only through execution readiness');
    expected = structuredClone(expected); source = structuredClone(source); options = structuredClone(options);
    if (this.#preparationAbort) throw Error('Guest workload preparation already in progress');
    const preparation = new AbortController(); this.#preparationAbort = preparation;
    try {
      const key = await this.#open(envelope, expected, options);
      const binding = Object.fromEntries(['packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256'].map(k => [k, expected.value[k].slice(2)]));
      for (const k of ['attempt', 'rank', 'worldSize']) binding[k] = expected.value[k];
      binding.acceleratorClass = this.#challenge.binding.acceleratorClass;
      const timeoutMs = this.#funding ? Math.min(options.timeoutMs ?? 600000, this.#funding.remainingMilliseconds()) : options.timeoutMs;
      const result = await prepareGuestWorkload(source, key, binding, { ...options, ...(timeoutMs === undefined ? {} : { timeoutMs }), signal: preparation.signal });
      this.#funding?.assertWindow();
      return result;
    } finally { this.#preparationAbort = undefined; }
  }
  async executeNative(envelope, expected) {
    this.#fresh();
    if (!this.#funding || !this.#execution) throw Error('Require a retained funded native execution profile');
    if (this.#preparationAbort) throw Error('Guest execution or preparation already in progress');
    const running = new AbortController(); this.#preparationAbort = running;
    let resultKey;
    try {
      expected = structuredClone(expected); this.#match(expected);
      if(!['2','3','4'].includes(expected.domain.version))throw Error('Native execution requires an approved confidential result channel');
      this.#funding.assertService(nativeServiceCommitment(this.#execution));
      const binding = Object.fromEntries(['packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256',
        'attempt', 'rank', 'worldSize', 'acceleratorClass'].map(k => [k, this.#challenge.binding[k]]));
      const result = await executeNativeGuest(this.#execution, binding, this.#funding.interval, async () => {
        if (running.signal.aborted) throw Error('Guest execution cancelled before key opening');
        const key = await this.#open(envelope, expected, { ageKeygen: path.join(path.dirname(this.#execution.source.age), 'age-keygen') });
        resultKey=key.resultKey;
        if (running.signal.aborted) throw Error('Guest execution cancelled during key opening');
        this.#funding.assertWindow(); return key;
      }, { timeoutMs: this.#funding.remainingMilliseconds(), signal: running.signal,dependency:this.#dependency });
      await this.#funding.refresh(); this.#funding.assertWindow();
      if (running.signal.aborted) throw Error('Guest execution cancelled before result acceptance');
      const resultEnvelope=await sealResultDelivery(result.receipt,resultKey,expected);
      this.#funding.assertWindow();
      if(running.signal.aborted)throw Error('Guest execution cancelled during result sealing');
      return Object.defineProperty({...result,resultEnvelope},'ciphertext',{value:result.ciphertext,enumerable:false});
    } catch (error) { this.close(); throw error; }
    finally { resultKey?.fill(0);this.#preparationAbort = undefined; }
  }
  #dispose(state) {
    clearTimeout(this.#timer); this.#abort.abort(); this.#key = undefined; this.#evidence = undefined; this.#state = state;
  }
  close() { this.#preparationAbort?.abort(); this.#funding?.close(); this.#dispose(this.#state === 'consumed' ? 'consumed' : 'closed'); }
}
