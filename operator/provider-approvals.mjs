// Local, operator-controlled signatures for retained assignments. This module
// never holds wallet keys, sends transactions or admits protected execution.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TypedDataEncoder } from 'ethers';
import { launchConsentPayload,inspectLaunchConsent } from '../compute/guest_consent.mjs';
import { peerChannelPayload,inspectPeerChannel } from '../compute/peer_channel.mjs';
import { readMarketLeaseState } from '../compute/market_lease.mjs';

const check=v=>{if(!v)throw Error('Provider approval unavailable; review the retained assignment and request state');};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?
  '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const id=()=>randomBytes(32).toString('hex');
const idOK=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const sigOK=v=>typeof v==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(v);
const seconds=()=>Math.floor(Date.now()/1000);
const activeStates=new Set(['checking-funding','awaiting-wallet','checking-signature','submitted']);
const bindingKeys=['origin','channelBinding','requesterNonce','providerNonce','validFrom','validUntil'];
function readJSON(file,limit) {
  const stat=fs.lstatSync(file);check(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<=limit);
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW??0));
  try{const actual=fs.fstatSync(fd);check(actual.ino===stat.ino&&actual.dev===stat.dev&&actual.size<=limit);
    const bytes=Buffer.alloc(limit+1);let size=0,n;
    while(size<bytes.length&&(n=fs.readSync(fd,bytes,size,bytes.length-size,null))>0)size+=n;
    check(size<=limit);return JSON.parse(bytes.subarray(0,size).toString('utf8'));
  }finally{fs.closeSync(fd);}
}
export function readProviderCatalog(file) {check(path.isAbsolute(file));return readJSON(file,16*1024*1024);}
function privateDirectory(directory) {
  check(typeof directory==='string'&&path.isAbsolute(directory));
  const resolved=path.resolve(directory),real=fs.realpathSync.native(resolved);
  check((process.platform==='win32'?real.toLowerCase():real)===(process.platform==='win32'?resolved.toLowerCase():resolved));
  const stat=fs.lstatSync(real);check(stat.isDirectory()&&!stat.isSymbolicLink());
  return real;
}
function syncDirectory(directory) {
  // Windows directory fsync is unavailable. An interrupted write is never
  // repaired/overwritten automatically; subsequent startup fails closed.
  if(process.platform==='win32')return;
  const fd=fs.openSync(directory,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}

export class ProviderApprovals {
  #entries=new Map();#requests=new Map();#tasks=new Set();#directory;#clock;#closed=false;
  constructor(catalog,directory,{clock=seconds}={}) {
    exact(catalog,['schema','assignments']);check(catalog.schema==='cannabis.provider-catalog.v1'&&
      Buffer.byteLength(canonical(catalog))<=16*1024*1024&&Array.isArray(catalog.assignments)&&catalog.assignments.length<=64);
    check(typeof clock==='function');this.#clock=clock;this.#directory=privateDirectory(directory);
    for(const input of catalog.assignments) {
      exact(input,['configuration','initialization','proof','requesterConsent','origin']);
      const e=structuredClone(input),url=new URL(e.origin);
      check(url.protocol==='https:'&&url.origin===e.origin&&!url.username&&!url.password&&e.origin.length<=512);
      const p=launchConsentPayload(e.configuration,e.initialization,e.proof,'provider');
      const signed={schema:'cannabis.guest-launch-consent.v1',configuration:e.configuration,
        consents:[e.requesterConsent,{role:'provider',signer:p.signer,signature:'0x01'}]};
      const d=inspectLaunchConsent(signed,e.initialization,e.proof,p.value.validFrom);
      const key=p.value.assignmentSHA256.slice(2);check(!this.#entries.has(key));
      e.id=key;e.payload=p;e.description=d;e.signed=null;
      const savedDirectory=path.join(this.#directory,key);
      if(fs.existsSync(savedDirectory)) {
        privateDirectory(savedDirectory);
        const saved=readJSON(path.join(savedDirectory,'approval.json'),256*1024);
        inspectLaunchConsent(saved,e.initialization,e.proof,p.value.validFrom);
        check(canonical(saved.configuration)===canonical(e.configuration)&&canonical(saved.consents[0])===canonical(e.requesterConsent));
        e.signed=saved;
      }
      this.#entries.set(key,e);
    }
  }
  #entry(key){check(!this.#closed&&idOK(key)&&this.#entries.has(key));return this.#entries.get(key);}
  #request(key){check(!this.#closed&&idOK(key)&&this.#requests.has(key));const r=this.#requests.get(key);this.#expire(r);return r;}
  #expire(r) {if(activeStates.has(r.state)&&(performance.now()>=r.deadline||this.#clock()>=r.until||r.external?.aborted))
    this.#finish(r,'expired');}
  #finish(r,state) {
    if(!activeStates.has(r.state))return;
    r.state=state;r.completedAt=Date.now();clearTimeout(r.timer);r.external?.removeEventListener('abort',r.abort);
    r.controller.abort();r.reject?.(Error('Provider approval ended'));r.resolve=r.reject=undefined;
  }
  #new(e,kind,timeoutMs,external) {
    check(!this.#closed&&Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=60000&&
      (!external||external instanceof AbortSignal)&&!external?.aborted);
    for(const r of this.#requests.values())this.#expire(r);
    const pending=[...this.#requests.values()].filter(r=>activeStates.has(r.state));
    check(pending.length<4&&!pending.some(r=>r.assignmentId===e.id&&r.kind===kind));
    while(this.#requests.size>=36){const old=[...this.#requests.values()].find(r=>!activeStates.has(r.state));check(old);this.#requests.delete(old.id);}
    const now=this.#clock();check(Number.isSafeInteger(now)&&now<e.payload.value.validUntil);
    const duration=Math.min(timeoutMs,(e.payload.value.validUntil-now)*1000);
    const r={id:id(),assignmentId:e.id,kind,state:'checking-funding',createdAt:Date.now(),expiresAt:Date.now()+duration,
      deadline:performance.now()+duration,until:e.payload.value.validUntil,controller:new AbortController(),external};
    r.abort=()=>this.#finish(r,'cancelled');external?.addEventListener('abort',r.abort,{once:true});
    r.timer=setTimeout(()=>this.#finish(r,'expired'),duration);r.timer.unref();this.#requests.set(r.id,r);return r;
  }
  #active(r,state) {this.#expire(r);check(!this.#closed&&r.state===state&&!r.controller.signal.aborted);}
  #track(r,action) {
    const task=Promise.resolve().then(action).catch(()=>this.#finish(r,'failed')).finally(()=>this.#tasks.delete(task));
    this.#tasks.add(task);
  }
  #runtime(r) {this.#expire(r);check(activeStates.has(r.state));return {
    timeoutMs:Math.max(1,Math.floor(r.deadline-performance.now())),signal:r.controller.signal};}
  #clockFor(r) {
    let previous=this.#clock();return ()=>{this.#expire(r);const now=this.#clock();check(activeStates.has(r.state)&&
      Number.isSafeInteger(now)&&now>=previous&&now<r.until);previous=now;return now;};
  }
  #publicRequest(r) {return {id:r.id,assignmentId:r.assignmentId,kind:r.kind,state:r.state,
    createdAt:r.createdAt,expiresAt:r.expiresAt,...(r.completedAt?{completedAt:r.completedAt}:{})};}
  snapshot() {
    check(!this.#closed);for(const r of this.#requests.values())this.#expire(r);
    return {state:'available',assignments:[...this.#entries.values()].map(e=>({id:e.id,provider:e.payload.signer,
      requester:e.payload.value.requester,bookingId:e.payload.value.bookingId,chainId:e.configuration.network.chainId,
      validFrom:e.payload.value.validFrom,validUntil:e.payload.value.validUntil,consentRetained:Boolean(e.signed)})),
      requests:[...this.#requests.values()].map(r=>this.#publicRequest(r)),executionAuthorized:false,keyReleaseAuthorized:false};
  }
  detail(key) {
    const r=this.#request(key),e=this.#entry(r.assignmentId);check(r.state==='awaiting-wallet');
    const d=e.description,c=e.configuration;
    return {...this.#publicRequest(r),signer:r.payload.signer,genesisHash:c.network.genesisHash,
      digest:r.payload.digest,typedData:TypedDataEncoder.getPayload(r.payload.domain,r.payload.types,r.payload.value),
      summary:{origin:e.origin,escrow:d.lease.escrow,token:c.network.token,resourceId:d.reservation.resourceId,
        serviceSHA256:d.reservation.serviceSHA256,runtimeSHA256:e.initialization.binding.runtimeSHA256,
        taskSHA256:e.initialization.binding.taskSHA256,attempt:e.initialization.binding.attempt,rank:e.initialization.binding.rank,
        worldSize:e.initialization.binding.worldSize,units:d.reservation.units,grossBaseUnits:d.reservation.grossBaseUnits,
        workerBaseUnits:(BigInt(d.reservation.grossBaseUnits)*99n/100n).toString(),
        serviceFeeBaseUnits:(BigInt(d.reservation.grossBaseUnits)/100n).toString()},
      executionAuthorized:false,keyReleaseAuthorized:false};
  }
  beginLaunch(key) {
    const e=this.#entry(key);check(!e.signed&&!fs.existsSync(path.join(this.#directory,key)));
    const r=this.#new(e,'launch',60000);
    this.#track(r,async()=>{
      this.#active(r,'checking-funding');
      await readMarketLeaseState(e.proof,e.configuration.network,this.#clockFor(r),{},this.#runtime(r));
      this.#active(r,'checking-funding');r.payload=e.payload;r.state='awaiting-wallet';
    });return {requestId:r.id};
  }
  submit(key,signature) {
    const r=this.#request(key);this.#active(r,'awaiting-wallet');check(sigOK(signature));
    if(r.kind==='peer'){r.state='submitted';r.resolve(signature);r.resolve=r.reject=undefined;return {state:r.state};}
    r.state='checking-signature';const e=this.#entry(r.assignmentId);
    this.#track(r,async()=>{
      this.#active(r,'checking-signature');
      const signed={schema:'cannabis.guest-launch-consent.v1',configuration:structuredClone(e.configuration),
        consents:[structuredClone(e.requesterConsent),{role:'provider',signer:e.payload.signer,signature}]};
      const d=inspectLaunchConsent(signed,e.initialization,e.proof,e.payload.value.validFrom);
      await readMarketLeaseState(e.proof,e.configuration.network,this.#clockFor(r),{launchApprovals:d.approvals},this.#runtime(r));
      this.#active(r,'checking-signature');
      const directory=path.join(this.#directory,e.id);fs.mkdirSync(directory,{mode:0o700});syncDirectory(this.#directory);
      const fd=fs.openSync(path.join(directory,'approval.json'),'wx',0o600);
      try{fs.writeFileSync(fd,JSON.stringify(signed)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
      syncDirectory(directory);e.signed=signed;this.#finish(r,'consent-retained');
    });return {state:r.state};
  }
  decline(key) {const r=this.#request(key);check(activeStates.has(r.state));this.#finish(r,'declined');return {state:r.state};}
  signed(key) {const e=this.#entry(key);check(e.signed);return structuredClone(e.signed);}
  peerRoute(key,handle) {
    const e=this.#entry(key),signed=this.signed(key);check(typeof handle==='function');
    return {signed,initialization:structuredClone(e.initialization),proof:structuredClone(e.proof),
      signApproval:(candidate,{signal,timeoutMs}={})=>{
        check(candidate&&candidate.value?.origin===e.origin);
        const binding=Object.fromEntries(bindingKeys.map(k=>[k,candidate.value[k]]));
        const p=peerChannelPayload(signed,e.initialization,e.proof,binding,'provider',this.#clock());
        check(['domain','types','value','digest','signer'].every(k=>canonical(candidate[k])===canonical(p[k])));
        const r=this.#new(e,'peer',timeoutMs,signal);r.until=Math.min(r.until,p.value.validUntil);
        r.expiresAt=Math.min(r.expiresAt,Date.now()+(r.until-this.#clock())*1000);
        r.payload=p;r.state='awaiting-wallet';
        return new Promise((resolve,reject)=>{r.resolve=resolve;r.reject=reject;});
      },
      handle:async(channel,context)=>{
        const binding=inspectPeerChannel(channel,'provider',signed,e.initialization,e.proof);
        const p=peerChannelPayload(signed,e.initialization,e.proof,binding,'provider',this.#clock());
        const r=[...this.#requests.values()].find(r=>r.assignmentId===key&&r.kind==='peer'&&r.payload?.digest===p.digest&&r.state==='submitted');
        check(r);this.#active(r,'submitted');this.#finish(r,'channel-verified');
        return handle(channel,context);
      }};
  }
  async close() {if(this.#closed)return;this.#closed=true;for(const r of this.#requests.values())this.#finish(r,'cancelled');
    await Promise.allSettled([...this.#tasks]);}
}
