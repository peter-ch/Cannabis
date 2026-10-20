// Ordinary-host session transport. The caller supplies the retained result of
// prepareGuestLaunch; the measured guest and requester still perform admission.
// Never expose this module as a raw caller-selected launch/configuration API.
import { createHash,createPublicKey } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TypedDataEncoder,verifyTypedData,getAddress } from 'ethers';
import { calculateJwkThumbprint } from 'jose';
import { guestInitialization } from '../compute/guest_initialization.mjs';
import { trusteeEvidenceRequest } from '../compute/attestation.mjs';
import { deliveryApprovalTypes } from '../compute/key_delivery.mjs';
import { validateRelayAccess } from '../web/work-relay.js';
import { validateUploadAccess } from './result-upload.mjs';
import { bridgeEncryptedResult } from './result-bridge.mjs';
import { claimPeerChannel } from '../compute/peer_channel.mjs';
import { assertResultSpool } from './result-spool.mjs';
import { assertPhysicalResultSpool } from './physical-spool.mjs';
const protocol='cannabis.guest-wire.v1',CHUNK=65536;
const integer=(n,min,max)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const fields=(v,n)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===n.sort().join();
const check=v=>{if(!v)throw Error('Configured encrypted session relay failed');};
const hash=v=>createHash('sha256').update(v).digest('hex');
function canonical(v) {
  if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
  if(v&&typeof v==='object')return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
  return JSON.stringify(v);
}
function abortable(fn,signal) {
  return new Promise((resolve,reject)=>{
    const abort=()=>reject(Error('Cancelled'));if(signal.aborted)return abort();
    signal.addEventListener('abort',abort,{once:true});
    Promise.resolve().then(()=>{check(!signal.aborted);return fn();}).then(resolve,reject)
      .finally(()=>signal.removeEventListener('abort',abort));
  });
}
// Network-facing adapters use this entry with a locally retained prepared launch
// and a provider-side authenticated requester channel. Guest admission remains
// the responsibility of the sealed launcher and requester evidence appraisal.
export async function relayAuthenticatedSession(guest,requester,options={}) {
  try {
    assertPhysicalResultSpool(options.spool);
    const launch=structuredClone(options.launch);
    claimPeerChannel(requester,'provider',launch.funding.consent,launch.initialization,launch.funding.proof);
    return await relayConfiguredSession(guest,requester,{...options,launch});
  } catch(error) {guest?.fail?.();requester?.fail?.();requester?.close?.();throw error;}
  // The owning listener closes the peer after its handler finishes guest
  // termination. Closing it here would cancel the bound boot socket while the
  // guest is still retiring its acknowledged result and protected resources.
}
export async function relayConfiguredSession(guest,requester,{launch,origin,spool,reserveResult,signal,
  fetchImpl=globalThis.fetch,wait}={}) {
  const controller=new AbortController(),listeners=[];let timer,reservation;
  const stop=()=>{if(controller.signal.aborted)return;controller.abort();guest.fail();requester.fail();};
  try {
    check(typeof reserveResult==='function'&&(!signal||signal instanceof AbortSignal));
    assertResultSpool(spool);
    launch=structuredClone(launch);
    const assignment=guestInitialization(launch.initialization).assignment,b=assignment.binding,challenge=launch.challenge;
    check(canonical(challenge.binding)===canonical(b)&&fields(launch.interval,['start','end'])&&
      integer(launch.interval.start,1,Number.MAX_SAFE_INTEGER)&&integer(launch.interval.end,launch.interval.start+1,Number.MAX_SAFE_INTEGER)&&
      fields(launch.transport,['timeoutMs','maxCiphertextBytes'])&&integer(launch.transport.timeoutMs,1,3600000)&&
      integer(launch.transport.maxCiphertextBytes,1,64*1024*1024));
    const inputLimit=launch.execution.profile.ciphertext.inputBytes;
    check(integer(inputLimit,1,1024**4)&&launch.transport.maxCiphertextBytes<=launch.execution.profile.ciphertext.outputBytes);
    const wall=Date.now(),started=performance.now(),end=Math.min(launch.interval.end*1000,wall+launch.transport.timeoutMs);
    const remaining=()=>Math.floor(Math.min(end-Date.now(),launch.transport.timeoutMs-(performance.now()-started)));
    const active=()=>{
      guest.assertActive();requester.assertActive();
      check(!controller.signal.aborted&&Date.now()>=wall&&Date.now()>=launch.interval.start*1000&&remaining()>0);
    };
    for(const s of [guest.signal,requester.signal,signal].filter(Boolean)) {
      check(!s.aborted);s.addEventListener('abort',stop,{once:true});listeners.push(s);
    }
    active();timer=setTimeout(stop,remaining());
    // Relay encrypted input without spooling it on the operator. The exact
    // frame size also bounds framing overhead and enforces backpressure.
    const inputs=[{digest:b.packageSHA256,limit:inputLimit}];
    let inputCiphertextBytes=0,dependencyCiphertextBytes=0;
    if(launch.dependency)inputs.push({digest:launch.dependency.signed.handoff.ciphertextSHA256,
      limit:launch.execution.profile.ciphertext.dependencyBytes,bytes:launch.dependency.signed.handoff.ciphertextBytes});
    for(const incoming of inputs) {
      check(integer(incoming.limit,1,1024**4));
      const ready=await guest.readJSON(1024);active();
      check(fields(ready,['protocol','operation','packageSHA256','maxCiphertextBytes'])&&ready.protocol===protocol&&
        ready.operation==='input-ready'&&ready.packageSHA256===incoming.digest&&ready.maxCiphertextBytes===incoming.limit);
      await requester.writeJSON(ready);
      const input=await requester.readJSON(1024);active();
      check(fields(input,['protocol','operation','packageSHA256','ciphertextBytes'])&&input.protocol===protocol&&
        input.operation==='input'&&input.packageSHA256===incoming.digest&&integer(input.ciphertextBytes,1,incoming.limit)&&
        (incoming.bytes===undefined||input.ciphertextBytes===incoming.bytes));
      await guest.writeJSON(input);
      const whole=createHash('sha256');let count=0;
      while(count<input.ciphertextBytes) {
        const chunk=await requester.readChunk();active();check(chunk.length===Math.min(CHUNK,input.ciphertextBytes-count));
        whole.update(chunk);await guest.writeChunk(chunk);count+=chunk.length;
      }
      const inputEnd=await requester.readJSON(1024);active();
      check(fields(inputEnd,['protocol','operation','packageSHA256'])&&inputEnd.protocol===protocol&&inputEnd.operation==='input-end'&&
        inputEnd.packageSHA256===incoming.digest&&whole.digest('hex')===incoming.digest);
      await guest.writeJSON(inputEnd);
      const stored=await guest.readJSON(1024);active();
      check(fields(stored,['protocol','operation','packageSHA256','ciphertextBytes'])&&stored.protocol===protocol&&stored.operation==='input-stored'&&
        stored.packageSHA256===incoming.digest&&stored.ciphertextBytes===count);
      await requester.writeJSON(stored);
      if(incoming===inputs[0])inputCiphertextBytes=count;else dependencyCiphertextBytes=count;
    }
    const evidence=await guest.readJSON(5*1024*1024);active();
    check(fields(evidence,['protocol','operation','evidence'])&&evidence.protocol===protocol&&evidence.operation==='evidence');
    const e=evidence.evidence;
    check(fields(e,['schema','nonce','channelJwk','evidence','agent','evidenceSHA256','hardwareVerified','executionAuthorized'])&&
      e.schema==='cannabis.guest-evidence.v1'&&e.nonce===challenge.nonce&&e.hardwareVerified===false&&e.executionAuthorized===false);
    // Format/binding checks are not hardware appraisal. The requester must still
    // verify the evidence with the configured verifier before wrapping any key.
    trusteeEvidenceRequest(launch.policy,challenge,e.channelJwk,e.evidence);
    check(hash(Buffer.from(e.evidence,'base64url'))===e.evidenceSHA256);
    await requester.writeJSON(evidence);
    const command=await requester.readJSON(128*1024);active();
    check(fields(command,['protocol','operation','envelope','expected'])&&command.protocol===protocol&&command.operation==='execute'&&
      typeof command.envelope==='string'&&command.envelope.length<=32768&&
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(command.envelope));
    const expected=command.expected,v=expected?.value,d=expected?.domain,types=deliveryApprovalTypes(d?.version);
    check(fields(d,['name','version','chainId','verifyingContract'])&&d.name==='Cannabis confidential key delivery'&&['2','3','4'].includes(d.version)&&
      d.chainId===b.chainId&&getAddress(d.verifyingContract)===b.escrow&&expected.requester===assignment.requester&&expected.jobId===assignment.jobId&&
      fields(v,types.JobKeyDelivery.map(x=>x.name)));
    check((['3','4'].includes(d.version))===Object.hasOwn(b,'configurationSHA256')&&
      (!['3','4'].includes(d.version)||v.configurationSHA256===b.configurationSHA256));
    check((d.version==='4')===!!launch.dependency&&(!launch.dependency||v.dependencyApprovalDigest===launch.dependency.approvalDigest));
    for(const k of ['orderId','leaseDigest','reservationId','attempt','rank','worldSize'])check(v[k]===b[k]);
    for(const k of ['packageSHA256','policySHA256','runtimeSHA256','taskSHA256'])check(v[k]==='0x'+b[k]);
    check(v.nonce==='0x'+challenge.nonce&&v.attestationPolicySHA256==='0x'+challenge.attestationPolicySHA256&&
      v.channelKeySHA256==='0x'+hash(canonical(e.channelJwk))&&
      expected.digest===TypedDataEncoder.hash(d,types,v)&&verifyTypedData(d,types,v,expected.requesterSignature)===assignment.requester);
    const headerText=command.envelope.split('.')[0];check(headerText.length<=4096);
    const headerBytes=Buffer.from(headerText,'base64url');check(headerBytes.toString('base64url')===headerText);
    const header=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(headerBytes));
    check(fields(header,['alg','enc','typ','kid','cannabis-approval','epk'])&&header.alg==='ECDH-ES+A256KW'&&header.enc==='A256GCM'&&
      header.typ==='cannabis-job-key+jwe'&&header['cannabis-approval']===expected.digest&&header.kid===await calculateJwkThumbprint(e.channelJwk));
    check(fields(header.epk,['crv','kty','x','y'])&&header.epk.kty==='EC'&&header.epk.crv==='P-256');
    for(const coordinate of [header.epk.x,header.epk.y])check(typeof coordinate==='string'&&
      /^[A-Za-z0-9_-]{43}$/.test(coordinate)&&Buffer.from(coordinate,'base64url').toString('base64url')===coordinate);
    check(createPublicKey({key:header.epk,format:'jwk'}).asymmetricKeyDetails?.namedCurve==='prime256v1');
    const fresh=()=>{
      active();const now=Math.floor(Date.now()/1000);
      check(integer(v.notBefore,Math.max(launch.interval.start,challenge.issuedAt),now)&&
        integer(v.expiresAt,now+1,Math.min(launch.interval.end,challenge.expiresAt)));
    };
    fresh();
    // Local and remote storage are independent. Commit aggregate local capacity
    // before contacting the chosen relay or forwarding the sealed command.
    reservation=spool.reserve({expected,maxCiphertextBytes:launch.transport.maxCiphertextBytes,serviceEnd:launch.interval.end},controller.signal);
    // A late remote callback can leave an expiring remote reservation but cannot
    // revive the cancelled local reservation or forward execution.
    const provision=await abortable(()=>reserveResult({approvalDigest:expected.digest,
      maxCiphertextBytes:launch.transport.maxCiphertextBytes,serviceEnd:launch.interval.end},controller.signal),controller.signal);
    fresh();check(fields(provision,['upload','read']));
    const upload=validateUploadAccess(provision.upload,origin),[read]=validateRelayAccess([provision.read],origin,[{approvalDigest:expected.digest}]);
    check(upload.approvalDigest===expected.digest&&upload.id===read.id&&upload.expiresAt===read.expiresAt&&
      upload.token!==read.token&&Date.now()<upload.expiresAt);
    await requester.writeJSON({protocol:'cannabis.hosted-session.v1',operation:'result-access',approvalDigest:expected.digest,access:read});
    // The requester must validate receipt of its read grant before the sealed
    // command reaches the guest. This is readiness, never a payment or key grant.
    const accepted=await requester.readJSON(1024);fresh();
    check(fields(accepted,['protocol','operation','approvalDigest','relayId'])&&accepted.protocol==='cannabis.hosted-session.v1'&&
      accepted.operation==='result-access-ready'&&accepted.approvalDigest===expected.digest&&accepted.relayId===read.id);
    spool.dispatch(reservation); // durable uncertainty BEFORE any execution bytes
    fresh(); // native storage inspection may consume the remaining service time
    await guest.writeJSON(command);active();
    const result=await bridgeEncryptedResult(guest,requester,{expected,access:upload,origin,reservation,
      maxCiphertextBytes:launch.transport.maxCiphertextBytes,timeoutMs:remaining(),signal:controller.signal,fetchImpl,wait});
    active();return {...result,schema:'cannabis.session-relay-report.v1',inputCiphertextBytes,
      ...(launch.dependency?{dependencyCiphertextBytes}:{}),
      evidenceForwarded:true,executionRequestForwarded:true,hardwareValidated:false};
  } catch(error) {
    stop();const failure=Error('Configured encrypted session relay failed; retain complete ciphertext and requester recovery material');
    if(error?.recoveryDirectory)Object.defineProperty(failure,'recoveryDirectory',{value:error.recoveryDirectory,enumerable:false});
    throw failure;
  } finally {
    clearTimeout(timer);for(const s of listeners)s.removeEventListener('abort',stop);
    if(reservation)spool.cancelUnused(reservation);
  }
}
