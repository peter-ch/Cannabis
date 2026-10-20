// Booked launch authorized by its requester/provider and fresh canonical state.
// Consent is not hardware admission or an independent security review.
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { inspectLaunchConsent } from './guest_consent.mjs';
import { guestInitialization } from './guest_initialization.mjs';
import { validateAttestationPolicy } from './attestation.mjs';
import { GuestFunding } from './guest_funding.mjs';
import { nativeServiceCommitment } from './guest_execution.mjs';
import { inspectGuestDependency } from './guest_dependency.mjs';

const fail=()=>{throw Error('Guest launch configuration is not authorized');};
const exact=(v,keys)=>{if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).sort().join()!==keys.sort().join())fail();};
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
function canonical(value) {
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  if(typeof value==='number'&&!Number.isSafeInteger(value))fail();
  if(value===undefined)fail();return JSON.stringify(value);
}
export const encodeLaunchJSON=value=>canonical(value)+'\n';
function parseLaunchJSON(text,limit) {
  if(typeof text!=='string'||Buffer.byteLength(text)>limit)fail();
  const value=JSON.parse(text);
  if(text!==encodeLaunchJSON(value))fail();
  return value;
}
export function parseLaunchSnapshot(bytes) {
  if(!Buffer.isBuffer(bytes)||!integer(bytes.length,1,17*1024**2))fail();
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),snapshot=JSON.parse(text);
  if(text!==canonical(snapshot))fail();
  exact(snapshot,['configuration','initialization','request']);
  return {signed:parseLaunchJSON(snapshot.configuration,256*1024),
    initialization:parseLaunchJSON(snapshot.initialization,65536),request:parseLaunchJSON(snapshot.request,16*1024**2)};
}
export async function readRetainedLaunch() {
  // The outer Python launcher checks all four kernel seals before passing this
  // fd. Authorization is still checked here; an inherited fd is never authority.
  const text=process.env.CANNABIS_LAUNCH_FD;
  if(arguments.length!==0||process.platform!=='linux'||!text||!/^[1-9][0-9]{0,5}$/.test(text)||Number(text)<3)fail();
  const fd=Number(text),s=fs.fstatSync(fd);
  if(!s.isFile()||!integer(s.size,1,17*1024**2)||
    fs.readlinkSync(`/proc/self/fd/${fd}`)!=='/memfd:cannabis-public-launch (deleted)')fail();
  const bytes=Buffer.alloc(s.size);let offset=0;
  while(offset<bytes.length){const count=fs.readSync(fd,bytes,offset,bytes.length-offset,offset);if(!count)fail();offset+=count;}
  const value=parseLaunchSnapshot(bytes);
  // No global-authority or legacy local-ledger fallback in the operating entry.
  if(value.signed?.schema!=='cannabis.guest-launch-consent.v1'||
    value.signed.configuration?.schema!=='cannabis.guest-launch-configuration.v3')fail();
  return prepareGuestLaunch(value.signed,value.initialization,value.request);
}
export function publicLaunchAdmission(launch) {
  if(!['cannabis.market-lease.v1','cannabis.market-lease.v2'].includes(launch.funding?.proof?.schema)||launch.initialization?.schema!=='cannabis.guest-initialization.v2'||
    launch.initialization.binding.configurationSHA256!==launch.configurationSHA256||
    launch.funding.consent?.schema!=='cannabis.guest-launch-consent.v1')fail();
  const service=nativeServiceCommitment(launch.execution);
  return {schema:'cannabis.guest-launch-admission.v1',profile:launch.execution.profile,
    serviceSHA256:service.serviceSHA256,units:service.units,interval:launch.interval,transport:launch.transport,source:launch.execution.source};
}
export function readLaunchJSON(file,{limit=256*1024,trusted=false}={}) {
  if(!integer(limit,1,16*1024*1024)||typeof file!=='string'||!path.isAbsolute(file))fail();
  if(trusted) {
    if(process.platform!=='linux')fail();
    for(let directory=path.dirname(file);;directory=path.dirname(directory)) {
      const s=fs.lstatSync(directory);if(!s.isDirectory()||s.uid!==0||s.mode&0o022)fail();if(directory===path.dirname(directory))break;
    }
  }
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try {
    const s=fs.fstatSync(fd);if(!s.isFile()||!integer(s.size,1,limit)||trusted&&(s.uid!==0||s.mode&0o022))fail();
    const data=Buffer.alloc(s.size+1);let length=0;
    while(length<data.length){const count=fs.readSync(fd,data,length,data.length-length,null);if(!count)break;length+=count;}
    if(length!==s.size)fail();const text=new TextDecoder('utf-8',{fatal:true}).decode(data.subarray(0,length));
    const value=JSON.parse(text);
    // A single canonical representation also refuses duplicate JSON keys.
    if(text!==canonical(value)+'\n')fail();return value;
  }finally{fs.closeSync(fd);}
}
export async function prepareGuestLaunch(signed,initialization,request,{clock=()=>Math.floor(Date.now()/1000)}={}) {
  const started=performance.now(),now=clock();
  signed=structuredClone(signed);request=structuredClone(request);
  exact(request,['proof','challenge',...(Object.hasOwn(request??{},'dependency')?['dependency']:[])]);
  const checked=inspectLaunchConsent(signed,initialization,request.proof,now),c=checked.configuration;
  const retained=guestInitialization(initialization);
  const dependency=inspectGuestDependency({proof:request.proof,network:c.network,binding:retained.assignment.binding,
    execution:c.execution,dependency:request.dependency,now});
  if(Buffer.byteLength(canonical(request))>16*1024*1024||retained.assignment.tee!==c.attestationPolicyTemplate.tee)fail();
  const policy=structuredClone(c.attestationPolicyTemplate);policy.measurements.initData=retained.digest;
  const digest=validateAttestationPolicy(policy),challenge=request.challenge;
  exact(challenge,['schema','nonce','issuedAt','expiresAt','attestationPolicySHA256','binding']);
  if(challenge.schema!=='cannabis.attestation.challenge.v1'||typeof challenge.nonce!=='string'||!/^[0-9a-f]{64}$/.test(challenge.nonce)||
    /^0+$/.test(challenge.nonce)||challenge.attestationPolicySHA256!==digest||canonical(challenge.binding)!==canonical(retained.assignment.binding)||
    !integer(challenge.issuedAt,c.validFrom,now)||!integer(challenge.expiresAt,now+1,Math.min(c.validUntil,challenge.issuedAt+policy.challengeTTLSeconds)))fail();
  const service=nativeServiceCommitment(c.execution);
  const funding={proof:request.proof,context:c.context,network:c.network,provider:c.provider,
    resourceId:c.resourceId,serviceSHA256:service.serviceSHA256,consent:signed};
  let last=now;
  const activeClock=()=>{
    const current=clock();
    if(!integer(current,last,challenge.expiresAt-1)||performance.now()-started>=c.transport.timeoutMs)fail();
    last=current;return current;
  };
  const inspected=new GuestFunding(funding,retained.assignment,{clock:activeClock});
  let interval;
  try{
    inspected.assertService(service);interval=inspected.interval;
    if(interval.start<c.validFrom||interval.end>c.validUntil)fail();
    await inspected.refresh();activeClock();
  }
  finally{inspected.close();}
  // This is a total budget from entry, not a fresh allowance after RPC work.
  // Fixed JS entries and the outer Python authorizer start their clocks before
  // awaiting this function and charge all elapsed authorization time to it.
  return {initialization:retained.assignment,policy,challenge,funding,execution:c.execution,bootstrap:c.bootstrap,
    interval,transport:{...c.transport,timeoutMs:Math.min(c.transport.timeoutMs,(interval.end-now)*1000)},
    configurationSHA256:checked.configurationSHA256,...(dependency?{dependency}: {})};
}
