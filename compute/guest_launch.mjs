// Public launch configuration authenticated by authorities embedded in the image.
// Signature acceptance establishes authorization under those keys, not an audit.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { TypedDataEncoder, getAddress, verifyTypedData, ZeroAddress } from 'ethers';
import { validateGuestConfiguration } from './guest_configuration.mjs';
import { guestInitialization } from './guest_initialization.mjs';
import { validateAttestationPolicy } from './attestation.mjs';
import { GuestFunding } from './guest_funding.mjs';
import { nativeServiceCommitment } from './guest_execution.mjs';

const fail=()=>{throw Error('Guest launch configuration is not authorized');};
const exact=(v,keys)=>{if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).sort().join()!==keys.sort().join())fail();};
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const address=v=>{const a=getAddress(v);if(a===ZeroAddress)fail();return a;};
function canonical(value) {
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  if(typeof value==='number'&&!Number.isSafeInteger(value))fail();
  if(value===undefined)fail();return JSON.stringify(value);
}
const hash=value=>'0x'+createHash('sha256').update(canonical(value)).digest('hex');
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
export function readRetainedLaunch(authorities) {
  // The outer Python launcher checks all four kernel seals before passing this
  // fd. Authorization is still checked here; an inherited fd is never authority.
  const text=process.env.CANNABIS_LAUNCH_FD;
  if(process.platform!=='linux'||!text||!/^[1-9][0-9]{0,5}$/.test(text)||Number(text)<3)fail();
  const fd=Number(text),s=fs.fstatSync(fd);
  if(!s.isFile()||!integer(s.size,1,17*1024**2)||
    fs.readlinkSync(`/proc/self/fd/${fd}`)!=='/memfd:cannabis-public-launch (deleted)')fail();
  const bytes=Buffer.alloc(s.size);let offset=0;
  while(offset<bytes.length){const count=fs.readSync(fd,bytes,offset,bytes.length-offset,offset);if(!count)fail();offset+=count;}
  const value=parseLaunchSnapshot(bytes);
  // The operating entry has no legacy local-ledger fallback. Old configuration
  // parsing remains only for historical/offline component verification.
  if(value.signed?.configuration?.schema!=='cannabis.guest-launch-configuration.v3')fail();
  return prepareGuestLaunch(authorities,value.signed,value.initialization,value.request);
}
export function publicLaunchAdmission(launch) {
  if(launch.funding?.proof?.schema!=='cannabis.market-lease.v1'||launch.initialization?.schema!=='cannabis.guest-initialization.v2'||
    launch.initialization.binding.configurationSHA256!==launch.configurationSHA256)fail();
  const service=nativeServiceCommitment(launch.execution);
  return {schema:'cannabis.guest-launch-admission.v1',profile:launch.execution.profile,
    serviceSHA256:service.serviceSHA256,units:service.units,interval:launch.interval,transport:launch.transport,source:launch.execution.source};
}
export function validateLaunchAuthorities(input) {
  const a=structuredClone(input);
  exact(a,['schema','chainId','signers','threshold','maxValiditySeconds']);
  if(a.schema!=='cannabis.guest-launch-authorities.v1'||!integer(a.chainId,1,Number.MAX_SAFE_INTEGER)||
    !Array.isArray(a.signers)||!integer(a.signers.length,1,16)||!integer(a.threshold,1,a.signers.length)||
    !integer(a.maxValiditySeconds,1,365*86400))fail();
  a.signers=a.signers.map(address).sort();if(new Set(a.signers).size!==a.signers.length)fail();return a;
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
export const launchConfigurationTypes={GuestLaunchConfiguration:[
  {name:'configurationSHA256',type:'bytes32'},{name:'validFrom',type:'uint64'},{name:'validUntil',type:'uint64'}
]};
export function launchConfigurationPayload(authorities,configuration) {
  const a=validateLaunchAuthorities(authorities);
  const {configuration:c,configurationSHA256}=validateGuestConfiguration(configuration,{chainId:a.chainId,maxValiditySeconds:a.maxValiditySeconds});
  const domain={name:'Cannabis guest launch configuration',version:c.schema.slice(-1),chainId:a.chainId,salt:hash(a)};
  const value={configurationSHA256,validFrom:c.validFrom,validUntil:c.validUntil};
  return {domain,types:launchConfigurationTypes,value,digest:TypedDataEncoder.hash(domain,launchConfigurationTypes,value)};
}
export function verifyLaunchConfiguration(authorities,signed,now=Math.floor(Date.now()/1000)) {
  const a=validateLaunchAuthorities(authorities);signed=structuredClone(signed);exact(signed,['configuration','signatures']);
  const c=signed.configuration,payload=launchConfigurationPayload(a,c);
  if(!integer(now,c.validFrom,c.validUntil-1)||!Array.isArray(signed.signatures)||
    !integer(signed.signatures.length,a.threshold,a.signers.length))fail();
  const seen=new Set();
  for(const entry of signed.signatures) {
    exact(entry,['signer','signature']);const signer=address(entry.signer);
    if(seen.has(signer)||!a.signers.includes(signer)||typeof entry.signature!=='string'||
      verifyTypedData(payload.domain,payload.types,payload.value,entry.signature)!==signer)fail();seen.add(signer);
  }
  return {configuration:c,configurationSHA256:payload.value.configurationSHA256,authoritySHA256:hash(a)};
}
export function prepareGuestLaunch(authorities,signed,initialization,request,{now=Math.floor(Date.now()/1000)}={}) {
  const checked=verifyLaunchConfiguration(authorities,signed,now),c=checked.configuration;
  const retained=guestInitialization(initialization);request=structuredClone(request);exact(request,['proof','challenge']);
  if(c.schema!=='cannabis.guest-launch-configuration.v1'&&request.proof?.schema!=='cannabis.market-lease.v1')fail();
  const configured=c.schema==='cannabis.guest-launch-configuration.v3';
  if(retained.assignment.schema!==(configured?'cannabis.guest-initialization.v2':'cannabis.guest-initialization.v1')||
    configured&&retained.assignment.binding.configurationSHA256!==checked.configurationSHA256)fail();
  if(c.schema==='cannabis.guest-launch-configuration.v1'&&request.proof?.schema!=='cannabis.lease-proof.v1')fail();
  if(Buffer.byteLength(canonical(request))>16*1024*1024||retained.assignment.tee!==c.attestationPolicyTemplate.tee)fail();
  const policy=structuredClone(c.attestationPolicyTemplate);policy.measurements.initData=retained.digest;
  const digest=validateAttestationPolicy(policy),challenge=request.challenge;
  exact(challenge,['schema','nonce','issuedAt','expiresAt','attestationPolicySHA256','binding']);
  if(challenge.schema!=='cannabis.attestation.challenge.v1'||typeof challenge.nonce!=='string'||!/^[0-9a-f]{64}$/.test(challenge.nonce)||
    /^0+$/.test(challenge.nonce)||challenge.attestationPolicySHA256!==digest||canonical(challenge.binding)!==canonical(retained.assignment.binding)||
    !integer(challenge.issuedAt,c.validFrom,now)||!integer(challenge.expiresAt,now+1,Math.min(c.validUntil,challenge.issuedAt+policy.challengeTTLSeconds)))fail();
  const service=nativeServiceCommitment(c.execution);
  const funding={proof:request.proof,context:c.context,network:c.network,provider:c.provider,
    resourceId:c.resourceId,serviceSHA256:service.serviceSHA256};
  const inspected=new GuestFunding(funding,retained.assignment,{clock:()=>now});
  let interval;
  try{inspected.assertService(service);interval=inspected.interval;if(interval.start<c.validFrom||interval.end>c.validUntil)fail();}
  finally{inspected.close();}
  return {initialization:retained.assignment,policy,challenge,funding,execution:c.execution,bootstrap:c.bootstrap,
    interval,transport:{...c.transport,timeoutMs:Math.min(c.transport.timeoutMs,(interval.end-now)*1000)},
    configurationSHA256:checked.configurationSHA256,authoritySHA256:checked.authoritySHA256};
}
