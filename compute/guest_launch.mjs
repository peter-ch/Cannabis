// Public launch configuration authenticated by authorities embedded in the image.
// Signature acceptance establishes authorization under those keys, not an audit.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { TypedDataEncoder, getAddress, verifyTypedData, ZeroAddress } from 'ethers';
import { guestInitialization } from './guest_initialization.mjs';
import { validateAttestationPolicy } from './attestation.mjs';
import { GuestFunding } from './guest_funding.mjs';
import { nativeServiceCommitment } from './guest_execution.mjs';

const fail=()=>{throw Error('Guest launch configuration is not authorized');};
const exact=(v,keys)=>{if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).sort().join()!==keys.sort().join())fail();};
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const bytes32=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const address=v=>{const a=getAddress(v);if(a===ZeroAddress)fail();return a;};
function canonical(value) {
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  if(typeof value==='number'&&!Number.isSafeInteger(value))fail();
  if(value===undefined)fail();return JSON.stringify(value);
}
const hash=value=>'0x'+createHash('sha256').update(canonical(value)).digest('hex');
export const encodeLaunchJSON=value=>canonical(value)+'\n';
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
  const a=validateLaunchAuthorities(authorities),c=structuredClone(configuration);
  exact(c,['schema','configurationId','validFrom','validUntil','context','network','provider','resourceId',
    'execution','attestationPolicyTemplate','bootstrap','transport']);
  if(Buffer.byteLength(canonical(c))>256*1024||c.schema!=='cannabis.guest-launch-configuration.v1'||!bytes32(c.configurationId)||
    !integer(c.validFrom,1,Number.MAX_SAFE_INTEGER)||!integer(c.validUntil,c.validFrom+1,c.validFrom+a.maxValiditySeconds))fail();
  exact(c.context,['chainId','registryId','token']);
  if(c.context.chainId!==a.chainId||!bytes32(c.context.registryId))fail();getAddress(c.context.token);
  const n=c.network;exact(n,['rpc','chainId','token','escrow','genesisHash','escrowCodeHash','tokenCodeHash',
    'finality','maxFinalizedAgeSeconds','maxHeadAgeSeconds']);
  const rpc=new URL(n.rpc);
  if(rpc.username||rpc.password||rpc.search||rpc.hash||rpc.protocol!=='https:'&&!(rpc.protocol==='http:'&&rpc.hostname==='127.0.0.1')||
    n.chainId!==a.chainId||getAddress(n.token)!==getAddress(c.context.token)||n.finality!=='rpc-finalized'||
    !integer(n.maxFinalizedAgeSeconds,1,7200)||!integer(n.maxHeadAgeSeconds,1,120)||
    !bytes32(n.genesisHash)||!bytes32(n.escrowCodeHash)||
    (getAddress(n.token)===ZeroAddress?n.tokenCodeHash!==null:!bytes32(n.tokenCodeHash)))fail();
  address(n.escrow);address(c.provider);if(!bytes32(c.resourceId))fail();
  nativeServiceCommitment(c.execution);
  const profile=c.execution.profile;
  exact(profile,['schema','units','runtime','resources','total','control','helper','processLimit','scratchInodes','staging','maxInputBytes','tools']);
  exact(profile.runtime,['adapter','architecture','os','digestSHA256']);
  exact(profile.resources,['cpus','memoryMiB','scratchMiB','wallSeconds','nodes']);
  exact(profile.total,['cpu_millis','memory_bytes','processes','wall_seconds','children']);
  for(const name of ['control','helper'])exact(profile[name],['cpu_millis','memory_bytes','processes','wall_seconds']);
  exact(profile.staging,['bytes','inodes']);exact(profile.tools,['pythonSHA256','ageSHA256','ageKeygenSHA256']);
  for(const value of [...Object.values(profile.resources),...Object.values(profile.total),...Object.values(profile.control),
    ...Object.values(profile.helper),...Object.values(profile.staging),profile.processLimit,profile.scratchInodes])
    if(!integer(value,1,Number.MAX_SAFE_INTEGER))fail();
  if(!integer(profile.maxInputBytes,0,profile.staging.bytes)||
    Object.values(profile.tools).some(v=>typeof v!=='string'||!/^[0-9a-f]{64}$/.test(v))||
    typeof profile.runtime.digestSHA256!=='string'||!/^[0-9a-f]{64}$/.test(profile.runtime.digestSHA256)||
    Object.values(profile.runtime).some(v=>typeof v!=='string'||!/^[A-Za-z0-9_.-]{1,128}$/.test(v)))fail();
  for(const file of Object.values(c.execution.source))if(!path.posix.isAbsolute(file)||file.includes('\\')||file.includes('\0')||file.split('/').includes('..'))fail();
  const b=c.bootstrap;exact(b,['agentBinary','bridgeBinary','runtimeDirectory','port']);
  for(const field of ['agentBinary','bridgeBinary','runtimeDirectory'])if(typeof b[field]!=='string'||!path.posix.isAbsolute(b[field])||b[field].includes('\\')||b[field].includes('\0')||b[field].split('/').includes('..'))fail();
  if(!integer(b.port,1024,65535))fail();
  exact(c.transport,['timeoutMs','maxCiphertextBytes']);
  if(!integer(c.transport.timeoutMs,1,3600000)||!integer(c.transport.maxCiphertextBytes,1,1024**4))fail();
  const p=structuredClone(c.attestationPolicyTemplate);
  // The assignment digest is derived locally after reading the retained canonical
  // assignment. Everything else, including the image measurement, is signed.
  if(p?.measurements?.initData!==null)fail();
  p.measurements.initData='11'.repeat(p.tee==='snp'?32:48);validateAttestationPolicy(p);
  const domain={name:'Cannabis guest launch configuration',version:'1',chainId:a.chainId,salt:hash(a)};
  const value={configurationSHA256:hash(c),validFrom:c.validFrom,validUntil:c.validUntil};
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
