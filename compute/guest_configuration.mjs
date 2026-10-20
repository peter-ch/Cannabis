// Public configuration validation only. A matching hash is not launch consent,
// trusted hardware, an independently expected measurement or permission to run.
import path from 'node:path';
import { createHash } from 'node:crypto';
import { getAddress, ZeroAddress } from 'ethers';
import { validateAttestationPolicy } from './attestation.mjs';
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
export function validateGuestConfiguration(configuration,{chainId,maxValiditySeconds=365*86400}={}) {
  const c=structuredClone(configuration);
  if(!integer(maxValiditySeconds,1,365*86400))fail();
  exact(c,['schema','configurationId','validFrom','validUntil','context','network','provider','resourceId',
    'execution','attestationPolicyTemplate','bootstrap','transport']);
  const marketBased=['cannabis.guest-launch-configuration.v2','cannabis.guest-launch-configuration.v3'].includes(c.schema);
  if(Buffer.byteLength(canonical(c))>256*1024||!['cannabis.guest-launch-configuration.v1','cannabis.guest-launch-configuration.v2','cannabis.guest-launch-configuration.v3'].includes(c.schema)||!bytes32(c.configurationId)||
    !integer(c.validFrom,1,Number.MAX_SAFE_INTEGER)||!integer(c.validUntil,c.validFrom+1,c.validFrom+maxValiditySeconds))fail();
  exact(c.context,['chainId',marketBased?'market':'registryId','token']);
  if(!integer(c.context.chainId,1,Number.MAX_SAFE_INTEGER)||chainId!==undefined&&c.context.chainId!==chainId||!marketBased&&!bytes32(c.context.registryId))fail();getAddress(c.context.token);
  if(marketBased)address(c.context.market);
  const n=c.network;exact(n,['rpc','chainId','token','escrow','genesisHash','escrowCodeHash','tokenCodeHash',
    'finality','maxFinalizedAgeSeconds','maxHeadAgeSeconds',...(marketBased?['market','marketCodeHash']:[])]);
  if(marketBased&&(getAddress(n.market)!==getAddress(c.context.market)||!bytes32(n.marketCodeHash)))fail();
  const rpc=new URL(n.rpc);
  if(rpc.username||rpc.password||rpc.search||rpc.hash||rpc.protocol!=='https:'&&!(rpc.protocol==='http:'&&rpc.hostname==='127.0.0.1')||
    n.chainId!==c.context.chainId||getAddress(n.token)!==getAddress(c.context.token)||n.finality!=='rpc-finalized'||
    !integer(n.maxFinalizedAgeSeconds,1,7200)||!integer(n.maxHeadAgeSeconds,1,120)||
    !bytes32(n.genesisHash)||!bytes32(n.escrowCodeHash)||
    (getAddress(n.token)===ZeroAddress?n.tokenCodeHash!==null:!bytes32(n.tokenCodeHash)))fail();
  address(n.escrow);address(c.provider);if(!bytes32(c.resourceId))fail();
  nativeServiceCommitment(c.execution);
  const profile=c.execution.profile;
  const dependencies=profile.schema==='cannabis.guest-native-service.v3';
  exact(profile,['schema','units','runtime','resources','total','control','helper','processLimit','scratchInodes','staging','ciphertext','maxInputBytes','tools',...(dependencies?['maxDependencyBytes']:[])]);
  exact(profile.runtime,['adapter','architecture','os','digestSHA256']);
  exact(profile.resources,['cpus','memoryMiB','scratchMiB','wallSeconds','nodes']);
  exact(profile.total,['cpu_millis','memory_bytes','processes','wall_seconds','children']);
  for(const name of ['control','helper'])exact(profile[name],['cpu_millis','memory_bytes','processes','wall_seconds']);
  exact(profile.staging,['bytes','inodes']);exact(profile.tools,['pythonSHA256','ageSHA256','ageKeygenSHA256']);
  exact(profile.ciphertext,['bytes','inodes','inputBytes','outputBytes',...(dependencies?['dependencyBytes']:[])]);
  for(const value of [...Object.values(profile.resources),...Object.values(profile.total),...Object.values(profile.control),
    ...Object.values(profile.helper),...Object.values(profile.staging),...Object.values(profile.ciphertext),profile.processLimit,profile.scratchInodes])
    if(!integer(value,1,Number.MAX_SAFE_INTEGER))fail();
  if(!integer(profile.maxInputBytes,0,profile.staging.bytes)||
    dependencies&&(!integer(profile.maxDependencyBytes,0,profile.staging.bytes)||profile.maxInputBytes+profile.maxDependencyBytes>profile.staging.bytes)||
    Object.values(profile.tools).some(v=>typeof v!=='string'||!/^[0-9a-f]{64}$/.test(v))||
    typeof profile.runtime.digestSHA256!=='string'||!/^[0-9a-f]{64}$/.test(profile.runtime.digestSHA256)||
    Object.values(profile.runtime).some(v=>typeof v!=='string'||!/^[A-Za-z0-9_.-]{1,128}$/.test(v)))fail();
  for(const file of Object.values(c.execution.source))if(!path.posix.isAbsolute(file)||file.includes('\\')||file.includes('\0')||file.split('/').includes('..'))fail();
  const b=c.bootstrap;exact(b,['agentBinary','bridgeBinary','runtimeDirectory','port']);
  for(const field of ['agentBinary','bridgeBinary','runtimeDirectory'])if(typeof b[field]!=='string'||!path.posix.isAbsolute(b[field])||b[field].includes('\\')||b[field].includes('\0')||b[field].split('/').includes('..'))fail();
  if(!integer(b.port,1024,65535))fail();
  exact(c.transport,['timeoutMs','maxCiphertextBytes']);
  if(!integer(c.transport.timeoutMs,1,3600000)||!integer(c.transport.maxCiphertextBytes,1,profile.ciphertext.outputBytes))fail();
  const p=structuredClone(c.attestationPolicyTemplate);
  // The assignment digest is derived locally after reading the retained canonical
  // assignment. Everything else, including the image measurement, is signed.
  if(p?.measurements?.initData!==null)fail();
  p.measurements.initData='11'.repeat(p.tee==='snp'?32:48);validateAttestationPolicy(p);
  return {configuration:c,configurationSHA256:hash(c)};
}
