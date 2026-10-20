// One complete, requester-approved set of attested execution peers. These
// commitments do not establish current funding, runtime readiness or payment.
import {createHash,webcrypto} from 'node:crypto';
import {TypedDataEncoder,getAddress,verifyTypedData} from 'ethers';
import {verifyMarketLeaseProof} from './market_lease.mjs';
import {inspectLaunchConsent} from './guest_consent.mjs';
import {guestInitialization} from './guest_initialization.mjs';
import {verifyTrusteeResult} from './attestation.mjs';

const admissions=new WeakMap(),seconds=()=>Math.floor(Date.now()/1000);
const failure=()=>Error('Protected group admission differs from its complete booked attempt');
const check=v=>{if(!v)throw failure();};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
export const groupCanonical=v=>Array.isArray(v)?'['+v.map(groupCanonical).join(',')+']':v&&typeof v==='object'
  ?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+groupCanonical(v[k])).join(',')+'}':JSON.stringify(v);
export const groupHash=v=>'0x'+createHash('sha256').update(typeof v==='string'?v:groupCanonical(v)).digest('hex');
const same=(a,b)=>groupCanonical(a)===groupCanonical(b);
export const GROUP_SCHEMA='cannabis.protected-group.v1';
export const GROUP_ADAPTER='native-group-linux-x86_64-v1';
export const GROUP_BACKEND='attested-tls-ip-v1';
export const GROUP_MAX_BYTES=4*1024*1024;

export function groupEndpoint(value) {
  check(typeof value==='string'&&value.length<=512);
  const u=new URL(value);
  check(u.protocol==='tls:'&&u.hostname&&u.hostname.length<=253&&u.port&&integer(Number(u.port),1024,65535)&&
    !u.username&&!u.password&&!u.search&&!u.hash&&!u.pathname&&value==='tls://'+u.host);
  return {host:u.hostname.replace(/^\[|\]$/g,''),port:Number(u.port)};
}
export async function groupPublicKey(value) {
  exact(value,['kty','crv','x','y']);
  check(value.kty==='EC'&&value.crv==='P-256'&&['x','y'].every(k=>typeof value[k]==='string'&&/^[A-Za-z0-9_-]{43}$/.test(value[k])));
  return webcrypto.subtle.importKey('jwk',value,{name:'ECDH',namedCurve:'P-256'},false,[]);
}
export const groupAdmissionTypes=Object.freeze({ProtectedGroup:Object.freeze([
  ['genesisHash','bytes32'],['leaseDigest','bytes32'],['executionPlanSHA256','bytes32'],
  ['taskSHA256','bytes32'],['attempt','uint32'],['worldSize','uint32'],['groupDigest','bytes32'],
  ['requester','address'],['validFrom','uint64'],['validUntil','uint64']
].map(([name,type])=>Object.freeze({name,type})))});
export const groupStartTypes=Object.freeze({ProtectedGroupStart:Object.freeze([
  ['groupDigest','bytes32'],['readinessDigest','bytes32'],['requester','address'],
  ['validFrom','uint64'],['validUntil','uint64']
].map(([name,type])=>Object.freeze({name,type})))});

async function describe(proof,network,input,now) {
  check(integer(now,1,Number.MAX_SAFE_INTEGER)&&Buffer.byteLength(groupCanonical(input))<=GROUP_MAX_BYTES);
  const group=structuredClone(input);
  exact(group,['schema','task','issuedAt','expiresAt','requesterChannelJwk','peers']);
  check(group.schema===GROUP_SCHEMA&&integer(group.task,0,63)&&integer(group.issuedAt,1,now)&&
    integer(group.expiresAt,now+1,group.issuedAt+120));
  await groupPublicKey(group.requesterChannelJwk);
  const lease=verifyMarketLeaseProof(proof,network),plan=lease.executionPlan?.plan;
  check(plan&&same(plan.genesisHash,network.genesisHash));
  const requirement=plan.requirements[group.task],selected=lease.assignments.filter(a=>a.task===group.task);
  check(requirement&&integer(requirement.resources.nodes,2,64)&&selected.length===requirement.resources.nodes&&
    requirement.runtime.adapter===GROUP_ADAPTER&&requirement.runtime.collectiveBackend===GROUP_BACKEND&&
    requirement.runtime.architecture==='x86_64'&&requirement.runtime.os==='linux'&&
    requirement.resources.accelerators===0&&requirement.resources.acceleratorMemoryMiB===0&&
    Array.isArray(group.peers)&&group.peers.length===selected.length);
  const seen=new Set(),nonces=new Set(),keys=new Set(),endpoints=new Set(),peers=[];
  for(const [rank,entry] of group.peers.entries()) {
    exact(entry,['signed','initialization','challenge','channelJwk','appraisal','endpoint']);
    groupEndpoint(entry.endpoint);await groupPublicKey(entry.channelJwk);
    const d=inspectLaunchConsent(entry.signed,entry.initialization,proof,now),b=entry.initialization.binding,
      assignment=selected.find(a=>a.reservationId===b.reservationId),r=d.reservation;
    check(assignment&&assignment.run.rank===rank&&b.rank===rank&&b.worldSize===selected.length&&
      entry.signed.configuration.execution.profile.schema==='cannabis.guest-native-service.v4'&&
      d.lease.digest===lease.digest&&d.lease.executionPlan.digestSHA256===lease.executionPlan.digestSHA256&&
      ['chainId','genesisHash','market','escrow','token','marketCodeHash','escrowCodeHash','tokenCodeHash','finality']
        .every(k=>same(entry.signed.configuration.network[k],network[k]))&&same(entry.challenge.binding,b)&&
      group.issuedAt>=r.start&&group.expiresAt<=r.end&&group.expiresAt<=entry.challenge.expiresAt&&
      group.issuedAt>=entry.challenge.issuedAt&&!seen.has(r.reservationId)&&!nonces.has(entry.challenge.nonce)&&
      !keys.has(groupHash(entry.channelJwk))&&!endpoints.has(entry.endpoint)&&
      !same(entry.channelJwk,group.requesterChannelJwk));
    const policy=structuredClone(entry.signed.configuration.attestationPolicyTemplate);
    policy.measurements.initData=guestInitialization(entry.initialization).digest;
    const appraisal=await verifyTrusteeResult(entry.appraisal,policy,entry.challenge,entry.channelJwk,now);
    check(group.expiresAt<=appraisal.expiresAt);
    seen.add(r.reservationId);nonces.add(entry.challenge.nonce);keys.add(groupHash(entry.channelJwk));endpoints.add(entry.endpoint);
    peers.push({rank,reservationId:r.reservationId,provider:r.provider,endpoint:entry.endpoint,
      channelJwk:entry.channelJwk,nonce:entry.challenge.nonce,configurationSHA256:d.configurationSHA256,
      serviceSHA256:r.serviceSHA256,start:r.start,end:r.end,appraisalSHA256:appraisal.tokenSHA256});
  }
  const attempt=group.peers[0].initialization.binding.attempt;
  check(selected.every(a=>a.run.attempt===attempt)&&peers.every(p=>p.start===peers[0].start&&p.end===peers[0].end));
  const domain={name:'Cannabis protected group',version:'1',chainId:plan.chainId,verifyingContract:getAddress(plan.market)},
    value={genesisHash:plan.genesisHash,leaseDigest:lease.digest,executionPlanSHA256:'0x'+lease.executionPlan.digestSHA256,
      taskSHA256:requirement.taskSHA256.startsWith('0x')?requirement.taskSHA256:'0x'+requirement.taskSHA256,
      attempt,worldSize:peers.length,groupDigest:groupHash(group),requester:lease.requester,
      validFrom:group.issuedAt,validUntil:group.expiresAt};
  const payload={domain,types:groupAdmissionTypes,value,digest:TypedDataEncoder.hash(domain,groupAdmissionTypes,value)};
  return {group,lease,requirement,peers,payload};
}

export async function groupAdmissionPayload(proof,network,group,{clock=seconds}={}) {
  const d=await describe(proof,network,group,clock());
  return {...d.payload,signer:d.lease.requester,executionAuthorized:false,keyReleaseAuthorized:false,chainVerified:false};
}

export async function verifyGroupAdmission(proof,network,signed,{clock=seconds}={}) {
  signed=structuredClone(signed);exact(signed,['schema','group','requesterSignature']);
  check(signed.schema==='cannabis.protected-group-approval.v1');
  const now=clock(),d=await describe(proof,network,signed.group,now),p=d.payload;
  check(verifyTypedData(p.domain,p.types,p.value,signed.requesterSignature)===d.lease.requester);
  const capability=Object.freeze({groupDigest:p.value.groupDigest,worldSize:d.peers.length,
    executionAuthorized:false,keyReleaseAuthorized:false,chainVerified:false});
  admissions.set(capability,{...d,signed,network:structuredClone(network),clock,verifiedAt:now,lastNow:now});
  return capability;
}

export function inspectGroupAdmission(capability,{allowStarted=false}={}) {
  const d=admissions.get(capability);check(d);
  const now=d.clock();check(integer(now,d.lastNow,Number.MAX_SAFE_INTEGER)&&now>=d.group.issuedAt&&
    now<(allowStarted?d.peers[0].end:d.group.expiresAt));d.lastNow=now;
  return structuredClone({group:d.group,signed:d.signed,network:d.network,peers:d.peers,requirement:d.requirement,
    payload:d.payload,leaseDigest:d.lease.digest,executionPlanSHA256:d.lease.executionPlan.digestSHA256,
    requester:d.lease.requester,jobId:d.lease.job.id,serviceEnd:d.peers[0].end,observedAt:now});
}

export function groupStartPayload(capability,readiness,now=seconds()) {
  const d=inspectGroupAdmission(capability);
  check(Array.isArray(readiness)&&readiness.length===d.peers.length&&Buffer.byteLength(groupCanonical(readiness))<=65536);
  for(const [rank,r] of readiness.entries()) {
    exact(r,['schema','groupDigest','rank','meshDigest','readyAt','authenticator']);
    check(r.schema==='cannabis.protected-group-ready.v1'&&r.groupDigest===d.payload.value.groupDigest&&r.rank===rank&&
      /^0x[0-9a-f]{64}$/.test(r.meshDigest)&&/^[A-Za-z0-9_-]{43}$/.test(r.authenticator)&&
      integer(r.readyAt,d.group.issuedAt,now));
  }
  check(integer(now,d.group.issuedAt,d.group.expiresAt-1));
  const domain={...d.payload.domain,name:'Cannabis protected group start'},value={groupDigest:d.payload.value.groupDigest,
    readinessDigest:groupHash(readiness),requester:d.requester,validFrom:now,validUntil:d.group.expiresAt};
  return {domain,types:groupStartTypes,value,digest:TypedDataEncoder.hash(domain,groupStartTypes,value),
    executionAuthorized:false,keyReleaseAuthorized:false};
}

export function verifyGroupStart(capability,start,ownReadiness,now=seconds()) {
  exact(start,['schema','readiness','payload','requesterSignature']);check(start.schema==='cannabis.protected-group-start.v1');
  const p=groupStartPayload(capability,start.readiness,start.payload?.value?.validFrom),d=inspectGroupAdmission(capability);
  check(same(p,start.payload)&&integer(now,p.value.validFrom,p.value.validUntil-1)&&
    same(start.readiness[ownReadiness.rank],ownReadiness)&&
    verifyTypedData(p.domain,p.types,p.value,start.requesterSignature)===d.requester);
  return p.digest;
}

// This describes a requester-approved key release; it cannot activate a guest.
// The guest additionally requires its own live mesh and retained readiness.
export function groupDeliveryBinding(capability,bundle,binding,channelJwk,now=seconds()) {
  exact(bundle,['approval','start']);
  const d=inspectGroupAdmission(capability),own=d.group.peers[binding.rank];
  check(same(bundle.approval,d.signed)&&own&&same(own.initialization.binding,binding)&&same(own.channelJwk,channelJwk));
  const groupStartDigest=verifyGroupStart(capability,bundle.start,bundle.start.readiness[binding.rank],now);
  return {groupDigest:d.payload.value.groupDigest,groupStartDigest};
}
