// Requester-owned dependency preparation. A handoff approves exact input bytes;
// it does not attest a worker, release keys, execute software or accept payment.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { TypedDataEncoder, verifyTypedData } from 'ethers';
import { verifyMarketLeaseProof } from './market_lease.mjs';

const hash=v=>createHash('sha256').update(v).digest('hex');
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':
  v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const check=(v,message='Dependency handoff differs from the selected execution plan')=>{if(!v)throw Error(message);};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join());
const hex=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const number=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const digest=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);

function retained(proof,network,reservationId,descriptor) {
  const lease=verifyMarketLeaseProof(proof,network);
  check(lease.executionPlan&&network.genesisHash===lease.executionPlan.plan.genesisHash);
  const target=lease.assignments.find(a=>a.reservationId===reservationId);check(target);
  const requirement=lease.executionPlan.plan.requirements[target.task];
  check(requirement.dependsOn.length>0);
  check(descriptor?.schema==='cannabis.package.v2'&&descriptor.id===lease.job.id&&
    descriptor.ciphertextSHA256===lease.job.packageSHA256&&descriptor.policySHA256===lease.job.policySHA256&&
    typeof descriptor.recipient==='string'&&/^age1[0-9a-z]{58}$/.test(descriptor.recipient));
  const reservation=lease.reservations.find(r=>r.reservationId===reservationId);
  return {lease,target,requirement,reservation,context:{schema:'cannabis.dependency-context.v1',
    chainId:lease.executionPlan.plan.chainId,genesisHash:network.genesisHash,escrow:lease.escrow,requester:lease.requester,
    jobId:lease.job.id,packageSHA256:lease.job.packageSHA256,policySHA256:lease.job.policySHA256,
    executionPlanSHA256:lease.executionPlan.digestSHA256,leaseDigest:lease.digest,orderId:lease.orderId,
    reservationId,task:target.task,...target.run,inputRecipient:descriptor.recipient}};
}
function sourcesFor(retained,sources) {
  check(Array.isArray(sources)&&sources.length>0&&sources.length<=64);
  const {lease,requirement}=retained,seen=new Set(),deps=new Set();
  const normalized=sources.map(s=>{
    exact(s,['reservationId','task','taskSHA256','attempt','rank','worldSize','approvalDigest','receiptSHA256','ciphertextSHA256','ciphertextBytes']);
    const a=lease.assignments.find(a=>a.reservationId===s.reservationId);
    check(a&&a.task===s.task&&requirement.dependsOn.includes(a.task)&&!seen.has(s.reservationId));
    for(const key of ['taskSHA256','attempt','rank','worldSize'])check(s[key]===a.run[key]);
    check(digest(s.approvalDigest)&&hex(s.receiptSHA256)&&hex(s.ciphertextSHA256)&&number(s.ciphertextBytes,1,2**40));
    seen.add(s.reservationId);deps.add(s.task);return structuredClone(s);
  }).sort((a,b)=>a.task-b.task||a.rank-b.rank);
  check(deps.size===requirement.dependsOn.length);
  return normalized;
}
export const dependencyHandoffTypes={DependencyHandoff:[
  ['leaseDigest','bytes32'],['orderId','bytes32'],['executionPlanSHA256','bytes32'],['genesisHash','bytes32'],
  ['reservationId','bytes32'],['taskSHA256','bytes32'],['attempt','uint32'],['rank','uint32'],['worldSize','uint32'],
  ['inputRecipient','string'],['ciphertextSHA256','bytes32'],['ciphertextBytes','uint64'],['contextSHA256','bytes32'],
  ['notBefore','uint64'],['expiresAt','uint64']
].map(([name,type])=>({name,type}))};

// Offline signing payload. The complete capsule context stays local/encrypted;
// the typed signature commits its digest, not private file names or content.
export function dependencyHandoffPayload(proof,network,reservationId,descriptor,handoff,window) {
  const r=retained(proof,network,reservationId,descriptor);
  exact(handoff,['schema','context','ciphertextSHA256','ciphertextBytes','format','recipient']);
  check(handoff.schema==='cannabis.dependency-handoff.v1'&&handoff.format==='age-v1+ustar'&&
    handoff.recipient===descriptor.recipient&&hex(handoff.ciphertextSHA256)&&number(handoff.ciphertextBytes,1,2**40));
  const context={...r.context,sources:sourcesFor(r,handoff.context?.sources)};
  check(canonical(context)===canonical(handoff.context));
  exact(window,['notBefore','expiresAt']);
  check(number(window.notBefore,r.reservation.start,r.reservation.end-1)&&
    number(window.expiresAt,window.notBefore+1,r.reservation.end));
  const value={leaseDigest:r.lease.digest,orderId:r.lease.orderId,executionPlanSHA256:'0x'+context.executionPlanSHA256,
    genesisHash:context.genesisHash,reservationId,taskSHA256:'0x'+context.taskSHA256,
    attempt:context.attempt,rank:context.rank,worldSize:context.worldSize,inputRecipient:context.inputRecipient,
    ciphertextSHA256:'0x'+handoff.ciphertextSHA256,ciphertextBytes:handoff.ciphertextBytes,
    contextSHA256:'0x'+hash(canonical(context)),...window};
  const domain={name:'Cannabis dependency handoff',version:'1',chainId:context.chainId,verifyingContract:context.escrow};
  return {domain,types:dependencyHandoffTypes,value,digest:TypedDataEncoder.hash(domain,dependencyHandoffTypes,value),
    requester:context.requester,executionAuthorized:false,keyReleaseAuthorized:false,paymentAuthorized:false};
}
// An admitted guest must ALSO enforce current funding, attestation, storage
// and lifecycle controls. Signature verification alone cannot launch anything.
export function verifyDependencyHandoff(proof,network,reservationId,descriptor,signed,now) {
  exact(signed,['handoff','window','requesterSignature']);
  const payload=dependencyHandoffPayload(proof,network,reservationId,descriptor,signed.handoff,signed.window);
  check(number(now,payload.value.notBefore,payload.value.expiresAt-1));
  check(verifyTypedData(payload.domain,payload.types,payload.value,signed.requesterSignature)===payload.requester);
  return {approvalDigest:payload.digest,inputAuthorized:true,executionAuthorized:false,keyReleaseAuthorized:false,paymentAuthorized:false};
}

// Call again immediately before presenting/signing the prepared input approval.
// A retired/superseded upstream selection invalidates an unsigned saved handoff.
export function reviewDependencyHandoff(inbox,proof,network,reservationId,descriptor,prepared) {
  const h=prepared.handoff;
  const approval=dependencyHandoffPayload(proof,network,reservationId,descriptor,h,prepared.window);
  return inbox.useCurrent(h.context.sources.map(s=>({approvalDigest:s.approvalDigest,receiptSHA256:s.receiptSHA256})),approvals=>{
    approvals.forEach((a,i)=>{
      const s=h.context.sources[i],v=a.value;
      check(a.digest===s.approvalDigest&&v.reservationId===s.reservationId&&v.leaseDigest===h.context.leaseDigest&&
        v.orderId===h.context.orderId&&v.taskSHA256==='0x'+s.taskSHA256&&v.attempt===s.attempt&&v.rank===s.rank&&v.worldSize===s.worldSize);
    });
    return approval;
  });
}

export async function prepareDependencyHandoff({inbox,proof,network,reservationId,descriptor,results,source,window,loadResultKey}) {
  proof=structuredClone(proof);network=structuredClone(network);descriptor=structuredClone(descriptor);
  results=structuredClone(results);source=structuredClone(source);window=structuredClone(window);
  const r=retained(proof,network,reservationId,descriptor);
  exact(window,['notBefore','expiresAt']);
  check(number(window.notBefore,r.reservation.start,r.reservation.end-1)&&number(window.expiresAt,window.notBefore+1,r.reservation.end));
  exact(source,['python','age','identity','manifest','destination']);
  for(const p of Object.values(source))check(typeof p==='string'&&path.isAbsolute(p)&&!p.includes('\0'));
  check(Array.isArray(results)&&results.length>0&&results.length<=64);
  for(const item of results){exact(item,['approvalDigest','file']);check(path.isAbsolute(item.file)&&!item.file.includes('\0'));}
  const recovered=[];
  for(const item of results)recovered.push(await inbox.recover(item.approvalDigest,loadResultKey));
  const selections=recovered.map(x=>({approvalDigest:x.approvalDigest,receiptSHA256:x.receiptSHA256}));
  return inbox.useCurrent(selections,approvals=>{
    const sources=sourcesFor(r,approvals.map((a,i)=>{
      const v=a.value,receipt=recovered[i].receipt,assignment=r.lease.assignments.find(x=>x.reservationId===v.reservationId);
      check(assignment&&['3','4','5','6'].includes(a.domain.version)&&a.requester===r.lease.requester&&a.jobId===r.lease.job.id&&
        Number(a.domain.chainId)===r.context.chainId&&a.domain.verifyingContract===r.context.escrow&&
        v.leaseDigest===r.lease.digest&&v.orderId===r.lease.orderId&&v.inputRecipient===descriptor.recipient);
      for(const k of ['packageSHA256','policySHA256'])check(v[k]==='0x'+r.context[k]);
      for(const k of ['runtimeSHA256','taskSHA256'])check(v[k]==='0x'+assignment.run[k]);
      for(const k of ['attempt','rank','worldSize'])check(v[k]===assignment.run[k]&&receipt[k]===v[k]);
      return {reservationId:v.reservationId,task:assignment.task,taskSHA256:assignment.run.taskSHA256,
        attempt:v.attempt,rank:v.rank,worldSize:v.worldSize,approvalDigest:a.digest,
        receiptSHA256:recovered[i].receiptSHA256,ciphertextSHA256:receipt.ciphertextSHA256,ciphertextBytes:receipt.ciphertextBytes};
    }));
    const context={...r.context,sources}, {python,...local}=source;
    const request={source:local,context,results:recovered.map((x,i)=>({receipt:x.receipt,file:results[i].file,approval:approvals[i]}))};
    const raw=Buffer.from(JSON.stringify(request));check(raw.length<=16*1024*1024);
    let handoff;
    try {handoff=JSON.parse(execFileSync(python,[fileURLToPath(new URL('../scripts/compute-dependency-handoff-pipe.py',import.meta.url))],
      {input:raw,encoding:'utf8',timeout:600000,maxBuffer:1024*1024,windowsHide:true,stdio:['pipe','pipe','ignore']}));}
    finally {raw.fill(0);}
    const approval=dependencyHandoffPayload(proof,network,reservationId,descriptor,handoff,window);
    return {schema:'cannabis.prepared-dependency-handoff.v1',handoff,window,approval,
      sourceReceiptsAuthenticated:true,sourceIntegrityVerified:true,qualityAccepted:false,
      executionAuthorized:false,keyReleaseAuthorized:false,paymentAuthorized:false};
  });
}
