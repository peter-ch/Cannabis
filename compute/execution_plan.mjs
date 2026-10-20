// Complete public task/rank booking commitments. No chain reads or admission.
// Private program names, arguments, files and output paths never belong here.
import {getAddress,ZeroAddress,sha256,toUtf8Bytes,concat,toBeHex,zeroPadValue,parseUnits} from 'ethers';

const fail=()=>{throw Error('Execution plan does not completely match the workload and bookings');};
const check=v=>{if(!v)fail();};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const name=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(v);
const digest=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)&&!/^0+$/.test(v);
const bytes32=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const address=(v,zero=false)=>check(typeof v==='string'&&getAddress(v)===v&&(zero||v!==ZeroAddress));
const uint=(v,max=Number.MAX_SAFE_INTEGER)=>{
  check(typeof v==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(v)&&BigInt(v)<=BigInt(max));return BigInt(v);
};
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'
  ?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const same=(a,b)=>canonical(a)===canonical(b);
const bookingKeys=['reservationId','offerId','start','end','units','gross','holdUntil'];
export const EXECUTION_PLAN_SCHEMA='cannabis.execution-plan.v1';

export function taskCommitment(packageSHA256,index) {
  check(digest(packageSHA256)&&integer(index,0,4095));
  return sha256(concat([toUtf8Bytes('cannabis.task.v1\0'),'0x'+packageSHA256,zeroPadValue(toBeHex(index),4)])).slice(2);
}
function runtime(value) {
  check(value&&typeof value==='object'&&!Array.isArray(value));
  exact(value,['adapter','architecture','os','digestSHA256',...['features','collectiveBackend'].filter(k=>Object.hasOwn(value,k))]);
  check(['adapter','architecture','os'].every(k=>name(value[k]))&&digest(value.digestSHA256));
  const features=value.features??[];
  check(Array.isArray(features)&&features.every(name)&&new Set(features).size===features.length);
  if(Object.hasOwn(value,'collectiveBackend'))check(name(value.collectiveBackend));
  return {...value,features:[...features].sort()};
}
function resources(value) {
  check(value&&typeof value==='object'&&!Array.isArray(value));
  exact(value,['cpus','memoryMiB','scratchMiB','wallSeconds','nodes',...['accelerators','acceleratorMemoryMiB'].filter(k=>Object.hasOwn(value,k))]);
  check(['cpus','memoryMiB','scratchMiB'].every(k=>integer(value[k],1,Number.MAX_SAFE_INTEGER))&&
    integer(value.wallSeconds,1,2592000)&&integer(value.nodes,1,100000));
  const r={...value,accelerators:value.accelerators??0,acceleratorMemoryMiB:value.acceleratorMemoryMiB??0};
  check(integer(r.accelerators,0,100000)&&integer(r.acceleratorMemoryMiB,0,Number.MAX_SAFE_INTEGER)&&
    (r.accelerators===0?r.acceleratorMemoryMiB===0:r.acceleratorMemoryMiB>0));
  return r;
}
function booking(value) {
  exact(value,bookingKeys);
  check(bytes32(value.reservationId)&&bytes32(value.offerId));
  const start=uint(value.start),end=uint(value.end),hold=uint(value.holdUntil),gross=uint(value.gross,2n**256n-1n);
  check(start>0n&&end>start&&end-start<=90n*86400n&&hold>0n&&hold<=start&&value.units==='1'&&gross>=100n&&gross%100n===0n);
}
export function inspectExecutionPlan(input) {
  check(toUtf8Bytes(JSON.stringify(input)).length<=256*1024);
  const p=structuredClone(input);
  exact(p,['schema','chainId','genesisHash','market','escrow','token','requester','jobId','packageSHA256','policySHA256','requirements','assignments']);
  check(p.schema===EXECUTION_PLAN_SCHEMA&&integer(p.chainId,1,Number.MAX_SAFE_INTEGER)&&bytes32(p.genesisHash)&&
    name(p.jobId)&&digest(p.packageSHA256)&&digest(p.policySHA256));
  for(const k of ['market','escrow','requester'])address(p[k]);address(p.token,true);
  check(Array.isArray(p.requirements)&&p.requirements.length>=1);
  if(p.requirements.length>64)throw Error('Atomic market plans support at most 64 task/rank bookings; never truncate the workload');
  let ranks=0;
  for(const [index,t] of p.requirements.entries()) {
    exact(t,['task','taskSHA256','dependsOn','runtime','resources']);
    check(t.task===index&&t.taskSHA256===taskCommitment(p.packageSHA256,index)&&Array.isArray(t.dependsOn)&&
      t.dependsOn.every(d=>integer(d,0,p.requirements.length-1)&&d!==index)&&new Set(t.dependsOn).size===t.dependsOn.length);
    t.dependsOn.sort((a,b)=>a-b);t.runtime=runtime(t.runtime);t.resources=resources(t.resources);
    if(t.resources.nodes>1)check(name(t.runtime.collectiveBackend));
    ranks+=t.resources.nodes;
  }
  // One service unit for each rank, one atomic group with <=64 bookings. Do not
  // silently truncate a larger workload or confuse this with human enrollment.
  if(ranks>64)throw Error('Atomic market plans support at most 64 task/rank bookings; never truncate the workload');
  check(Array.isArray(p.assignments)&&p.assignments.length===ranks);
  const assigned=new Set(),nonces=new Set(),byTask=new Map(),prices=new Map();let total=0n;
  for(const a of p.assignments) {
    exact(a,['task','rank','attempt','acceleratorClass','provider','serviceSHA256','booking']);
    check(integer(a.task,0,p.requirements.length-1)&&integer(a.rank,0,p.requirements[a.task].resources.nodes-1)&&
      integer(a.attempt,1,1000000)&&name(a.acceleratorClass)&&bytes32(a.serviceSHA256));
    address(a.provider);check(a.provider!==p.requester);booking(a.booking);
    const t=p.requirements[a.task],key=a.task+':'+a.rank;
    check(!assigned.has(key)&&!nonces.has(a.booking.reservationId));assigned.add(key);nonces.add(a.booking.reservationId);
    check(t.resources.accelerators===0?a.acceleratorClass==='cpu':a.acceleratorClass!=='cpu');
    check(Number(a.booking.end)-Number(a.booking.start)>=t.resources.wallSeconds);
    const previous=byTask.get(a.task);
    if(previous)check(previous.attempt===a.attempt&&previous.acceleratorClass===a.acceleratorClass&&
      previous.booking.start===a.booking.start&&previous.booking.end===a.booking.end);
    else byTask.set(a.task,a);
    const gross=BigInt(a.booking.gross);total+=gross;
    check(total<2n**256n);prices.set(a.provider,(prices.get(a.provider)??0n)+gross);
  }
  const done=new Set();
  while(done.size<p.requirements.length) {
    const ready=p.requirements.filter(t=>!done.has(t.task)&&t.dependsOn.every(d=>done.has(d)));
    check(ready.length>0);
    for(const t of ready) {
      const a=byTask.get(t.task);check(a);
      for(const d of t.dependsOn)check(BigInt(byTask.get(d).booking.end)<=BigInt(a.booking.start));
      done.add(t.task);
    }
  }
  p.assignments.sort((a,b)=>a.task-b.task||a.rank-b.rank);
  const encoded=canonical(p);
  return {plan:p,digestSHA256:sha256(toUtf8Bytes(encoded)).slice(2),grossBaseUnits:total.toString(),
    providers:[...prices].sort(([a],[b])=>a.localeCompare(b)).map(([account,gross])=>({account,grossBaseUnits:gross.toString()})),
    executionAuthorized:false,keyReleaseAuthorized:false,paymentAuthorized:false};
}
// Select fields from a requester-retained package descriptor. Never copy private
// launch fields or interpret an arbitrary advertisement as a complete workload.
export function prepareExecutionPlan(descriptor,context,assignments) {
  check(['cannabis.package.v1','cannabis.package.v2'].includes(descriptor?.schema)&&
    descriptor.executionAuthorized===false&&descriptor.keyReleaseAuthorized===false);
  exact(context,['chainId','genesisHash','market','escrow','token','requester']);
  return inspectExecutionPlan({schema:EXECUTION_PLAN_SCHEMA,...context,jobId:descriptor.id,
    packageSHA256:descriptor.ciphertextSHA256,policySHA256:descriptor.policySHA256,
    requirements:descriptor.requirements,assignments});
}
export function executionPlanForOrder(input,job,context) {
  const checked=inspectExecutionPlan(input),p=checked.plan;
  check(job?.schema==='cannabis.compute.order.v3'&&job.executionPlanSHA256===checked.digestSHA256&&
    job.id===p.jobId&&job.requester===p.requester&&job.packageSHA256===p.packageSHA256&&job.policySHA256===p.policySHA256&&
    parseUnits(job.payment.totalBudget,18)===BigInt(checked.grossBaseUnits));
  check(BigInt(context.chainId)===BigInt(p.chainId));
  for(const k of ['market','escrow','token'])check(getAddress(context[k])===p[k]);
  if(Object.hasOwn(context,'genesisHash'))check(context.genesisHash===p.genesisHash);
  return checked;
}
export function matchExecutionBookings(checked,bookings) {
  check(Array.isArray(bookings)&&bookings.length===checked.plan.assignments.length);
  const byNonce=new Map(checked.plan.assignments.map(a=>[a.booking.reservationId,a]));
  const seen=new Set();
  return bookings.map(b=>{
    const nonce=b.reservationId,a=byNonce.get(nonce);check(a&&!seen.has(nonce));seen.add(nonce);
    check(same(a.booking,Object.fromEntries(bookingKeys.map(k=>[k,b[k]]))));return a;
  });
}
export function assertExecutionSettlement(checked,settlement) {
  const prices=new Map(checked.providers.map(p=>[p.account,BigInt(p.grossBaseUnits)])),total=BigInt(checked.grossBaseUnits);
  check(prices.size===settlement.accounts.length&&settlement.accounts.every((a,i)=>
    prices.has(a)&&prices.get(a)*10000n===total*BigInt(settlement.shares[i])));
  for(const a of checked.plan.assignments)check(BigInt(a.booking.start)>=BigInt(settlement.terms.acceptBy)&&
    BigInt(a.booking.end)<=BigInt(settlement.terms.deliverBy));
}
export function plannedRun(requirement,assignment) {
  return {runtimeSHA256:requirement.runtime.digestSHA256,taskSHA256:requirement.taskSHA256,
    attempt:assignment.attempt,rank:assignment.rank,worldSize:requirement.resources.nodes,acceleratorClass:assignment.acceleratorClass};
}
export function assertPlannedService(lease,reservationId,profile,network) {
  if(!lease.executionPlan)return;
  check(lease.executionPlan.plan.genesisHash===network.genesisHash);
  const assignment=lease.assignments.find(a=>a.reservationId===reservationId);check(assignment);
  const t=lease.executionPlan.plan.requirements[assignment.task];
  check(same(runtime(profile.runtime),t.runtime)&&same(resources(profile.resources),t.resources)&&profile.units===1);
}
