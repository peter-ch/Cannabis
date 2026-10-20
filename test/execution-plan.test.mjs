import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {inspectExecutionPlan,prepareExecutionPlan,executionPlanForOrder,matchExecutionBookings,plannedRun,taskCommitment,assertExecutionSettlement,assertPlannedService} from '../compute/execution_plan.mjs';
import {publicOrderPlan,settlementForPlan} from '../compute/settlement.mjs';
import {prepareMarketPlan,marketAction} from '../operator/market-plan.mjs';
import {executionPlanFixture} from './helpers/execution_plan_fixture.mjs';

test('planned consent binds the selected runtime resources before guest funding construction',async()=>{
  const {consentFixture}=await import('./helpers/consent_fixture.mjs');
  const {AbiCoder,keccak256}=await import('ethers');
  const {termsDigest}=await import('../compute/settlement.mjs');
  const {bookingPayload}=await import('../compute/market.mjs');
  const {verifyMarketLeaseProof}=await import('../compute/market_lease.mjs');
  const {validateGuestConfiguration}=await import('../compute/guest_configuration.mjs');
  const {configuredMarketAttestationBinding}=await import('../compute/attestation.mjs');
  const {launchConsentPayload,inspectLaunchConsent}=await import('../compute/guest_consent.mjs');
  const {GuestFunding}=await import('../compute/guest_funding.mjs');
  const f=await consentFixture(),c=f.configuration,p=f.proof,r=p.bookings[0],coder=AbiCoder.defaultAbiCoder();
  const fields=['reservationId','offerId','start','end','units','gross','holdUntil'];
  const checked=inspectExecutionPlan({schema:'cannabis.execution-plan.v1',chainId:p.chainId,genesisHash:c.network.genesisHash,
    market:p.market,escrow:p.escrow,token:p.token,requester:p.job.requester,jobId:p.job.id,packageSHA256:p.job.packageSHA256,policySHA256:p.job.policySHA256,
    requirements:[{task:0,taskSHA256:taskCommitment(p.job.packageSHA256,0),dependsOn:[],runtime:c.execution.profile.runtime,resources:c.execution.profile.resources}],
    assignments:[{task:0,rank:0,attempt:1,acceleratorClass:'cpu',provider:c.provider,serviceSHA256:r.resource.serviceHash,
      booking:Object.fromEntries(fields.map(k=>[k,r.booking[k]]))}]});
  p.schema='cannabis.market-lease.v2';p.executionPlan=checked.plan;
  p.job.schema='cannabis.compute.order.v3';p.job.executionPlanSHA256=checked.digestSHA256;
  const s=settlementForPlan(p.job,p.settlement,publicOrderPlan(p.job));
  r.booking.orderId=keccak256(coder.encode(['string','uint256','address','address','bytes32'],['Cannabis compute order v1',p.chainId,p.escrow,p.job.requester,s.terms.jobHash]));
  r.booking.termsDigest=termsDigest({chainId:p.chainId,escrow:p.escrow,token:p.token,founderRecipient:p.job.payment.founderRecipient,...s});
  r.bookingId=bookingPayload(c.context,r.booking).digest;
  const lease=verifyMarketLeaseProof(p,c.context),run=lease.assignments[0].run;
  const binding=configuredMarketAttestationBinding(p,c.context,r.bookingId,run,validateGuestConfiguration(c).configurationSHA256,1001);
  f.initialization.binding=binding;
  const consents=[];
  for(const [role,wallet] of [['requester',f.requester],['provider',f.provider]]) {
    const payload=launchConsentPayload(c,f.initialization,p,role);
    consents.push({role,signer:wallet.address,signature:await wallet.signTypedData(payload.domain,payload.types,payload.value)});
  }
  const signed={...f.signed,consents};
  const consent=inspectLaunchConsent(signed,f.initialization,p,1001);
  assert.equal(consent.executionAuthorized,false);
  const funding=new GuestFunding({proof:p,context:c.context,network:c.network,provider:c.provider,resourceId:c.resourceId,
    serviceSHA256:r.resource.serviceHash,consent:signed},f.initialization,{clock:()=>1001});
  try{funding.assertService({serviceSHA256:r.resource.serviceHash,units:1});}finally{funding.close();}
  const changed=structuredClone(f.initialization);changed.binding.attempt=2;
  assert.throws(()=>inspectLaunchConsent(signed,changed,p,1001));
  const bad=structuredClone(c);bad.network.genesisHash='0x'+'99'.repeat(32);
  assert.throws(()=>launchConsentPayload(bad,f.initialization,p,'requester'));
});


test('complete DAG and group plans use the original Python task commitment and exact costs',()=>{
  for(const group of [false,true]) {
    const f=executionPlanFixture({group}),checked=prepareExecutionPlan(f.descriptor,f.context,f.assignments);
    assert.equal(checked.digestSHA256,f.job.executionPlanSHA256);assert.equal(checked.grossBaseUnits,'20000');
    const index=Buffer.alloc(4);index.writeUInt32BE(0);
    const expected=createHash('sha256').update(Buffer.from('cannabis.task.v1\0')).update(Buffer.from(f.job.packageSHA256,'hex')).update(index).digest('hex');
    assert.equal(checked.plan.requirements[0].taskSHA256,expected);
    assert.equal(checked.executionAuthorized,false);assert.equal(checked.paymentAuthorized,false);
    assert.deepEqual(plannedRun(checked.plan.requirements[0],checked.plan.assignments[0]),{
      runtimeSHA256:f.descriptor.requirements[0].runtime.digestSHA256,taskSHA256:expected,attempt:1,rank:0,worldSize:group?2:1,acceleratorClass:'cpu'});
  }
});
test('incomplete ranks, duplicate bookings and inconsistent groups cannot prepare funding',()=>{
  const f=executionPlanFixture({group:true});
  for(const change of [
    p=>p.assignments.pop(),p=>p.assignments[1].rank=0,p=>p.assignments[1].attempt=2,
    p=>p.assignments[1].booking.reservationId=p.assignments[0].booking.reservationId,
    p=>p.assignments[1].booking.start='1001',p=>p.assignments[1].booking.end='1101',
    p=>p.assignments[0].booking.units='2',p=>p.assignments[0].booking.gross='101',
    p=>p.assignments[0].acceleratorClass='cuda',p=>p.requirements[0].resources.nodes=65,
    p=>p.requirements[0].runtime.privateArguments=['secret'],p=>p.requirements[0].taskSHA256='99'.repeat(32)
  ]) {const p=structuredClone(f.checked.plan);change(p);assert.throws(()=>inspectExecutionPlan(p));}
});
test('DAG cycle, early successor and under-sized service windows are refused',()=>{
  const f=executionPlanFixture();
  for(const change of [
    p=>p.requirements[0].dependsOn=[1],p=>p.assignments[1].booking.start='1099',
    p=>p.requirements[1].resources.wallSeconds=101,p=>p.requirements[1].dependsOn=[0,0]
  ]) {const p=structuredClone(f.checked.plan);change(p);assert.throws(()=>inspectExecutionPlan(p));}
});
test('runtime, task, attempt and network changes invalidate the funded order commitment',()=>{
  const f=executionPlanFixture();const original=publicOrderPlan(f.job);
  executionPlanForOrder(f.checked.plan,f.job,f.context);
  for(const change of [
    p=>p.requirements[0].runtime.digestSHA256='99'.repeat(32),p=>p.assignments[0].attempt=2,
    p=>p.assignments[0].serviceSHA256='0x'+'99'.repeat(32),p=>p.genesisHash='0x'+'99'.repeat(32),
    p=>p.requirements[0].resources.cpus=2,p=>p.assignments[0].provider=p.assignments[1].provider
  ]) {
    const p=structuredClone(f.checked.plan);change(p);const changed=inspectExecutionPlan(p);
    assert.notEqual(changed.digestSHA256,f.job.executionPlanSHA256);
    assert.throws(()=>executionPlanForOrder(p,f.job,f.context));
    assert.notEqual(publicOrderPlan({...f.job,executionPlanSHA256:changed.digestSHA256}).jobHash,original.jobHash);
  }
  assert.throws(()=>executionPlanForOrder(f.checked.plan,f.job,{...f.context,chainId:1}));
  assert.throws(()=>executionPlanForOrder(f.checked.plan,f.job,{...f.context,genesisHash:'0x'+'99'.repeat(32)}));
  const legacy={...f.job,schema:'cannabis.compute.order.v2'};delete legacy.executionPlanSHA256;
  assert.notEqual(publicOrderPlan(legacy).jobHash,original.jobHash);
});
test('market preparation and wallet handoff retain the complete exact plan',()=>{
  const f=executionPlanFixture(),input={schema:'cannabis.market-plan.v1',kind:'order',asset:'ETH',job:f.job,settlement:f.settlement,
    executionPlan:f.checked.plan,bookings:f.assignments.map(a=>a.booking)};
  const retained=prepareMarketPlan(f.configuration,input);
  assert.equal(retained.detail.plannedTasks,2);assert.equal(retained.detail.plannedRanks,2);
  const action=marketAction(f.configuration,retained,{method:'fund',actor:f.job.requester,bookingId:null});
  assert.equal(action.summary.executionPlanSHA256,f.job.executionPlanSHA256);assert.equal(action.transaction.value,'20000');
  assert.equal(action.summary.serviceFeeBaseUnits,'200');assert.equal(action.summary.workerBaseUnits,'19800');
  const bad=structuredClone(input);bad.bookings[0].offerId=bad.bookings[1].offerId;
  assert.throws(()=>prepareMarketPlan(f.configuration,bad));
  delete bad.executionPlan;assert.throws(()=>prepareMarketPlan(f.configuration,bad));
  const terms=settlementForPlan(f.job,f.settlement,publicOrderPlan(f.job));
  assertExecutionSettlement(f.checked,terms);
  assert.throws(()=>assertExecutionSettlement(f.checked,{...terms,shares:[6000,4000]}));
});
test('requester/provider consent compares planned resources, runtime and network',()=>{
  const f=executionPlanFixture(),t=f.checked.plan.requirements[0],a=f.checked.plan.assignments[0];
  const lease={executionPlan:f.checked,assignments:[{reservationId:'selected-booking',task:0,run:plannedRun(t,a)}]};
  const profile={runtime:t.runtime,resources:t.resources,units:1};
  assertPlannedService(lease,'selected-booking',profile,f.context);
  assert.throws(()=>assertPlannedService(lease,'selected-booking',{...profile,resources:{...profile.resources,cpus:2}},f.context));
  assert.throws(()=>assertPlannedService(lease,'selected-booking',profile,{genesisHash:'0x'+'99'.repeat(32)}));
  assert.throws(()=>matchExecutionBookings(f.checked,[f.assignments[0].booking,f.assignments[0].booking]));
});
test('offline CLI prepares a group commitment and a directly importable market plan',()=>{
  const f=executionPlanFixture(),directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-plan-'));
  const write=(name,value)=>{const file=path.join(directory,name);fs.writeFileSync(file,JSON.stringify(value));return file;};
  const run=(command,context,input)=>{
    const result=spawnSync(process.execPath,['scripts/compute-execution-plan.mjs',command,write('context.json',context),write('input.json',input)],{encoding:'utf8',timeout:30000});
    assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);
  };
  try {
    const prepared=run('prepare',f.context,{descriptor:f.descriptor,assignments:f.assignments});
    const legacy={...f.job,schema:'cannabis.compute.order.v2'};delete legacy.executionPlanSHA256;
    const committed=run('commit-order',f.context,{job:legacy,executionPlan:prepared.plan});
    assert.equal(committed.job.executionPlanSHA256,f.job.executionPlanSHA256);assert.equal(committed.paymentAuthorized,false);
    const market=run('market-plan',f.configuration,{asset:'ETH',job:committed.job,executionPlan:committed.executionPlan,settlement:f.settlement});
    assert.equal(market.schema,'cannabis.market-plan.v1');assert.equal(market.bookings.length,2);
    prepareMarketPlan(f.configuration,market);
  } finally {fs.rmSync(directory,{recursive:true});}
});
