import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {Wallet,AbiCoder,TypedDataEncoder,keccak256,formatUnits,ZeroAddress} from 'ethers';
import {prepareExecutionPlan} from '../compute/execution_plan.mjs';
import {settlementTerms,termsDigest} from '../scripts/compute-escrow.mjs';
import {policy} from '../compute/settlement.mjs';
import {bookingPayload} from '../compute/market.mjs';
import {verifyMarketLeaseProof} from '../compute/market_lease.mjs';
import {deliveryApprovalTypes} from '../compute/key_delivery.mjs';
import {resultKeyCommitment} from '../compute/result_keys.mjs';
import {sealResultDelivery} from '../compute/result_delivery.mjs';
import {ResultInbox} from '../compute/result_inbox.mjs';
import {prepareDependencyHandoff,reviewDependencyHandoff,verifyDependencyHandoff} from '../compute/dependency_handoff.mjs';
import {launchFixture} from './helpers/launch_fixture.mjs';
import {nativeServiceCommitment} from '../compute/guest_execution.mjs';
import {validateGuestConfiguration} from '../compute/guest_configuration.mjs';
import {inspectGuestDependency} from '../compute/guest_dependency.mjs';
import {configuredMarketAttestationBinding,AttestationLedger} from '../compute/attestation.mjs';
import {guestInitialization} from '../compute/guest_initialization.mjs';
import {launchConsentPayload} from '../compute/guest_consent.mjs';
import {keyDeliveryPayload,openJobKeyDelivery,recoverRequesterJobKey} from '../compute/key_delivery.mjs';
import {GuestEvidenceSession} from '../compute/guest_session.mjs';
import {generateKeyPair,exportJWK,CompactEncrypt,calculateJwkThumbprint} from 'jose';

const h=n=>'0x'+n.toString(16).padStart(64,'0');
const python=process.env.CANNABIS_PYTHON||'python',age=process.env.CANNABIS_AGE||'age';
const script=path.resolve('test/helpers/dependency_bundle_fixture.py');
function run(root,action,extra={}) {
  return JSON.parse(execFileSync(python,[script],{input:JSON.stringify({root,age,action,...extra}),encoding:'utf8',
    windowsHide:true,stdio:['pipe','pipe','ignore'],timeout:60000,maxBuffer:1024*1024}));
}
async function fixture(t,{operating=false}={}) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-handoff-')),keys=[];
  let inbox;
  t.after(()=>{inbox?.close();keys.forEach(k=>k.fill(0));
    assert.equal(path.dirname(path.resolve(root)),path.resolve(os.tmpdir()));assert.ok(path.basename(root).startsWith('cannabis-handoff-'));
    fs.rmSync(root,{recursive:true,force:true});});
  const data=run(root,'setup',{native:operating}),owner=Wallet.createRandom(),providerWallets=Array.from({length:4},()=>Wallet.createRandom()),providers=providerWallets.map(w=>w.address);
  const network={chainId:31337,genesisHash:h(1),market:Wallet.createRandom().address,escrow:Wallet.createRandom().address,token:ZeroAddress,requester:owner.address};
  let configuration;
  if(operating) {
    configuration=launchFixture().configuration;
    Object.assign(configuration,{schema:'cannabis.guest-launch-configuration.v3',context:{chainId:31337,market:network.market,token:network.token},provider:providers[3],resourceId:h(53)});
    Object.assign(configuration.network,{market:network.market,marketCodeHash:h(500),escrow:network.escrow,genesisHash:network.genesisHash});
    const p=configuration.execution.profile;
    Object.assign(p,{schema:'cannabis.guest-native-service.v3',runtime:data.spec.tasks[2].runtime,resources:data.spec.tasks[2].resources,maxDependencyBytes:128});
    Object.assign(p.ciphertext,{bytes:12*1024**2,dependencyBytes:4*1024**2});
  }
  const assignments=[[0,0],[1,0],[1,1],[2,0]].map(([task,rank],i)=>({task,rank,attempt:1,acceleratorClass:'cpu',provider:providers[i],serviceSHA256:h(10+i),
    booking:{reservationId:h(20+i),offerId:h(30+i),start:task===2?'1100':'1000',end:task===2?'1200':'1100',holdUntil:'900',gross:'10000',units:'1'}}));
  if(operating)assignments[3].serviceSHA256=nativeServiceCommitment(configuration.execution).serviceSHA256;
  const plan=prepareExecutionPlan(data.descriptor,network,assignments),coder=AbiCoder.defaultAbiCoder();
  const job={schema:'cannabis.compute.order.v3',id:data.descriptor.id,requester:owner.address,packageSHA256:data.descriptor.ciphertextSHA256,
    policySHA256:data.descriptor.policySHA256,executionPlanSHA256:plan.digestSHA256,acceptanceSHA256:h(40).slice(2),
    payment:{totalBudget:formatUnits(40000n,18),feeBasisPoints:100,founderRecipient:policy.founderRecipient}};
  const settlement={workers:providers.map(account=>({account,shareBps:2500})),deliveryManager:providers[0],adjudicator:Wallet.createRandom().address,
    acceptBy:'1970-01-01T00:15:00Z',deliverBy:'1970-01-01T00:21:40Z',reviewSeconds:86400,disputeSeconds:86400};
  const terms=settlementTerms(job,settlement),orderId=keccak256(coder.encode(['string','uint256','address','address','bytes32'],
    ['Cannabis compute order v1',network.chainId,network.escrow,owner.address,terms.terms.jobHash]));
  const termsHash=termsDigest({chainId:network.chainId,escrow:network.escrow,token:network.token,founderRecipient:policy.founderRecipient,...terms});
  const bookings=assignments.map((a,i)=>{
    const booking={...a.booking,requester:owner.address,orderId,termsDigest:termsHash};
    return {booking,bookingId:bookingPayload(network,booking).digest,resource:{provider:a.provider,serviceHash:a.serviceSHA256,units:'1'},
      offer:{resource:h(50+i),escrow:network.escrow,policyHash:'0x'+job.policySHA256,manifestHash:h(60+i),
        start:booking.start,end:booking.end,expiresAt:'900',units:'1',grossPerUnitSecond:'100'}};
  }).sort((a,b)=>a.bookingId.localeCompare(b.bookingId));
  // Consistent invented records are used solely for offline commitment checks.
  const proof={schema:'cannabis.market-lease.v2',chainId:network.chainId,market:network.market,escrow:network.escrow,token:network.token,
    job,settlement,executionPlan:plan.plan,bookings,fundedAnchor:{number:1,hash:h(70),timestamp:900}};
  const lease=verifyMarketLeaseProof(proof,network);
  inbox=new ResultInbox(path.join(root,'inbox.sqlite'),{chainId:network.chainId,escrow:network.escrow,requester:owner.address});
  const types=deliveryApprovalTypes('3'),domain={name:'Cannabis confidential key delivery',version:'3',chainId:network.chainId,verifyingContract:network.escrow};
  const results=[],byRelease=new Map();
  for(const [i,item] of data.results.entries()) {
    const task=data.spec.tasks.findIndex(t=>t.id===item.receipt.taskId),a=lease.assignments.find(a=>a.task===task&&a.run.rank===item.receipt.rank);
    const key=randomBytes(32);keys.push(key);byRelease.set(h(100+i),key);
    const value=Object.fromEntries(types.JobKeyDelivery.map(({name,type})=>[name,type==='bytes32'?h(200):type==='string'?data.descriptor.recipient:1]));
    Object.assign(value,{releaseId:h(100+i),leaseDigest:lease.digest,orderId:lease.orderId,reservationId:a.reservationId,
      packageSHA256:'0x'+job.packageSHA256,policySHA256:'0x'+job.policySHA256,runtimeSHA256:'0x'+a.run.runtimeSHA256,
      taskSHA256:'0x'+a.run.taskSHA256,rank:a.run.rank,worldSize:a.run.worldSize,resultKeySHA256:resultKeyCommitment(key),notBefore:1000,expiresAt:1050});
    const approval={domain,value,digest:TypedDataEncoder.hash(domain,types,value),requester:owner.address,jobId:job.id,
      requesterSignature:await owner.signTypedData(domain,types,value)};
    inbox.activate({schema:'cannabis.key-delivery.record.v3',keyWrapped:true,releaseId:value.releaseId,approvalDigest:approval.digest,expectedApproval:approval},
      {resultRecipient:data.spec.resultRecipient});
    await inbox.receive(approval.digest,await sealResultDelivery(item.receipt,key,approval),async()=>Buffer.from(key));
    results.push({approvalDigest:approval.digest,file:item.file});
  }
  const reservationId=lease.assignments.find(a=>a.task===2).reservationId;
  const options={inbox,proof,network,reservationId,descriptor:data.descriptor,results,window:{notBefore:1100,expiresAt:1150},
    source:{python:execFileSync(python,['-c','import sys; print(sys.executable)'],{encoding:'utf8',windowsHide:true}).trim(),
      age:path.isAbsolute(age)?age:execFileSync(python,['-c','import shutil; print(shutil.which("age"))'],{encoding:'utf8',windowsHide:true}).trim(),
      identity:path.join(root,'owner.key'),manifest:path.join(root,'workload.json'),destination:path.join(root,'dependency.age')},
    loadResultKey:async binding=>Buffer.from(byRelease.get(binding.releaseId))};
  return {root,...data,owner,inbox,options,configuration,provider:providerWallets[3]};
}

test('authenticated three-result fan-in is encrypted to the job key with only declared files',async t=>{
  const f=await fixture(t),prepared=await prepareDependencyHandoff(f.options);
  assert.equal(prepared.sourceReceiptsAuthenticated,true);assert.equal(prepared.sourceIntegrityVerified,true);
  assert.equal(prepared.paymentAuthorized,false);assert.equal(prepared.keyReleaseAuthorized,false);
  const payload=reviewDependencyHandoff(f.inbox,f.options.proof,f.options.network,f.options.reservationId,f.descriptor,prepared);
  const signed={handoff:prepared.handoff,window:prepared.window,requesterSignature:await f.owner.signTypedData(payload.domain,payload.types,payload.value)};
  assert.equal(verifyDependencyHandoff(f.options.proof,f.options.network,f.options.reservationId,f.descriptor,signed,1100).inputAuthorized,true);
  const opened=run(f.root,'open',{handoff:prepared.handoff,ciphertext:'dependency.age',destination:'opened'});
  assert.deepEqual(opened.files,{'inputs/first-0.txt':'first:0:authenticated','inputs/second-0.txt':'second:0:authenticated','inputs/second-1.txt':'second:1:authenticated'});
  for(const privateText of ['selected.txt','unselected.txt','first:0:authenticated']) {
    assert.equal(JSON.stringify(payload).includes(privateText),false);
    assert.equal(fs.readFileSync(f.options.source.destination).includes(Buffer.from(privateText)),false);
  }
  assert.throws(()=>verifyDependencyHandoff(f.options.proof,f.options.network,f.options.reservationId,f.descriptor,signed,1150));
  for(const mutate of [s=>s.handoff.ciphertextSHA256='ab'.repeat(32),s=>s.handoff.context.sources[0].attempt++,
    s=>s.handoff.context.rank++,s=>s.handoff.context.genesisHash=h(999),s=>s.window.expiresAt++]) {
    const altered=structuredClone(signed);mutate(altered);
    assert.throws(()=>verifyDependencyHandoff(f.options.proof,f.options.network,f.options.reservationId,f.descriptor,altered,1101));
  }
  const wrong={...signed,requesterSignature:await Wallet.createRandom().signTypedData(payload.domain,payload.types,payload.value)};
  assert.throws(()=>verifyDependencyHandoff(f.options.proof,f.options.network,f.options.reservationId,f.descriptor,wrong,1101));
  f.inbox.retire(f.options.results[0].approvalDigest);
  assert.throws(()=>reviewDependencyHandoff(f.inbox,f.options.proof,f.options.network,f.options.reservationId,f.descriptor,prepared),/retired/);
});

test('dependency preparation refuses incomplete inputs, corruption, mapping collisions and bounded overflow',async t=>{
  const f=await fixture(t);
  assert.equal(run(f.root,'mapping-refusals').refusals,9);
  await assert.rejects(prepareDependencyHandoff({...f.options,results:f.options.results.slice(1)}));
  assert.equal(fs.existsSync(f.options.source.destination),false);
  await assert.rejects(prepareDependencyHandoff({...f.options,window:{notBefore:1099,expiresAt:1150}}));
  const file=f.options.results[0].file,original=fs.readFileSync(file),changed=Buffer.from(original);changed[changed.length-1]^=1;fs.writeFileSync(file,changed);
  await assert.rejects(prepareDependencyHandoff(f.options));fs.writeFileSync(file,original);
  const limited=structuredClone(f.spec);limited.tasks[2].dependencyInputMaxBytes=1;
  fs.writeFileSync(f.options.source.manifest,JSON.stringify(limited));
  await assert.rejects(prepareDependencyHandoff(f.options));fs.writeFileSync(f.options.source.manifest,JSON.stringify(f.spec));
  assert.equal(fs.existsSync(f.options.source.destination),false);
  const prepared=await prepareDependencyHandoff(f.options),swapped=structuredClone(prepared.handoff);swapped.context.sources[0].ciphertextSHA256='fe'.repeat(32);
  assert.throws(()=>run(f.root,'open',{handoff:swapped,ciphertext:'dependency.age',destination:'bad-open'}));
  assert.equal(fs.existsSync(path.join(f.root,'bad-open')),false);
  assert.equal(fs.readdirSync(f.root).some(n=>n.startsWith('.cannabis-')),false);
});

test('dependent guest key approval retains the signed capsule through v4 encryption and refuses downgrade',async t=>{
  const f=await fixture(t,{operating:true}),o=f.options,c=f.configuration,prepared=await prepareDependencyHandoff(o);
  const signed={handoff:prepared.handoff,window:prepared.window,
    requesterSignature:await f.owner.signTypedData(prepared.approval.domain,prepared.approval.types,prepared.approval.value)};
  const dependency={descriptor:f.descriptor,signed},lease=verifyMarketLeaseProof(o.proof,c.context),run=lease.assignments.find(a=>a.reservationId===o.reservationId).run;
  const binding=configuredMarketAttestationBinding(o.proof,c.context,o.reservationId,run,validateGuestConfiguration(c).configurationSHA256,1101);
  const inspect=d=>inspectGuestDependency({proof:o.proof,network:c.network,binding,execution:c.execution,dependency:d,now:1101});
  const retained=inspect(dependency);assert.equal(retained.approvalDigest,prepared.approval.digest);
  assert.throws(()=>inspect(undefined),/Dependency/);
  const bad=structuredClone(dependency);bad.signed.handoff.context.sources[0].ciphertextSHA256='aa'.repeat(32);assert.throws(()=>inspect(bad));
  const tooSmall=structuredClone(c.execution);tooSmall.profile.ciphertext.dependencyBytes=1;
  assert.throws(()=>inspectGuestDependency({proof:o.proof,network:c.network,binding,execution:tooSmall,dependency,now:1101}));
  const initialization={schema:'cannabis.guest-initialization.v2',tee:'snp',requester:f.owner.address,jobId:f.descriptor.id,binding};
  const consents=[];
  for(const [role,wallet] of [['requester',f.owner],['provider',f.provider]]) {
    const p=launchConsentPayload(c,initialization,o.proof,role);
    consents.push({role,signer:wallet.address,signature:await wallet.signTypedData(p.domain,p.types,p.value)});
  }
  const consent={schema:'cannabis.guest-launch-consent.v1',configuration:c,consents};
  const policy=structuredClone(c.attestationPolicyTemplate);policy.measurements.initData=guestInitialization(initialization).digest;
  const ledger=new AttestationLedger(':memory:',policy,()=>1101);t.after(()=>ledger.close());const challenge=ledger.challenge(binding);
  const pair=await generateKeyPair('ECDH-ES+A256KW'),channelJwk=await exportJWK(pair.publicKey),resultKey=randomBytes(32);t.after(()=>resultKey.fill(0));
  const capacity={schema:'cannabis.market-requester.v3',context:c.context,proof:o.proof,configuration:c,consent};
  const request={releaseId:h(900),leaseId:lease.digest,nonce:challenge.nonce,channelJwk,descriptor:f.descriptor,
    notBefore:1101,expiresAt:1140,resultKeySHA256:resultKeyCommitment(resultKey),dependency:signed};
  const payload=keyDeliveryPayload(capacity,ledger,request,1101);
  assert.equal(payload.domain.version,'4');assert.equal(payload.value.dependencyApprovalDigest,prepared.approval.digest);
  const missing={...request};delete missing.dependency;assert.throws(()=>keyDeliveryPayload(capacity,ledger,missing,1101));
  assert.throws(()=>keyDeliveryPayload(capacity,ledger,{...request,expiresAt:1151},1101),/window/);
  const requesterSignature=await f.owner.signTypedData(payload.domain,payload.types,payload.value);
  const recovered=await recoverRequesterJobKey({python:o.source.python,age:o.source.age,identity:o.source.identity,
    capsule:path.join(f.root,'job/job-key.age'),descriptor:path.join(f.root,'job/descriptor.json')},
    {jobId:f.descriptor.id,packageSHA256:f.descriptor.ciphertextSHA256,policySHA256:f.descriptor.policySHA256,
      capsuleSHA256:f.descriptor.keyCustody.ciphertextSHA256,inputRecipient:f.descriptor.recipient});
  const plain=Buffer.from(JSON.stringify({schema:'cannabis.job-key.delivery.v4',notAfter:1140,
    approval:{domain:payload.domain,value:payload.value,requester:f.owner.address,signature:requesterSignature},job:recovered,resultKey:resultKey.toString('base64url')}));
  let envelope;
  try{envelope=await new CompactEncrypt(plain).setProtectedHeader({alg:'ECDH-ES+A256KW',enc:'A256GCM',typ:'cannabis-job-key+jwe',
    kid:await calculateJwkThumbprint(channelJwk),'cannabis-approval':payload.digest}).encrypt(pair.publicKey);}finally{plain.fill(0);}
  const opened=await openJobKeyDelivery(envelope,pair.privateKey,payload,{clock:()=>1101,ageKeygen:path.join(path.dirname(o.source.age),process.platform==='win32'?'age-keygen.exe':'age-keygen')});
  assert.equal(opened.inputRecipient,f.descriptor.recipient);assert.deepEqual(opened.resultKey,resultKey);opened.resultKey.fill(0);
  const changed=structuredClone(payload);changed.value.dependencyApprovalDigest=h(998);
  await assert.rejects(openJobKeyDelivery(envelope,pair.privateKey,changed,{clock:()=>1101}));
  const funding={proof:o.proof,context:c.context,network:c.network,provider:c.provider,resourceId:c.resourceId,
    serviceSHA256:nativeServiceCommitment(c.execution).serviceSHA256,consent};
  const session=await GuestEvidenceSession.create({initialization,policy,challenge,expectedBinding:binding,requester:f.owner.address,
    jobId:f.descriptor.id,funding,execution:c.execution,dependency:retained},{clock:()=>1101});
  try {
    const downgraded={...payload,domain:{...payload.domain,version:'3'}};
    await assert.rejects(session.executeNative(envelope,downgraded),/dependency approval/);
  } finally {session.close();}
});
