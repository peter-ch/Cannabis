import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { ContractFactory, formatUnits, keccak256, ZeroAddress } from 'ethers';
import { compile } from '../scripts/compile.mjs';
import { startNode } from '../scripts/lib.mjs';
import { CapacityLedger, offerPayload, reservationPayload } from '../compute/capacity.mjs';
import { inspectLease, leasePayload, promoteLease } from '../compute/leases.mjs';
import { readFinalizedEscrow } from '../compute/finality.mjs';
import { leaseAttestationBinding } from '../compute/attestation.mjs';
import { AttestationLedger, trusteeRuntimeData, requestTrusteeResult, trusteeEvidenceRequest } from '../compute/attestation.mjs';
import { keyDeliveryPayload, sealJobKeyDelivery, openJobKeyDelivery, recoverRequesterJobKey, inspectKeyDelivery } from '../compute/key_delivery.mjs';
import { settlementTerms } from '../scripts/compute-escrow.mjs';
import { policy } from '../scripts/compute-plan.mjs';
import { guestInitialization } from '../compute/guest_initialization.mjs';
import { exportLeaseProof, verifyLeaseProof } from '../compute/lease_proof.mjs';
import { GuestFunding } from '../compute/guest_funding.mjs';
import { nativeServiceCommitment } from '../compute/guest_execution.mjs';
import { createResultKeyCustody, recoverRequesterResultKey } from '../compute/result_keys.mjs';
import { openResultDelivery, sealResultDelivery } from '../compute/result_delivery.mjs';

const h=n=>'0x'+n.toString(16).padStart(64,'0');
const utc=t=>new Date(t*1000).toISOString().replace('.000Z','Z');
let node,provider,owner,first,second,resolver,asset,escrow,network,nativeEscrow,nativeNetwork,snapshot;
async function port(){return new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});}
function cleanTemp(dir){for(const name of fs.readdirSync(dir))fs.unlinkSync(path.join(dir,name));fs.rmdirSync(dir);}
before(async()=>{
  const artifacts=compile({'LeaseFixture.sol':{content:`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract LeaseAsset is ERC20 { constructor() ERC20("Isolated lease verification", "FIX") { _mint(msg.sender, 1000000 ether); } }`}});
  node=await startNode(await port(),'lease-test-node.log');provider=node.provider;
  [owner,first,second,resolver]=await Promise.all([0,1,2,3].map(i=>provider.getSigner(i)));
  asset=await new ContractFactory(artifacts.LeaseAsset.abi,artifacts.LeaseAsset.bytecode,owner).deploy();await asset.waitForDeployment();
  escrow=await new ContractFactory(artifacts.ComputeEscrow.abi,artifacts.ComputeEscrow.bytecode,owner).deploy(await asset.getAddress(),policy.founderRecipient);await escrow.waitForDeployment();
  await (await asset.approve(await escrow.getAddress(),1000000000n)).wait();
  network={rpc:node.rpc,chainId:31337,token:await asset.getAddress(),escrow:await escrow.getAddress(),
    genesisHash:(await provider.getBlock(0)).hash,escrowCodeHash:keccak256(await provider.getCode(await escrow.getAddress())),
    tokenCodeHash:keccak256(await provider.getCode(await asset.getAddress())),finality:'rpc-finalized',maxFinalizedAgeSeconds:1800};
  nativeEscrow=await new ContractFactory(artifacts.ComputeEscrow.abi,artifacts.ComputeEscrow.bytecode,owner).deploy(ZeroAddress,policy.founderRecipient);await nativeEscrow.waitForDeployment();
  nativeNetwork={...network,token:ZeroAddress,escrow:await nativeEscrow.getAddress(),tokenCodeHash:null,
    escrowCodeHash:keccak256(await provider.getCode(await nativeEscrow.getAddress()))};
  snapshot=await provider.send('evm_snapshot',[]);
});
after(()=>{provider?.destroy();node?.child.kill();});

async function setup({file=':memory:',gross=[3000n,2000n],packageSHA256=h(80).slice(2),serviceSHA256=h(20),native=false}={}) {
  await provider.send('evm_revert',[snapshot]);snapshot=await provider.send('evm_snapshot',[]);
  const now=(await provider.getBlock('latest')).timestamp;
  const selectedNetwork=native?nativeNetwork:network;
  const context={chainId:31337,registryId:h(1),token:selectedNetwork.token},ledger=new CapacityLedger(file,context);
  const signers=[first,second],requester=await owner.getAddress(),reservations=[];
  for(let i=0;i<2;i++) {
    const address=await signers[i].getAddress();
    ledger.admitResource({provider:address,resourceId:h(10+i),serviceSHA256:i===0?serviceSHA256:h(20+i),units:1});
    const offer={offerId:h(30+i),provider:address,resourceId:h(10+i),serviceSHA256:i===0?serviceSHA256:h(20+i),policySHA256:h(90),token:context.token,
      windowStart:now+100,windowEnd:now+10000,expiresAt:now+1800,units:1,grossPerUnitSecond:(gross[i]/100n).toString(),feeBps:100,termsSHA256:h(40+i)};
    const op=offerPayload(context,offer),signed={offer,signature:await signers[i].signTypedData(op.domain,op.types,op.value)};
    const digest=ledger.addOffer(signed,now).offerDigest;
    const reservation={reservationId:h(50+i),offerDigest:digest,requester,jobSHA256:'0x'+packageSHA256,start:now+900,end:now+1000,units:1,grossBaseUnits:gross[i].toString(),holdUntil:now+600};
    const rp=reservationPayload(context,reservation),sr={reservation,requesterSignature:await owner.signTypedData(rp.domain,rp.types,rp.value),providerSignature:await signers[i].signTypedData(rp.domain,rp.types,rp.value)};
    ledger.reserve(sr,now);reservations.push(sr);
  }
  const total=gross.reduce((a,b)=>a+b,0n);
  const job={schema:'cannabis.compute.order.v2',id:'private-workload',requester,packageSHA256,policySHA256:h(90).slice(2),acceptanceSHA256:h(91).slice(2),payment:{totalBudget:formatUnits(total,18),feeBasisPoints:100,founderRecipient:policy.founderRecipient}};
  const settlement={workers:[{account:await first.getAddress(),shareBps:6000},{account:await second.getAddress(),shareBps:4000}],deliveryManager:await first.getAddress(),adjudicator:await resolver.getAddress(),acceptBy:utc(now+700),deliverBy:utc(now+1200),reviewSeconds:86400,disputeSeconds:86400};
  const request={leaseId:h(60),reservationIds:reservations.map(x=>x.reservation.reservationId),job,settlement,escrow:selectedNetwork.escrow,expiresAt:now+500};
  const clock=()=>now+30;
  return {ledger,context,now,clock,request,reservations,network:selectedNetwork};
}
async function sign(ledger,request,now) {
  const p=leasePayload(ledger,request,now);
  return {request,requesterSignature:await owner.signTypedData(p.domain,p.types,p.value),providerSignatures:await Promise.all([first,second].map(async s=>({provider:await s.getAddress(),signature:await s.signTypedData(p.domain,p.types,p.value)})))};
}
async function fund(request,{activate=true}={}) {
  const t=settlementTerms(request.job,request.settlement);
  const native=request.escrow===nativeNetwork.escrow,selected=native?nativeEscrow:escrow;
  await (await selected.fund(t.terms,t.accounts,t.shares,native?{value:t.terms.budget}:{})).wait();
  const id=await selected.orderId(t.requester,t.terms.jobHash);
  if(activate){await (await selected.connect(first).accept(id)).wait();await (await selected.connect(second).accept(id)).wait();}
  return id;
}
async function competing(setup,id,changes={},at=setup.now+601) {
  const reservation={...setup.reservations[0].reservation,reservationId:h(id),holdUntil:setup.now+800,...changes};
  const p=reservationPayload(setup.context,reservation);
  const signed={reservation,requesterSignature:await owner.signTypedData(p.domain,p.types,p.value),providerSignature:await first.signTypedData(p.domain,p.types,p.value)};
  return ()=>setup.ledger.reserve(signed,at);
}

test('finalized funding promotes a whole provider group atomically and protects capacity after hold expiry',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-funded-lease-')),file=path.join(dir,'capacity.sqlite');
  const s=await setup({file});let reopened;
  try {
    const signed=await sign(s.ledger,s.request,s.now);await fund(s.request);
    const record=await promoteLease(s.ledger,signed,network,s.clock);
    assert.equal(record.executionAuthorized,false);assert.equal(record.keyReleaseAuthorized,false);assert.equal(record.paymentSent,false);
    assert.equal(record.reservations.length,2);assert.equal(record.finalityEvidence.state,2);
    assert.equal(record.finalityEvidence.finalizedBlock.hash,(await provider.getBlock('finalized')).hash);
    const run={runtimeSHA256:h(92).slice(2),taskSHA256:h(93).slice(2),attempt:1,rank:0,worldSize:1,acceleratorClass:'cpu'};
    const binding=leaseAttestationBinding(s.ledger,record.leaseId,h(50),run,s.now+30);
    assert.equal(binding.leaseDigest,record.digest);assert.equal(binding.orderId,record.orderId);
    assert.equal(binding.packageSHA256,s.request.job.packageSHA256);assert.equal(binding.policySHA256,s.request.job.policySHA256);
    assert.throws(()=>leaseAttestationBinding(s.ledger,record.leaseId,h(999),run,s.now+30),/Unknown/);
    assert.throws(()=>leaseAttestationBinding(s.ledger,record.leaseId,h(50),run,s.now+1000),/elapsed/);
    assert.throws(await competing(s,100),/already reserved/);
    assert.throws(await competing(s,101,{start:s.now+950,end:s.now+1050}),/already reserved/);
    // A touching future interval is independently available.
    assert.equal((await competing(s,102,{start:s.now+1000,end:s.now+1100}))().executionAuthorized,false);
    await assert.rejects(promoteLease(s.ledger,signed,network,s.clock),/already belongs/);
    s.ledger.close();reopened=new CapacityLedger(file,s.context);
    assert.equal(inspectLease(reopened,s.request.leaseId).digest,record.digest);
    s.ledger=reopened;assert.throws(await competing(s,103),/already reserved/);
  }finally{s.ledger.close();cleanTemp(dir);}
});

test('unsigned or altered lease agreements cannot bind capacity or substitute jobs, policies or prices',async()=>{
  const s=await setup();try {
    const signed=await sign(s.ledger,s.request,s.now);await fund(s.request);
    for(const change of [{requesterSignature:signed.providerSignatures[0].signature},{providerSignatures:[signed.providerSignatures[0],signed.providerSignatures[0]]}])
      await assert.rejects(promoteLease(s.ledger,{...signed,...change},network,s.clock),/signature/);
    for(const change of [{packageSHA256:h(99).slice(2)},{policySHA256:h(99).slice(2)},{requester:await resolver.getAddress()},{payment:{...s.request.job.payment,totalBudget:formatUnits(6000n,18)}}])
      assert.throws(()=>leasePayload(s.ledger,{...s.request,job:{...s.request.job,...change}},s.now));
    assert.throws(()=>leasePayload(s.ledger,{...s.request,reservationIds:[h(50),h(50)]},s.now),/unique/);
    assert.throws(()=>leasePayload(s.ledger,{...s.request,settlement:{...s.request.settlement,privateArguments:['must stay encrypted']}},s.now),/lease fields/);
    assert.throws(()=>leasePayload(s.ledger,{...s.request,expiresAt:s.now+601},s.now),/signing window/);
    assert.throws(()=>leasePayload(s.ledger,{...s.request,settlement:{...s.request.settlement,deliverBy:utc(s.now+999)}},s.now),/service interval/);
    assert.equal(s.ledger.db.prepare('SELECT count(*) AS n FROM lease_bundles').get().n,0);
  }finally{s.ledger.close();}
});

test('unfunded, partly accepted and already delivered orders cannot promote a service lease',async()=>{
  const s=await setup();try {
    const signed=await sign(s.ledger,s.request,s.now);
    await assert.rejects(promoteLease(s.ledger,signed,network,s.clock),/does not exist/);
    const id=await fund(s.request,{activate:false});await (await escrow.connect(first).accept(id)).wait();
    await assert.rejects(promoteLease(s.ledger,signed,network,s.clock),/Every provider/);
    await (await escrow.connect(second).accept(id)).wait();await (await escrow.connect(first).deliver(id,h(104))).wait();
    await assert.rejects(promoteLease(s.ledger,signed,network,s.clock),/Every provider/);
    assert.equal(s.ledger.db.prepare('SELECT count(*) AS n FROM leased_reservations').get().n,0);
  }finally{s.ledger.close();}
});

test('finality checks reject wrong network, runtime, stale views and changed settlement',async()=>{
  const s=await setup();try {
    const signed=await sign(s.ledger,s.request,s.now),id=await fund(s.request);
    for(const change of [{chainId:1},{genesisHash:h(200)},{escrowCodeHash:h(201)},{tokenCodeHash:h(202)},{finality:'latest'}])
      await assert.rejects(promoteLease(s.ledger,signed,{...network,...change},s.clock));
    await assert.rejects(readFinalizedEscrow({...network,orderId:id,maxFinalizedAgeSeconds:1},()=>s.now+100),/stale/);
    const changed={...s.request,settlement:{...s.request.settlement,reviewSeconds:172800}};
    await assert.rejects(promoteLease(s.ledger,await sign(s.ledger,changed,s.now),network,s.clock),/differs from the signed lease/);
  }finally{s.ledger.close();}
});

// A forwarding RPC changes only the targeted observation. Contract execution remains real.
async function proxy(transform) {
  const server=http.createServer(async(req,res)=>{
    const parts=[];for await(const part of req)parts.push(part);
    const body=JSON.parse(Buffer.concat(parts));
    const one=async message=>{
      const upstream=await fetch(node.rpc,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(message)});
      return transform(message,await upstream.json());
    };
    const result=Array.isArray(body)?await Promise.all(body.map(one)):await one(body);
    res.setHeader('content-type','application/json');res.end(JSON.stringify(result));
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  return {url:'http://127.0.0.1:'+server.address().port,close:async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));}};
}

test('unsupported hash-bound reads and canonicality changes fail closed without partial lease writes',async()=>{
  const s=await setup();try {
    const signed=await sign(s.ledger,s.request,s.now);await fund(s.request);
    for(const mode of ['unsupported','reorg']) {
      let hashReads=0;
      const p=await proxy((request,response)=>{
        if(['eth_call','eth_getCode'].includes(request.method)) {
          assert.equal(request.params[1].requireCanonical,true);assert.match(request.params[1].blockHash,/^0x[0-9a-f]{64}$/);hashReads++;
          if(mode==='unsupported')return {id:request.id,jsonrpc:'2.0',error:{code:-32602,message:'No hash parameter'}};
        }
        if(mode==='reorg' && request.method==='eth_getBlockByNumber' && /^0x[1-9a-f]/i.test(request.params[0]))return {...response,result:{...response.result,hash:h(999)}};
        return response;
      });
      try{await assert.rejects(promoteLease(s.ledger,signed,{...network,rpc:p.url},s.clock),mode==='unsupported'?/block\/hash support/:/chain changed/);assert.ok(hashReads>0);}
      finally{await p.close();}
      assert.equal(s.ledger.db.prepare('SELECT count(*) AS n FROM lease_bundles').get().n,0);
    }
  }finally{s.ledger.close();}
});

test('expiry during RPC observation cannot resurrect a hold that another booking has acquired',async()=>{
  const s=await setup();let p;
  try {
    const signed=await sign(s.ledger,s.request,s.now);await fund(s.request);let now=s.now+30,changed=false;
    const replace=await competing(s,250,{holdUntil:s.now+800},s.now+601);
    p=await proxy((request,response)=>{
      if(request.method==='eth_call'&&!changed){changed=true;now=s.now+601;replace();}
      return response;
    });
    await assert.rejects(promoteLease(s.ledger,signed,{...network,rpc:p.url},()=>now),/expired/);
    assert.equal(s.ledger.db.prepare('SELECT count(*) AS n FROM leased_reservations').get().n,0);
    assert.ok(s.ledger.db.prepare('SELECT id FROM reservations WHERE id=?').get(h(250)));
  }finally{if(p)await p.close();s.ledger.close();}
});

test('basis-point settlement never silently changes signed capacity prices',async()=>{
  const s=await setup({gross:[1000n,2000n]});try {
    assert.throws(()=>leasePayload(s.ledger,s.request,s.now),/cannot be represented/);
  }finally{s.ledger.close();}
});

test('concurrent promoters on separate connections can commit a bundle only once',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-lease-race-')),file=path.join(dir,'capacity.sqlite');
  const s=await setup({file}),other=new CapacityLedger(file,s.context);
  try {
    const signed=await sign(s.ledger,s.request,s.now);await fund(s.request);
    const results=await Promise.allSettled([promoteLease(s.ledger,signed,network,s.clock),promoteLease(other,signed,network,s.clock)]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
    assert.equal(s.ledger.db.prepare('SELECT count(*) AS n FROM lease_bundles').get().n,1);
    assert.equal(other.db.prepare('SELECT count(*) AS n FROM leased_reservations').get().n,2);
  }finally{other.close();s.ledger.close();cleanTemp(dir);}
});

test('multiple resources belonging to one provider aggregate into the exact funded provider share',async()=>{
  const s=await setup();try {
    const account=await first.getAddress();
    s.ledger.admitResource({provider:account,resourceId:h(300),serviceSHA256:h(301),units:1});
    const offer={offerId:h(302),provider:account,resourceId:h(300),serviceSHA256:h(301),policySHA256:h(90),token:s.context.token,
      windowStart:s.now+100,windowEnd:s.now+10000,expiresAt:s.now+1800,units:1,grossPerUnitSecond:'30',feeBps:100,termsSHA256:h(303)};
    const op=offerPayload(s.context,offer),offerDigest=s.ledger.addOffer({offer,signature:await first.signTypedData(op.domain,op.types,op.value)},s.now).offerDigest;
    const reservation={...s.reservations[0].reservation,reservationId:h(304),offerDigest};
    const rp=reservationPayload(s.context,reservation);
    s.ledger.reserve({reservation,requesterSignature:await owner.signTypedData(rp.domain,rp.types,rp.value),providerSignature:await first.signTypedData(rp.domain,rp.types,rp.value)},s.now);
    s.request.reservationIds.push(reservation.reservationId);s.request.job.payment.totalBudget=formatUnits(8000n,18);
    s.request.settlement.workers[0].shareBps=7500;s.request.settlement.workers[1].shareBps=2500;
    const signed=await sign(s.ledger,s.request,s.now);await fund(s.request);
    const promoted=await promoteLease(s.ledger,signed,network,s.clock);
    assert.equal(promoted.reservations.length,3);assert.deepEqual(promoted.finalityEvidence.shares,[7500,2500]);
    assert.equal(s.ledger.db.prepare('SELECT count(*) AS n FROM leased_reservations').get().n,3);
  }finally{s.ledger.close();}
});

// Cross-language integration: real age capsule, real local escrow, synthetic EAR
// signed by a disposable verifier. These fixtures do not claim protected hardware.
import { GuestEvidenceSession } from '../compute/guest_session.mjs';
import { guestAgentFixture } from './helpers/guest_agent_fixture.mjs';
const verifierKey=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
function canonicalFixture(value) {
  if(Array.isArray(value))return value.map(canonicalFixture);
  if(value && typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonicalFixture(value[k])]));
  return value;
}
function earFixture(d) {
  const runtime=trusteeRuntimeData(d.challenge,d.channel),m=d.attestationPolicy.measurements;
  const claims={iss:d.attestationPolicy.issuer,iat:d.time,exp:d.time+300,eat_profile:'tag:github.com,2024:confidential-containers/Trustee',
    'ear.verifier-id':{developer:'https://confidentialcontainers.org',build:d.attestationPolicy.verifierBuild},
    submods:{cpu0:{'ear.status':'affirming','ear.appraisal-policy-id':d.attestationPolicy.appraisalPolicyId,
      'ear.trustworthiness-vector':{'instance-identity':0,configuration:2,executables:3,'file-system':0,hardware:2,'runtime-opaque':0,'storage-opaque':0,'sourced-data':0},
      'ear.veraison.annotated-evidence':{snp:{measurement:m.launch,policy_debug_allowed:false,policy_migrate_ma:false,
        reported_tcb_bootloader:1,reported_tcb_tee:1,reported_tcb_snp:1,reported_tcb_microcode:1},
        init_data:m.initData,init_data_claims:null,runtime_data_claims:runtime,
        report_data:createHash('sha384').update(JSON.stringify(canonicalFixture(runtime))).digest('hex')+'00'.repeat(16)}}}};
  const data=[{alg:'ES256',typ:'JWT',jwk:verifierKey.publicKey.export({format:'jwk'})},claims].map(v=>Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
  return data+'.'+cryptoSign('sha256',Buffer.from(data),{key:verifierKey.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
}
function removeDeliveryFixture(directory) {
  const resolved=fs.realpathSync(directory);
  assert.equal(path.dirname(resolved),fs.realpathSync(os.tmpdir()));assert.ok(path.basename(resolved).startsWith('cannabis-key-delivery-'));
  fs.rmSync(resolved,{recursive:true});
}
async function deliverySetup({maxTokenAgeSeconds=90,serviceSHA256,native=false}={}) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-key-delivery-'));
  let s,attestations;
  try {
    const info=JSON.parse(execFileSync(process.env.CANNABIS_PYTHON || 'python',['test/helpers/job_key_fixture.py',dir,h(90).slice(2)],{encoding:'utf8',windowsHide:true,timeout:30000}));
    s=await setup({packageSHA256:info.descriptor.ciphertextSHA256,serviceSHA256,native});
    const signed=await sign(s.ledger,s.request,s.now);await fund(s.request);
    const lease=await promoteLease(s.ledger,signed,s.network,s.clock);
    let time=s.now+905;const clock=()=>time;
    await provider.send('evm_setNextBlockTimestamp',[time]);await provider.send('evm_mine',[]);
    const attestationPolicy={schema:'cannabis.attestation.trustee-policy.v1',issuer:'FixtureAS',signingJwk:verifierKey.publicKey.export({format:'jwk'}),
      verifierBuild:'synthetic CPU fixture',appraisalPolicyId:'fixture-cpu',maxTokenAgeSeconds,maxTokenLifetimeSeconds:300,challengeTTLSeconds:90,tee:'snp',
      measurements:{launch:'11'.repeat(48),initData:'22'.repeat(32),minimumTCB:{bootloader:1,tee:1,snp:1,microcode:1}}};
    const taskSHA256=createHash('sha256').update(Buffer.concat([Buffer.from('cannabis.task.v1\0'),Buffer.from(info.descriptor.ciphertextSHA256,'hex'),Buffer.alloc(4)])).digest('hex');
    assert.equal(info.descriptor.requirements[0].taskSHA256,taskSHA256);
    const run={runtimeSHA256:'b'.repeat(64),taskSHA256,attempt:1,rank:0,worldSize:1,acceleratorClass:'cpu'};
    const binding=leaseAttestationBinding(s.ledger,lease.leaseId,h(50),run,time);
    const initialization={schema:'cannabis.guest-initialization.v1',tee:'snp',requester:s.request.job.requester,jobId:s.request.job.id,binding};
    attestationPolicy.measurements.initData=guestInitialization(initialization).digest;
    attestations=new AttestationLedger(path.join(dir,'attestation.sqlite'),attestationPolicy,clock);
    const challenge=attestations.challenge(binding),guest=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),channel=guest.publicKey.export({format:'jwk'});
    const request={releaseId:h(501),leaseId:lease.leaseId,nonce:challenge.nonce,channelJwk:channel,descriptor:info.descriptor,notBefore:time,expiresAt:time+60};
    const payload=keyDeliveryPayload(s.ledger,attestations,request,time);
    const approval={request,requesterSignature:await owner.signTypedData(payload.domain,payload.types,payload.value)};
    const d={...s,dir,info,lease,clock,time,challenge,guest,channel,request,payload,approval,attestations,attestationPolicy,initialization,
      setTime:t=>{time=t;},cleanup:()=>{attestations.close();s.ledger.close();removeDeliveryFixture(dir);}};
    d.token=earFixture(d);d.network={...s.network,maxHeadAgeSeconds:120};
    d.load=expected=>recoverRequesterJobKey(info.source,expected);
    return d;
  } catch(error) {attestations?.close();s?.ledger.close();removeDeliveryFixture(dir);throw error;}
}

function guestFundingConfiguration(d) {
  const proof = exportLeaseProof(d.ledger, d.lease.leaseId);
  return { proof, context: d.context, network: d.network,
    provider: d.lease.reservations[0].provider, resourceId: h(10), serviceSHA256: proof.offers.find(p => p.offer.resourceId === h(10)).offer.serviceSHA256 };
}

test('native ETH funding retains signed asset and runtime pins through fresh guest key release',async()=>{
  const d=await deliverySetup({native:true}),agent=await guestAgentFixture();let guest,p;
  try {
    assert.equal(d.context.token,ZeroAddress);
    assert.equal(d.lease.finalityEvidence.runtimeCodeHashes.token,null);
    const proof=exportLeaseProof(d.ledger,d.lease.leaseId);
    assert.equal(verifyLeaseProof(proof,d.context).digest,d.lease.digest);
    assert.throws(()=>verifyLeaseProof(proof,{...d.context,token:network.token}),/mismatch|domain|Token/);
    for(const field of ['provider','token']) {
      const altered={...proof.offers[0].offer,[field]:field==='provider'?ZeroAddress:network.token};
      assert.throws(()=>offerPayload(d.context,altered),/Zero address|Token mismatch/);
    }
    assert.throws(()=>reservationPayload(d.context,{...proof.reservations[0].reservation,requester:ZeroAddress}),/Zero address/);
    for(const change of [{tokenCodeHash:undefined},{tokenCodeHash:network.tokenCodeHash},{escrow:ZeroAddress},
      {token:network.token,tokenCodeHash:null},{escrow:network.escrow,escrowCodeHash:network.escrowCodeHash}])
      await assert.rejects(readFinalizedEscrow({...d.network,orderId:d.lease.orderId,...change},d.clock));
    // Native reads still pin the escrow at canonical block hashes. They never
    // pretend that the zero asset address contains an ERC-20 implementation.
    const codeReads=[];
    p=await proxy((request,response)=>{if(request.method==='eth_getCode')codeReads.push(request.params);return response;});
    const options=guestFundingConfiguration(d);options.network.rpc=p.url;
    guest=await GuestEvidenceSession.create({initialization:d.initialization,policy:d.attestationPolicy,challenge:d.challenge,
      expectedBinding:d.challenge.binding,requester:d.payload.requester,jobId:d.payload.jobId,funding:options,agentUrl:agent.url},{clock:d.clock});
    const evidence=await guest.evidence(),request={...d.request,channelJwk:evidence.channelJwk};
    const payload=keyDeliveryPayload(d.ledger,d.attestations,request,d.clock());
    const approval={request,requesterSignature:await owner.signTypedData(payload.domain,payload.types,payload.value)};
    const record=await sealJobKeyDelivery(d.ledger,d.attestations,approval,earFixture({...d,channel:evidence.channelJwk}),
      {...d.network,rpc:p.url},d.load,{clock:d.clock});
    const prepared=await guest.prepare(record.envelope,payload,{python:d.info.source.python,age:d.info.source.age,
      ciphertext:path.join(d.dir,'job/workload.age'),destination:path.join(d.dir,'native-prepared')},{maxBytes:1024*1024});
    assert.equal(prepared.packageVerified,true);assert.equal(prepared.assignmentVerified,true);
    assert.equal(prepared.executionAuthorized,false);
    assert.ok(codeReads.length>=8);
    for(const [account,tag] of codeReads){assert.equal(account.toLowerCase(),d.network.escrow.toLowerCase());assert.equal(tag.requireCanonical,true);}
    assert.equal(guest.status.state,'consumed');
    await assert.rejects(guest.open(record.envelope,payload),/closed|expired/);
  }finally{guest?.close();await p?.close();await agent.close();d.cleanup();}
});

test('a funded native session retains its service commitment and cannot bypass readiness with open or prepare', async () => {
  const limits = (cpu, memory, pids, wall) => ({cpu_millis:cpu,memory_bytes:memory*1024**2,processes:pids,wall_seconds:wall});
  const execution = { profile:{schema:'cannabis.guest-native-service.v1',units:1,
    runtime:{adapter:'native-linux-x86_64-v1',architecture:'x86_64',os:'linux',digestSHA256:'b'.repeat(64)},
    resources:{cpus:1,memoryMiB:128,scratchMiB:8,wallSeconds:60,nodes:1},
    total:{...limits(3000,1024,192,120),children:3},control:limits(1000,512,64,120),helper:limits(1000,256,64,60),
    processLimit:32,scratchInodes:512,staging:{bytes:16*1024**2,inodes:1024},maxInputBytes:1024**2,
    tools:{pythonSHA256:'22'.repeat(32),ageSHA256:'22'.repeat(32),ageKeygenSHA256:'22'.repeat(32)}},
    source:Object.fromEntries(['python','rootfs','age','ciphertext','destination'].map(k=>[k,path.join(os.tmpdir(),'owned-unavailable-'+k)])) };
  const d=await deliverySetup(nativeServiceCommitment(execution)),agent=await guestAgentFixture();let guest,legacy;
  try {
    const args={initialization:d.initialization,policy:d.attestationPolicy,challenge:d.challenge,expectedBinding:d.challenge.binding,
      requester:d.payload.requester,jobId:d.payload.jobId,funding:guestFundingConfiguration(d),execution,agentUrl:agent.url};
    const changed=structuredClone(execution);changed.profile.control.memory_bytes+=4096;
    await assert.rejects(GuestEvidenceSession.create({...args,execution:changed},{clock:d.clock}),/signed service/);
    await assert.rejects(GuestEvidenceSession.create({...args,funding:undefined},{clock:d.clock}),/signed funding/);
    guest=await GuestEvidenceSession.create(args,{clock:d.clock});
    legacy=await GuestEvidenceSession.create(args,{clock:d.clock});
    const legacyEvidence=await legacy.evidence();
    const legacyPayload=keyDeliveryPayload(d.ledger,d.attestations,{...d.request,channelJwk:legacyEvidence.channelJwk},d.clock());
    await assert.rejects(legacy.executeNative('unopened',legacyPayload),/result channel/);
    assert.equal(legacy.status.state,'closed');
    execution.profile.control.memory_bytes+=4096;
    const evidence=await guest.evidence();
    await assert.rejects(guest.open('unopened',d.payload),/only through execution readiness/);
    await assert.rejects(guest.prepare('unopened',d.payload,{}),/only through execution readiness/);
    assert.equal(guest.status.state,'quoted');
    const payload=keyDeliveryPayload(d.ledger,d.attestations,{...d.request,channelJwk:evidence.channelJwk,resultKeySHA256:h(777)},d.clock());
    // Unavailable interpreter fails before key opening; external mutation did
    // not change the signed service retained by the session.
    await assert.rejects(guest.executeNative('unopened',payload),error=>!error.message.includes('signed service'));
    assert.equal(guest.status.state,'closed');
    assert.equal(d.attestations.db.prepare("SELECT count(*) AS n FROM sqlite_schema WHERE name='key_deliveries'").get().n,0);
  } finally {guest?.close();legacy?.close();await agent.close();d.cleanup();}
});

test('portable lease proofs independently verify all signatures, quotes and the complete provider bundle', async () => {
  const s = await setup();
  try {
    const signed = await sign(s.ledger, s.request, s.now); await fund(s.request);
    const lease = await promoteLease(s.ledger, signed, network, s.clock);
    const proof = exportLeaseProof(s.ledger, lease.leaseId), verified = verifyLeaseProof(proof, s.context);
    assert.equal(verified.digest, lease.digest); assert.equal(verified.orderId, lease.orderId);
    assert.equal(verified.reservations[0].serviceSHA256, h(20));
    assert.equal('executionAuthorized' in proof, false); assert.equal('finalityEvidence' in proof, false);
    for (const mutate of [
      p => { p.agreement.requesterSignature = p.agreement.providerSignatures[0].signature; },
      p => { p.agreement.providerSignatures.pop(); },
      p => { p.reservations[0].reservation.grossBaseUnits = '4000'; },
      p => { p.reservations[0].providerSignature = p.reservations[0].requesterSignature; },
      p => { p.offers[0].offer.serviceSHA256 = h(999); },
      p => { p.reservations[1] = p.reservations[0]; },
      p => { p.offers.push(p.offers[0]); },
      p => { p.agreement.request.job.id = 'different-job'; },
      p => { p.agreement.request.expiresAt = s.now + 601; },
      p => { p.fundedAnchor.timestamp = s.now + 501; }
    ]) { const changed = structuredClone(proof); mutate(changed); assert.throws(() => verifyLeaseProof(changed, s.context)); }
    assert.throws(() => verifyLeaseProof(proof, { ...s.context, registryId: h(999) }), /signature/);
  } finally { s.ledger.close(); }
});

test('guest funding rereads the original finalized anchor and fresh active escrow after signing holds expire', async () => {
  const d = await deliverySetup();
  try {
    const options = guestFundingConfiguration(d), funding = new GuestFunding(options, d.initialization, { clock: d.clock });
    assert.ok(d.clock() > d.lease.agreement.request.expiresAt);
    assert.ok(options.proof.reservations.every(s => s.reservation.holdUntil < d.clock()));
    // Mutating external copies cannot change the retained approved network or lease.
    options.proof.agreement.request.job.id = 'changed'; options.network.rpc = 'https://invalid.example/';
    const checked = await funding.refresh();
    assert.deepEqual(checked.interval, { start: d.now + 900, end: d.now + 1000 });
    assert.equal(checked.leaseDigest, d.lease.digest); assert.equal(checked.executionAuthorized, false);
    assert.equal(checked.hardwareVerified, false); assert.equal(JSON.stringify(funding), '{}');
    d.setTime(d.now + 1000); assert.throws(() => funding.assertWindow(), /expired/);
    d.setTime(d.time); await assert.rejects(funding.refresh(), /closed/);
  } finally { d.cleanup(); }
});

test('guest funding binds execution to the signed service definition and exact unit count', async () => {
  const d = await deliverySetup();
  try {
    const options = guestFundingConfiguration(d), units = options.proof.reservations[0].reservation.units;
    const good = new GuestFunding(options, d.initialization, { clock: d.clock });
    good.assertService({ serviceSHA256: options.serviceSHA256, units });
    for (const changed of [{ serviceSHA256: h(999), units }, { serviceSHA256: options.serviceSHA256, units: units + 1 },
      { serviceSHA256: options.serviceSHA256, units: String(units) }]) {
      const funding = new GuestFunding(options, d.initialization, { clock: d.clock });
      assert.throws(() => funding.assertService(changed), /signed service or unit count/);
      assert.throws(() => funding.assertWindow(), /closed/);
    }
  } finally { d.cleanup(); }
});

test('guest funding refuses assignment, approved resource and service-window substitution', async () => {
  const d = await deliverySetup();
  try {
    const options = guestFundingConfiguration(d);
    for (const change of [{ resourceId: h(999) }, { serviceSHA256: h(999) }, { provider: await second.getAddress() },
      { context: { ...d.context, token: await resolver.getAddress() } }, { network: { ...d.network, chainId: 1 } }]) {
      assert.throws(() => new GuestFunding({ ...options, ...change }, d.initialization, { clock: d.clock }));
    }
    for (const field of ['leaseDigest', 'orderId', 'reservationId', 'packageSHA256', 'policySHA256']) {
      const initialization = structuredClone(d.initialization);
      initialization.binding[field] = field.endsWith('SHA256') ? h(999).slice(2) : h(999);
      assert.throws(() => new GuestFunding(options, initialization, { clock: d.clock }), /retained guest assignment/);
    }
    d.setTime(d.now + 899);
    await assert.rejects(new GuestFunding(options, d.initialization, { clock: d.clock }).refresh(), /not started/);
    d.setTime(d.time);
    const funding = new GuestFunding(options, d.initialization, { clock: d.clock });
    funding.assertWindow(); d.setTime(d.time - 1); assert.throws(() => funding.assertWindow(), /closed/);
  } finally { d.cleanup(); }
});

test('guest funding does not trust a fabricated original anchor or a stale latest head', async () => {
  const d = await deliverySetup(); let p;
  try {
    const options = guestFundingConfiguration(d);
    const changed = structuredClone(options); changed.proof.fundedAnchor.hash = h(999);
    await assert.rejects(new GuestFunding(changed, d.initialization, { clock: d.clock }).refresh(), /anchor changed/);
    const falseTime = structuredClone(options); falseTime.proof.fundedAnchor.timestamp--;
    await assert.rejects(new GuestFunding(falseTime, d.initialization, { clock: d.clock }).refresh(), /signing window/);
    p = await proxy((req, res) => req.method === 'eth_getBlockByNumber' && req.params[0] === 'latest'
      ? { ...res, result: { ...res.result, timestamp: '0x' + (d.time - 121).toString(16) } } : res);
    await assert.rejects(new GuestFunding({ ...options, network: { ...d.network, rpc: p.url } }, d.initialization, { clock: d.clock }).refresh(), /stale/);
  } finally { if (p) await p.close(); d.cleanup(); }
});

test('guest funding rejects delivered orders despite an older active finalized view', async () => {
  const d = await deliverySetup(); let p;
  try {
    const options = guestFundingConfiguration(d), active = await provider.send('eth_getBlockByNumber', ['latest', false]);
    await (await escrow.connect(first).deliver(d.lease.orderId, h(891))).wait();
    p = await proxy((req, res) => req.method === 'eth_getBlockByNumber' && req.params[0] === 'finalized' ? { ...res, result: active } : res);
    await assert.rejects(new GuestFunding({ ...options, network: { ...d.network, rpc: p.url } }, d.initialization, { clock: d.clock }).refresh(), /active order/);
  } finally { if (p) await p.close(); d.cleanup(); }
});

test('a funded guest closes if its service interval ends during RPC inspection', async () => {
  const d = await deliverySetup(); let p;
  try {
    const options = guestFundingConfiguration(d);
    p = await proxy((req, res) => { if (req.method === 'eth_call') d.setTime(d.now + 1000); return res; });
    const funding = new GuestFunding({ ...options, network: { ...d.network, rpc: p.url } }, d.initialization, { clock: d.clock });
    await assert.rejects(funding.refresh(), /expired/);
    d.setTime(d.time); await assert.rejects(funding.refresh(), /closed/);
  } finally { if (p) await p.close(); d.cleanup(); }
});

test('the original funding anchor must remain canonical throughout current-state inspection', async () => {
  const d = await deliverySetup(); let p;
  try {
    const options = guestFundingConfiguration(d), anchor = options.proof.fundedAnchor;
    let headSeen = false;
    p = await proxy((req, res) => {
      if (req.method === 'eth_getBlockByNumber' && req.params[0] === 'latest') headSeen = true;
      if (headSeen && req.method === 'eth_getBlockByNumber' && req.params[0] === '0x' + anchor.number.toString(16))
        return { ...res, result: { ...res.result, hash: h(998) } };
      return res;
    });
    await assert.rejects(new GuestFunding({ ...options, network: { ...d.network, rpc: p.url } }, d.initialization, { clock: d.clock }).refresh(), /anchor changed/);
  } finally { if (p) await p.close(); d.cleanup(); }
});

test('a requester-wrapped key is withheld after delivery, cancellation or expiry during the second funding check', async () => {
  for (const mode of ['delivered', 'cancel', 'expire-after-open', 'key-expiry-after-open']) {
    const d = await deliverySetup(), agent = await guestAgentFixture(); let guest, p;
    try {
      const options = guestFundingConfiguration(d);
      let anchorReads = 0;
      if (mode !== 'delivered') {
        const anchorTag = '0x' + options.proof.fundedAnchor.number.toString(16);
        p = await proxy((req, res) => {
          if (mode === 'cancel' && req.method === 'eth_call') guest.close();
          if (mode.endsWith('after-open') && req.method === 'eth_getBlockByNumber' && req.params[0] === anchorTag && ++anchorReads === 4)
            d.setTime(mode === 'expire-after-open' ? d.now + 1000 : d.request.expiresAt);
          return res;
        });
        options.network = { ...d.network, rpc: p.url };
      }
      guest = await GuestEvidenceSession.create({ initialization: d.initialization, policy: d.attestationPolicy,
        challenge: d.challenge, expectedBinding: d.challenge.binding, requester: d.payload.requester,
        jobId: d.payload.jobId, funding: options, agentUrl: agent.url }, { clock: d.clock });
      const evidence = await guest.evidence(), request = { ...d.request, channelJwk: evidence.channelJwk };
      const payload = keyDeliveryPayload(d.ledger, d.attestations, request, d.clock());
      const approval = { request, requesterSignature: await owner.signTypedData(payload.domain, payload.types, payload.value) };
      const record = await sealJobKeyDelivery(d.ledger, d.attestations, approval,
        earFixture({ ...d, channel: evidence.channelJwk }), d.network, d.load, { clock: d.clock });
      if (mode === 'delivered') await (await escrow.connect(first).deliver(d.lease.orderId, h(892))).wait();
      await assert.rejects(guest.open(record.envelope, payload), mode === 'delivered' ? /active order/ : /closed|expired/);
      if (mode.endsWith('after-open')) assert.ok(anchorReads >= 4);
      assert.equal(guest.status.state, 'closed');
      await assert.rejects(guest.open(record.envelope, payload), /closed/);
    } finally { guest?.close(); if (p) await p.close(); await agent.close(); d.cleanup(); }
  }
});

test('signed funded key delivery recovers a real capsule, wraps to the attested guest and preserves the funded package',async()=>{
  const d=await deliverySetup({maxTokenAgeSeconds:15});try {
    const record=await sealJobKeyDelivery(d.ledger,d.attestations,d.approval,d.token,d.network,d.load,{clock:d.clock});
    assert.equal(record.keyWrapped,true);assert.equal(record.transmitted,false);assert.equal(record.executionAuthorized,false);
    assert.equal(record.expiresAt,d.time+15);
    assert.equal(record.envelope.includes('AGE-SECRET-KEY-'),false);
    assert.deepEqual(inspectKeyDelivery(d.attestations,d.request.releaseId),record);
    assert.throws(()=>d.attestations.pending(d.challenge.nonce),/consumed/);
    const opened=await openJobKeyDelivery(record.envelope,d.guest.privateKey,d.payload,{clock:d.clock});
    assert.equal(opened.deliveryExpiresAt,record.expiresAt);
    assert.equal(Object.keys(opened).includes('deliveryExpiresAt'),false);
    let clockReads=0;
    await assert.rejects(openJobKeyDelivery(record.envelope,d.guest.privateKey,d.payload,
      {clock:()=>++clockReads<=2?d.time:record.expiresAt}),/time or rank/);
    assert.equal(JSON.stringify(opened).includes('AGE-SECRET-KEY-'),false);
    const code="import sys,json;from compute.client import open_archive;m=open_archive(sys.argv[1],sys.stdin.buffer.read(),sys.argv[3],sys.argv[2]);print(json.dumps({'kind':m['kind'],'resultRecipient':m['context']['resultRecipient']}))";
    const result=JSON.parse(execFileSync(d.info.source.python,['-c',code,path.join(d.dir,'job/workload.age'),opened.packageSHA256,path.join(d.dir,'decoded')],
      {input:opened.identity,encoding:'utf8',windowsHide:true,timeout:30000,env:{...process.env,CANNABIS_AGE:d.info.source.age}}));
    assert.equal(result.kind,'workload');assert.equal(result.resultRecipient,opened.resultRecipient);
    assert.equal(createHash('sha256').update(fs.readFileSync(path.join(d.dir,'job/workload.age'))).digest('hex'),d.request.descriptor.ciphertextSHA256);
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,d.approval,d.token,d.network,d.load,{clock:d.clock}),/consumed/);
    await assert.rejects(openJobKeyDelivery(record.envelope,generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey,d.payload,{clock:d.clock}));
    await assert.rejects(openJobKeyDelivery(record.envelope,d.guest.privateKey,{...d.payload,value:{...d.payload.value,rank:1}},{clock:d.clock}),/expected approval/);
    const parts=record.envelope.split('.');parts[3]=(parts[3][0]==='A'?'B':'A')+parts[3].slice(1);
    await assert.rejects(openJobKeyDelivery(parts.join('.'),d.guest.privateKey,d.payload,{clock:d.clock}));
    d.setTime(record.expiresAt);assert.ok(d.clock()<d.request.expiresAt);
    await assert.rejects(openJobKeyDelivery(record.envelope,d.guest.privateKey,d.payload,{clock:d.clock}));
  }finally{d.cleanup();}
});

test('signed result custody crosses only the admitted key envelope and requires requester recovery',async()=>{
  const d=await deliverySetup({native:true});let opened,key;
  try {
    const custody=await createResultKeyCustody({releaseId:d.request.releaseId,recipient:d.info.ownerRecipient});
    const saved=path.join(d.dir,'result-key-custody.json');fs.writeFileSync(saved,JSON.stringify(custody),{flag:'wx',mode:0o600});
    const source={python:d.info.source.python,age:d.info.source.age,identity:d.info.source.identity,custody:saved};
    const request={...d.request,resultKeySHA256:custody.resultKeySHA256};
    const payload=keyDeliveryPayload(d.ledger,d.attestations,request,d.clock());
    const approval={request,requesterSignature:await owner.signTypedData(payload.domain,payload.types,payload.value)};
    const options={clock:d.clock,loadResultKey:expected=>recoverRequesterResultKey(source,expected)};
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,{...approval,request:{...request,resultKeySHA256:h(888)}},
      d.token,d.network,d.load,options),/signature mismatch/);
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,approval,d.token,d.network,d.load,
      {...options,loadResultKey:async()=>Buffer.alloc(32,1)}),/Result key differs/);
    assert.equal(d.attestations.pending(d.challenge.nonce).nonce,d.challenge.nonce);
    const record=await sealJobKeyDelivery(d.ledger,d.attestations,approval,d.token,d.network,d.load,options);
    const restored=inspectKeyDelivery(d.attestations,request.releaseId);
    assert.equal(restored.schema,'cannabis.key-delivery.record.v2');
    assert.deepEqual(restored.expectedApproval,{...payload,requesterSignature:approval.requesterSignature});
    opened=await openJobKeyDelivery(record.envelope,d.guest.privateKey,payload,{clock:d.clock});
    assert.ok(opened.resultKey instanceof Uint8Array);assert.equal(Object.keys(opened).includes('resultKey'),false);
    const binding={releaseId:request.releaseId,recipient:d.info.ownerRecipient,resultKeySHA256:request.resultKeySHA256};
    key=await recoverRequesterResultKey(source,binding);assert.deepEqual(opened.resultKey,key);
    const receipt={schema:'cannabis.result.v1',jobId:payload.jobId,taskId:'owned-private-task',packageSHA256:payload.value.packageSHA256.slice(2),
      attempt:1,rank:0,worldSize:1,recipient:d.info.ownerRecipient,ciphertextSHA256:'ac'.repeat(32),ciphertextBytes:100};
    const envelope=await sealResultDelivery(receipt,opened.resultKey,payload);
    const authenticated=await openResultDelivery(envelope,key,restored.expectedApproval);
    assert.equal(authenticated.receipt.taskId,receipt.taskId);assert.equal(authenticated.paymentAuthorized,false);
    assert.equal(JSON.stringify(opened).includes(key.toString('base64url')),false);
    await assert.rejects(recoverRequesterResultKey(source,{...binding,releaseId:h(999)}));
  }finally{opened?.resultKey?.fill(0);key?.fill(0);d.cleanup();}
});

test('invalid requester approval and mismatched attestation never reach key recovery',async()=>{
  const d=await deliverySetup();let loads=0;const load=async expected=>{loads++;return d.load(expected);};
  try {
    const bad={...d.approval,requesterSignature:await first.signTypedData(d.payload.domain,d.payload.types,d.payload.value)};
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,bad,d.token,d.network,load,{clock:d.clock}),/signature mismatch/);
    const wrongToken=earFixture({...d,channel:generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'})});
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,d.approval,wrongToken,d.network,load,{clock:d.clock}),/runtime binding/);
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,d.approval,d.token,{...d.network,genesisHash:h(700)},load,{clock:d.clock}),/genesis/);
    assert.equal(loads,0);assert.equal(d.attestations.pending(d.challenge.nonce).nonce,d.challenge.nonce);
  }finally{d.cleanup();}
});

test('an active finalized snapshot cannot hide a delivered order at the latest head',async()=>{
  const d=await deliverySetup();let p,loads=0;
  try {
    const active=await provider.send('eth_getBlockByNumber',['latest',false]);
    await (await escrow.connect(first).deliver(d.lease.orderId,h(702))).wait();
    p=await proxy((req,res)=>req.method==='eth_getBlockByNumber'&&req.params[0]==='finalized'?{...res,result:active}:res);
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,d.approval,d.token,{...d.network,rpc:p.url},async expected=>{loads++;return d.load(expected);},{clock:d.clock}),/still be active/);
    assert.equal(loads,0);assert.equal(d.attestations.db.prepare('SELECT count(*) AS n FROM key_deliveries').get().n,0);
  }finally{if(p)await p.close();d.cleanup();}
});

test('state changes during local recovery are rechecked before publishing wrapped keys',async()=>{
  const d=await deliverySetup();try {
    const load=async expected=>{const recovered=await d.load(expected);await (await escrow.connect(first).deliver(d.lease.orderId,h(703))).wait();return recovered;};
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,d.approval,d.token,d.network,load,{clock:d.clock}),/still be active/);
    assert.equal(d.attestations.db.prepare('SELECT count(*) AS n FROM key_deliveries').get().n,0);
    assert.equal(d.attestations.pending(d.challenge.nonce).nonce,d.challenge.nonce);
  }finally{d.cleanup();}
});

test('latest-state checks cannot switch away from the finalized funding anchor',async()=>{
  const d=await deliverySetup();let p,changed=false;
  try {
    const anchor=await provider.send('eth_getBlockByNumber',['finalized',false]);
    p=await proxy((req,res)=>changed&&req.method==='eth_getBlockByNumber'&&req.params[0]===anchor.number?{...res,result:{...res.result,hash:h(799)}}:res);
    const load=async expected=>{const recovered=await d.load(expected);await provider.send('evm_mine',[]);changed=true;return recovered;};
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,d.approval,d.token,{...d.network,rpc:p.url},load,{clock:d.clock}),/funding anchor changed/);
    assert.equal(d.attestations.db.prepare('SELECT count(*) AS n FROM key_deliveries').get().n,0);
  }finally{if(p)await p.close();d.cleanup();}
});

test('cancellation, expiry and wrong recovered identity prevent key publication',async()=>{
  for(const mode of ['cancel','expire','wrong-key']) {
    const d=await deliverySetup();try {
      const load=async expected=>{
        const recovered=await d.load(expected);
        if(mode==='cancel')d.attestations.cancel(d.challenge.nonce);
        if(mode==='expire')d.setTime(d.request.expiresAt);
        if(mode==='wrong-key') {
          const keygen=path.join(path.dirname(d.info.source.age),process.platform==='win32'?'age-keygen.exe':'age-keygen');
          recovered.identity=execFileSync(keygen,[],{encoding:'utf8',stdio:['ignore','pipe','ignore'],windowsHide:true}).split(/\r?\n/).filter(s=>s&&!s.startsWith('#')).join('\n')+'\n';
        }
        return recovered;
      };
      await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,d.approval,d.token,d.network,load,{clock:d.clock}));
      assert.equal(d.attestations.db.prepare('SELECT count(*) AS n FROM key_deliveries').get().n,0);
    }finally{d.cleanup();}
  }
});

test('concurrent key delivery journals one ciphertext and consumes its challenge once',async()=>{
  const d=await deliverySetup();try {
    const results=await Promise.allSettled([0,1].map(()=>sealJobKeyDelivery(d.ledger,d.attestations,d.approval,d.token,d.network,d.load,{clock:d.clock})));
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
    assert.equal(d.attestations.db.prepare('SELECT count(*) AS n FROM key_deliveries').get().n,1);
    const stored=d.attestations.db.prepare('SELECT body FROM key_deliveries').get().body;
    assert.equal(stored.includes('AGE-SECRET-KEY-'),false);
    const next=d.attestations.challenge(d.challenge.binding),request={...d.request,nonce:next.nonce,releaseId:h(705)};
    const payload=keyDeliveryPayload(d.ledger,d.attestations,request,d.clock());
    const signed={request,requesterSignature:await owner.signTypedData(payload.domain,payload.types,payload.value)};
    let loaded=false;
    await assert.rejects(sealJobKeyDelivery(d.ledger,d.attestations,signed,earFixture({...d,challenge:next}),d.network,async()=>{loaded=true;},{clock:d.clock}),/already exists/);
    assert.equal(loaded,false);
  }finally{d.cleanup();}
});

test('guest-held channel opens and prepares the funded task once without exposing its private contract',async()=>{
  const d=await deliverySetup(),agent=await guestAgentFixture();let guest,as,captured;
  try {
    guest=await GuestEvidenceSession.create({initialization:d.initialization,policy:d.attestationPolicy,challenge:d.challenge,expectedBinding:d.challenge.binding,
      requester:d.payload.requester,jobId:d.payload.jobId,funding:guestFundingConfiguration(d),agentUrl:agent.url},{clock:d.clock});
    assert.equal(guest.status.fundingRequired,true);
    assert.deepEqual(guest.serviceInterval,{start:d.now+900,end:d.now+1000});
    const evidence=await guest.evidence();
    const request={...d.request,channelJwk:evidence.channelJwk};
    const payload=keyDeliveryPayload(d.ledger,d.attestations,request,d.clock());
    const approval={request,requesterSignature:await owner.signTypedData(payload.domain,payload.types,payload.value)};
    as=http.createServer(async(req,res)=>{let raw='';for await(const part of req)raw+=part;captured=JSON.parse(raw);res.end(earFixture({...d,channel:evidence.channelJwk}));});
    await new Promise(resolve=>as.listen(0,'127.0.0.1',resolve));
    const appraised=await requestTrusteeResult(d.attestations,`http://127.0.0.1:${as.address().port}/attestation`,d.challenge.nonce,evidence.channelJwk,evidence.evidence);
    assert.deepEqual(captured,trusteeEvidenceRequest(d.attestationPolicy,d.challenge,evidence.channelJwk,evidence.evidence,d.clock()));
    assert.equal(appraised.challengeConsumed,false);assert.equal(d.attestations.pending(d.challenge.nonce).nonce,d.challenge.nonce);
    const record=await sealJobKeyDelivery(d.ledger,d.attestations,approval,appraised.token,d.network,d.load,{clock:d.clock});
    const source={python:d.info.source.python,age:d.info.source.age,ciphertext:path.join(d.dir,'job/workload.age'),destination:path.join(d.dir,'prepared-guest')};
    const results=await Promise.allSettled([guest.prepare(record.envelope,payload,source,{maxBytes:1024*1024}),guest.open(record.envelope,payload)]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
    const prepared=results.find(r=>r.status==='fulfilled').value;
    assert.equal(prepared.packageVerified,true);assert.equal(prepared.assignmentVerified,true);assert.equal(prepared.executionAuthorized,false);
    assert.equal(prepared.taskIndex,0);assert.equal(prepared.workload.resultRecipient,d.info.ownerRecipient);
    assert.equal(Object.keys(prepared).includes('workload'),false);
    assert.equal(JSON.stringify(prepared).includes('AGE-SECRET-KEY-'),false);
    assert.equal(JSON.stringify(prepared).includes('launch'),false);
    assert.ok(fs.statSync(path.join(source.destination,'program.bin')).isFile());
    assert.equal(guest.status.state,'consumed');assert.equal(guest.status.executionAuthorized,false);
    assert.equal(JSON.stringify(guest),'{}');
    await assert.rejects(guest.open(record.envelope,payload),/closed|expired/);
  }finally{guest?.close();if(as)await new Promise(resolve=>as.close(resolve));await agent.close();d.cleanup();}
});

test('closing a consumed guest session cancels preparation and cannot reopen its key',async()=>{
  const d=await deliverySetup(),agent=await guestAgentFixture();let guest,pending;
  try {
    guest=await GuestEvidenceSession.create({initialization:d.initialization,policy:d.attestationPolicy,challenge:d.challenge,expectedBinding:d.challenge.binding,
      requester:d.payload.requester,jobId:d.payload.jobId,agentUrl:agent.url},{clock:d.clock});
    const evidence=await guest.evidence(),request={...d.request,channelJwk:evidence.channelJwk};
    const payload=keyDeliveryPayload(d.ledger,d.attestations,request,d.clock());
    const approval={request,requesterSignature:await owner.signTypedData(payload.domain,payload.types,payload.value)};
    const record=await sealJobKeyDelivery(d.ledger,d.attestations,approval,earFixture({...d,channel:evidence.channelJwk}),d.network,d.load,{clock:d.clock});
    const source={python:d.info.source.python,age:d.info.source.age,ciphertext:path.join(d.dir,'job/workload.age'),destination:path.join(d.dir,'cancelled-guest')};
    let settled=false;
    pending=guest.prepare(record.envelope,payload,source,{maxBytes:1024*1024})
      .then(value=>{settled=true;return {value};},error=>{settled=true;return {error};});
    await assert.rejects(guest.prepare(record.envelope,payload,source,{maxBytes:1024*1024}),/already in progress/);
    const deadline=Date.now()+5000;
    while(guest.status.state!=='consumed') {
      assert.ok(!settled && Date.now()<deadline,'Observe consumption before preparation finishes');
      await new Promise(resolve=>setTimeout(resolve,1));
    }
    assert.equal(settled,false);guest.close();
    assert.match((await pending).error?.message||'',/preparation failed/);
    assert.equal(guest.status.state,'consumed');assert.equal(guest.status.executionAuthorized,false);
    await assert.rejects(guest.open(record.envelope,payload),/closed|expired/);
  } finally {guest?.close();if(pending)await pending;await agent.close();d.cleanup();}
});
