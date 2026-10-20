// Owned requester for a two-rank actual-kernel integration. Disposable loopback
// chain/signers and synthetic CPU appraisals; never public custody or admission.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {Socket} from 'node:net';
import {generateKeyPairSync} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {ContractFactory,formatUnits,keccak256,ZeroAddress} from 'ethers';
import {localProvider} from '../../scripts/lib.mjs';
import {compile} from '../../scripts/compile.mjs';
import {settlementTerms,termsDigest} from '../../scripts/compute-escrow.mjs';
import {policy} from '../../scripts/compute-plan.mjs';
import {bookingPayload} from '../../compute/market.mjs';
import {createMarketLeaseProof,verifyMarketLeaseProof} from '../../compute/market_lease.mjs';
import {inspectExecutionPlan} from '../../compute/execution_plan.mjs';
import {nativeServiceCommitment} from '../../compute/guest_execution.mjs';
import {validateGuestConfiguration} from '../../compute/guest_configuration.mjs';
import {launchConsentPayload,inspectLaunchConsent} from '../../compute/guest_consent.mjs';
import {configuredMarketAttestationBinding,AttestationLedger,verifyTrusteeResult} from '../../compute/attestation.mjs';
import {guestInitialization} from '../../compute/guest_initialization.mjs';
import {keyDeliveryPayload,sealJobKeyDelivery,recoverRequesterJobKey} from '../../compute/key_delivery.mjs';
import {createResultKeyCustody,recoverRequesterResultKey} from '../../compute/result_keys.mjs';
import {ResultInbox} from '../../compute/result_inbox.mjs';
import {GuestWire,receiveGuestEvidence,sendGuestExecution} from '../../compute/result_transport.mjs';
import {connectBookedPeer} from '../../compute/peer_network.mjs';
import {sendLaunchHandoff} from '../../compute/launch_handoff.mjs';
import {sendEncryptedInput} from '../../compute/input_transport.mjs';
import {receiveSessionResultAccess} from '../../requester/session-access.mjs';
import {receiveHostedResult} from '../../requester/hosted-result.mjs';
import {WorkflowGroup} from '../../requester/workflow-group.mjs';
import {syntheticGroupEAR} from './group_fixture.mjs';
import tlsFixture from './peer-tls-fixture.json' with {type:'json'};

const h=n=>'0x'+n.toString(16).padStart(64,'0'),clock=()=>Math.floor(Date.now()/1000),
  utc=n=>new Date(n*1000).toISOString().replace('.000Z','Z');
const input=JSON.parse(fs.readFileSync(0,'utf8')),provider=await localProvider(input.rpc),channels=[],ledgers=[],boot=[];
let inbox,coordinator;
const write=(file,value)=>fs.writeFileSync(file,JSON.stringify(value),{mode:0o600,flag:'wx'});
try {
  assert.equal(input.ranks.length,2);
  const [requester,...accounts]=await Promise.all([0,1,2,3,4].map(i=>provider.getSigner(i))),
    workers=accounts.slice(0,2),adjudicator=accounts[2],receiver=accounts[3],account=await requester.getAddress(),
    workerAccounts=await Promise.all(workers.map(w=>w.getAddress()));
  const artifacts=compile({'GroupKernelAsset.sol':{content:`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract GroupKernelAsset is ERC20 { constructor() ERC20("Isolated group fixture", "FIX") {} }
`}});
  const deploy=async(name,args=[])=>{const a=artifacts[name],c=await new ContractFactory(a.abi,a.bytecode,requester).deploy(...args);await c.waitForDeployment();return c;};
  const escrow=await deploy('ComputeEscrow',[ZeroAddress,policy.founderRecipient]),asset=await deploy('GroupKernelAsset'),
    tokenEscrow=await deploy('ComputeEscrow',[await asset.getAddress(),policy.founderRecipient]),
    market=await deploy('ComputeMarket',[await escrow.getAddress(),await tokenEscrow.getAddress()]),
    context={chainId:31337,market:await market.getAddress(),token:ZeroAddress};
  const network={...context,rpc:input.rpc,escrow:await escrow.getAddress(),genesisHash:(await provider.getBlock(0)).hash,
    escrowCodeHash:keccak256(await provider.getCode(await escrow.getAddress())),tokenCodeHash:null,
    marketCodeHash:keccak256(await provider.getCode(context.market)),finality:'rpc-finalized',maxFinalizedAgeSeconds:1800,maxHeadAgeSeconds:120};
  const start=Math.max(clock(),(await provider.getBlock('latest')).timestamp)+20,end=start+120,gross=12000n,slots=[];
  for(const [rank,worker] of workers.entries()) {
    const service=nativeServiceCommitment(input.ranks[rank].execution);
    await (await market.connect(worker).publishResource(h(20+rank),service.serviceSHA256,1)).wait();
    const resourceId=await market.resourceKey(workerAccounts[rank],h(20+rank)),
      offer={resource:resourceId,escrow:network.escrow,policyHash:'0x'+input.descriptor.policySHA256,manifestHash:h(30+rank),
        start,end,expiresAt:start,units:1,grossPerUnitSecond:'100'};
    const tx=await (await market.connect(worker).publishOffer(h(40+rank),offer)).wait(),
      offerId=tx.logs.map(l=>{try{return market.interface.parseLog(l);}catch{return null;}}).find(e=>e?.name==='OfferPublished').args.offerId;
    slots.push({rank,resourceId,service,booking:{reservationId:h(50+rank),offerId,start:String(start),end:String(end),units:'1',gross:String(gross),holdUntil:String(start-1)}});
  }
  const plan=inspectExecutionPlan({schema:'cannabis.execution-plan.v1',...context,genesisHash:network.genesisHash,escrow:network.escrow,
    requester:account,jobId:input.descriptor.id,packageSHA256:input.descriptor.ciphertextSHA256,policySHA256:input.descriptor.policySHA256,
    requirements:input.descriptor.requirements,assignments:slots.map(s=>({task:0,rank:s.rank,attempt:1,acceleratorClass:'cpu',
      provider:workerAccounts[s.rank],serviceSHA256:s.service.serviceSHA256,booking:s.booking}))});
  const job={schema:'cannabis.compute.order.v3',id:input.descriptor.id,requester:account,packageSHA256:input.descriptor.ciphertextSHA256,
    policySHA256:input.descriptor.policySHA256,acceptanceSHA256:h(6).slice(2),executionPlanSHA256:plan.digestSHA256,
    payment:{totalBudget:formatUnits(2n*gross,18),feeBasisPoints:100,founderRecipient:policy.founderRecipient}},
    settlement={workers:workerAccounts.map(account=>({account,shareBps:5000})),deliveryManager:workerAccounts[0],
      adjudicator:await adjudicator.getAddress(),acceptBy:utc(start-1),deliverBy:utc(end+15),reviewSeconds:86400,disputeSeconds:86400},
    terms=settlementTerms(job,settlement),orderId=await escrow.orderId(account,terms.terms.jobHash),
    digest=termsDigest({chainId:31337,escrow:network.escrow,token:ZeroAddress,founderRecipient:policy.founderRecipient,...terms});
  const bookings=slots.map(s=>({...s.booking,requester:account,orderId,termsDigest:digest})),
    bookingApprovals=bookings.map(b=>bookingPayload(context,b));
  await (await market.reserveBatch(bookings,await Promise.all(bookingApprovals.map((p,i)=>workers[i].signTypedData(p.domain,p.types,p.value))))).wait();
  await (await escrow.fund(terms.terms,terms.accounts,terms.shares,{value:2n*gross})).wait();
  for(const worker of workers)await (await escrow.connect(worker).accept(orderId)).wait();
  const bookingIds=bookingApprovals.map(p=>p.digest).sort();await (await market.activate(bookingIds)).wait();
  const proof=await createMarketLeaseProof(network,{job,settlement,bookingIds,executionPlan:plan.plan}),lease=verifyMarketLeaseProof(proof,context);
  while(clock()<start)await new Promise(resolve=>setTimeout(resolve,100));
  await provider.send('evm_setNextBlockTimestamp',[clock()]);await provider.send('evm_mine',[]);
  const signer=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),assignments=[];
  for(const s of slots) {
    const selected=lease.assignments.find(a=>a.run.rank===s.rank),configuration={schema:'cannabis.guest-launch-configuration.v3',
      configurationId:h(60+s.rank),validFrom:start-20,validUntil:end+30,context,network,provider:workerAccounts[s.rank],resourceId:s.resourceId,
      execution:input.ranks[s.rank].execution,attestationPolicyTemplate:{schema:'cannabis.attestation.trustee-policy.v1',
        issuer:'Owned funded group fixture',signingJwk:signer.publicKey.export({format:'jwk'}),verifierBuild:'Synthetic owned appraisal only',
        appraisalPolicyId:'owned-group',maxTokenAgeSeconds:90,maxTokenLifetimeSeconds:120,challengeTTLSeconds:90,tee:'snp',
        measurements:{launch:'11'.repeat(48),initData:null,minimumTCB:{bootloader:1,tee:1,snp:1,microcode:1}}},
      bootstrap:{agentBinary:'/usr/local/bin/ttrpc-aa',bridgeBinary:'/usr/local/bin/api-server-rest',runtimeDirectory:'/run',port:8006},
      transport:{timeoutMs:90000,maxCiphertextBytes:4*1024**2}};
    const binding=configuredMarketAttestationBinding(proof,context,selected.reservationId,selected.run,
      validateGuestConfiguration(configuration).configurationSHA256,clock()),
      initialization={schema:'cannabis.guest-initialization.v2',tee:'snp',requester:account,jobId:job.id,binding},consents=[];
    for(const [role,wallet] of [['requester',requester],['provider',workers[s.rank]]]) {
      const p=launchConsentPayload(configuration,initialization,proof,role);
      consents.push({role,signer:await wallet.getAddress(),signature:await wallet.signTypedData(p.domain,p.types,p.value)});
    }
    const signed={schema:'cannabis.guest-launch-consent.v1',configuration,consents},policy=structuredClone(configuration.attestationPolicyTemplate);
    policy.measurements.initData=guestInitialization(initialization).digest;
    const ledger=new AttestationLedger(':memory:',policy),challenge=ledger.challenge(binding);ledgers.push(ledger);
    const config=input.ranks[s.rank],wire=new GuestWire(new Socket({fd:config.fds.read,readable:true,writable:false}),
      new Socket({fd:config.fds.write,readable:false,writable:true}),{timeoutMs:90000});boot.push(wire);
    assignments.push({task:0,rank:s.rank,signed,initialization,description:inspectLaunchConsent(signed,initialization,proof),
      groupEndpoint:'tls://127.0.0.1:'+configuration.execution.profile.group.port,policy,ledger,challenge,config});
    await wire.writeJSON({signedConfiguration:signed,initialization,request:{proof,challenge}});
  }
  coordinator=new WorkflowGroup({proof,network,assignments:assignments.map(({task,signed,initialization,description,groupEndpoint})=>
    ({task,signed,initialization,description,groupEndpoint})),clock,
    sign:(_kind,p)=>requester.signTypedData(p.domain,p.types,p.value),save:(kind,value)=>write(path.join(input.directory,'group-'+kind+'.json'),value)});
  inbox=new ResultInbox(path.join(input.directory,'results.sqlite'),{chainId:31337,escrow:network.escrow,requester:account});
  const results=await Promise.all(assignments.map(async a=>{
    const ready=await boot[a.rank].readJSON(1024);assert.equal(ready.protocol,'cannabis.owned-peer-ready.v1');
    const wire=await connectBookedPeer({origin:ready.origin,signed:a.signed,initialization:a.initialization,proof,ca:tlsFixture.cert,
      signApproval:p=>requester.signTypedData(p.domain,p.types,p.value)});channels.push(wire);
    try {
      await sendLaunchHandoff(wire,{signed:a.signed,initialization:a.initialization,proof},a.challenge);
      await sendEncryptedInput(wire,{source:input.inputCiphertext,packageSHA256:job.packageSHA256,maxCiphertextBytes:4*1024**2});
      const evidence=await receiveGuestEvidence(wire),token=syntheticGroupEAR(signer,a.policy,a.challenge,evidence.channelJwk,clock()),
        appraisal=await verifyTrusteeResult(token,a.policy,a.challenge,evidence.channelJwk,clock()),
        group=await coordinator.join(a.rank,{channel:wire,challenge:a.challenge,evidence,appraisal:{token,appraisal}});
      const releaseId=h(70+a.rank),custody=await createResultKeyCustody({releaseId,recipient:input.spec.resultRecipient}),
        custodyFile=path.join(input.directory,`result-key-${a.rank}.json`);write(custodyFile,custody);
      const resultSource={python:input.custody.python,age:input.custody.age,identity:input.custody.identity,custody:custodyFile},
        loadResultKey=expected=>recoverRequesterResultKey(resultSource,expected),
        request={releaseId,leaseId:lease.digest,nonce:a.challenge.nonce,channelJwk:evidence.channelJwk,descriptor:input.descriptor,
          notBefore:clock(),expiresAt:group.bundle.start.payload.value.validUntil,resultKeySHA256:custody.resultKeySHA256,group:group.bundle},
        source={schema:'cannabis.market-requester.v3',context,proof,configuration:a.signed.configuration,consent:a.signed},
        payload=keyDeliveryPayload(source,a.ledger,request,clock(),{groupAdmission:group.admission});
      assert.equal(payload.domain.version,'5');
      const record=await sealJobKeyDelivery(source,a.ledger,{request,requesterSignature:await requester.signTypedData(payload.domain,payload.types,payload.value)},
        token,network,expected=>recoverRequesterJobKey(input.custody,expected),{ageKeygen:input.ageKeygen,loadResultKey});
      write(path.join(input.directory,`delivery-${a.rank}.json`),record);
      inbox.activate(record,{resultRecipient:input.spec.resultRecipient});await sendGuestExecution(wire,record);
      const access=await receiveSessionResultAccess(wire,{approvalDigest:record.approvalDigest,origin:a.config.resultOrigin}),
        result=await receiveHostedResult(wire,{inbox,approvalDigest:record.approvalDigest,loadResultKey,
          destination:path.join(input.directory,`result-${a.rank}.age`),maxCiphertextBytes:4*1024**2,
          signStored:p=>requester.signTypedData(p.domain,p.types,p.value),access,origin:a.config.resultOrigin,timeoutMs:90000});
      assert.equal(result.storageAcknowledged,true);assert.equal(result.paymentAuthorized,false);
      const recovered=await inbox.recover(record.approvalDigest,loadResultKey);
      return {approval:record.expectedApproval,receipt:recovered.receipt,file:result.destination,
        selection:{approvalDigest:record.approvalDigest,receiptSHA256:recovered.receiptSHA256}};
    }catch(error){
      process.stderr.write('Owned group rank '+a.rank+' failed at '+(error.transportStage??'session')+': '+error.message+'\n');
      coordinator.abort();throw error;
    }
    finally{wire.close();}
  }));
  const assembled=inbox.useCurrent(results.map(r=>r.selection),approvals=>JSON.parse(execFileSync(input.custody.python,
    [path.join(import.meta.dirname,'../../scripts/compute-result-reconstruct-pipe.py')],{encoding:'utf8',timeout:60000,
      input:JSON.stringify({source:{age:input.custody.age,identity:input.custody.identity,manifest:input.manifest,destination:input.assembled},
        packageSHA256:job.packageSHA256,results:results.map((r,i)=>({receipt:r.receipt,file:r.file,approval:approvals[i]}))}),stdio:['pipe','pipe','ignore']})));
  assert.equal(assembled.integrityVerified,true);assert.equal(assembled.paymentAuthorized,false);
  for(const rank of [0,1])assert.equal(fs.readFileSync(path.join(input.assembled,`rank-${rank}/result.txt`),'utf8'),'42');
  const before=await escrow.credits(policy.founderRecipient),commitment=keccak256(Buffer.from(JSON.stringify(results.map(r=>r.receipt.ciphertextSHA256))));
  await (await escrow.connect(workers[0]).deliver(orderId,commitment)).wait();await (await escrow.approve(orderId)).wait();
  assert.equal(await escrow.credits(policy.founderRecipient)-before,240n);
  const target=await receiver.getAddress(),old=await provider.getBalance(target);
  for(const worker of workers){assert.equal(await escrow.workerDue(orderId,await worker.getAddress()),11880n);await (await escrow.connect(worker).withdrawWorker(orderId,target)).wait();}
  assert.equal(await provider.getBalance(target)-old,23760n);assert.equal(await escrow.totalLiability(),240n);
  process.stdout.write(JSON.stringify({schema:'cannabis.funded-group-fixture.v1',checks:{completeFundedPlan:true,
    protectedGroupStart:true,sessionOwnedKeys:true,v5Delivery:true,encryptedNativeComputation:true,authenticatedReconstruction:true,
    exactFeeAndWorkerSettlement:true,workerWithdrawals:true},grossBaseUnits:'24000',workerBaseUnits:'23760',founderFeeBaseUnits:'240',
    realPaidJob:false,hardwareValidated:false,customerKeysUsed:false}));
}catch(error){coordinator?.abort();process.stderr.write('Owned funded group requester failed: '+error.stack+'\n');process.exitCode=1;}
finally{coordinator?.close();for(const wire of [...channels,...boot]){wire.fail();wire.close();}for(const ledger of ledgers)ledger.close();inbox?.close();provider.destroy();}
