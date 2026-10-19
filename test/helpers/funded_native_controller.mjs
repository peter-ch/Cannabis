// Owned requester integration fixture. A separate guarded guest uses only the
// encrypted wire. Synthetic appraisal and loopback chain; not a service launcher.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { Socket } from 'node:net';
import { ContractFactory, formatUnits, keccak256, ZeroAddress } from '../../node_modules/ethers/lib.esm/index.js';
import { localProvider } from '../../scripts/lib.mjs';
import { CapacityLedger, offerPayload, reservationPayload } from '../../compute/capacity.mjs';
import { leasePayload, promoteLease } from '../../compute/leases.mjs';
import { exportLeaseProof } from '../../compute/lease_proof.mjs';
import { AttestationLedger, leaseAttestationBinding, trusteeRuntimeData } from '../../compute/attestation.mjs';
import { guestInitialization } from '../../compute/guest_initialization.mjs';
import { nativeServiceCommitment } from '../../compute/guest_execution.mjs';
import { keyDeliveryPayload, sealJobKeyDelivery, recoverRequesterJobKey } from '../../compute/key_delivery.mjs';
import { settlementTerms } from '../../scripts/compute-escrow.mjs';
import { policy } from '../../scripts/compute-plan.mjs';
import { createResultKeyCustody, recoverRequesterResultKey } from '../../compute/result_keys.mjs';
import { ResultInbox } from '../../compute/result_inbox.mjs';
import { GuestWire, receiveGuestEvidence, sendGuestExecution, receiveEncryptedResult } from '../../compute/result_transport.mjs';
import { launchConfigurationPayload } from '../../compute/guest_launch.mjs';
import { sendEncryptedInput } from '../../compute/input_transport.mjs';

const h=n=>'0x'+n.toString(16).padStart(64,'0');
const utc=t=>new Date(t*1000).toISOString().replace('.000Z','Z');
const clock=()=>Math.floor(Date.now()/1000);
function canonical(value) {
  if(Array.isArray(value))return value.map(canonical);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
  return value;
}
function syntheticEAR(key,attestationPolicy,challenge,channel) {
  const runtime=trusteeRuntimeData(challenge,channel),m=attestationPolicy.measurements;
  const claims={iss:attestationPolicy.issuer,iat:clock(),exp:clock()+120,eat_profile:'tag:github.com,2024:confidential-containers/Trustee',
    'ear.verifier-id':{developer:'https://confidentialcontainers.org',build:attestationPolicy.verifierBuild},
    submods:{cpu0:{'ear.status':'affirming','ear.appraisal-policy-id':attestationPolicy.appraisalPolicyId,
      'ear.trustworthiness-vector':{'instance-identity':0,configuration:2,executables:3,'file-system':0,hardware:2,'runtime-opaque':0,'storage-opaque':0,'sourced-data':0},
      'ear.veraison.annotated-evidence':{snp:{measurement:m.launch,policy_debug_allowed:false,policy_migrate_ma:false,
        reported_tcb_bootloader:1,reported_tcb_tee:1,reported_tcb_snp:1,reported_tcb_microcode:1},
        init_data:m.initData,init_data_claims:null,runtime_data_claims:runtime,
        report_data:createHash('sha384').update(JSON.stringify(canonical(runtime))).digest('hex')+'00'.repeat(16)}}}};
  const data=[{alg:'ES256',typ:'JWT',jwk:key.publicKey.export({format:'jwk'})},claims].map(x=>Buffer.from(JSON.stringify(x)).toString('base64url')).join('.');
  return data+'.'+sign('sha256',Buffer.from(data),{key:key.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
}

let raw='';for await(const part of process.stdin)raw+=part;
const input=JSON.parse(raw),provider=await localProvider(input.rpc);
let capacity,attestations,inbox;
const wire=new GuestWire(new Socket({fd:input.wireFDs.read,readable:true,writable:false}),
  new Socket({fd:input.wireFDs.write,readable:false,writable:true}),{timeoutMs:100000});
try {
  const [requester,worker,adjudicator,receiver]=await Promise.all([0,1,2,3].map(i=>provider.getSigner(i)));
  const artifact=JSON.parse(fs.readFileSync(input.artifact));
  const escrow=await new ContractFactory(artifact.abi,artifact.bytecode,requester).deploy(ZeroAddress,policy.founderRecipient);
  await escrow.waitForDeployment();
  const address=await escrow.getAddress(),account=await requester.getAddress(),workerAccount=await worker.getAddress();
  const context={chainId:31337,registryId:h(1),token:ZeroAddress};
  capacity=new CapacityLedger(':memory:',context);
  const service=nativeServiceCommitment(input.execution);
  const now=clock(),start=Math.max(now,(await provider.getBlock('latest')).timestamp)+15,end=start+120;
  const gross=12000n;
  capacity.admitResource({provider:workerAccount,resourceId:h(2),...service});
  const offer={offerId:h(3),provider:workerAccount,resourceId:h(2),serviceSHA256:service.serviceSHA256,
    policySHA256:'0x'+input.descriptor.policySHA256,token:ZeroAddress,windowStart:start,windowEnd:end,
    expiresAt:start,units:1,grossPerUnitSecond:'100',feeBps:100,termsSHA256:h(4)};
  const op=offerPayload(context,offer);
  const offerDigest=capacity.addOffer({offer,signature:await worker.signTypedData(op.domain,op.types,op.value)},now).offerDigest;
  const reservation={reservationId:h(5),offerDigest,requester:account,jobSHA256:'0x'+input.descriptor.ciphertextSHA256,
    start,end,units:1,grossBaseUnits:gross.toString(),holdUntil:start-1};
  const rp=reservationPayload(context,reservation);
  capacity.reserve({reservation,requesterSignature:await requester.signTypedData(rp.domain,rp.types,rp.value),
    providerSignature:await worker.signTypedData(rp.domain,rp.types,rp.value)},now);
  const job={schema:'cannabis.compute.order.v2',id:input.descriptor.id,requester:account,
    packageSHA256:input.descriptor.ciphertextSHA256,policySHA256:input.descriptor.policySHA256,acceptanceSHA256:h(6).slice(2),
    payment:{totalBudget:formatUnits(gross,18),feeBasisPoints:100,founderRecipient:policy.founderRecipient}};
  const settlement={workers:[{account:workerAccount,shareBps:10000}],deliveryManager:workerAccount,
    adjudicator:await adjudicator.getAddress(),acceptBy:utc(start-1),deliverBy:utc(end+15),reviewSeconds:86400,disputeSeconds:86400};
  const request={leaseId:h(7),reservationIds:[reservation.reservationId],job,settlement,escrow:address,expiresAt:start-1};
  const lp=leasePayload(capacity,request,now);
  const signed={request,requesterSignature:await requester.signTypedData(lp.domain,lp.types,lp.value),
    providerSignatures:[{provider:workerAccount,signature:await worker.signTypedData(lp.domain,lp.types,lp.value)}]};
  const terms=settlementTerms(job,settlement);
  await (await escrow.fund(terms.terms,terms.accounts,terms.shares,{value:gross})).wait();
  const orderId=await escrow.orderId(account,terms.terms.jobHash);
  await (await escrow.connect(worker).accept(orderId)).wait();
  const network={rpc:input.rpc,chainId:31337,token:ZeroAddress,escrow:address,
    genesisHash:(await provider.getBlock(0)).hash,escrowCodeHash:keccak256(await provider.getCode(address)),tokenCodeHash:null,
    finality:'rpc-finalized',maxFinalizedAgeSeconds:1800,maxHeadAgeSeconds:120};
  const lease=await promoteLease(capacity,signed,network);
  // Advance the fixture chain only when actual UTC enters the reserved interval.
  // Production deadlines and clocks are not replaced with synthetic values.
  while(clock()<start)await new Promise(r=>setTimeout(r,100));
  await provider.send('evm_setNextBlockTimestamp',[clock()]);await provider.send('evm_mine',[]);
  const binding=leaseAttestationBinding(capacity,lease.leaseId,reservation.reservationId,input.run,clock());
  const initialization={schema:'cannabis.guest-initialization.v1',tee:'snp',requester:account,jobId:job.id,binding};
  const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const attestationPolicy={schema:'cannabis.attestation.trustee-policy.v1',issuer:'Owned joint fixture',
    signingJwk:key.publicKey.export({format:'jwk'}),verifierBuild:'synthetic fixture, no hardware',appraisalPolicyId:'owned-fixture',
    maxTokenAgeSeconds:90,maxTokenLifetimeSeconds:120,challengeTTLSeconds:90,tee:'snp',
    measurements:{launch:'11'.repeat(48),initData:guestInitialization(initialization).digest,
      minimumTCB:{bootloader:1,tee:1,snp:1,microcode:1}}};
  attestations=new AttestationLedger(':memory:',attestationPolicy);
  const challenge=attestations.challenge(binding);
  const funding={proof:exportLeaseProof(capacity,lease.leaseId),context,network,provider:workerAccount,
    resourceId:h(2),serviceSHA256:service.serviceSHA256};
  // Disposable authority for this fixture only. Production reads its public
  // authorities from the measured image, never from the requester/host wire.
  const authorities={schema:'cannabis.guest-launch-authorities.v1',chainId:31337,signers:[account],threshold:1,maxValiditySeconds:3600};
  const template=structuredClone(attestationPolicy);template.measurements.initData=null;
  const configuration={schema:'cannabis.guest-launch-configuration.v1',configurationId:h(9),validFrom:start-15,validUntil:end+60,
    context,network,provider:workerAccount,resourceId:h(2),execution:input.execution,attestationPolicyTemplate:template,
    bootstrap:{agentBinary:'/usr/local/bin/ttrpc-aa',bridgeBinary:'/usr/local/bin/api-server-rest',runtimeDirectory:'/run',port:8006},
    transport:{timeoutMs:90000,maxCiphertextBytes:4*1024*1024}};
  const configPayload=launchConfigurationPayload(authorities,configuration);
  const signedConfiguration={configuration,signatures:[{signer:account,signature:await requester.signTypedData(configPayload.domain,configPayload.types,configPayload.value)}]};
  await wire.writeJSON({authorities,signedConfiguration,initialization,request:{proof:funding.proof,challenge}});
  const inputTransfer=await sendEncryptedInput(wire,{source:input.inputCiphertext,
    packageSHA256:input.descriptor.ciphertextSHA256,maxCiphertextBytes:input.execution.profile.ciphertext.inputBytes});
  assert.equal(inputTransfer.peerReportedStorage,true);assert.equal(inputTransfer.keyReleased,false);
  const evidence=await receiveGuestEvidence(wire);
  const resultCustody=await createResultKeyCustody({releaseId:h(8),recipient:input.spec.resultRecipient});
  fs.writeFileSync(input.resultCustody,JSON.stringify(resultCustody),{flag:'wx',mode:0o600});
  const resultSource={python:input.custody.python,age:input.custody.age,identity:input.custody.identity,custody:input.resultCustody};
  const delivery={releaseId:h(8),leaseId:lease.leaseId,nonce:challenge.nonce,channelJwk:evidence.channelJwk,
    descriptor:input.descriptor,notBefore:clock(),expiresAt:clock()+60,resultKeySHA256:resultCustody.resultKeySHA256};
  const payload=keyDeliveryPayload(capacity,attestations,delivery,clock());
  const approval={request:delivery,requesterSignature:await requester.signTypedData(payload.domain,payload.types,payload.value)};
  const record=await sealJobKeyDelivery(capacity,attestations,approval,syntheticEAR(key,attestationPolicy,challenge,evidence.channelJwk),
    network,expected=>recoverRequesterJobKey(input.custody,expected),{ageKeygen:input.ageKeygen,
      loadResultKey:expected=>recoverRequesterResultKey(resultSource,expected)});
  const saved={config:input.resultBase+'-config.json',record:input.resultBase+'-record.json',
    envelope:input.resultBase+'-envelope.json',input:input.resultBase+'-input.json'};
  const write=(file,value)=>fs.writeFileSync(file,JSON.stringify(value),{mode:0o600});
  write(saved.config,{inbox:input.resultBase+'.sqlite',context:{chainId:31337,escrow:address,requester:account},
    resultKeySources:{[h(8)]:resultSource},
    reconstruction:{python:input.custody.python,age:input.custody.age,identity:input.custody.identity}});
  write(saved.record,record);
  // Every CLI action starts a new process. Only the encrypted journal/inbox and
  // owner-held recovery custody survive between receive, recover and assemble.
  const runResults=(action,value)=>{
    write(saved.input,value);
    return JSON.parse(execFileSync(process.execPath,[input.resultsCLI,action,saved.config,saved.input],
      {encoding:'utf8',timeout:30000,stdio:['ignore','pipe','ignore']}));
  };
  assert.equal(runResults('activate',{deliveryRecord:saved.record,resultRecipient:input.spec.resultRecipient}).newSelection,true);
  const selection={approvalDigest:payload.digest};
  inbox=new ResultInbox(input.resultBase+'.sqlite',{chainId:31337,escrow:address,requester:account});
  await sendGuestExecution(wire,record);
  const transported=await receiveEncryptedResult(wire,{inbox,approvalDigest:payload.digest,
    loadResultKey:expected=>recoverRequesterResultKey(resultSource,expected),
    destination:input.resultBase+'-download.age',maxCiphertextBytes:4*1024*1024,
    signStored:payload=>requester.signTypedData(payload.domain,payload.types,payload.value)});
  assert.equal(transported.storageAcknowledged,true);assert.equal(transported.paymentAuthorized,false);
  const authenticated=await inbox.recover(payload.digest,expected=>recoverRequesterResultKey(resultSource,expected));
  const receipt=authenticated.receipt;inbox.close();inbox=undefined;
  write(saved.envelope,{approvalDigest:payload.digest,resultEnvelope:transported.resultEnvelope});
  const received=runResults('receive',{...selection,envelopeFile:saved.envelope});
  assert.equal(received.newDelivery,false);assert.equal(received.receiptAuthenticated,true);
  assert.equal(JSON.stringify(received).includes('owned-task'),false);
  assert.equal(runResults('recover',selection).newDelivery,false);
  assert.equal(runResults('receive',{...selection,envelopeFile:saved.envelope}).newDelivery,false);
  const assembly={manifest:input.resultManifest,packageSHA256:job.packageSHA256,
    results:[{...selection,file:transported.destination}],destination:input.assembled};
  const altered=structuredClone(input.spec);altered.tasks[0].runtime.digestSHA256='ff'.repeat(32);
  const changedManifest=input.resultBase+'-changed-manifest.json';write(changedManifest,altered);
  assert.throws(()=>runResults('assemble',{...assembly,manifest:changedManifest}));
  assert.equal(fs.existsSync(input.assembled),false);
  const reconstruction=runResults('assemble',assembly);
  assert.equal(reconstruction.integrityVerified,true);assert.equal(reconstruction.approvedAttemptsVerified,true);
  assert.equal(reconstruction.qualityAccepted,false);assert.equal(reconstruction.paymentAuthorized,false);
  // Separate owned application acceptance, after authenticated reconstruction.
  assert.equal(fs.readFileSync(input.assembled+'/result.txt','utf8'),'OWNED PRIVATE CHANNEL INPUT');
  assert.equal(fs.readFileSync(input.assembled+'/stdout.txt','utf8'),'owned private channel log\n');
  const beforeCredit=await escrow.credits(policy.founderRecipient);
  await (await escrow.connect(worker).deliver(orderId,'0x'+receipt.ciphertextSHA256)).wait();
  await (await escrow.approve(orderId)).wait();
  assert.equal(await escrow.workerDue(orderId,workerAccount),11880n);
  assert.equal(await escrow.credits(policy.founderRecipient)-beforeCredit,120n);
  const target=await receiver.getAddress(),before=await provider.getBalance(target);
  await (await escrow.connect(worker).withdrawWorker(orderId,target)).wait();
  assert.equal(await provider.getBalance(target)-before,11880n);
  assert.equal(await escrow.workerDue(orderId,workerAccount),0n);
  assert.equal(await escrow.totalLiability(),120n);
  process.stdout.write(JSON.stringify({schema:'cannabis.funded-native-fixture.v1',
    checks:{signedNativeCapacity:true,freshFundedAdmission:true,guardedNativeExecution:true,requesterReconstruction:true,
      exactFeeAndWorkerSettlement:true,workerWithdrawal:true,sessionReplayRefused:true,encryptedReceiptAuthenticated:true,
      requesterProcessRestartRecovery:true,duplicateReceiptIdempotent:true,approvedWorkloadReconstruction:true,
      separateGuestProcess:true,encryptedStreamingHandoff:true,requesterStorageAcknowledgement:true,
      authorizedLaunchConfiguration:true,preSessionKernelAdmission:true,encryptedInputStreamedBeforeEvidence:true},
    grossBaseUnits:'12000',workerBaseUnits:'11880',founderFeeBaseUnits:'120',chainId:31337,
    realPaidJob:false,hardwareValidated:false,customerKeysUsed:false}));
} catch(error) {process.stderr.write('Owned funded native fixture failed: '+error.stack+'\n');process.exitCode=1;}
finally {wire.fail();wire.close();inbox?.close();attestations?.close();capacity?.close();provider.destroy();}
