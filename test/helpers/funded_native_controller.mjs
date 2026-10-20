// Owned requester integration fixture. A separate guarded guest uses only the
// encrypted wire. Synthetic appraisal and loopback chain; not a service launcher.
import fs from 'node:fs';
import http from 'node:http';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { Socket } from 'node:net';
import { AbiCoder, ContractFactory, formatUnits, keccak256, ZeroAddress } from '../../node_modules/ethers/lib.esm/index.js';
import { localProvider } from '../../scripts/lib.mjs';
import { compile } from '../../scripts/compile.mjs';
import { bookingPayload } from '../../compute/market.mjs';
import { createMarketLeaseProof, verifyMarketLeaseProof } from '../../compute/market_lease.mjs';
import { AttestationLedger, configuredMarketAttestationBinding, trusteeRuntimeData } from '../../compute/attestation.mjs';
import { guestInitialization } from '../../compute/guest_initialization.mjs';
import { nativeServiceCommitment } from '../../compute/guest_execution.mjs';
import { keyDeliveryPayload, sealJobKeyDelivery, recoverRequesterJobKey } from '../../compute/key_delivery.mjs';
import { settlementTerms, termsDigest } from '../../scripts/compute-escrow.mjs';
import { policy } from '../../scripts/compute-plan.mjs';
import { createResultKeyCustody, recoverRequesterResultKey } from '../../compute/result_keys.mjs';
import { ResultInbox } from '../../compute/result_inbox.mjs';
import { GuestWire, receiveGuestEvidence, sendGuestExecution, receiveEncryptedResult } from '../../compute/result_transport.mjs';
import { validateGuestConfiguration } from '../../compute/guest_configuration.mjs';
import { launchConsentPayload } from '../../compute/guest_consent.mjs';
import { sendEncryptedInput } from '../../compute/input_transport.mjs';
import { receiveSessionResultAccess } from '../../requester/session-access.mjs';
import { receiveHostedResult } from '../../requester/hosted-result.mjs';
import { connectBookedPeer } from '../../compute/peer_network.mjs';
import { sendLaunchHandoff } from '../../compute/launch_handoff.mjs';
import { encodeProviderManifest, readProviderManifest } from '../../compute/provider_manifest.mjs';
import tlsFixture from '../../test/helpers/peer-tls-fixture.json' with {type:'json'};

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
let capacity,attestations,inbox,selectedPeer;const mirrors=[];
async function mirror(bytes) {
  const requests=[],server=http.createServer((req,res)=>{
    requests.push({url:req.url,authorization:req.headers.authorization,cookie:req.headers.cookie});
    res.writeHead(200,{'Content-Type':'application/json','Content-Length':bytes.length});res.end(bytes);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));mirrors.push(server);
  return {origin:'http://127.0.0.1:'+server.address().port,requests};
}
const bootstrapWire=new GuestWire(new Socket({fd:input.wireFDs.read,readable:true,writable:false}),
  new Socket({fd:input.wireFDs.write,readable:false,writable:true}),{timeoutMs:100000});
let wire=bootstrapWire;
try {
  const [requester,worker,adjudicator,receiver]=await Promise.all([0,1,2,3].map(i=>provider.getSigner(i)));
  const artifacts=compile({'KernelMarketFixture.sol':{content:`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract KernelMarketAsset is ERC20 { constructor() ERC20("Isolated kernel fixture", "FIX") {} }
`}}),artifact=artifacts.ComputeEscrow;
  const escrow=await new ContractFactory(artifact.abi,artifact.bytecode,requester).deploy(ZeroAddress,policy.founderRecipient);
  await escrow.waitForDeployment();
  const address=await escrow.getAddress(),account=await requester.getAddress(),workerAccount=await worker.getAddress();
  const token=await new ContractFactory(artifacts.KernelMarketAsset.abi,artifacts.KernelMarketAsset.bytecode,requester).deploy();await token.waitForDeployment();
  const tokenEscrow=await new ContractFactory(artifact.abi,artifact.bytecode,requester).deploy(await token.getAddress(),policy.founderRecipient);await tokenEscrow.waitForDeployment();
  const market=await new ContractFactory(artifacts.ComputeMarket.abi,artifacts.ComputeMarket.bytecode,requester).deploy(address,await tokenEscrow.getAddress());await market.waitForDeployment();
  const context={chainId:31337,market:await market.getAddress(),token:ZeroAddress};
  const network={rpc:input.rpc,chainId:31337,token:ZeroAddress,escrow:address,
    genesisHash:(await provider.getBlock(0)).hash,escrowCodeHash:keccak256(await provider.getCode(address)),tokenCodeHash:null,
    finality:'rpc-finalized',maxFinalizedAgeSeconds:1800,maxHeadAgeSeconds:120,
    market:context.market,marketCodeHash:keccak256(await provider.getCode(context.market))};
  const service=nativeServiceCommitment(input.execution);
  const now=clock(),start=Math.max(now,(await provider.getBlock('latest')).timestamp)+15,end=start+120;
  const gross=12000n;
  await (await market.connect(worker).publishResource(h(2),service.serviceSHA256,service.units)).wait();
  const resourceId=await market.resourceKey(workerAccount,h(2));
  const offer={resource:resourceId,escrow:address,policyHash:'0x'+input.descriptor.policySHA256,manifestHash:h(4),
    start,end,expiresAt:start,units:1,grossPerUnitSecond:'100'};
  const predictedOffer=keccak256(AbiCoder.defaultAbiCoder().encode(['address','bytes32'],[workerAccount,h(3)]));
  let encodedManifest;
  if(input.independentNetwork) {
    const {manifestHash,...terms}=offer;
    encodedManifest=encodeProviderManifest({schema:'cannabis.provider-manifest.v1',chainId:'31337',
      genesisHash:network.genesisHash,market:context.market,offerId:predictedOffer,
      resource:{id:resourceId,provider:workerAccount,serviceHash:service.serviceSHA256,units:String(service.units)},
      offer:Object.fromEntries(Object.entries(terms).map(([k,v])=>[k,String(v)])),
      endpoints:['booking','session'].map(role=>({role,origin:input.independentNetwork.peerOrigin})),
      runtimes:[{...input.execution.profile.runtime,digestSHA256:'0x'+input.execution.profile.runtime.digestSHA256,
        tee:'snp',acceleratorClass:'cpu'}],
      terms:'Owned independent-network check. Synthetic appraisal, no real capacity or payment.'});
    offer.manifestHash=encodedManifest.manifestHash;
  }
  const offered=await (await market.connect(worker).publishOffer(h(3),offer)).wait();
  const offerId=offered.logs.map(l=>{try{return market.interface.parseLog(l);}catch{return null;}}).find(e=>e?.name==='OfferPublished').args.offerId;
  assert.equal(offerId,predictedOffer);
  if(input.independentNetwork) {
    const bad=await mirror(Buffer.from('{}\n')),good=await mirror(encodedManifest.bytes);
    const observed=await readProviderManifest(network,{offerId,fromBlock:offered.blockNumber,toBlock:offered.blockNumber,
      mirrors:[bad.origin,good.origin]});
    assert.equal(observed.chainVerified,true);assert.equal(observed.mirror,good.origin);
    assert.equal(observed.hardwareValidated,false);assert.equal(observed.keyReleaseAuthorized,false);
    assert.equal(observed.manifest.resource.provider,workerAccount);
    selectedPeer=observed.manifest.endpoints.find(e=>e.role==='session').origin;
    for(const endpoint of [bad,good]) {
      assert.equal(endpoint.requests.length,1);
      assert.equal(endpoint.requests[0].url,'/.well-known/cannabis/manifests/sha256/'+offer.manifestHash.slice(2)+'.json');
      assert.equal(endpoint.requests[0].authorization,undefined);assert.equal(endpoint.requests[0].cookie,undefined);
    }
  }
  const job={schema:'cannabis.compute.order.v2',id:input.descriptor.id,requester:account,
    packageSHA256:input.descriptor.ciphertextSHA256,policySHA256:input.descriptor.policySHA256,acceptanceSHA256:h(6).slice(2),
    payment:{totalBudget:formatUnits(gross,18),feeBasisPoints:100,founderRecipient:policy.founderRecipient}};
  const settlement={workers:[{account:workerAccount,shareBps:10000}],deliveryManager:workerAccount,
    adjudicator:await adjudicator.getAddress(),acceptBy:utc(start-1),deliverBy:utc(end+15),reviewSeconds:86400,disputeSeconds:86400};
  const terms=settlementTerms(job,settlement);
  const orderId=await escrow.orderId(account,terms.terms.jobHash);
  const digest=termsDigest({chainId:31337,escrow:address,token:ZeroAddress,founderRecipient:policy.founderRecipient,...terms});
  const reservation={reservationId:h(5),offerId,requester:account,orderId,termsDigest:digest,start,end,units:1,gross:gross.toString(),holdUntil:start-1};
  const rp=bookingPayload(context,reservation);
  await (await market.reserveBatch([reservation],[await worker.signTypedData(rp.domain,rp.types,rp.value)])).wait();
  await (await escrow.fund(terms.terms,terms.accounts,terms.shares,{value:gross})).wait();
  await (await escrow.connect(worker).accept(orderId)).wait();
  await (await market.activate([rp.digest])).wait();
  const proof=await createMarketLeaseProof(network,{job,settlement,bookingIds:[rp.digest]});
  const lease=verifyMarketLeaseProof(proof,context);
  // Advance the fixture chain only when actual UTC enters the reserved interval.
  // Production deadlines and clocks are not replaced with synthetic values.
  while(clock()<start)await new Promise(r=>setTimeout(r,100));
  await provider.send('evm_setNextBlockTimestamp',[clock()]);await provider.send('evm_mine',[]);
  const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const attestationPolicy={schema:'cannabis.attestation.trustee-policy.v1',issuer:'Owned joint fixture',
    signingJwk:key.publicKey.export({format:'jwk'}),verifierBuild:'synthetic fixture, no hardware',appraisalPolicyId:'owned-fixture',
    maxTokenAgeSeconds:90,maxTokenLifetimeSeconds:120,challengeTTLSeconds:90,tee:'snp',
    measurements:{launch:'11'.repeat(48),initData:null,
      minimumTCB:{bootloader:1,tee:1,snp:1,microcode:1}}};
  const funding={proof,context,network,provider:workerAccount,resourceId,serviceSHA256:service.serviceSHA256};
  const template=structuredClone(attestationPolicy);template.measurements.initData=null;
  const configuration={schema:'cannabis.guest-launch-configuration.v3',configurationId:h(9),validFrom:start-15,validUntil:end+60,
    context,network,provider:workerAccount,resourceId,execution:input.execution,attestationPolicyTemplate:template,
    bootstrap:{agentBinary:'/usr/local/bin/ttrpc-aa',bridgeBinary:'/usr/local/bin/api-server-rest',runtimeDirectory:'/run',port:8006},
    transport:{timeoutMs:90000,maxCiphertextBytes:4*1024*1024}};
  const configurationSHA256=validateGuestConfiguration(configuration).configurationSHA256;
  const binding=configuredMarketAttestationBinding(proof,context,rp.digest,input.run,configurationSHA256,clock());
  const initialization={schema:'cannabis.guest-initialization.v2',tee:'snp',requester:account,jobId:job.id,binding};
  attestationPolicy.measurements.initData=guestInitialization(initialization).digest;
  attestations=new AttestationLedger(':memory:',attestationPolicy);
  const challenge=attestations.challenge(binding);
  const consents=[];
  for(const [role,signer,address] of [['requester',requester,account],['provider',worker,workerAccount]]) {
    const p=launchConsentPayload(configuration,initialization,proof,role);
    consents.push({role,signer:address,signature:await signer.signTypedData(p.domain,p.types,p.value)});
  }
  const signedConfiguration={schema:'cannabis.guest-launch-consent.v1',configuration,consents};
  capacity={schema:'cannabis.market-requester.v3',context,proof,configuration,consent:signedConfiguration};
  await wire.writeJSON({signedConfiguration,initialization,request:{proof:funding.proof,challenge}});
  if(input.resultOrigin) {
    const ready=await bootstrapWire.readJSON(1024);
    assert.deepEqual(Object.keys(ready).sort(),['origin','protocol']);assert.equal(ready.protocol,'cannabis.owned-peer-ready.v1');
    const endpoint=new URL(ready.origin);assert.equal(endpoint.hostname,'localhost');assert.equal(endpoint.protocol,'https:');
    if(input.independentNetwork)assert.equal(ready.origin,selectedPeer);
    wire=await connectBookedPeer({origin:selectedPeer??ready.origin,signed:signedConfiguration,initialization,proof,ca:tlsFixture.cert,
      signApproval:p=>requester.signTypedData(p.domain,p.types,p.value)});
    assert.equal(wire.report.channelAuthenticated,true);assert.equal(wire.report.configurationSHA256,configurationSHA256);
    assert.equal(wire.report.hardwareVerified,false);
    if(!input.independentNetwork){bootstrapWire.fail();bootstrapWire.close();}
    const handoff=await sendLaunchHandoff(wire,{signed:signedConfiguration,initialization,proof},challenge);
    assert.equal(handoff.executionAuthorized,false);assert.equal(handoff.keyReleaseAuthorized,false);
  }
  const inputTransfer=await sendEncryptedInput(wire,{source:input.inputCiphertext,
    packageSHA256:input.descriptor.ciphertextSHA256,maxCiphertextBytes:input.execution.profile.ciphertext.inputBytes});
  assert.equal(inputTransfer.peerReportedStorage,true);assert.equal(inputTransfer.keyReleased,false);
  const evidence=await receiveGuestEvidence(wire);
  const resultCustody=await createResultKeyCustody({releaseId:h(8),recipient:input.spec.resultRecipient});
  fs.writeFileSync(input.resultCustody,JSON.stringify(resultCustody),{flag:'wx',mode:0o600});
  const resultSource={python:input.custody.python,age:input.custody.age,identity:input.custody.identity,custody:input.resultCustody};
  // Chain/consent admission consumes the existing challenge and service time.
  // Never ask key delivery to restart a full minute after those observations.
  const deliveryStart=clock(),deliveryEnd=Math.min(deliveryStart+60,challenge.expiresAt,end);
  assert.ok(deliveryEnd>deliveryStart,'Existing delivery interval already expired');
  const delivery={releaseId:h(8),leaseId:lease.digest,nonce:challenge.nonce,channelJwk:evidence.channelJwk,
    descriptor:input.descriptor,notBefore:deliveryStart,expiresAt:deliveryEnd,resultKeySHA256:resultCustody.resultKeySHA256};
  const payload=keyDeliveryPayload(capacity,attestations,delivery,clock());
  assert.equal(payload.domain.version,'3');assert.equal(payload.value.configurationSHA256,configurationSHA256);
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
  const hosted=input.resultOrigin?{origin:input.resultOrigin,
    access:await receiveSessionResultAccess(wire,{approvalDigest:payload.digest,origin:input.resultOrigin}),timeoutMs:90000}:{};
  const transported=await (input.resultOrigin?receiveHostedResult:receiveEncryptedResult)(wire,{inbox,approvalDigest:payload.digest,
    loadResultKey:expected=>recoverRequesterResultKey(resultSource,expected),
    destination:input.resultBase+'-download.age',maxCiphertextBytes:4*1024*1024,
    signStored:payload=>requester.signTypedData(payload.domain,payload.types,payload.value),...hosted});
  assert.equal(transported.storageAcknowledged,true);assert.equal(transported.paymentAuthorized,false);
  const authenticated=await inbox.recover(payload.digest,expected=>recoverRequesterResultKey(resultSource,expected));
  const receipt=authenticated.receipt;inbox.close();inbox=undefined;
  let resultDestination=transported.destination;
  if(input.independentNetwork) {
    await bootstrapWire.writeJSON({protocol:'cannabis.owned-replacement.v1',operation:'replace'});
    const replacement=await bootstrapWire.readJSON(6*1024*1024+8192);
    assert.equal(replacement.protocol,'cannabis.owned-replacement.v1');
    assert.equal(replacement.origin,input.independentNetwork.replacementOrigin);
    assert.equal(replacement.header.resultEnvelope,transported.resultEnvelope);
    assert.equal(replacement.header.ciphertextSHA256,receipt.ciphertextSHA256);
    assert.equal(replacement.header.approvalDigest,payload.digest);
    assert.equal(replacement.originalRelayStopped,true);
    const original=fs.readFileSync(transported.destination);
    fs.renameSync(transported.destination,transported.destination+'.retained');
    const recovered=JSON.parse(execFileSync(process.execPath,[input.independentNetwork.recoveryScript],{
      input:JSON.stringify({rpc:input.rpc,inbox:input.resultBase+'.sqlite',context:{chainId:31337,escrow:address,requester:account},
        resultSource,approvalDigest:payload.digest,origin:replacement.origin,originalOrigin:input.resultOrigin,
        access:replacement.access,header:replacement.header,destination:input.resultBase+'-replacement.age'}),
      encoding:'utf8',timeout:45000,stdio:['pipe','pipe','inherit']}));
    assert.equal(recovered.cancelledRetrievalRefused,true);assert.equal(recovered.cancelledFileRemoved,true);
    assert.equal(recovered.recovered,true);assert.equal(recovered.paymentAuthorized,false);
    resultDestination=input.resultBase+'-replacement.age';
    assert.deepEqual(fs.readFileSync(resultDestination),original);
    await bootstrapWire.writeJSON({protocol:'cannabis.owned-replacement.v1',operation:'stored',signature:recovered.signature});
    const completed=await bootstrapWire.readJSON(1024);
    assert.equal(completed.replacementStorageSignatureVerified,true);assert.equal(completed.executions,1);
  }
  write(saved.envelope,{approvalDigest:payload.digest,resultEnvelope:transported.resultEnvelope});
  const received=runResults('receive',{...selection,envelopeFile:saved.envelope});
  assert.equal(received.newDelivery,false);assert.equal(received.receiptAuthenticated,true);
  assert.equal(JSON.stringify(received).includes('owned-task'),false);
  assert.equal(runResults('recover',selection).newDelivery,false);
  assert.equal(runResults('receive',{...selection,envelopeFile:saved.envelope}).newDelivery,false);
  const assembly={manifest:input.resultManifest,packageSHA256:job.packageSHA256,
    results:[{...selection,file:resultDestination}],destination:input.assembled};
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
    checks:{signedNativeCapacity:true,onChainMarketBooking:true,noCapacityDatabase:true,configurationBoundApproval:true,freshFundedAdmission:true,guardedNativeExecution:true,requesterReconstruction:true,
      exactFeeAndWorkerSettlement:true,workerWithdrawal:true,sessionReplayRefused:true,encryptedReceiptAuthenticated:true,
      requesterProcessRestartRecovery:true,duplicateReceiptIdempotent:true,approvedWorkloadReconstruction:true,
      separateGuestProcess:true,encryptedStreamingHandoff:true,requesterStorageAcknowledgement:true,
      authorizedLaunchConfiguration:true,preSessionKernelAdmission:true,encryptedInputStreamedBeforeEvidence:true,
      ...(input.resultOrigin?{hostedHTTPRecovery:true,sessionReadCapabilityVerified:true,bookedTLSRequesterAuthenticated:true}:{}),
      ...(input.independentNetwork?{manifestDiscoveredFromChain:true,badMirrorRejected:true,peerSelectedFromManifest:true,
        replacementResultRecovered:true,recoveryInNewProcess:true,cancelledRetrievalRefused:true,cancelledFileRemoved:true}:{})},
    grossBaseUnits:'12000',workerBaseUnits:'11880',founderFeeBaseUnits:'120',chainId:31337,
    realPaidJob:false,hardwareValidated:false,customerKeysUsed:false}));
} catch(error) {process.stderr.write('Owned funded native fixture failed: '+error.stack+'\n');process.exitCode=1;}
finally {wire.fail();wire.close();bootstrapWire.fail();bootstrapWire.close();inbox?.close();attestations?.close();provider.destroy();
  for(const server of mirrors){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}}
