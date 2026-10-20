// Synthetic signed appraisals/booking records for isolated protocol checks only.
// No real hardware, chain funding, participant identity or wallet is used here.
import net from 'node:net';
import {createHash,generateKeyPairSync,sign,webcrypto} from 'node:crypto';
import {Wallet,AbiCoder,formatUnits,keccak256,ZeroAddress} from 'ethers';
import {launchFixture} from './launch_fixture.mjs';
import {nativeServiceCommitment} from '../../compute/guest_execution.mjs';
import {validateGuestConfiguration} from '../../compute/guest_configuration.mjs';
import {configuredMarketAttestationBinding,AttestationLedger,trusteeRuntimeData} from '../../compute/attestation.mjs';
import {guestInitialization} from '../../compute/guest_initialization.mjs';
import {inspectExecutionPlan,taskCommitment} from '../../compute/execution_plan.mjs';
import {verifyMarketLeaseProof} from '../../compute/market_lease.mjs';
import {bookingPayload} from '../../compute/market.mjs';
import {launchConsentPayload} from '../../compute/guest_consent.mjs';
import {settlementTerms,termsDigest} from '../../scripts/compute-escrow.mjs';
import {policy} from '../../scripts/compute-plan.mjs';
import {groupCanonical,GROUP_ADAPTER,GROUP_BACKEND,GROUP_SCHEMA,groupAdmissionPayload,verifyGroupAdmission} from '../../compute/group_admission.mjs';
const h=n=>'0x'+n.toString(16).padStart(64,'0'),coder=AbiCoder.defaultAbiCoder();
const utc=n=>new Date(n*1000).toISOString().replace('.000Z','Z');
const port=()=>new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
const publicJwk=async key=>{const j=await webcrypto.subtle.exportKey('jwk',key);return Object.fromEntries(['kty','crv','x','y'].map(k=>[k,j[k]]));};
export function syntheticGroupEAR(key,policy,challenge,channel,now) {
  const runtime=trusteeRuntimeData(challenge,channel),m=policy.measurements;
  const claims={iss:policy.issuer,iat:now,exp:now+120,eat_profile:'tag:github.com,2024:confidential-containers/Trustee',
    'ear.verifier-id':{developer:'https://confidentialcontainers.org',build:policy.verifierBuild},submods:{cpu0:{
      'ear.status':'affirming','ear.appraisal-policy-id':policy.appraisalPolicyId,
      'ear.trustworthiness-vector':{'instance-identity':0,configuration:2,executables:3,'file-system':0,hardware:2,'runtime-opaque':0,'storage-opaque':0,'sourced-data':0},
      'ear.veraison.annotated-evidence':{snp:{measurement:m.launch,policy_debug_allowed:false,policy_migrate_ma:false,
        reported_tcb_bootloader:1,reported_tcb_tee:1,reported_tcb_snp:1,reported_tcb_microcode:1},init_data:m.initData,
        init_data_claims:null,runtime_data_claims:runtime,report_data:createHash('sha384').update(groupCanonical(runtime)).digest('hex')+'00'.repeat(16)}}}};
  const body=[{alg:'ES256',typ:'JWT'},claims].map(v=>Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
  return body+'.'+sign('sha256',Buffer.from(body),{key:key.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
}
export async function groupFixture({now=Math.floor(Date.now()/1000),nodes=2,executions,workload,channelJwks,realTime=false}={}) {
  if(![2,4].includes(nodes))throw Error('Owned fixture supports two or four ranks');
  const clock=realTime?()=>Math.floor(Date.now()/1000):()=>now;
  const requester=Wallet.createRandom(),providers=Array.from({length:nodes},()=>Wallet.createRandom()),signer=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const c=launchFixture().configuration,start=now-5,end=now+300;
  c.schema='cannabis.guest-launch-configuration.v3';c.context={chainId:31337,market:Wallet.createRandom().address,token:ZeroAddress};
  c.network.market=c.context.market;c.network.marketCodeHash=h(99);c.validFrom=start;c.validUntil=end;
  c.attestationPolicyTemplate.signingJwk=signer.publicKey.export({format:'jwk'});
  if(executions)c.execution=structuredClone(executions[0]);
  const p=c.execution.profile;p.schema='cannabis.guest-native-service.v4';p.resources.nodes=nodes;
  p.runtime.adapter=GROUP_ADAPTER;p.runtime.collectiveBackend=GROUP_BACKEND;p.maxDependencyBytes=1024**2;p.ciphertext.dependencyBytes=1024**2;
  if(!executions)p.ciphertext.bytes+=1024**2;
  p.group={protocol:'cannabis.group-tls-ip.v1',bindHost:'127.0.0.1',port:await port(),maxBufferedBytes:131072,maxTrafficBytes:1048576};
  const configurations=[];
  for(const [rank,provider] of providers.entries()) {
    const configuration=structuredClone(c);configuration.configurationId=h(100+rank);configuration.provider=provider.address;
    if(executions)configuration.execution.source=structuredClone(executions[rank].source);
    configuration.resourceId=keccak256(coder.encode(['address','bytes32'],[provider.address,h(200+rank)]));
    if(rank)configuration.execution.profile.group.port=await port();configurations.push(configuration);
  }
  const packageSHA256=workload?.ciphertextSHA256??h(2).slice(2),policySHA256=workload?.policySHA256??h(3).slice(2),
    jobId=workload?.id??'owned-group-fixture',gross=BigInt(end-start)*100n;
  const rawBookings=configurations.map((_,rank)=>({reservationId:h(300+rank),offerId:h(400+rank),start:String(start),end:String(end),units:'1',gross:String(gross),holdUntil:String(start-1)}));
  const plan=inspectExecutionPlan({schema:'cannabis.execution-plan.v1',chainId:c.context.chainId,genesisHash:c.network.genesisHash,
    market:c.context.market,escrow:c.network.escrow,token:ZeroAddress,requester:requester.address,jobId,packageSHA256,policySHA256,
    requirements:[{task:0,taskSHA256:taskCommitment(packageSHA256,0),dependsOn:[],runtime:p.runtime,resources:p.resources}],
    assignments:configurations.map((configuration,rank)=>({task:0,rank,attempt:1,acceleratorClass:'cpu',provider:providers[rank].address,
      serviceSHA256:nativeServiceCommitment(configuration.execution).serviceSHA256,booking:rawBookings[rank]}))});
  const job={schema:'cannabis.compute.order.v3',id:jobId,requester:requester.address,packageSHA256,policySHA256,
    acceptanceSHA256:h(4).slice(2),executionPlanSHA256:plan.digestSHA256,
    payment:{totalBudget:formatUnits(gross*BigInt(nodes),18),feeBasisPoints:100,founderRecipient:policy.founderRecipient}};
  const settlement={workers:providers.map(p=>({account:p.address,shareBps:10000/nodes})),deliveryManager:providers[0].address,
    adjudicator:Wallet.createRandom().address,acceptBy:utc(start-1),deliverBy:utc(end+100),reviewSeconds:86400,disputeSeconds:86400};
  const terms=settlementTerms(job,settlement),orderId=keccak256(coder.encode(['string','uint256','address','address','bytes32'],
    ['Cannabis compute order v1',31337,c.network.escrow,requester.address,terms.terms.jobHash])),
    digest=termsDigest({chainId:31337,escrow:c.network.escrow,token:ZeroAddress,founderRecipient:policy.founderRecipient,...terms});
  const bookings=configurations.map((configuration,rank)=>{
    const booking={...rawBookings[rank],requester:requester.address,orderId,termsDigest:digest};
    return {bookingId:bookingPayload(c.context,booking).digest,booking,
      offer:{resource:configuration.resourceId,escrow:c.network.escrow,policyHash:'0x'+policySHA256,manifestHash:h(500+rank),
        start:String(start),end:String(end),expiresAt:String(start-1),units:'1',grossPerUnitSecond:'100'},
      resource:{provider:providers[rank].address,serviceHash:nativeServiceCommitment(configuration.execution).serviceSHA256,units:'1'}};
  }).sort((a,b)=>a.bookingId.localeCompare(b.bookingId));
  const proof={schema:'cannabis.market-lease.v2',chainId:31337,market:c.context.market,token:ZeroAddress,escrow:c.network.escrow,
    job,settlement,bookings,executionPlan:plan.plan,fundedAnchor:{number:12,hash:h(8),timestamp:start-1}};
  const lease=verifyMarketLeaseProof(proof,c.network),peers=[],keys=[],ledgers=[];
  for(const [rank,configuration] of configurations.entries()) {
    const configHash=validateGuestConfiguration(configuration).configurationSHA256,assignment=lease.assignments.find(a=>a.run.rank===rank),
      binding=configuredMarketAttestationBinding(proof,c.context,assignment.reservationId,assignment.run,configHash,now);
    const initialization={schema:'cannabis.guest-initialization.v2',tee:'snp',requester:requester.address,jobId:job.id,binding},consents=[];
    for(const [role,wallet] of [['requester',requester],['provider',providers[rank]]]) {
      const payload=launchConsentPayload(configuration,initialization,proof,role);
      consents.push({role,signer:wallet.address,signature:await wallet.signTypedData(payload.domain,payload.types,payload.value)});
    }
    const policy=structuredClone(configuration.attestationPolicyTemplate);policy.measurements.initData=guestInitialization(initialization).digest;
    const ledger=new AttestationLedger(':memory:',policy,clock);ledgers.push(ledger);
    const challenge=ledger.challenge(binding),key=channelJwks?null:await webcrypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);keys.push(key?.privateKey);
    const channelJwk=channelJwks?structuredClone(channelJwks[rank]):await publicJwk(key.publicKey);
    peers.push({signed:{schema:'cannabis.guest-launch-consent.v1',configuration,consents},initialization,challenge,channelJwk,
      appraisal:syntheticGroupEAR(signer,policy,challenge,channelJwk,challenge.issuedAt),endpoint:'tls://127.0.0.1:'+configuration.execution.profile.group.port});
  }
  const requesterKey=await webcrypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']),
    group={schema:GROUP_SCHEMA,task:0,issuedAt:clock(),expiresAt:now+60,requesterChannelJwk:await publicJwk(requesterKey.publicKey),peers};
  const payload=await groupAdmissionPayload(proof,c.network,group,{clock}),
    approval={schema:'cannabis.protected-group-approval.v1',group,requesterSignature:await requester.signTypedData(payload.domain,payload.types,payload.value)};
  const admission=await verifyGroupAdmission(proof,c.network,approval,{clock});
  return {proof,network:c.network,approval,admission,keys,requesterKey:requesterKey.privateKey,requester,ledgers,clock,
    close:()=>ledgers.forEach(l=>l.close())};
}
