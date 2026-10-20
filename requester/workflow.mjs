// A requester owns this scheduler, custody and recovery. Providers remain
// independently booked; this module never submits a payment or changes a plan.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {verifyTypedData} from 'ethers';
import {verifyMarketLeaseProof} from '../compute/market_lease.mjs';
import {inspectExecutionPlan} from '../compute/execution_plan.mjs';
import {inspectLaunchConsent,launchConsentPayload} from '../compute/guest_consent.mjs';
import {guestInitialization} from '../compute/guest_initialization.mjs';
import {AttestationLedger,requestTrusteeResult,trusteeEvidenceRequest} from '../compute/attestation.mjs';
import {keyDeliveryPayload,sealJobKeyDelivery,recoverRequesterJobKey} from '../compute/key_delivery.mjs';
import {createResultKeyCustody,recoverRequesterResultKey} from '../compute/result_keys.mjs';
import {ResultInbox} from '../compute/result_inbox.mjs';
import {prepareDependencyHandoff,reviewDependencyHandoff,verifyDependencyHandoff} from '../compute/dependency_handoff.mjs';
import {connectBookedPeer} from '../compute/peer_network.mjs';
import {sendLaunchHandoff} from '../compute/launch_handoff.mjs';
import {sendEncryptedInput} from '../compute/input_transport.mjs';
import {receiveGuestEvidence,sendGuestExecution} from '../compute/result_transport.mjs';
import {receiveSessionResultAccess} from './session-access.mjs';
import {receiveHostedResult} from './hosted-result.mjs';
import {WorkflowStore,workflowCheck as check,canonical,sha,privateDirectory,readWorkflowJSON as read,saveWorkflowJSON as save} from './workflow-store.mjs';

const seconds=()=>Math.floor(Date.now()/1000),MIB=1024**2;
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const absolute=v=>check(typeof v==='string'&&path.isAbsolute(v)&&!v.includes('\0'));
const origin=v=>{const u=new URL(v);check(u.protocol==='https:'&&u.origin===v&&!u.username&&!u.password);return v;};
const validEndpoint=(v,trustee=false)=>{const u=new URL(v);check(!u.username&&!u.password&&
  (u.protocol==='https:'||u.protocol==='http:'&&(trustee?['127.0.0.1','[::1]']:['127.0.0.1']).includes(u.hostname))&&
  (!trustee||u.pathname==='/attestation'&&!u.search&&!u.hash));};
function hashFile(file,limit) {
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try {const s=fs.fstatSync(fd);check(s.isFile()&&s.size>0&&s.size<=limit);
    // Stream actual ciphertext; requester data is never logged or executed here.
    const state=createFileHash(),buffer=Buffer.alloc(65536);let count=0,n;
    while((n=fs.readSync(fd,buffer,0,buffer.length,null))){count+=n;check(count<=limit);state.update(buffer.subarray(0,n));}
    check(count===s.size);return {sha256:state.digest('hex'),bytes:count};
  }finally{fs.closeSync(fd);}
}
import {createHash} from 'node:crypto';
const createFileHash=()=>createHash('sha256');

export function readWorkflow(configFile,{verifyInput=true}={}) {
  const c=read(configFile);exact(c,['schema','proofFile','descriptorFile','manifestFile','ciphertextFile','directory','keySource',
    'reconstruction','resultRecipient','maxParallel','maxStoredBytes','assignments']);
  check(c.schema==='cannabis.requester-workflow.v1'&&Number.isSafeInteger(c.maxParallel)&&c.maxParallel>=1&&c.maxParallel<=8&&
    Number.isSafeInteger(c.maxStoredBytes)&&c.maxStoredBytes>0&&c.maxStoredBytes<=1024**4&&/^age1[0-9a-z]{58}$/.test(c.resultRecipient));
  for(const k of ['proofFile','descriptorFile','manifestFile','ciphertextFile','directory'])absolute(c[k]);
  exact(c.keySource,['python','age','identity','capsule','descriptor']);Object.values(c.keySource).forEach(absolute);
  exact(c.reconstruction,['python','age','identity']);Object.values(c.reconstruction).forEach(absolute);
  check(c.keySource.descriptor===c.descriptorFile&&Array.isArray(c.assignments)&&c.assignments.length>0&&c.assignments.length<=64);
  const snapshotFile=path.join(c.directory,'workflow-input.json'),saved=fs.existsSync(snapshotFile)?read(snapshotFile):null;
  if(saved){exact(saved,['config','proof','descriptor','manifest','assignments']);check(canonical(saved.config)===canonical(c)&&saved.assignments.length===c.assignments.length);}
  const proof=saved?.proof??read(c.proofFile),descriptor=saved?.descriptor??read(c.descriptorFile),manifest=saved?.manifest??read(c.manifestFile);
  const assignments=c.assignments.map(input=>{
    exact(input,['reservationId','origin','resultOrigin','consentFile','initializationFile','trusteeEndpoint',...(Object.hasOwn(input,'caFile')?['caFile']:[])]);
    absolute(input.consentFile);absolute(input.initializationFile);origin(input.origin);validEndpoint(input.resultOrigin);
    check(new URL(input.resultOrigin).origin===input.resultOrigin);validEndpoint(input.trusteeEndpoint,true);
    const retained=saved?.assignments.find(a=>a.reservationId===input.reservationId);if(saved)check(retained);
    const signed=retained?.signed??read(input.consentFile,256*1024),initialization=retained?.initialization??read(input.initializationFile,65536);
    const payload=launchConsentPayload(signed.configuration,initialization,proof,'requester');
    const description=inspectLaunchConsent(signed,initialization,proof,payload.value.validFrom),r=description.reservation;
    check(r.reservationId===input.reservationId&&initialization.binding.worldSize===1&&initialization.binding.rank===0&&
      initialization.binding.acceleratorClass==='cpu'&&signed.configuration.execution.profile.runtime.adapter==='native-linux-x86_64-v1');
    const policy=structuredClone(signed.configuration.attestationPolicyTemplate);policy.measurements.initData=guestInitialization(initialization).digest;
    let ca;if(input.caFile){absolute(input.caFile);
      if(retained){check(typeof retained.ca==='string'&&Buffer.byteLength(retained.ca)<=262144);ca=retained.ca;}
      else {const s=fs.lstatSync(input.caFile);check(s.isFile()&&!s.isSymbolicLink()&&s.size<=262144);ca=fs.readFileSync(input.caFile,'utf8');}}
    return {...structuredClone(input),signed,initialization,description,policy,...(ca?{ca}:{})};
  });
  const network=assignments[0].signed.configuration.network,lease=verifyMarketLeaseProof(proof,network);
  check(lease.executionPlan&&assignments.length===lease.assignments.length&&new Set(assignments.map(a=>a.reservationId)).size===assignments.length&&
    lease.assignments.every(a=>assignments.some(e=>e.reservationId===a.reservationId))&&descriptor.schema==='cannabis.package.v2'&&
    descriptor.id===lease.job.id&&descriptor.ciphertextSHA256===lease.job.packageSHA256&&descriptor.policySHA256===lease.job.policySHA256&&
    inspectExecutionPlan({...lease.executionPlan.plan,requirements:descriptor.requirements}).digestSHA256===lease.executionPlan.digestSHA256&&manifest.id===lease.job.id&&
    manifest.policySHA256===lease.job.policySHA256&&manifest.resultRecipient===c.resultRecipient);
  let budget=0,inputBound=Infinity;
  for(const a of assignments) {
    const planned=lease.assignments.find(p=>p.reservationId===a.reservationId),p=a.signed.configuration.execution.profile;
    check(verifyMarketLeaseProof(proof,a.signed.configuration.network).digest===lease.digest&&
      a.signed.configuration.network.genesisHash===network.genesisHash&&p.ciphertext.outputBytes<=64*MIB);
    a.task=planned.task;a.dependsOn=lease.executionPlan.plan.requirements[a.task].dependsOn;
    check(!a.dependsOn.length||p.schema==='cannabis.guest-native-service.v3');
    budget+=p.ciphertext.outputBytes+(a.dependsOn.length?p.ciphertext.dependencyBytes:0)+8*MIB;inputBound=Math.min(inputBound,p.ciphertext.inputBytes);
  }
  check(budget<=c.maxStoredBytes);
  if(verifyInput){const input=hashFile(c.ciphertextFile,inputBound);check(input.sha256===descriptor.ciphertextSHA256);}
  const commitment={schema:c.schema,config:c,proof,descriptor,manifest,assignments:assignments.map(a=>({
    reservationId:a.reservationId,signed:a.signed,initialization:a.initialization,...(a.ca?{caSHA256:sha(a.ca)}:{})}))};
  const inputSnapshot={config:c,proof,descriptor,manifest,assignments:assignments.map(a=>({reservationId:a.reservationId,
    signed:a.signed,initialization:a.initialization,...(a.ca?{ca:a.ca}:{})}))};
  return {config:c,proof,descriptor,manifest,assignments,lease,network,inputSnapshot,
    storeManifest:{schema:'cannabis.requester-workflow-store.v1',workflowSHA256:sha(canonical(commitment)),
      leaseDigest:lease.digest,reservations:assignments.map(a=>({reservationId:a.reservationId,task:a.task})).sort((a,b)=>a.task-b.task)}};
}

export class RequesterWorkflow {
  #w;#store;#inbox;#clock;#running=false;#closed=false;#sign;#signal;
  constructor(workflow,{create=false,clock=seconds}={}) {
    const w=structuredClone(workflow);this.#w=w;this.#clock=clock;
    if(create){privateDirectory(path.dirname(w.config.directory));fs.mkdirSync(w.config.directory,{mode:0o700});}
    privateDirectory(w.config.directory);
    this.#store=new WorkflowStore(path.join(w.config.directory,'workflow.sqlite'),w.storeManifest,{create,clock});
    try {
      const inboxFile=path.join(w.config.directory,'results.sqlite');
      if(!create){const s=fs.lstatSync(inboxFile);check(s.isFile()&&!s.isSymbolicLink()&&s.size>0);}
      this.#inbox=new ResultInbox(inboxFile,{chainId:w.network.chainId,escrow:w.lease.escrow,requester:w.lease.requester});
      if(create){
        save(path.join(w.config.directory,'workflow-input.json'),w.inputSnapshot);
        save(path.join(w.config.directory,'config.json'),w.config);
        save(path.join(w.config.directory,'workload.json'),w.manifest);
        for(const a of w.assignments)fs.mkdirSync(this.#dir(a.reservationId),{mode:0o700});
      }
      check(canonical(read(path.join(w.config.directory,'workload.json')))===canonical(w.manifest));
    }catch(e){this.#store.close();throw e;}
  }
  #dir(id){check(this.#w.assignments.some(a=>a.reservationId===id));return path.join(this.#w.config.directory,id.slice(2));}
  #file(id,name){return path.join(privateDirectory(this.#dir(id)),name);}
  #row(id){const r=this.#store.snapshot().find(r=>r.reservationId===id);check(r);return r;}
  #active(){check(!this.#closed&&!this.#signal?.aborted);}
  #recoverySource(id){return {...this.#w.config.reconstruction,custody:this.#file(id,'result-key.json')};}
  #loadResult=async expected=>{
    const row=this.#store.snapshot().find(r=>r.releaseId===expected.releaseId);check(row);
    return recoverRequesterResultKey(this.#recoverySource(row.reservationId),expected);
  };
  async #signature(a,kind,payload,until) {
    this.#active();check(this.#clock()<until&&typeof this.#sign==='function');
    const controller=new AbortController(),stop=()=>controller.abort(),timer=setTimeout(stop,Math.min(60000,(until-this.#clock())*1000));
    this.#signal?.addEventListener('abort',stop,{once:true});
    try {
      const stopped=new Promise((_,reject)=>controller.signal.addEventListener('abort',()=>reject(Error('Approval expired or cancelled')),{once:true}));
      const signature=await Promise.race([stopped,Promise.resolve().then(()=>{this.#active();check(!controller.signal.aborted);
        return this.#sign({kind,reservationId:a.reservationId,requester:this.#w.lease.requester,
          genesisHash:this.#w.network.genesisHash,expiresAt:Math.min(until,this.#clock()+60),payload:structuredClone(payload)},controller.signal);})]);
      this.#active();check(!controller.signal.aborted&&this.#clock()<until&&verifyTypedData(payload.domain,payload.types,payload.value,signature)===this.#w.lease.requester);
      return signature;
    }finally{clearTimeout(timer);this.#signal?.removeEventListener('abort',stop);controller.abort();}
  }
  snapshot(){return {schema:'cannabis.requester-workflow-state.v1',workflowSHA256:this.#w.storeManifest.workflowSHA256,
    leaseDigest:this.#w.lease.digest,slots:this.#store.snapshot(),qualityAccepted:false,paymentAuthorized:false};}
  async #selected(id) {
    const row=this.#row(id);check(row.state==='stored'&&row.approvalDigest);
    const result=await this.#inbox.recover(row.approvalDigest,this.#loadResult);
    check(result.receiptSHA256===row.receiptSHA256);this.#verifyCiphertext(id,result.receipt);
    return {approvalDigest:row.approvalDigest,receiptSHA256:result.receiptSHA256,file:this.#file(id,'result.age')};
  }
  #verifyCiphertext(id,receipt) {
    const found=hashFile(this.#file(id,'result.age'),receipt.ciphertextBytes);
    check(found.sha256===receipt.ciphertextSHA256&&found.bytes===receipt.ciphertextBytes);
  }
  async #dependency(a) {
    if(!a.dependsOn.length)return undefined;
    const sources=this.#w.assignments.filter(s=>a.dependsOn.includes(s.task)),results=[];
    for(const source of sources)results.push(await this.#selected(source.reservationId));
    this.#active();const now=this.#clock(),window={notBefore:now,expiresAt:a.description.reservation.end};
    const prepared=await prepareDependencyHandoff({inbox:this.#inbox,proof:this.#w.proof,network:a.signed.configuration.network,
      reservationId:a.reservationId,descriptor:this.#w.descriptor,results:results.map(({approvalDigest,file})=>({approvalDigest,file})),
      source:{...this.#w.config.reconstruction,manifest:path.join(this.#w.config.directory,'workload.json'),destination:this.#file(a.reservationId,'dependency.age')},
      window,loadResultKey:this.#loadResult});
    const payload=reviewDependencyHandoff(this.#inbox,this.#w.proof,a.signed.configuration.network,a.reservationId,this.#w.descriptor,prepared);
    const requesterSignature=await this.#signature(a,'dependency',payload,window.expiresAt);
    reviewDependencyHandoff(this.#inbox,this.#w.proof,a.signed.configuration.network,a.reservationId,this.#w.descriptor,prepared);
    const dependency={descriptor:this.#w.descriptor,signed:{handoff:prepared.handoff,window,requesterSignature}};
    verifyDependencyHandoff(this.#w.proof,a.signed.configuration.network,a.reservationId,this.#w.descriptor,dependency.signed,this.#clock());
    save(this.#file(a.reservationId,'dependency.json'),dependency);return dependency;
  }
  async #execute(a) {
    this.#active();const token=this.#store.claim(a.reservationId),r=a.description.reservation,c=a.signed.configuration;
    let ledger,channel,stage='preparing-input';
    try {
      const dependency=await this.#dependency(a);this.#active();
      const custody=await createResultKeyCustody({releaseId:token.releaseId,recipient:this.#w.config.resultRecipient});
      save(this.#file(a.reservationId,'result-key.json'),custody);
      ledger=new AttestationLedger(this.#file(a.reservationId,'attestation.sqlite'),a.policy,this.#clock);
      stage='connecting-provider';
      channel=await connectBookedPeer({origin:a.origin,signed:a.signed,initialization:a.initialization,proof:this.#w.proof,
        ...(a.ca?{ca:a.ca}:{}),signal:this.#signal,clock:this.#clock,
        signApproval:p=>this.#signature(a,'peer',p,p.value.validUntil)});
      const challenge=ledger.challenge(a.initialization.binding);save(this.#file(a.reservationId,'challenge.json'),challenge);
      await sendLaunchHandoff(channel,{signed:a.signed,initialization:a.initialization,proof:this.#w.proof},challenge,
        {clock:this.#clock,signal:this.#signal,...(dependency?{dependency}:{})});
      stage='sending-input';
      await sendEncryptedInput(channel,{source:this.#w.config.ciphertextFile,packageSHA256:this.#w.descriptor.ciphertextSHA256,
        maxCiphertextBytes:c.execution.profile.ciphertext.inputBytes});
      if(dependency)await sendEncryptedInput(channel,{source:this.#file(a.reservationId,'dependency.age'),
        packageSHA256:dependency.signed.handoff.ciphertextSHA256,maxCiphertextBytes:c.execution.profile.ciphertext.dependencyBytes});
      const evidence=await receiveGuestEvidence(channel);this.#active();check(evidence.nonce===challenge.nonce);
      stage='appraising-evidence';
      trusteeEvidenceRequest(a.policy,challenge,evidence.channelJwk,evidence.evidence,this.#clock());
      const appraisal=await requestTrusteeResult(ledger,a.trusteeEndpoint,challenge.nonce,evidence.channelJwk,evidence.evidence);
      this.#active();channel.assertActive();
      const source={schema:'cannabis.market-requester.v3',context:c.context,proof:this.#w.proof,configuration:c,consent:a.signed};
      const request={releaseId:token.releaseId,leaseId:this.#w.lease.digest,nonce:challenge.nonce,channelJwk:evidence.channelJwk,
        descriptor:this.#w.descriptor,notBefore:this.#clock(),expiresAt:Math.min(r.end,challenge.expiresAt),
        resultKeySHA256:custody.resultKeySHA256,...(dependency?{dependency:dependency.signed}:{})};
      const payload=keyDeliveryPayload(source,ledger,request,this.#clock());
      stage='approving-key-release';
      const requesterSignature=await this.#signature(a,'key-release',payload,request.expiresAt);
      // Recheck current upstream selections after asynchronous wallet review.
      if(dependency)this.#inbox.useCurrent(dependency.signed.handoff.context.sources.map(s=>({approvalDigest:s.approvalDigest,receiptSHA256:s.receiptSHA256})),()=>true);
      const record=await sealJobKeyDelivery(source,ledger,{request,requesterSignature},appraisal.token,c.network,
        expected=>recoverRequesterJobKey(this.#w.config.keySource,expected),{clock:this.#clock,
          ageKeygen:path.join(path.dirname(this.#w.config.keySource.age),process.platform==='win32'?'age-keygen.exe':'age-keygen'),loadResultKey:this.#loadResult});
      save(this.#file(a.reservationId,'delivery.json'),record);token.approval(record.approvalDigest);
      this.#inbox.activate(record,{resultRecipient:this.#w.config.resultRecipient});this.#active();channel.assertActive();
      if(dependency)this.#inbox.useCurrent(dependency.signed.handoff.context.sources.map(s=>({approvalDigest:s.approvalDigest,receiptSHA256:s.receiptSHA256})),()=>true);
      await sendGuestExecution(channel,record);
      stage='receiving-result';
      const access=await receiveSessionResultAccess(channel,{approvalDigest:record.approvalDigest,origin:a.resultOrigin});
      save(this.#file(a.reservationId,'result-access.json'),access);
      // Save the authenticated-channel header before retrieval. It carries only
      // encrypted receipts/commitments and permits later download without launch.
      const wire={signal:channel.signal,assertActive:()=>channel.assertActive(),fail:()=>channel.fail(),
        readJSON:async(...args)=>{const header=await channel.readJSON(...args);save(this.#file(a.reservationId,'result-header.json'),header);return header;},
        writeJSON:ack=>channel.writeJSON(ack)};
      await receiveHostedResult(wire,{inbox:this.#inbox,approvalDigest:record.approvalDigest,loadResultKey:this.#loadResult,
        destination:this.#file(a.reservationId,'result.age'),maxCiphertextBytes:c.execution.profile.ciphertext.outputBytes,
        signStored:p=>this.#signature(a,'stored',p,r.end),access,origin:a.resultOrigin,
        timeoutMs:Math.max(1,Math.min(3600000,(r.end-this.#clock())*1000)),signal:this.#signal});
      stage='checking-stored-result';await this.#reconcile(a);return true;
    }catch(error){
      save(this.#file(a.reservationId,'interrupted.json'),{stage,transportStage:error.transportStage??null,
        resultHeaderSaved:fs.existsSync(this.#file(a.reservationId,'result-header.json')),
        resultCiphertextSaved:fs.existsSync(this.#file(a.reservationId,'result.age')),executionRetried:false,recoveryRequired:true});
      throw error;
    }finally{channel?.close();ledger?.close();}
  }
  #retainedDelivery(a) {
    const row=this.#row(a.reservationId),record=read(this.#file(a.reservationId,'delivery.json')),v=record.expectedApproval?.value,b=a.initialization.binding;
    check(row.state!=='queued'&&record.releaseId===row.releaseId&&record.expectedApproval?.jobId===this.#w.lease.job.id);
    for(const k of ['leaseDigest','orderId','reservationId','configurationSHA256','attempt','rank','worldSize'])check(v[k]===b[k]);
    for(const k of ['packageSHA256','policySHA256','runtimeSHA256','taskSHA256'])check(v[k]==='0x'+b[k]);
    check(v.inputRecipient===this.#w.descriptor.recipient);
    this.#inbox.activate(record,{resultRecipient:this.#w.config.resultRecipient});return record;
  }
  async #reconcile(a) {
    const record=this.#retainedDelivery(a),recovered=await this.#inbox.recover(record.approvalDigest,this.#loadResult);
    this.#verifyCiphertext(a.reservationId,recovered.receipt);
    this.#inbox.useCurrent([{approvalDigest:record.approvalDigest,receiptSHA256:recovered.receiptSHA256}],()=>
      this.#store.stored(a.reservationId,record.releaseId,record.approvalDigest,recovered.receiptSHA256));
    return {reservationId:a.reservationId,ciphertextStored:true,receiptAuthenticated:true,qualityAccepted:false,paymentAuthorized:false};
  }
  async recover(reservationId,{signApproval,signal}={}) {
    check(!this.#running);this.#running=true;this.#sign=signApproval;this.#signal=signal;
    try {
      this.#active();const a=this.#w.assignments.find(a=>a.reservationId===reservationId);check(a);
      const record=this.#retainedDelivery(a);
      if(!fs.existsSync(this.#file(reservationId,'result.age'))) {
        const access=read(this.#file(reservationId,'result-access.json')),header=read(this.#file(reservationId,'result-header.json')),
          controller=new AbortController();let readOnce=false;
        const wire={signal:controller.signal,assertActive:()=>{this.#active();check(!controller.signal.aborted);},fail:()=>controller.abort(),
          readJSON:async()=>{check(!readOnce);readOnce=true;return header;},
          writeJSON:async ack=>save(this.#file(reservationId,'recovery-storage-ack.json'),ack)};
        await receiveHostedResult(wire,{inbox:this.#inbox,approvalDigest:record.approvalDigest,loadResultKey:this.#loadResult,
          destination:this.#file(reservationId,'result.age'),maxCiphertextBytes:a.signed.configuration.execution.profile.ciphertext.outputBytes,
          signStored:p=>this.#signature(a,'stored',p,Math.floor(access.expiresAt/1000)),access,origin:a.resultOrigin,timeoutMs:3600000,signal});
      }
      return {...await this.#reconcile(a),executionRetried:false,storageSignatureForwarded:false};
    }finally{this.#running=false;this.#sign=undefined;this.#signal=undefined;}
  }
  async run({signApproval,signal,onState=()=>{}}={}) {
    check(!this.#running&&typeof signApproval==='function'&&typeof onState==='function');this.#running=true;this.#sign=signApproval;this.#signal=signal;
    const pending=new Map(),outcomes=[];
    try {
      const input=hashFile(this.#w.config.ciphertextFile,Math.min(...this.#w.assignments.map(a=>a.signed.configuration.execution.profile.ciphertext.inputBytes)));
      check(input.sha256===this.#w.descriptor.ciphertextSHA256);
      const notify=()=>{try{onState(this.snapshot());}catch{/* An observer cannot change dispatch or recovery state. */}};
      while(true) {
        this.#active();const rows=this.#store.snapshot(),now=this.#clock();
        for(const a of this.#w.assignments) {
          if(pending.size>=this.#w.config.maxParallel)break;
          const row=rows.find(r=>r.reservationId===a.reservationId),r=a.description.reservation;
          if(row.state!=='queued'||pending.has(a.reservationId)||now<r.start||now>=r.end)continue;
          if(this.#w.assignments.some(s=>a.dependsOn.includes(s.task)&&rows.find(v=>v.reservationId===s.reservationId).state!=='stored'))continue;
          const task=this.#execute(a).then(()=>({reservationId:a.reservationId,stored:true}),()=>({reservationId:a.reservationId,recoveryRequired:true}))
            .then(report=>{outcomes.push(report);pending.delete(a.reservationId);notify();});
          pending.set(a.reservationId,task);notify();
        }
        if(!pending.size) {
          const remaining=rows.filter(r=>r.state==='queued');
          const impossible=new Set(rows.filter(r=>r.state==='uncertain').map(r=>r.reservationId));
          for(const a of this.#w.assignments)if(this.#row(a.reservationId).state==='queued'&&a.description.reservation.end<=now)impossible.add(a.reservationId);
          for(let i=0;i<this.#w.assignments.length;i++)for(const a of this.#w.assignments)
            if(this.#w.assignments.some(s=>a.dependsOn.includes(s.task)&&impossible.has(s.reservationId)))impossible.add(a.reservationId);
          if(!remaining.length||remaining.every(row=>impossible.has(row.reservationId)))break;
        }
        await new Promise((resolve,reject)=>{const abort=()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);reject(Error('Cancelled'));};
          const timer=setTimeout(()=>{signal?.removeEventListener('abort',abort);resolve();},250);signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();});
      }
      return {...this.snapshot(),outcomes};
    }finally{await Promise.allSettled([...pending.values()]);this.#running=false;this.#sign=undefined;this.#signal=undefined;}
  }
  async assemble(destination) {
    check(!this.#running);absolute(destination);const rows=this.#store.snapshot();check(rows.every(r=>r.state==='stored'));
    const results=[];
    for(const r of rows){await this.#selected(r.reservationId);const recovered=await this.#inbox.recover(r.approvalDigest,this.#loadResult);
      results.push({receipt:recovered.receipt,file:this.#file(r.reservationId,'result.age'),selection:{approvalDigest:r.approvalDigest,receiptSHA256:recovered.receiptSHA256}});}
    return this.#inbox.useCurrent(results.map(r=>r.selection),approvals=>{
      const request={source:{age:this.#w.config.reconstruction.age,identity:this.#w.config.reconstruction.identity,
        manifest:path.join(this.#w.config.directory,'workload.json'),destination},packageSHA256:this.#w.descriptor.ciphertextSHA256,
        results:results.map((r,i)=>({receipt:r.receipt,file:r.file,approval:approvals[i]}))};
      const raw=Buffer.from(JSON.stringify(request));check(raw.length<=16*MIB);
      try{return JSON.parse(execFileSync(this.#w.config.reconstruction.python,[fileURLToPath(new URL('../scripts/compute-result-reconstruct-pipe.py',import.meta.url))],
        {input:raw,encoding:'utf8',timeout:600000,maxBuffer:4*MIB,windowsHide:true,stdio:['pipe','pipe','ignore']}));}
      finally{raw.fill(0);}
    });
  }
  close(){check(!this.#running);if(!this.#closed){this.#closed=true;this.#inbox.close();this.#store.close();}}
}
