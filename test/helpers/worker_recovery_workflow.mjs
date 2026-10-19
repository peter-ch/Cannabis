// Owned physical-store and loopback-console integration. All accounts/results
// are isolated workflow fixtures, never live activity or paid execution.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { createHash,randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { TypedDataEncoder } from 'ethers';
import { PhysicalResultSpool } from '../../operator/physical-spool.mjs';
import { ResultConsole } from '../../operator/storage-console.mjs';
import { createConsoleServer,createObserver } from '../../operator/server.mjs';
import { createWorkServer } from '../../service/work-server.mjs';
import { deliveryApprovalTypes } from '../../compute/key_delivery.mjs';
import { approvedBrowserFixture } from '../fixtures/approved-browser.mjs';
import { approvedArchiveDescriptors,openApprovedResults } from '../../web/work-approvals.js';
import { downloadApprovedArchives } from '../../web/work-relay.js';

const [home,configFile,stopFile]=process.argv.slice(2),directory=path.join(home,'mount/spool');
const hash=v=>createHash('sha256').update(v).digest('hex'),checks={};
let spool,results,observer,consoleServer,relayServer,stallServer;
try {
  const f=await approvedBrowserFixture({repetitions:6000}),entry=f.bundle.entries[0],expected=entry.approval,bytes=Buffer.from(f.encrypted[0]);
  spool=new PhysicalResultSpool(directory,{create:true});
  const request={expected,maxCiphertextBytes:1024**2,serviceEnd:Math.floor(Date.now()/1000)+600};
  const complete=spool.reserve(request);spool.dispatch(complete);spool.begin(complete,{resultEnvelope:entry.envelope,ciphertextBytes:bytes.length});
  for(let i=0;i<bytes.length;i+=65536)spool.append(complete,bytes.subarray(i,i+65536));
  const retained=spool.seal(complete,hash(bytes));
  const second=structuredClone(expected),types=deliveryApprovalTypes(second.domain.version);
  second.value.nonce='0x'+randomBytes(32).toString('hex');second.digest=TypedDataEncoder.hash(second.domain,types,second.value);
  second.requesterSignature=await f.owner.signTypedData(second.domain,types,second.value);
  const partial=spool.reserve({...request,expected:second});spool.dispatch(partial);
  spool.begin(partial,{resultEnvelope:entry.envelope,ciphertextBytes:bytes.length});spool.append(partial,bytes.subarray(0,64));spool.close();spool=null;

  const reserve=net.createServer();await new Promise(r=>reserve.listen(0,'127.0.0.1',r));
  const port=reserve.address().port;await new Promise(r=>reserve.close(r));
  const relayOrigin='http://127.0.0.1:'+port,opened=createWorkServer({file:':memory:',resultFile:':memory:',origin:relayOrigin});
  relayServer=opened.server;await new Promise(r=>relayServer.listen(port,'127.0.0.1',r));
  let stalled;stallServer=http.createServer(()=>{stalled?.();});await new Promise(r=>stallServer.listen(0,'127.0.0.1',r));
  const stallOrigin='http://127.0.0.1:'+stallServer.address().port;
  results=new ResultConsole(directory,{relayOrigins:[relayOrigin,stallOrigin]});
  observer=createObserver({cpu:'Owned recovery fixture — not a live worker',graphics:[],logicalCpus:1,os:'linux',architecture:'fixture'});
  consoleServer=createConsoleServer(observer,{results});await new Promise(r=>consoleServer.listen(0,'127.0.0.1',r));
  const origin='http://127.0.0.1:'+consoleServer.address().port;
  const control=await (await fetch(origin+'/api/control')).json();
  const call=async(action,body,wanted=200)=>{
    const response=await fetch(origin+'/api/results/'+action,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json',
      'X-Cannabis-Console':control.actionToken},body:JSON.stringify(body)});
    const result=await response.json();assert.equal(response.status,wanted,JSON.stringify(result));return result;
  };
  const status=async()=>{const response=await fetch(origin+'/api/status');assert.equal(response.status,200);return response.json();};
  let observed=await status();assert.equal(observed.resultStorage.records.length,2);assert.equal(observed.worker.admitted,false);
  assert.equal(observed.resultStorage.records.find(r=>r.id===partial.id).recoverable,false);
  assert.equal((await call('recover',{id:complete.id})).ciphertextSHA256,hash(bytes));
  await call('recover',{id:partial.id},409);checks.physicalSnapshotAndRecovery=true;checks.incompleteRecoveryRefused=true;
  const reserveGrant=()=>{
    const {uploadToken,readToken,...a}=opened.relay.reserve({approvalDigest:expected.digest,maxCiphertextBytes:bytes.length,expiresAt:Date.now()+600000});
    return {upload:{...a,origin:relayOrigin,role:'upload',token:uploadToken},read:{...a,origin:relayOrigin,role:'read',token:readToken}};
  };
  const grants=reserveGrant();
  for(const mutate of [g=>g.upload.origin='https://unselected.invalid',g=>g.read.token=g.upload.token,
    g=>g.read.role='upload',g=>g.read.id='00000000-0000-4000-8000-000000000000',g=>g.upload.expiresAt=1]) {
    const bad=structuredClone(grants);mutate(bad);await call('prepare-retry',{id:complete.id,grants:bad},409);
  }
  assert.equal(opened.relay.status(grants.upload.id,grants.upload.token).complete,false);checks.changedRouteOrGrantRefused=true;
  let review=await call('prepare-retry',{id:complete.id,grants});
  await call('discard-review',{reviewId:review.reviewId});await call('start-retry',{reviewId:review.reviewId},409);
  checks.discardedReviewRefused=true;
  review=await call('prepare-retry',{id:complete.id,grants});
  assert.deepEqual(review.readAccess,[grants.read]);
  const statusText=JSON.stringify(await status());
  for(const secret of [control.actionToken,review.reviewId,grants.read.token,grants.upload.token,retained.sourceFile,entry.envelope])
    assert.equal(statusText.includes(secret),false);
  checks.statusOmitsPathsAndCapabilities=true;
  await call('start-retry',{reviewId:review.reviewId},202);
  await call('start-retry',{reviewId:review.reviewId},409);checks.reviewIsSingleUse=true;
  const until=Date.now()+20000;
  do{await delay(100);observed=await status();assert.ok(Date.now()<until);}while(observed.resultStorage.operation.state==='uploading');
  assert.equal(observed.resultStorage.operation.state,'uploaded');assert.equal(observed.resultStorage.operation.paymentAuthorized,false);
  assert.equal(observed.resultStorage.records.find(r=>r.id===complete.id).state,'complete');
  const descriptors=await approvedArchiveDescriptors(f);
  const downloaded=await downloadApprovedArchives({descriptors,accessFiles:review.readAccess,origin:relayOrigin,assertCurrent:async()=>{}});
  const files=await openApprovedResults({...f,encrypted:downloaded});assert.equal(files.size,1);
  assert.equal(new TextDecoder().decode(files.get('finished/answer.txt')),'owned verification result\n'.repeat(6000));
  assert.equal(hash(fs.readFileSync(retained.source.ciphertext)),hash(bytes));checks.explicitReplacementDelivered=true;
  checks.requesterVerifiedDecryption=true;checks.uploadDoesNotAcknowledgeOrPay=true;

  const stallGrants=structuredClone(reserveGrant());stallGrants.upload.origin=stallGrants.read.origin=stallOrigin;
  const blocked=await call('prepare-retry',{id:complete.id,grants:stallGrants});
  const reached=new Promise(r=>stalled=r);const operation=await call('start-retry',{reviewId:blocked.reviewId},202);
  await Promise.race([reached,delay(10000).then(()=>{throw Error('Stalled fixture not reached');})]);
  await call('cancel-retry',{operationId:operation.operationId});
  const stopped=Date.now()+10000;
  do{await delay(100);observed=await status();assert.ok(Date.now()<stopped);}while(observed.resultStorage.operation.state==='uploading');
  assert.equal(observed.resultStorage.operation.state,'cancelled');assert.equal(hash(fs.readFileSync(retained.source.ciphertext)),hash(bytes));
  checks.cancelPreservesResult=true;
  if(configFile) {
    assert.ok(stopFile&&path.isAbsolute(configFile)&&path.isAbsolute(stopFile));
    fs.writeFileSync(configFile,JSON.stringify({origin,grants:reserveGrant(),completeId:complete.id,partialId:partial.id,
      label:'Owned synthetic recovery workflow; no hardware admission or paid work'}),{flag:'wx',mode:0o600});
    const deadline=Date.now()+300000;
    while(!fs.existsSync(stopFile)){assert.ok(Date.now()<deadline,'Browser checkpoint deadline');await delay(200);}
  }
  const closingReview=results.prepareRetry(complete.id,stallGrants),closingReached=new Promise(r=>stalled=r);
  results.startRetry(closingReview.reviewId);
  await Promise.race([closingReached,delay(10000).then(()=>{throw Error('Shutdown fixture not reached');})]);
  await results.close();results=null;assert.equal(hash(fs.readFileSync(retained.source.ciphertext)),hash(bytes));
  checks.shutdownAwaitsUploadCancellation=true;
  const reopened=new ResultConsole(directory,{relayOrigins:[relayOrigin]});
  try{assert.equal(reopened.snapshot().operation,null);assert.equal(reopened.recover(complete.id).ciphertextSHA256,hash(bytes));
    assert.throws(()=>reopened.startRetry(review.reviewId));}finally{await reopened.close();}
  checks.restartRetainsResultNotControls=true;
  process.stdout.write(JSON.stringify({checks,actualHardwareValidated:false,realPaidJob:false})+'\n');
}finally {
  await results?.close();spool?.close();observer?.close();
  for(const server of [consoleServer,relayServer,stallServer])if(server?.listening){server.closeAllConnections();await new Promise(r=>server.close(r));}
}
