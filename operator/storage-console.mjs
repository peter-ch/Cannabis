// Local operator control over retained ciphertext, never execution or settlement.
import { createHash,randomBytes } from 'node:crypto';
import { PhysicalResultSpool,assertPhysicalResultSpool } from './physical-spool.mjs';
import { validateUploadAccess } from './result-upload.mjs';
import { validateRelayAccess } from '../web/work-relay.js';
import { uploadRetainedResult } from './result-bridge.mjs';

const check=v=>{if(!v)throw Error('Result recovery unavailable; retain the store and review its configuration');};
const idValue=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const hash=v=>createHash('sha256').update(v).digest('hex');
const token=()=>randomBytes(32).toString('hex');
const recoverable=state=>['sealed','complete','acknowledged'].includes(state);
function originValue(value) {
  const u=new URL(value);check(u.origin===value&&!u.username&&!u.password&&
    (u.protocol==='https:'||u.protocol==='http:'&&u.hostname==='127.0.0.1'));return value;
}
function description(source) {
  return {approvalDigest:source.approvalDigest,ciphertextSHA256:source.ciphertextSHA256,
    ciphertextBytes:source.ciphertextBytes,envelopeSHA256:hash(source.resultEnvelope)};
}

export class ResultConsole {
  #spool;#origins;#review;#operation;#controller;#task;#closed=false;#ownsSpool;
  constructor(directory,{relayOrigins=[]}={}) {
    check(Array.isArray(relayOrigins)&&relayOrigins.length<=8&&new Set(relayOrigins).size===relayOrigins.length);
    this.#origins=relayOrigins.map(originValue);this.#ownsSpool=typeof directory==='string';
    if(!this.#ownsSpool)assertPhysicalResultSpool(directory);
    this.#spool=this.#ownsSpool?new PhysicalResultSpool(directory):directory;
  }
  #ready(){check(!this.#closed&&this.#operation?.state!=='uploading');}
  snapshot() {
    check(!this.#closed);
    try {
      const volume=this.#spool.checkCapacity(),saved=this.#spool.snapshot();
      return {state:'available',observedAt:saved.observedAt,
        capacity:{reservedBytes:saved.reservedBytes,maxBytes:saved.limits.maxBytes,maxRecords:saved.limits.maxRecords,
          backingBytes:volume.backingAllocatedBytes,availableBytes:volume.availableBytes,availableInodes:volume.availableInodes},
        retentionMs:saved.limits.retentionMs,relayOrigins:[...this.#origins],
        records:saved.records.map(r=>({...r,recoverable:recoverable(r.state),
          retryAvailable:recoverable(r.state)&&r.retryUntil>Date.now()&&this.#origins.length>0,
          deletionEligibleAt:r.acknowledgedAt===null?null:r.acknowledgedAt+saved.limits.retentionMs})),
        operation:this.#operation?structuredClone(this.#operation):null};
    }catch{return {state:'unavailable',reason:'Result storage needs local reconciliation. Retained files have not been deleted.',
      operation:this.#operation?structuredClone(this.#operation):null};}
  }
  recover(id) {
    this.#ready();check(idValue(id));this.#spool.checkCapacity();
    const retained=this.#spool.recover(id);
    return {id,...description(retained.source),recovered:true,qualityAccepted:false,paymentAuthorized:false};
  }
  prepareRetry(id,grants) {
    this.#ready();this.#review=undefined;
    check(idValue(id)&&grants&&Object.keys(grants).sort().join()===['read','upload'].join());
    const origin=grants.upload?.origin;check(this.#origins.includes(origin));
    const upload=validateUploadAccess(grants.upload,origin),read=validateRelayAccess([grants.read],origin,[{approvalDigest:upload.approvalDigest}])[0];
    check(read.id===upload.id&&read.expiresAt===upload.expiresAt&&read.token!==upload.token);
    const result=this.recover(id),saved=this.#spool.status(id);
    check(upload.approvalDigest===result.approvalDigest);
    const expiresAt=Math.min(Date.now()+300000,upload.expiresAt,saved.retryUntil);check(expiresAt>Date.now());
    const reviewId=token();this.#review={reviewId,id,origin,upload,expiresAt,descriptor:result};
    return {reviewId,id,origin,expiresAt,...descriptionFromRecovery(result),readAccess:[read],paymentAuthorized:false};
  }
  startRetry(reviewId) {
    this.#ready();check(idValue(reviewId)&&this.#review?.reviewId===reviewId);
    const review=this.#review;this.#review=undefined;check(Date.now()<review.expiresAt);
    const current=this.recover(review.id);
    check(JSON.stringify(current)===JSON.stringify(review.descriptor));
    const operationId=token(),controller=new AbortController();this.#controller=controller;
    this.#operation={id:operationId,resultId:review.id,origin:review.origin,state:'uploading',
      startedAt:Date.now(),totalBytes:current.ciphertextBytes,uploadedBytes:0,reusedBytes:0,
      requesterAcknowledgedStorage:false,qualityAccepted:false,paymentAuthorized:false};
    this.#task=uploadRetainedResult({spool:this.#spool,id:review.id,access:review.upload,origin:review.origin,
      timeoutMs:Math.min(1800000,review.upload.expiresAt-Date.now()),signal:controller.signal,
      onProgress:progress=>{
        if(progress.phase==='upload')Object.assign(this.#operation,{uploadedBytes:progress.uploadedBytes,reusedBytes:progress.reusedBytes});
      }}).then(report=>{
        Object.assign(this.#operation,{state:'uploaded',completedAt:Date.now(),uploadedBytes:report.uploadedBytes,
          reusedBytes:report.reusedBytes,relayReportedComplete:true});
      },()=>{Object.assign(this.#operation,{state:controller.signal.aborted?'cancelled':'failed',completedAt:Date.now(),
        reason:'Upload did not complete. The retained encrypted result is unchanged.'});})
      .finally(()=>{this.#controller=undefined;});
    return {operationId};
  }
  discardReview(reviewId) {
    check(!this.#closed&&idValue(reviewId));
    if(this.#review?.reviewId===reviewId)this.#review=undefined;
    return {discarded:true};
  }
  cancelRetry(operationId) {
    check(!this.#closed&&idValue(operationId)&&this.#operation?.id===operationId&&this.#operation.state==='uploading');
    this.#controller.abort();return {cancellationRequested:true};
  }
  async close() {
    this.#closed=true;this.#review=undefined;this.#controller?.abort();
    try{await this.#task;}finally{if(this.#ownsSpool)this.#spool.close();}
  }
}
function descriptionFromRecovery(r) {
  return {approvalDigest:r.approvalDigest,ciphertextSHA256:r.ciphertextSHA256,
    ciphertextBytes:r.ciphertextBytes,envelopeSHA256:r.envelopeSHA256};
}
