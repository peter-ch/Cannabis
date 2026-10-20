// Ordinary-host bridge for the result phase only. It holds ciphertext, never
// customer keys, and cannot replace the requester's signed storage acknowledgement.
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TypedDataEncoder,verifyTypedData } from 'ethers';
import { deliveryApprovalTypes } from '../compute/key_delivery.mjs';
import { resultStoredPayload } from '../compute/result_transport.mjs';
import { uploadEncryptedResult,validateUploadAccess } from './result-upload.mjs';
import { assertResultSpool,claimResultReservation } from './result-spool.mjs';
const integer=(n,min,max)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const fields=(v,n)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===n.sort().join();
const check=v=>{if(!v)throw Error('Encrypted result bridge failed');};
const hash=v=>createHash('sha256').update(v).digest('hex');
export async function bridgeEncryptedResult(guest,requester,{expected,access,origin,reservation,maxCiphertextBytes,
  timeoutMs,signal,fetchImpl=globalThis.fetch,wait}={}) {
  let spool,directory,sourceFile,timer;const controller=new AbortController(),listeners=[];
  const stop=()=>{if(controller.signal.aborted)return;controller.abort();guest.fail();requester.fail();};
  try {
    check(integer(timeoutMs,1,3600000)&&integer(maxCiphertextBytes,1,64*1024*1024)&&
      (!signal||signal instanceof AbortSignal));
    expected=structuredClone(expected);access=validateUploadAccess(access,origin);
    const types=deliveryApprovalTypes(expected?.domain?.version);
    check(expected?.domain?.name==='Cannabis confidential key delivery'&&['2','3','4','5','6'].includes(expected.domain.version)&&
      fields(expected.value,types.JobKeyDelivery.map(x=>x.name))&&
      expected.digest===access.approvalDigest&&TypedDataEncoder.hash(expected.domain,types,expected.value)===expected.digest&&
      verifyTypedData(expected.domain,types,expected.value,expected.requesterSignature)===expected.requester);
    spool=claimResultReservation(reservation,expected,maxCiphertextBytes);
    const wall=Date.now(),started=performance.now(),end=Math.min(access.expiresAt,wall+timeoutMs);
    const remaining=()=>Math.floor(Math.min(end-Date.now(),timeoutMs-(performance.now()-started)));
    const active=()=>{guest.assertActive();requester.assertActive();check(!controller.signal.aborted&&Date.now()>=wall&&remaining()>0);};
    for(const s of [guest.signal,requester.signal,signal].filter(Boolean)) {
      check(!s.aborted);s.addEventListener('abort',stop,{once:true});listeners.push(s);
    }
    active();timer=setTimeout(stop,remaining());
    const header=await guest.readJSON();active();
    check(fields(header,['protocol','operation','approvalDigest','resultEnvelope','ciphertextBytes'])&&
      header.protocol==='cannabis.guest-wire.v1'&&header.operation==='result'&&header.approvalDigest===expected.digest&&
      typeof header.resultEnvelope==='string'&&header.resultEnvelope.length<=6*1024*1024&&
      integer(header.ciphertextBytes,1,maxCiphertextBytes));
    directory=spool.begin(reservation,header);
    const whole=createHash('sha256');let received=0;
    while(received<header.ciphertextBytes) {
      const bytes=await guest.readChunk();active();check(bytes.length>0&&received+bytes.length<=header.ciphertextBytes);
      whole.update(bytes);spool.append(reservation,bytes);
      received+=bytes.length;
    }
    const endFrame=await guest.readJSON(1024),ciphertextSHA256=whole.digest('hex');active();
    check(fields(endFrame,['protocol','operation','ciphertextSHA256'])&&endFrame.protocol==='cannabis.guest-wire.v1'&&
      endFrame.operation==='end'&&endFrame.ciphertextSHA256===ciphertextSHA256);
    const recovered=spool.seal(reservation,ciphertextSHA256),source=recovered.source;sourceFile=recovered.sourceFile;
    active();
    await uploadEncryptedResult({source,access,origin,timeoutMs:remaining(),signal:controller.signal,fetchImpl,wait});
    active();
    await requester.writeJSON({protocol:'cannabis.hosted-result.v1',operation:'result',relayId:access.id,
      approvalDigest:expected.digest,resultEnvelope:header.resultEnvelope,ciphertextSHA256,ciphertextBytes:received});
    const ack=await requester.readJSON(2048);active();
    const payload=resultStoredPayload(expected,{envelopeSHA256:hash(header.resultEnvelope),ciphertextSHA256,ciphertextBytes:received});
    check(fields(ack,['protocol','operation','signature'])&&ack.protocol==='cannabis.guest-wire.v1'&&ack.operation==='stored'&&
      typeof ack.signature==='string'&&verifyTypedData(payload.domain,payload.types,payload.value,ack.signature)===expected.requester);
    spool.acknowledge(reservation.id,ack.signature);
    active();await guest.writeJSON(ack);active();
    return {schema:'cannabis.result-bridge-report.v1',approvalDigest:expected.digest,directory,sourceFile,spoolReservationId:reservation.id,
      ciphertextBytes:received,requesterStorageSignatureVerified:true,signatureForwarded:true,
      guestCompletionObserved:false,qualityAccepted:false,paymentAuthorized:false};
  } catch {
    stop();const error=Error('Encrypted result bridge failed; retain complete ciphertext and requester recovery material');
    if(directory)Object.defineProperty(error,'recoveryDirectory',{value:directory,enumerable:false});
    throw error;
  } finally {
    clearTimeout(timer);for(const s of listeners)s.removeEventListener('abort',stop);
    // Uncertain execution and partial output remain charged. A timeout does not
    // prove checked guest termination or authorize destroying the only result.
  }
}

// Explicit route replacement reuses the original immutable result. No execution,
// key release, requester acknowledgement, output acceptance or payment occurs.
export async function uploadRetainedResult({spool,id,...options}) {
  assertResultSpool(spool);const retained=spool.recover(id);
  const timeoutMs=Math.min(options.timeoutMs??1800000,retained.retryUntil-Date.now());check(timeoutMs>0);
  const report=await uploadEncryptedResult({...options,timeoutMs,source:retained.source});
  return {...report,directory:retained.directory,sourceFile:retained.sourceFile};
}
