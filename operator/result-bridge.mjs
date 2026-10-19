// Ordinary-host bridge for the result phase only. It holds ciphertext, never
// customer keys, and cannot replace the requester's signed storage acknowledgement.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TypedDataEncoder,verifyTypedData } from 'ethers';
import { deliveryTypesV2 } from '../compute/key_delivery.mjs';
import { resultStoredPayload } from '../compute/result_transport.mjs';
import { uploadEncryptedResult,validateUploadAccess } from './result-upload.mjs';
const integer=(n,min,max)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const fields=(v,n)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===n.sort().join();
const check=v=>{if(!v)throw Error('Encrypted result bridge failed');};
const hash=v=>createHash('sha256').update(v).digest('hex');
function syncDirectory(dir) {
  if(process.platform==='win32')return;
  const fd=fs.openSync(dir,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
export async function bridgeEncryptedResult(guest,requester,{expected,access,origin,spoolDirectory,maxCiphertextBytes,
  timeoutMs,signal,fetchImpl=globalThis.fetch,wait}={}) {
  let fd,directory,ciphertext,sourceFile,retained=false,timer;const controller=new AbortController(),listeners=[];
  const stop=()=>{if(controller.signal.aborted)return;controller.abort();guest.fail();requester.fail();};
  try {
    check(integer(timeoutMs,1,3600000)&&integer(maxCiphertextBytes,1,64*1024*1024)&&
      (!signal||signal instanceof AbortSignal)&&path.isAbsolute(spoolDirectory));
    const root=fs.lstatSync(spoolDirectory);check(root.isDirectory()&&!root.isSymbolicLink());
    expected=structuredClone(expected);access=validateUploadAccess(access,origin);
    check(expected?.domain?.name==='Cannabis confidential key delivery'&&expected.domain.version==='2'&&
      expected.digest===access.approvalDigest&&TypedDataEncoder.hash(expected.domain,deliveryTypesV2,expected.value)===expected.digest&&
      verifyTypedData(expected.domain,deliveryTypesV2,expected.value,expected.requesterSignature)===expected.requester);
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
    directory=fs.mkdtempSync(path.join(spoolDirectory,'cannabis-relay-'));fs.chmodSync(directory,0o700);
    ciphertext=path.join(directory,'result.age');sourceFile=path.join(directory,'source.json');
    fd=fs.openSync(ciphertext,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);
    const whole=createHash('sha256');let received=0;
    while(received<header.ciphertextBytes) {
      const bytes=await guest.readChunk();active();check(bytes.length>0&&received+bytes.length<=header.ciphertextBytes);
      whole.update(bytes);let offset=0;
      while(offset<bytes.length){const n=fs.writeSync(fd,bytes,offset,bytes.length-offset);check(n>0);offset+=n;}
      received+=bytes.length;
    }
    const endFrame=await guest.readJSON(1024),ciphertextSHA256=whole.digest('hex');active();
    check(fields(endFrame,['protocol','operation','ciphertextSHA256'])&&endFrame.protocol==='cannabis.guest-wire.v1'&&
      endFrame.operation==='end'&&endFrame.ciphertextSHA256===ciphertextSHA256);
    fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;retained=true;
    const source={approvalDigest:expected.digest,resultEnvelope:header.resultEnvelope,ciphertextSHA256,
      ciphertextBytes:received,ciphertext};
    fd=fs.openSync(sourceFile,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);
    fs.writeFileSync(fd,JSON.stringify(source)+'\n');fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    syncDirectory(directory);syncDirectory(spoolDirectory);
    active();
    await uploadEncryptedResult({source,access,origin,timeoutMs:remaining(),signal:controller.signal,fetchImpl,wait});
    active();
    await requester.writeJSON({protocol:'cannabis.hosted-result.v1',operation:'result',relayId:access.id,
      approvalDigest:expected.digest,resultEnvelope:header.resultEnvelope,ciphertextSHA256,ciphertextBytes:received});
    const ack=await requester.readJSON(2048);active();
    const payload=resultStoredPayload(expected,{envelopeSHA256:hash(header.resultEnvelope),ciphertextSHA256,ciphertextBytes:received});
    check(fields(ack,['protocol','operation','signature'])&&ack.protocol==='cannabis.guest-wire.v1'&&ack.operation==='stored'&&
      typeof ack.signature==='string'&&verifyTypedData(payload.domain,payload.types,payload.value,ack.signature)===expected.requester);
    active();await guest.writeJSON(ack);active();
    return {schema:'cannabis.result-bridge-report.v1',approvalDigest:expected.digest,directory,sourceFile,
      ciphertextBytes:received,requesterStorageSignatureVerified:true,signatureForwarded:true,
      guestCompletionObserved:false,qualityAccepted:false,paymentAuthorized:false};
  } catch {
    stop();const error=Error('Encrypted result bridge failed; retain complete ciphertext and requester recovery material');
    if(retained)Object.defineProperty(error,'recoveryDirectory',{value:directory,enumerable:false});
    throw error;
  } finally {
    clearTimeout(timer);for(const s of listeners)s.removeEventListener('abort',stop);
    if(fd!==undefined)fs.closeSync(fd);
    // Remove only this invocation's incomplete files, never an existing result
    // or a complete spool. Retention after acknowledgement is an operator policy.
    if(directory&&!retained) {
      for(const file of [sourceFile,ciphertext])if(file&&fs.existsSync(file))fs.unlinkSync(file);
      fs.rmdirSync(directory);
    }
  }
}
