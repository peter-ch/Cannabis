// Requester-only streaming adapter. Reuse the authenticated inbox, exclusive
// fsynced publication and owner-controlled acknowledgement of the direct wire.
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { receiveEncryptedResult } from '../compute/result_transport.mjs';
import { validateRelayAccess } from '../web/work-relay.js';
const CHUNK=65536,MAX_BYTES=64*1024*1024;
const fields=(v,n)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===n.sort().join();
const integer=(n,min,max)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const hash=v=>createHash('sha256').update(v).digest('hex');
const check=v=>{if(!v)throw Error('Hosted result retrieval failed');};
function delay(ms,signal) {
  return new Promise((resolve,reject)=>{
    if(signal.aborted)return reject(Error('Cancelled'));
    const abort=()=>{clearTimeout(timer);signal.removeEventListener('abort',abort);reject(Error('Cancelled'));};
    const timer=setTimeout(()=>{signal.removeEventListener('abort',abort);resolve();},ms);
    signal.addEventListener('abort',abort,{once:true});
  });
}
function abortable(operation,signal) {
  return new Promise((resolve,reject)=>{
    const abort=()=>reject(Error('Cancelled'));if(signal.aborted)return abort();
    signal.addEventListener('abort',abort,{once:true});
    Promise.resolve().then(()=>{check(!signal.aborted);return operation();}).then(resolve,reject)
      .finally(()=>signal.removeEventListener('abort',abort));
  });
}
export async function receiveHostedResult(wire,{inbox,approvalDigest,loadResultKey,destination,maxCiphertextBytes,
  signStored,access,origin,timeoutMs,signal,fetchImpl=globalThis.fetch,wait=delay}={}) {
  const controller=new AbortController(),listeners=[];let timer,stage='access';
  const stop=()=>{if(controller.signal.aborted)return;controller.abort();wire.fail();};
  try {
    check(integer(timeoutMs,1,3600000)&&integer(maxCiphertextBytes,1,MAX_BYTES)&&
      typeof signStored==='function'&&(!signal||signal instanceof AbortSignal));
    // The origin and read grant come from local requester configuration, never
    // from the bridge's message. This validation sends no request or secret.
    [access]=validateRelayAccess([access],origin,[{approvalDigest}]);
    const wall=Date.now(),started=performance.now(),end=Math.min(access.expiresAt,wall+timeoutMs);
    const remaining=()=>Math.floor(Math.min(end-Date.now(),timeoutMs-(performance.now()-started)));
    let header,selection,first=true,index=0,manifestChecked=false;
    const active=()=>{
      wire.assertActive();check(!controller.signal.aborted&&Date.now()>=wall&&remaining()>0);
      if(selection)inbox.useCurrent(selection,()=>true);
    };
    for(const s of [wire.signal,signal].filter(Boolean)) {
      check(!s.aborted);s.addEventListener('abort',stop,{once:true});listeners.push(s);
    }
    active();timer=setTimeout(stop,remaining());
    async function bytes(suffix,type,max) {
      for(let attempt=0;attempt<3;attempt++) {
        active();const request=new AbortController(),abort=()=>request.abort();
        controller.signal.addEventListener('abort',abort,{once:true});
        const requestTimer=setTimeout(abort,Math.min(15000,remaining()));let response,reader,retry=false,seconds=1;
        try {
          const url=origin+'/api/work/results/'+access.id+suffix;
          response=await fetchImpl(url,{method:'GET',headers:{Authorization:'Bearer '+access.token},
            redirect:'error',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',signal:request.signal});
          if([408,429,502,503,504].includes(response.status)) {
            retry=true;seconds=response.status===429?60:1;
            const value=response.headers.get('retry-after');if(value&&/^[0-9]{1,2}$/.test(value))seconds=Math.max(1,Math.min(60,Number(value)));
          } else {
            check(response.status===200&&!response.redirected&&(!response.url||response.url===url)&&
              (response.headers.get('content-type')??'').split(';')[0].trim()===type&&!response.headers.get('content-encoding'));
            const length=response.headers.get('content-length');
            check(length===null||/^[0-9]+$/.test(length)&&integer(Number(length),1,max));check(response.body);
            reader=response.body.getReader();const parts=[];let size=0;
            while(true) {
              const {done,value}=await reader.read();if(done)break;
              check(value instanceof Uint8Array&&size+value.length<=max);size+=value.length;parts.push(value);
            }
            check(size>0&&(length===null||size===Number(length)));active();return Buffer.concat(parts,size);
          }
        } catch(error) {
          if(controller.signal.aborted)throw error;
          if(request.signal.aborted||error instanceof TypeError)retry=true;else throw error;
        } finally {
          clearTimeout(requestTimer);controller.signal.removeEventListener('abort',abort);request.abort();
          if(reader){void reader.cancel().catch(()=>{});reader.releaseLock();}
          else if(response?.body)void response.body.cancel().catch(()=>{});
        }
        active();check(retry&&attempt<2&&seconds*1000<remaining());await wait(seconds*1000,controller.signal);
      }
    }
    const selectedInbox={
      receive:async(digest,envelope,load)=>{
        stage='receipt-authentication';
        const authenticated=await abortable(()=>inbox.receive(digest,envelope,load),controller.signal);
        check(authenticated.receipt.ciphertextSHA256===header.ciphertextSHA256&&
          authenticated.receipt.ciphertextBytes===header.ciphertextBytes&&authenticated.receiptSHA256===hash(header.resultEnvelope));
        selection=[{approvalDigest,receiptSHA256:authenticated.receiptSHA256}];active();return authenticated;
      },
      useCurrent:(...args)=>{active();return inbox.useCurrent(...args);}
    };
    const adapter={
      readJSON:async()=>{
        active();if(first) {
          stage='result-header';
          first=false;header=await wire.readJSON();active();
          check(fields(header,['protocol','operation','relayId','approvalDigest','resultEnvelope','ciphertextSHA256','ciphertextBytes'])&&
            header.protocol==='cannabis.hosted-result.v1'&&header.operation==='result'&&header.relayId===access.id&&header.approvalDigest===approvalDigest&&
            typeof header.resultEnvelope==='string'&&header.resultEnvelope.length<=6*1024*1024&&
            typeof header.ciphertextSHA256==='string'&&/^[0-9a-f]{64}$/.test(header.ciphertextSHA256)&&integer(header.ciphertextBytes,1,maxCiphertextBytes));
          return {protocol:'cannabis.guest-wire.v1',operation:'result',approvalDigest,
            resultEnvelope:header.resultEnvelope,ciphertextBytes:header.ciphertextBytes};
        }
        check(selection&&index===Math.ceil(header.ciphertextBytes/CHUNK));
        return {protocol:'cannabis.guest-wire.v1',operation:'end',ciphertextSHA256:header.ciphertextSHA256};
      },
      readChunk:async()=>{
        active();check(selection&&index<Math.ceil(header.ciphertextBytes/CHUNK));
        if(!manifestChecked) {
          stage='relay-manifest';
          const raw=await bytes('/manifest','application/json',6*1024*1024+2048);
          const m=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
          check(fields(m,['schema','id','approvalDigest','expiresAt','chunkBytes','resultEnvelope','ciphertextSHA256','ciphertextBytes'])&&
            m.schema==='cannabis.result-relay-manifest.v1'&&m.id===access.id&&m.approvalDigest===approvalDigest&&m.expiresAt===access.expiresAt&&
            m.chunkBytes===CHUNK&&m.resultEnvelope===header.resultEnvelope&&m.ciphertextSHA256===header.ciphertextSHA256&&m.ciphertextBytes===header.ciphertextBytes);
          manifestChecked=true;
        }
        stage='relay-chunks';
        const count=Math.min(CHUNK,header.ciphertextBytes-index*CHUNK),chunk=await bytes('/chunks/'+index,'application/octet-stream',count);
        check(chunk.length===count);active();index++;return chunk;
      },
      writeJSON:async ack=>{stage='storage-acknowledgement';active();await wire.writeJSON(ack);active();},
      assertActive:active,fail:stop
    };
    const result=await receiveEncryptedResult(adapter,{inbox:selectedInbox,approvalDigest,loadResultKey,destination,maxCiphertextBytes,
      signStored:async payload=>{stage='storage-approval';active();const signature=await abortable(()=>signStored(payload),controller.signal);active();return signature;}});
    active();return Object.defineProperty({...result,transport:'hosted-relay'},'resultEnvelope',{value:header.resultEnvelope,enumerable:false});
  } catch {stop();const error=Error('Hosted result retrieval failed; retain requester recovery material and any published ciphertext');
    Object.defineProperty(error,'transportStage',{value:stage});throw error;}
  finally{clearTimeout(timer);for(const s of listeners)s.removeEventListener('abort',stop);}
}
