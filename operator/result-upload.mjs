// Ordinary-host ciphertext courier. No content keys, requester signing or job
// admission. A relay's answer cannot establish requester storage or acceptance.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setImmediate as yieldIO } from 'node:timers/promises';

const CHUNK=65536,MAX_BYTES=64*1024*1024,MAX_ENVELOPE=6*1024*1024;
const agePrefix=Buffer.from('age-encryption.org/v1\n');
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const hash=value=>createHash('sha256').update(value).digest('hex');
const hex=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const digest=value=>typeof value==='string'&&/^0x[0-9a-f]{64}$/.test(value);
const fields=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===names.sort().join();
const check=(ok,message)=>{if(!ok)throw Error(message);};
const sameFile=(a,b)=>['dev','ino','size','mtimeNs','ctimeNs','nlink'].every(k=>a[k]===b[k]);
export function validateUploadAccess(value,origin) {
  const url=new URL(origin);
  check(url.origin===origin&&!url.username&&!url.password&&(url.protocol==='https:'||url.protocol==='http:'&&url.hostname==='127.0.0.1'),
    'Require the configured HTTPS relay origin');
  check(fields(value,['schema','id','approvalDigest','expiresAt','chunkBytes','origin','role','token'])&&
    value.schema==='cannabis.result-relay-access.v1'&&value.origin===origin&&value.role==='upload'&&value.chunkBytes===CHUNK&&
    typeof value.id==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.id)&&
    digest(value.approvalDigest)&&hex(value.token)&&integer(value.expiresAt,1,Number.MAX_SAFE_INTEGER),
    'Upload access differs from the configured origin or role');
  return structuredClone(value);
}
function sourceValue(value,approvalDigest) {
  check(fields(value,['approvalDigest','resultEnvelope','ciphertextSHA256','ciphertextBytes','ciphertext'])&&
    value.approvalDigest===approvalDigest&&hex(value.ciphertextSHA256)&&integer(value.ciphertextBytes,agePrefix.length+32,MAX_BYTES)&&
    typeof value.ciphertext==='string'&&path.isAbsolute(value.ciphertext)&&typeof value.resultEnvelope==='string'&&
    value.resultEnvelope.length<=MAX_ENVELOPE&&/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value.resultEnvelope),
    'Require bounded encrypted result metadata and an absolute ciphertext path');
  const encoded=value.resultEnvelope.split('.')[0];check(encoded.length<=4096,'Invalid encrypted receipt header');
  let header;try {
    const raw=Buffer.from(encoded,'base64url');check(raw.toString('base64url')===encoded,'Invalid encrypted receipt header');
    header=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  }catch{throw Error('Invalid encrypted receipt header');}
  check(fields(header,['alg','enc','typ','kid'])&&header.alg==='dir'&&header.enc==='A256GCM'&&
    header.typ==='cannabis-result+jwe'&&header.kid===approvalDigest,'Receipt framing differs from the selected approval');
  return structuredClone(value);
}
function delay(ms,signal) {
  return new Promise((resolve,reject)=>{
    if(signal?.aborted)return reject(Error('Encrypted result upload cancelled'));
    const aborted=()=>{clearTimeout(timer);signal?.removeEventListener('abort',aborted);reject(Error('Encrypted result upload cancelled'));};
    const timer=setTimeout(()=>{signal?.removeEventListener('abort',aborted);resolve();},ms);
    signal?.addEventListener('abort',aborted,{once:true});
  });
}
export async function uploadEncryptedResult({source,access,origin,timeoutMs=1800000,signal,onProgress=()=>{},fetchImpl=globalThis.fetch,wait=delay}) {
  check(integer(timeoutMs,1,3600000)&&(!signal||signal instanceof AbortSignal),'Invalid encrypted upload deadline');
  access=validateUploadAccess(access,origin);source=sourceValue(source,access.approvalDigest);
  const wall=Date.now(),started=performance.now(),end=Math.min(access.expiresAt,wall+timeoutMs);
  const remaining=()=>Math.floor(Math.min(end-Date.now(),timeoutMs-(performance.now()-started)));
  const active=()=>{
    check(!signal?.aborted,'Encrypted result upload cancelled');
    check(Date.now()>=wall&&remaining()>0,'Encrypted result upload expired or exceeded its deadline');
  };
  const expectedParts=Math.ceil(source.ciphertextBytes/CHUNK);
  function state(value) {
    check(fields(value,['schema','id','approvalDigest','expiresAt','chunkBytes','ciphertextSHA256','ciphertextBytes','received',
      'complete','outputVerified','qualityAccepted','paymentAuthorized'])&&value.schema==='cannabis.result-relay-state.v1'&&
      value.id===access.id&&value.approvalDigest===source.approvalDigest&&value.expiresAt===access.expiresAt&&value.chunkBytes===CHUNK&&
      value.ciphertextSHA256===source.ciphertextSHA256&&value.ciphertextBytes===source.ciphertextBytes&&
      typeof value.complete==='boolean'&&value.outputVerified===false&&value.qualityAccepted===false&&value.paymentAuthorized===false&&
      Array.isArray(value.received)&&value.received.length<=expectedParts&&value.received.every((n,i)=>integer(n,0,expectedParts-1)&&(i===0||n>value.received[i-1]))&&
      (!value.complete||value.received.length===expectedParts),'Relay upload state differs from this encrypted result');
    return value;
  }
  async function request(suffix,body,type) {
    for(let attempt=0;attempt<3;attempt++) {
      active();const controller=new AbortController(),abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});
      const timer=setTimeout(abort,Math.min(15000,remaining()));let response,reader,retry=false,seconds=1;
      try {
        response=await fetchImpl(origin+'/api/work/results/'+access.id+suffix,{method:'POST',body,
          headers:{Origin:origin,Authorization:'Bearer '+access.token,'Content-Type':type},
          redirect:'error',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',signal:controller.signal});
        if([408,429,502,503,504].includes(response.status)) {
          retry=true;seconds=response.status===429?60:1;
          const retryAfter=response.headers.get('retry-after');if(retryAfter&&/^[0-9]{1,2}$/.test(retryAfter))seconds=Math.max(1,Math.min(60,Number(retryAfter)));
        } else {
          check(response.status===200,'Relay refused the encrypted upload; retain its source and access files');
          check(!response.redirected&&(!response.url||response.url===origin+'/api/work/results/'+access.id+suffix)&&
            (response.headers.get('content-type')??'').split(';')[0].trim()==='application/json'&&!response.headers.get('content-encoding'),
            'Unexpected encrypted upload response');
          const length=response.headers.get('content-length');
          check(length===null||/^[0-9]+$/.test(length)&&integer(Number(length),1,32768),'Upload response exceeds its bound');
          check(response.body,'Missing upload response');reader=response.body.getReader();
          const chunks=[];let size=0;
          while(true){const {done,value}=await reader.read();if(done)break;
            check(value instanceof Uint8Array&&size+value.length<=32768,'Upload response exceeds its bound');size+=value.length;chunks.push(value);}
          check(size>0&&(length===null||size===Number(length)),'Truncated upload response');
          active();let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));}
          catch{throw Error('Invalid upload response');}return value;
        }
      }catch(error){
        if(signal?.aborted)throw Error('Encrypted result upload cancelled');
        if(controller.signal.aborted||error instanceof TypeError)retry=true;else throw error;
      }finally{
        clearTimeout(timer);signal?.removeEventListener('abort',abort);controller.abort();
        if(reader){void reader.cancel().catch(()=>{});reader.releaseLock();}
        else if(response?.body)void response.body.cancel().catch(()=>{});
      }
      active();check(retry&&attempt<2,'Encrypted upload interrupted; rerun with the same files to resume');
      check(seconds*1000<remaining(),'Insufficient time to retry this encrypted upload');
      onProgress({phase:'retry',retrySeconds:seconds});await wait(seconds*1000,signal);
    }
  }
  let fd;
  try {
    active();
    const selectedFile=fs.lstatSync(source.ciphertext);
    check(selectedFile.isFile()&&!selectedFile.isSymbolicLink(),'Ciphertext source must be a regular file');
    fd=fs.openSync(source.ciphertext,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    const initial=fs.fstatSync(fd,{bigint:true});
    check(initial.isFile()&&initial.size===BigInt(source.ciphertextBytes),'Ciphertext size differs from its recorded commitment');
    const read=index=>{
      active();check(sameFile(initial,fs.fstatSync(fd,{bigint:true})),'Ciphertext source changed; no replacement is uploaded');
      const size=Math.min(CHUNK,source.ciphertextBytes-index*CHUNK),bytes=Buffer.allocUnsafe(size);let offset=0;
      while(offset<size){const n=fs.readSync(fd,bytes,offset,size-offset,index*CHUNK+offset);check(n>0,'Ciphertext source ended early');offset+=n;}
      return bytes;
    };
    const pieces=[],whole=createHash('sha256');
    for(let index=0;index<expectedParts;index++) {
      const bytes=read(index);
      if(index===0)check(bytes.subarray(0,agePrefix.length).equals(agePrefix),'Only binary age result archives may be uploaded');
      pieces.push(hash(bytes));whole.update(bytes);await yieldIO();
    }
    check(whole.digest('hex')===source.ciphertextSHA256&&sameFile(initial,fs.fstatSync(fd,{bigint:true})),
      'Ciphertext source does not match its recorded commitment');
    active();onProgress({phase:'checked',ciphertextBytes:source.ciphertextBytes});
    const manifest=JSON.stringify({resultEnvelope:source.resultEnvelope,ciphertextSHA256:source.ciphertextSHA256,ciphertextBytes:source.ciphertextBytes});
    const selected=state(await request('/manifest',manifest,'application/json')),received=new Set(selected.received);
    let sent=0,reused=0;
    for(let index=0;index<expectedParts;index++) {
      // Recheck every retained chunk, including those the relay claims to hold.
      // No read token is given to an uploader; remote durability is unproven here.
      const bytes=read(index);check(hash(bytes)===pieces[index],'Ciphertext chunk changed; no replacement is uploaded');
      if(received.has(index))reused+=bytes.length;
      else {
        const answer=await request('/chunks/'+index,bytes,'application/octet-stream');
        check(fields(answer,['stored','index','complete'])&&answer.stored===true&&answer.index===index&&typeof answer.complete==='boolean',
          'Relay chunk acknowledgement differs');sent+=bytes.length;
      }
      onProgress({phase:'upload',uploadedBytes:sent,reusedBytes:reused,totalBytes:source.ciphertextBytes});await yieldIO();
    }
    active();check(sameFile(initial,fs.fstatSync(fd,{bigint:true})),'Ciphertext source changed during upload');
    const finished=state(await request('/finish','{}','application/json'));check(finished.complete,'Relay did not report a complete encrypted result');
    active();check(sameFile(initial,fs.fstatSync(fd,{bigint:true})),'Ciphertext source changed during completion');
    return {schema:'cannabis.result-upload-report.v1',approvalDigest:source.approvalDigest,ciphertextSHA256:source.ciphertextSHA256,
      ciphertextBytes:source.ciphertextBytes,uploadedBytes:sent,reusedBytes:reused,relayReportedComplete:true,
      requesterAcknowledgedStorage:false,outputVerified:false,qualityAccepted:false,paymentAuthorized:false};
  }finally{if(fd!==undefined)fs.closeSync(fd);}
}
