// Same-origin ciphertext retrieval. No identity, receipt plaintext, workload or
// signing data goes onto the network. Cache only unfinished encrypted archives.
import { sha256, MAX_RESULT_BYTES } from './work-results.js';
const chunkBytes=65536, envelopeLimit=6*1024*1024, enc=new TextEncoder(),utf8=new TextDecoder('utf-8',{fatal:true});
const integer=(n,min,max)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const hash=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s);
const digest=s=>typeof s==='string'&&/^0x[0-9a-f]{64}$/.test(s);
const fields=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join();
const check=(ok,message)=>{if(!ok)throw Error(message);};
function cancelled(){return Error('Result download was cancelled or superseded');}
function originValue(origin) {
  const url=new URL(origin);
  check(url.origin===origin&&!url.username&&!url.password&&(url.protocol==='https:'||url.protocol==='http:'&&url.hostname==='127.0.0.1'),
    'Use the current HTTPS website origin for result retrieval');return origin;
}
export function validateRelayAccess(input,origin,descriptors) {
  originValue(origin);
  check(Array.isArray(input)&&input.length>0&&input.length<=128&&input.length===descriptors.length,'Choose one read-access file per selected result');
  const wanted=new Map(descriptors.map(d=>[d.approvalDigest,d])),seen=new Set(),ids=new Set();
  return input.map(value=>{
    const a=structuredClone(value);
    check(fields(a,['schema','id','approvalDigest','expiresAt','chunkBytes','origin','role','token'])&&
      a.schema==='cannabis.result-relay-access.v1'&&a.role==='read'&&a.origin===origin&&a.chunkBytes===chunkBytes&&
      typeof a.id==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(a.id)&&
      digest(a.approvalDigest)&&wanted.has(a.approvalDigest)&&!seen.has(a.approvalDigest)&&!ids.has(a.id)&&
      integer(a.expiresAt,1,Number.MAX_SAFE_INTEGER)&&hash(a.token),
      'Read access must match this website and your selected approved result');
    seen.add(a.approvalDigest);ids.add(a.id);return a;
  });
}
export class EncryptedDownloadCache {
  #entries=new Map();#bytes=0;
  clear(){for(const entry of this.#entries.values())entry.bytes.fill(0);this.#entries.clear();this.#bytes=0;}
  obtain(key,size) {
    check(typeof key==='string'&&key.length<1024&&integer(size,1,MAX_RESULT_BYTES),'Invalid encrypted download cache entry');
    const old=this.#entries.get(key);if(old){check(old.bytes.length===size,'Download cache differs from the approved archive');return old;}
    check(this.#entries.size<128&&this.#bytes+size<=MAX_RESULT_BYTES,'Clear earlier encrypted downloads before retrieving another result set');
    const value={bytes:new Uint8Array(size),received:new Set(),verified:false};this.#entries.set(key,value);this.#bytes+=size;return value;
  }
  discard(key){const v=this.#entries.get(key);if(v){v.bytes.fill(0);this.#bytes-=v.bytes.length;this.#entries.delete(key);}}
}
function wait(ms,signal) {
  return new Promise((resolve,reject)=>{
    if(signal?.aborted)return reject(cancelled());
    const abort=()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);reject(cancelled());};
    const timer=setTimeout(()=>{signal?.removeEventListener('abort',abort);resolve();},ms);
    signal?.addEventListener('abort',abort,{once:true});
  });
}
export async function downloadApprovedArchives({descriptors,accessFiles,origin,cache=new EncryptedDownloadCache(),signal,
  assertCurrent,onProgress=()=>{},fetchImpl=globalThis.fetch,delay=wait}) {
  check(typeof assertCurrent==='function','A current requester selection is required');
  descriptors=structuredClone(descriptors);
  check(Array.isArray(descriptors)&&descriptors.length>0&&descriptors.length<=128&&descriptors.every(d=>
    fields(d,['approvalDigest','envelopeSHA256','ciphertextSHA256','ciphertextBytes'])&&digest(d.approvalDigest)&&
    hash(d.envelopeSHA256)&&hash(d.ciphertextSHA256)&&integer(d.ciphertextBytes,1,MAX_RESULT_BYTES))&&
    new Set(descriptors.map(d=>d.approvalDigest)).size===descriptors.length&&
    descriptors.reduce((n,d)=>n+d.ciphertextBytes,0)<=MAX_RESULT_BYTES,'Invalid authenticated archive commitments');
  const grants=validateRelayAccess(accessFiles,origin,descriptors),total=descriptors.reduce((n,d)=>n+d.ciphertextBytes,0);
  const until=Date.now()+30*60_000;let completed=0;
  const active=async grant=>{
    if(signal?.aborted)throw cancelled();
    check(Date.now()<until,'Download time limit reached; retry to resume encrypted chunks');
    if(grant)check(Date.now()<grant.expiresAt,'Result read access has expired');
    await assertCurrent();if(signal?.aborted)throw cancelled();
  };
  async function responseBytes(grant,suffix,type,max) {
    for(let attempt=0;attempt<3;attempt++) {
      await active(grant);
      const controller=new AbortController(),abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});
      const timer=setTimeout(abort,15000);let response,reader,retry=false,seconds=1;
      try {
        response=await fetchImpl(origin+'/api/work/results/'+grant.id+suffix,{method:'GET',headers:{Authorization:'Bearer '+grant.token},
          credentials:'omit',mode:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:controller.signal});
        if([408,429,502,503,504].includes(response.status)) {
          retry=true;seconds=response.status===429?60:1;
          const header=response.headers.get('retry-after');if(header&&/^[0-9]{1,2}$/.test(header))seconds=Math.max(1,Math.min(60,Number(header)));
        } else {
          check(response.status===200,'Encrypted delivery is unavailable; check read access or retry later');
          check(!response.redirected&&(!response.url||response.url===origin+'/api/work/results/'+grant.id+suffix),
            'Result response came from another address');
          check((response.headers.get('content-type')??'').split(';')[0].trim()===type&&!response.headers.get('content-encoding'),
            'Unexpected encrypted delivery response');
          const length=response.headers.get('content-length');
          check(length===null||/^[0-9]+$/.test(length)&&integer(Number(length),1,max),'Encrypted response exceeds its approved bound');
          check(response.body,'Missing encrypted delivery body');reader=response.body.getReader();
          const chunks=[];let size=0;
          while(true) {
            const {done,value}=await reader.read();if(done)break;
            check(value instanceof Uint8Array&&size+value.length<=max,'Encrypted response exceeds its approved bound');
            size+=value.length;chunks.push(value);
          }
          check(size>0&&(length===null||size===Number(length)),'Truncated encrypted delivery response');
          const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
          await active(grant);return bytes;
        }
      } catch(error) {
        if(signal?.aborted)throw cancelled();
        if(controller.signal.aborted||error instanceof TypeError)retry=true;
        else throw error;
      } finally {
        clearTimeout(timer);signal?.removeEventListener('abort',abort);controller.abort();
        if(reader){void reader.cancel().catch(()=>{});reader.releaseLock();}
        else if(response?.body)void response.body.cancel().catch(()=>{});
      }
      check(retry&&attempt<2,'Download interrupted; retry to resume the retained encrypted chunks');
      onProgress({completed,total,retrySeconds:seconds});await delay(seconds*1000,signal);
    }
  }
  const results=[];
  for(const descriptor of descriptors) {
    const grant=grants.find(a=>a.approvalDigest===descriptor.approvalDigest);await active(grant);
    const raw=await responseBytes(grant,'/manifest','application/json',envelopeLimit+2048);
    let manifest;try{manifest=JSON.parse(utf8.decode(raw));}catch{throw Error('Invalid encrypted delivery manifest');}
    check(fields(manifest,['schema','id','approvalDigest','expiresAt','chunkBytes','resultEnvelope','ciphertextSHA256','ciphertextBytes'])&&
      manifest.schema==='cannabis.result-relay-manifest.v1'&&manifest.id===grant.id&&manifest.approvalDigest===descriptor.approvalDigest&&
      manifest.expiresAt===grant.expiresAt&&manifest.chunkBytes===chunkBytes&&typeof manifest.resultEnvelope==='string'&&
      manifest.resultEnvelope.length<=envelopeLimit&&await sha256(enc.encode(manifest.resultEnvelope))===descriptor.envelopeSHA256&&
      manifest.ciphertextSHA256===descriptor.ciphertextSHA256&&manifest.ciphertextBytes===descriptor.ciphertextBytes,
      'Hosted metadata differs from your authenticated requester receipt');
    const key=JSON.stringify([origin,grant.id,descriptor]),saved=cache.obtain(key,descriptor.ciphertextBytes);
    for(let index=0;index<Math.ceil(descriptor.ciphertextBytes/chunkBytes);index++) {
      await active(grant);
      const length=Math.min(chunkBytes,descriptor.ciphertextBytes-index*chunkBytes);
      if(!saved.received.has(index)) {
        const bytes=await responseBytes(grant,'/chunks/'+index,'application/octet-stream',length);
        check(bytes.length===length,'Encrypted chunk has the wrong length');saved.bytes.set(bytes,index*chunkBytes);saved.received.add(index);
      }
      completed+=length;onProgress({completed,total,retrySeconds:0});
    }
    if(await sha256(saved.bytes)!==descriptor.ciphertextSHA256){cache.discard(key);throw Error('Downloaded ciphertext differs from the authenticated receipt; retry a fresh copy');}
    await active(grant);saved.verified=true;results.push(saved.bytes);
  }
  await active();return results;
}
