// Network-bound Node manifest reader; the canonical model is shared with browsers.
import {performance} from 'node:perf_hooks';
import {readMarketOffers} from './market_reader.mjs';
import {encodeProviderManifest as encodePortable,MAX_BYTES,check,exact,digest,integer,canonical,origin,selected,inspectProviderManifest} from './provider_manifest_model.mjs';
export {inspectProviderManifest};
export function encodeProviderManifest(manifest) {
  const value=encodePortable(manifest);return {...value,bytes:Buffer.from(value.bytes)};
}
async function fetchBytes(url,{fetchImpl,signal,remaining,active}) {
  const controller=new AbortController(),abort=()=>controller.abort();let reader;
  signal?.addEventListener('abort',abort,{once:true});
  const timer=setTimeout(abort,Math.min(10000,remaining()));
  try {
    active();
    const response=await fetchImpl(url,{method:'GET',redirect:'error',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',
      headers:{Accept:'application/json','Accept-Encoding':'identity'},signal:controller.signal});
    active();check(!controller.signal.aborted&&response.status===200&&!response.redirected&&(!response.url||response.url===url));
    check(/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')??'')&&
      [null,'identity'].includes(response.headers.get('content-encoding')));
    const declared=response.headers.get('content-length');
    check(declared===null||/^[1-9][0-9]{0,5}$/.test(declared)&&Number(declared)<=MAX_BYTES);
    reader=response.body.getReader();const chunks=[];let length=0;
    while(true) {
      const {done,value}=await reader.read();active();check(!controller.signal.aborted);
      if(done)break;
      length+=value.byteLength;check(length<=MAX_BYTES);chunks.push(Buffer.from(value));
    }
    check(declared===null||Number(declared)===length);return Buffer.concat(chunks);
  } finally {
    clearTimeout(timer);signal?.removeEventListener('abort',abort);
    controller.abort();try{await reader?.cancel();}catch{}reader?.releaseLock();
  }
}

// Mirrors are explicit local client choices, never URLs injected by the offer.
// A fixed content-addressed path permits untrusted interchangeable mirrors.
export async function readProviderManifest(network,query,{clock=()=>Math.floor(Date.now()/1000),timeoutMs=60000,
  signal,fetchImpl=globalThis.fetch}={}) {
  network=structuredClone(network);query=structuredClone(query);
  exact(query,['offerId','fromBlock','toBlock','mirrors']);check(digest(query.offerId));
  check(Array.isArray(query.mirrors)&&query.mirrors.length>=1&&query.mirrors.length<=8&&new Set(query.mirrors).size===query.mirrors.length);
  query.mirrors.forEach(m=>origin(m,true));check(integer(timeoutMs,1,60000)&&(!signal||signal instanceof AbortSignal));
  const started=performance.now(),wall=clock();let last=wall;
  const remaining=()=>Math.max(0,Math.floor(timeoutMs-(performance.now()-started)));
  const active=()=>{const now=clock();check(!signal?.aborted&&integer(now,wall,Number.MAX_SAFE_INTEGER)&&now>=last&&remaining()>0);last=now;return now;};
  const range={fromBlock:query.fromBlock,toBlock:query.toBlock};
  active();const first=await readMarketOffers(network,range,active,{signal,timeoutMs:Math.max(1,remaining())});active();
  const entry=selected(first,query.offerId,active());check(digest(entry.offer.manifestHash));
  const suffix='/.well-known/cannabis/manifests/sha256/'+entry.offer.manifestHash.slice(2)+'.json';
  let bytes,inspection,mirror;
  for(const candidate of query.mirrors) {
    active();
    try {
      const received=await fetchBytes(candidate+suffix,{fetchImpl,signal,remaining,active});
      const checked=inspectProviderManifest(received,first,query.offerId,active());
      bytes=received;inspection=checked;mirror=candidate;break;
    } catch {active();} // Try only another explicitly selected origin for the same hash.
  }
  check(inspection);
  const current=await readMarketOffers(network,range,active,{signal,timeoutMs:Math.max(1,remaining())});active();
  const latest=selected(current,query.offerId,active());
  check(canonical(entry)===canonical(latest)&&current.finalizedBlock.number>=first.finalizedBlock.number&&
    (current.finalizedBlock.number!==first.finalizedBlock.number||current.finalizedBlock.hash===first.finalizedBlock.hash));
  inspection=inspectProviderManifest(bytes,current,query.offerId,active());
  return {...inspection,schema:'cannabis.provider-manifest-observation.v1',chainVerified:true,
    chainVerification:'rpc-finalized',observedBlock:current.finalizedBlock,mirror,
    bookingGuaranteed:false,endpointAuthenticated:false,hardwareValidated:false,
    note:'Provider-committed public declarations at the observed RPC state; not local consensus, endpoint authentication or physical capacity admission.'};
}
