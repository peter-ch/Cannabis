// Provider-committed public metadata, never workload intake or admission.
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { getAddress, ZeroAddress } from 'ethers';
import { readMarketOffers } from './market_reader.mjs';

const MAX_BYTES=65536;
const fail=()=>{throw Error('Provider manifest does not match the selected market offer');};
const check=ok=>{if(!ok)fail();};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join());
const hash=b=>'0x'+createHash('sha256').update(b).digest('hex');
const digest=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const address=v=>typeof v==='string'&&v!==ZeroAddress&&getAddress(v)===v;
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const number=(v,bits)=>typeof v==='string'&&/^[1-9][0-9]*$/.test(v)&&v.length<=78&&BigInt(v)<2n**BigInt(bits);
const name=v=>typeof v==='string'&&/^[a-z0-9][a-z0-9._-]{0,63}$/.test(v);
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'
  ?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);

function origin(value,loopback=false) {
  check(typeof value==='string'&&value.length<=512);
  const u=new URL(value);
  check(u.origin===value&&!u.username&&!u.password&&(u.protocol==='https:'||loopback&&u.protocol==='http:'&&u.hostname==='127.0.0.1'));
  return value;
}
function validate(value) {
  exact(value,['schema','chainId','genesisHash','market','offerId','resource','offer','endpoints','runtimes','terms']);
  check(value.schema==='cannabis.provider-manifest.v1'&&number(value.chainId,256)&&digest(value.genesisHash)&&address(value.market)&&digest(value.offerId));
  const r=value.resource,o=value.offer;
  exact(r,['id','provider','serviceHash','units']);
  check(digest(r.id)&&address(r.provider)&&digest(r.serviceHash)&&number(r.units,32));
  // manifestHash is intentionally absent from its own committed document.
  exact(o,['resource','escrow','policyHash','start','end','expiresAt','units','grossPerUnitSecond']);
  check(o.resource===r.id&&address(o.escrow)&&digest(o.policyHash));
  for(const k of ['start','end','expiresAt'])check(number(o[k],64));
  check(BigInt(o.start)<BigInt(o.end)&&BigInt(o.expiresAt)<=BigInt(o.end)&&number(o.units,32)&&BigInt(o.units)<=BigInt(r.units)&&
    number(o.grossPerUnitSecond,256)&&BigInt(o.grossPerUnitSecond)%100n===0n);
  check(Array.isArray(value.endpoints)&&value.endpoints.length>=2&&value.endpoints.length<=8);
  const seen=new Set(),roles=new Set();
  for(const e of value.endpoints) {
    exact(e,['role','origin']);check(['booking','session','results'].includes(e.role));origin(e.origin);
    const id=e.role+' '+e.origin;check(!seen.has(id));seen.add(id);roles.add(e.role);
  }
  check(roles.has('booking')&&roles.has('session'));
  check(Array.isArray(value.runtimes)&&value.runtimes.length>=1&&value.runtimes.length<=16);
  const runtimes=new Set();
  for(const r of value.runtimes) {
    exact(r,['adapter','architecture','os','digestSHA256','tee','acceleratorClass']);
    check(['adapter','architecture','os','tee','acceleratorClass'].every(k=>name(r[k]))&&digest(r.digestSHA256));
    const id=canonical(r);check(!runtimes.has(id));runtimes.add(id);
  }
  check(typeof value.terms==='string'&&value.terms.trim().length>0&&Buffer.byteLength(value.terms)<=8192&&
    !/[\u0000-\u0008\u000b-\u001f\u007f]/.test(value.terms));
  return value;
}

// Exact sorted compact UTF-8 JSON followed by LF. This is this protocol's byte
// format, not a claim to implement another JSON canonicalization standard.
export function encodeProviderManifest(manifest) {
  manifest=validate(structuredClone(manifest));
  const bytes=Buffer.from(canonical(manifest)+'\n');check(bytes.length<=MAX_BYTES);
  return {manifest,bytes,manifestHash:hash(bytes)};
}
function selected(snapshot,offerId,now) {
  check(snapshot?.schema==='cannabis.market-snapshot.v1'&&snapshot.finality==='rpc-finalized'&&
    integer(now,1,Number.MAX_SAFE_INTEGER)&&Array.isArray(snapshot.offers));
  const matching=snapshot.offers.filter(v=>v.offerId===offerId);check(matching.length===1);
  const selected=matching[0];check(selected.withdrawn===false&&selected.expiredAtSnapshot===false&&
    BigInt(selected.offer.expiresAt)>BigInt(now)&&BigInt(selected.offer.end)>BigInt(now));
  return selected;
}
export function inspectProviderManifest(raw,snapshot,offerId,now=Math.floor(Date.now()/1000)) {
  check(Buffer.isBuffer(raw)||raw instanceof Uint8Array);const bytes=Buffer.from(raw);
  check(bytes.length>0&&bytes.length<=MAX_BYTES);
  const decoded=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  const encoded=encodeProviderManifest(decoded);check(bytes.equals(encoded.bytes));
  const entry=selected(snapshot,offerId,now),m=encoded.manifest,{manifestHash,...terms}=entry.offer;
  check(encoded.manifestHash===manifestHash&&m.chainId===snapshot.chainId&&m.genesisHash===snapshot.genesisHash&&
    m.market===snapshot.market&&m.offerId===entry.offerId&&canonical(m.offer)===canonical(terms)&&
    canonical(m.resource)===canonical({id:entry.offer.resource,...entry.resource}));
  return {schema:'cannabis.provider-manifest-inspection.v1',manifest:m,manifestHash,
    matchesSuppliedObservation:true,chainVerified:false,endpointAuthenticated:false,
    hardwareValidated:false,executionAuthorized:false,keyReleaseAuthorized:false};
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
