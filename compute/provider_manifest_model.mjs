// Provider-committed public metadata, never workload intake or admission.
import {getAddress,ZeroAddress,sha256,toUtf8Bytes} from 'ethers';

const MAX_BYTES=65536;
const fail=()=>{throw Error('Provider manifest does not match the selected market offer');};
const check=ok=>{if(!ok)fail();};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join());
const hash=b=>sha256(b);
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
  check(typeof value.terms==='string'&&value.terms.trim().length>0&&toUtf8Bytes(value.terms).length<=8192&&
    !/[\u0000-\u0008\u000b-\u001f\u007f]/.test(value.terms));
  return value;
}

// Exact sorted compact UTF-8 JSON followed by LF. This is this protocol's byte
// format, not a claim to implement another JSON canonicalization standard.
export function encodeProviderManifest(manifest) {
  manifest=validate(structuredClone(manifest));
  const bytes=toUtf8Bytes(canonical(manifest)+'\n');check(bytes.length<=MAX_BYTES);
  return {manifest,bytes,manifestHash:hash(bytes)};
}
export {MAX_BYTES,check,exact,digest,integer,canonical,origin};
export function selected(snapshot,offerId,now) {
  check(snapshot?.schema==='cannabis.market-snapshot.v1'&&snapshot.finality==='rpc-finalized'&&
    integer(now,1,Number.MAX_SAFE_INTEGER)&&Array.isArray(snapshot.offers));
  const matching=snapshot.offers.filter(v=>v.offerId===offerId);check(matching.length===1);
  const selected=matching[0];check(selected.withdrawn===false&&selected.expiredAtSnapshot===false&&
    BigInt(selected.offer.expiresAt)>BigInt(now)&&BigInt(selected.offer.end)>BigInt(now));
  return selected;
}
export function inspectProviderManifest(raw,snapshot,offerId,now=Math.floor(Date.now()/1000)) {
  check(raw instanceof Uint8Array);const bytes=new Uint8Array(raw);
  check(bytes.length>0&&bytes.length<=MAX_BYTES);
  const decoded=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  const encoded=encodeProviderManifest(decoded);check(bytes.length===encoded.bytes.length&&bytes.every((v,i)=>v===encoded.bytes[i]));
  const entry=selected(snapshot,offerId,now),m=encoded.manifest,{manifestHash,...terms}=entry.offer;
  check(encoded.manifestHash===manifestHash&&m.chainId===snapshot.chainId&&m.genesisHash===snapshot.genesisHash&&
    m.market===snapshot.market&&m.offerId===entry.offerId&&canonical(m.offer)===canonical(terms)&&
    canonical(m.resource)===canonical({id:entry.offer.resource,...entry.resource}));
  return {schema:'cannabis.provider-manifest-inspection.v1',manifest:m,manifestHash,
    matchesSuppliedObservation:true,chainVerified:false,endpointAuthenticated:false,
    hardwareValidated:false,executionAuthorized:false,keyReleaseAuthorized:false};
}
