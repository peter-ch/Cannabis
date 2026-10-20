// Commitment to encrypted results. Validation here authenticates no execution or
// quality: requesters must authenticate receipts and reconstruct outputs first.
import {getAddress,ZeroAddress,sha256,toUtf8Bytes} from 'ethers';
const check=v=>{if(!v)throw Error('Encrypted result commitment is invalid');};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const digest=(v,prefix=true)=>check(typeof v==='string'&&(prefix?/^0x[0-9a-f]{64}$/:/^[0-9a-f]{64}$/).test(v)&&!(/^(0x)?0+$/.test(v)));
export function resultCommitment(context,archives) {
  const c=structuredClone(context);exact(c,['chainId','genesisHash','escrow','requester','orderId','termsDigest','packageSHA256','policySHA256']);
  check(typeof c.chainId==='string'&&/^[1-9][0-9]{0,77}$/.test(c.chainId)&&BigInt(c.chainId)<2n**256n);
  for(const k of ['escrow','requester'])check(getAddress(c[k])===c[k]&&c[k]!==ZeroAddress);
  for(const k of ['genesisHash','orderId','termsDigest'])digest(c[k]);for(const k of ['packageSHA256','policySHA256'])digest(c[k],false);
  check(Array.isArray(archives)&&archives.length>0&&archives.length<=4096);
  const entries=structuredClone(archives).sort((a,b)=>a.approvalDigest<b.approvalDigest?-1:a.approvalDigest>b.approvalDigest?1:0);
  let total=0;const approvals=new Set(),ciphertexts=new Set();
  for(const entry of entries) {
    exact(entry,['approvalDigest','ciphertextSHA256','ciphertextBytes']);digest(entry.approvalDigest);digest(entry.ciphertextSHA256,false);
    check(Number.isSafeInteger(entry.ciphertextBytes)&&entry.ciphertextBytes>0);total+=entry.ciphertextBytes;check(Number.isSafeInteger(total));
    check(!approvals.has(entry.approvalDigest)&&!ciphertexts.has(entry.ciphertextSHA256));approvals.add(entry.approvalDigest);ciphertexts.add(entry.ciphertextSHA256);
  }
  const value={schema:'cannabis.encrypted-result-set.v1',context:c,entries};check(toUtf8Bytes(canonical(value)).length<=1048576);
  return {...value,outputDigest:sha256(toUtf8Bytes(canonical(value)))};
}
export function inspectResultCommitment(input) {
  exact(input,['schema','context','entries','outputDigest']);check(input.schema==='cannabis.encrypted-result-set.v1');
  const checked=resultCommitment(input.context,input.entries);check(canonical(checked)===canonical(input));return checked;
}
