// Browser verification of requester-exported recovery records. No RPC, signing,
// remote keys, server-supplied approvals, customer execution or payment.
import { TypedDataEncoder, getAddress, verifyTypedData, ZeroAddress, getBytes } from 'ethers';
import { compactDecrypt, base64url } from 'jose';
import { Decrypter, identityToRecipient } from 'age-encryption';
import { openResults, sha256, MAX_RESULT_BYTES } from './work-results.js';

export const MAX_RECOVERY_BYTES=8*1024*1024;
// Kept interoperable with the measured guest protocol by an exact schema test.
export const approvalTypes={JobKeyDelivery:[
  ['releaseId','bytes32'],['leaseDigest','bytes32'],['orderId','bytes32'],['reservationId','bytes32'],
  ['packageSHA256','bytes32'],['policySHA256','bytes32'],['attestationPolicySHA256','bytes32'],
  ['runtimeSHA256','bytes32'],['taskSHA256','bytes32'],['capsuleSHA256','bytes32'],
  ['inputRecipient','string'],['channelKeySHA256','bytes32'],['nonce','bytes32'],
  ['attempt','uint32'],['rank','uint32'],['worldSize','uint32'],['notBefore','uint64'],['expiresAt','uint64'],
  ['resultKeySHA256','bytes32']
].map(([name,type])=>({name,type}))};
const enc=new TextEncoder(),utf8=new TextDecoder('utf-8',{fatal:true});
const requireValue=(test,message='Recovery does not match the requester-approved execution')=>{if(!test)throw Error(message);};
const fields=(v,names)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===names.slice().sort().join();
const b32=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const recipient=v=>typeof v==='string'&&/^age1[0-9a-z]{58}$/.test(v);
const boundedJSON=(v,max)=>enc.encode(JSON.stringify(v)).length<=max;
function decode(value,max) {
  requireValue(typeof value==='string'&&value.length>0&&value.length<=max&&/^[A-Za-z0-9_-]+$/.test(value));
  const bytes=base64url.decode(value);requireValue(base64url.encode(bytes)===value);return bytes;
}
export function resultIdentity(text) {
  const values=text.split(/\r?\n/).map(s=>s.trim()).filter(s=>s&&!s.startsWith('#'));
  requireValue(values.length===1&&/^AGE-SECRET-KEY-1[0-9A-Z]+$/.test(values[0]),'Use one requester result identity, never a wallet seed');
  return values[0];
}
export async function validateRecoveryBundle(input) {
  const bundle=structuredClone(input),c=bundle?.context;
  requireValue(fields(bundle,['schema','context','entries'])&&bundle.schema==='cannabis.browser-recovery.v1'&&boundedJSON(bundle,MAX_RECOVERY_BYTES));
  requireValue(fields(c,['chainId','escrow','requester'])&&integer(c.chainId,1,Number.MAX_SAFE_INTEGER));
  c.escrow=getAddress(c.escrow);c.requester=getAddress(c.requester);
  requireValue(c.escrow!==ZeroAddress&&c.requester!==ZeroAddress&&Array.isArray(bundle.entries)&&bundle.entries.length>0&&bundle.entries.length<=128);
  const seen=new Set();let jobId,packageHash;
  const slots=[];
  for(const entry of bundle.entries) {
    requireValue(fields(entry,['approval','recipient','custody','envelope']));
    const p=entry.approval,d=p?.domain,v=p?.value;
    requireValue(fields(p,['domain','value','digest','requester','jobId','requesterSignature'])&&
      fields(d,['name','version','chainId','verifyingContract'])&&d.name==='Cannabis confidential key delivery'&&d.version==='2'&&
      Number(d.chainId)===c.chainId&&getAddress(d.verifyingContract)===c.escrow&&getAddress(p.requester)===c.requester&&
      fields(v,approvalTypes.JobKeyDelivery.map(f=>f.name))&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(p.jobId)&&boundedJSON(p,16384));
    for(const {name,type} of approvalTypes.JobKeyDelivery)if(type==='bytes32')requireValue(b32(v[name]));
    requireValue(recipient(v.inputRecipient)&&recipient(entry.recipient)&&integer(v.attempt,1,1000000)&&integer(v.worldSize,1,100000)&&
      integer(v.rank,0,v.worldSize-1)&&integer(v.notBefore,1,Number.MAX_SAFE_INTEGER)&&integer(v.expiresAt,v.notBefore+1,Number.MAX_SAFE_INTEGER));
    requireValue(TypedDataEncoder.hash(d,approvalTypes,v)===p.digest&&verifyTypedData(d,approvalTypes,v,p.requesterSignature)===c.requester);
    requireValue((jobId??p.jobId)===p.jobId&&(packageHash??v.packageSHA256)===v.packageSHA256,'Select a recovery export for one job and package');
    jobId=p.jobId;packageHash=v.packageSHA256;
    const slot=await sha256(enc.encode(JSON.stringify([v.orderId,v.packageSHA256,v.taskSHA256,v.rank])));
    requireValue(!seen.has(slot),'Recovery contains duplicate task attempts');seen.add(slot);slots.push(slot);
    const k=entry.custody;
    requireValue(fields(k,['schema','releaseId','recipient','resultKeySHA256','ciphertext','ciphertextSHA256'])&&
      k.schema==='cannabis.result-key.custody.v1'&&k.releaseId===v.releaseId&&k.recipient===entry.recipient&&k.resultKeySHA256===v.resultKeySHA256);
    const bytes=decode(k.ciphertext,16384);requireValue(await sha256(bytes)===k.ciphertextSHA256);
    requireValue(typeof entry.envelope==='string'&&entry.envelope.length<=6*1024*1024&&
      /^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(entry.envelope));
  }
  const id=await sha256(enc.encode(JSON.stringify([c.chainId,c.escrow,c.requester,jobId,packageHash])));
  return {id,bundle,slots,jobId,packageSHA256:packageHash.slice(2)};
}
async function openReceipt(entry,identity) {
  const p=entry.approval,v=p.value,k=entry.custody;
  const decrypter=new Decrypter();decrypter.addIdentity(identity);
  let clear,key,receiptBytes;
  try {
    clear=await decrypter.decrypt(decode(k.ciphertext,16384));requireValue(clear.length<=4096);
    const value=JSON.parse(utf8.decode(clear));
    requireValue(fields(value,['schema','releaseId','recipient','resultKeySHA256','key'])&&value.schema==='cannabis.result-key.v1'&&
      value.releaseId===v.releaseId&&value.recipient===entry.recipient&&value.resultKeySHA256===v.resultKeySHA256);
    key=decode(value.key,43);requireValue(key.length===32&&'0x'+await sha256(key)===v.resultKeySHA256);
    const opened=await compactDecrypt(entry.envelope,key,{keyManagementAlgorithms:['dir'],contentEncryptionAlgorithms:['A256GCM']});
    receiptBytes=opened.plaintext;const h=opened.protectedHeader;
    requireValue(fields(h,['alg','enc','typ','kid'])&&h.typ==='cannabis-result+jwe'&&h.kid===p.digest&&receiptBytes.length<=4*1024*1024);
    const record=JSON.parse(utf8.decode(receiptBytes));
    requireValue(fields(record,['schema','approvalDigest','requester','jobId','receipt'])&&record.schema==='cannabis.result-delivery.v1'&&
      record.approvalDigest===p.digest&&record.requester===p.requester&&record.jobId===p.jobId);
    const r=record.receipt;
    requireValue(r?.schema==='cannabis.result.v1'&&r.jobId===p.jobId&&r.packageSHA256===v.packageSHA256.slice(2)&&
      r.attempt===v.attempt&&r.rank===v.rank&&r.worldSize===v.worldSize&&r.recipient===entry.recipient&&
      typeof r.taskId==='string'&&r.taskId.length>0&&/^[0-9a-f]{64}$/.test(r.ciphertextSHA256)&&integer(r.ciphertextBytes,1,MAX_RESULT_BYTES));
    return r;
  } catch {throw Error('Encrypted receipt or result-key recovery does not match the selected approval');}
  finally {clear?.fill(0);key?.fill(0);receiptBytes?.fill(0);}
}
export async function openApprovedResults({bundle,spec,packageSHA256,identity,encrypted}) {
  const checked=await validateRecoveryBundle(bundle);identity=resultIdentity(identity);
  requireValue(checked.jobId===spec?.id&&checked.packageSHA256===packageSHA256&&Array.isArray(spec?.tasks)&&spec.tasks.length>0&&spec.tasks.length<=4096);
  const ownerRecipient=await identityToRecipient(identity);
  requireValue(spec.resultRecipient===ownerRecipient&&bundle.entries.every(e=>e.recipient===ownerRecipient),'Result identity differs from the original workload or recovery export');
  requireValue(Array.isArray(encrypted)&&encrypted.length===bundle.entries.length&&encrypted.every(b=>b instanceof Uint8Array)&&
    encrypted.reduce((n,b)=>n+b.length,0)<=MAX_RESULT_BYTES,'Select one encrypted archive per approved receipt, within 64 MiB');
  const files=new Map();
  for(const bytes of encrypted){const digest=await sha256(bytes);requireValue(!files.has(digest),'Duplicate encrypted result');files.set(digest,bytes);}
  const results=[];
  for(const entry of bundle.entries) {
    const receipt=await openReceipt(entry,identity),v=entry.approval.value;
    const index=spec.tasks.findIndex(t=>t.id===receipt.taskId),task=spec.tasks[index];
    requireValue(index>=0&&v.policySHA256==='0x'+spec.policySHA256&&v.runtimeSHA256==='0x'+task.runtime?.digestSHA256);
    const prefix=enc.encode('cannabis.task.v1\0'),binding=new Uint8Array(prefix.length+32+4);
    binding.set(prefix);binding.set(getBytes(v.packageSHA256),prefix.length);new DataView(binding.buffer).setUint32(prefix.length+32,index);
    requireValue(v.taskSHA256==='0x'+await sha256(binding),'Receipt differs from the original approved task');
    const bytes=files.get(receipt.ciphertextSHA256);requireValue(bytes,'Missing encrypted result for an authenticated receipt');files.delete(receipt.ciphertextSHA256);
    results.push({receipt,bytes});
  }
  requireValue(files.size===0);
  return openResults({spec,packageSHA256,identity,results});
}
