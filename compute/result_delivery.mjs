// Authenticated private result receipts. This does not accept work or send payment.
import { CompactEncrypt, compactDecrypt } from 'jose';
import { TypedDataEncoder, getAddress } from 'ethers';
import { deliveryApprovalTypes } from './key_delivery.mjs';
import { resultKeyCommitment } from './result_keys.mjs';

const maxPlaintext=4*1024*1024,maxEnvelope=6*1024*1024;
const fail=()=>Error('Result does not match the approved confidential session');
const fields=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.sort().join();
function approval(expected,key) {
  const types=deliveryApprovalTypes(expected?.domain?.version);
  if(expected?.domain?.name!=='Cannabis confidential key delivery'||!['2','3'].includes(expected.domain.version)||
    !fields(expected.value,types.JobKeyDelivery.map(x=>x.name))||
    resultKeyCommitment(key)!==expected.value.resultKeySHA256||
    TypedDataEncoder.hash(expected.domain,types,expected.value)!==expected.digest||
    getAddress(expected.requester)!==expected.requester||typeof expected.jobId!=='string')throw fail();
  return {approvalDigest:expected.digest,requester:expected.requester,jobId:expected.jobId};
}
function receiptBinding(receipt,expected) {
  const v=expected.value;
  if(!receipt||receipt.schema!=='cannabis.result.v1'||receipt.jobId!==expected.jobId||
    receipt.packageSHA256!==v.packageSHA256.slice(2)||receipt.attempt!==v.attempt||receipt.rank!==v.rank||receipt.worldSize!==v.worldSize||
    typeof receipt.taskId!=='string'||!receipt.taskId||typeof receipt.recipient!=='string'||!/^age1[0-9a-z]{58}$/.test(receipt.recipient)||
    !/^[0-9a-f]{64}$/.test(receipt.ciphertextSHA256)||!Number.isSafeInteger(receipt.ciphertextBytes)||receipt.ciphertextBytes<1)throw fail();
}
export async function sealResultDelivery(receipt,key,expected) {
  receipt=structuredClone(receipt);expected=structuredClone(expected);
  const binding=approval(expected,key);receiptBinding(receipt,expected);
  const retainedKey=Buffer.from(key);
  const bytes=Buffer.from(JSON.stringify({schema:'cannabis.result-delivery.v1',...binding,receipt}));
  try {
    if(bytes.length>maxPlaintext)throw fail();
    return await new CompactEncrypt(bytes).setProtectedHeader({alg:'dir',enc:'A256GCM',typ:'cannabis-result+jwe',kid:binding.approvalDigest}).encrypt(retainedKey);
  } finally {bytes.fill(0);retainedKey.fill(0);}
}
// Repeat decryption is deliberately permitted for recovery. A result receipt is
// neither a fresh execution nor a payment approval; the requester separately
// validates the complete result archive, expected attempt and application output.
export async function openResultDelivery(envelope,key,expected) {
  expected=structuredClone(expected);
  const binding=approval(expected,key);
  if(typeof envelope!=='string'||!envelope.length||envelope.length>maxEnvelope)throw fail();
  const retainedKey=Buffer.from(key);
  let plaintext;
  try {
    const opened=await compactDecrypt(envelope,retainedKey,{keyManagementAlgorithms:['dir'],contentEncryptionAlgorithms:['A256GCM']});
    plaintext=opened.plaintext;
    const header=opened.protectedHeader;
    if(!fields(header,['alg','enc','typ','kid'])||header.typ!=='cannabis-result+jwe'||header.kid!==binding.approvalDigest||plaintext.length>maxPlaintext)throw fail();
    const record=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plaintext));
    if(!fields(record,['schema','approvalDigest','requester','jobId','receipt'])||record.schema!=='cannabis.result-delivery.v1'||
      Object.entries(binding).some(([k,v])=>record[k]!==v))throw fail();
    receiptBinding(record.receipt,expected);
    return Object.defineProperty({schema:'cannabis.authenticated-result.v1',approvalDigest:binding.approvalDigest,
      receiptAuthenticated:true,outputVerified:false,qualityAccepted:false,paymentAuthorized:false},'receipt',{value:record.receipt,enumerable:false});
  } catch {throw fail();}
  finally {plaintext?.fill(0);retainedKey.fill(0);}
}
