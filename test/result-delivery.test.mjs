import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { TypedDataEncoder } from 'ethers';
import { createResultKeyCustody, recoverResultKey, resultKeyCommitment } from '../compute/result_keys.mjs';
import { deliveryTypesV2 } from '../compute/key_delivery.mjs';
import { openResultDelivery, sealResultDelivery } from '../compute/result_delivery.mjs';

const h=n=>'0x'+n.toString(16).padStart(64,'0');
async function fixture() {
  const identity=await generateIdentity(),recipient=await identityToRecipient(identity);
  const custody=await createResultKeyCustody({releaseId:h(1),recipient});
  const binding={releaseId:h(1),recipient,resultKeySHA256:custody.resultKeySHA256};
  const key=await recoverResultKey(custody,identity,binding);
  const domain={name:'Cannabis confidential key delivery',version:'2',chainId:31337,verifyingContract:'0x'+'11'.repeat(20)};
  const value=Object.fromEntries(deliveryTypesV2.JobKeyDelivery.map(({name,type})=>[name,type==='bytes32'?h(3):type==='string'?recipient:1]));
  Object.assign(value,{releaseId:h(1),resultKeySHA256:binding.resultKeySHA256,rank:0,notBefore:1000,expiresAt:1060});
  const approval={domain,value,digest:TypedDataEncoder.hash(domain,deliveryTypesV2,value),requester:'0x'+'22'.repeat(20),jobId:'owned-private-result'};
  const receipt={schema:'cannabis.result.v1',jobId:approval.jobId,taskId:'private-task-name',packageSHA256:value.packageSHA256.slice(2),
    attempt:1,rank:0,worldSize:1,recipient,ciphertextSHA256:'ab'.repeat(32),ciphertextBytes:500,
    files:[{name:'private-result.txt',sha256:'cd'.repeat(32),bytes:20}]};
  return {identity,recipient,custody,binding,key,approval,receipt};
}

test('fresh result secrets survive encrypted requester recovery without sharing the job input key',async()=>{
  const f=await fixture();try {
    const recovered=await recoverResultKey(JSON.parse(JSON.stringify(f.custody)),f.identity,f.binding);
    try{assert.deepEqual(recovered,f.key);assert.equal(resultKeyCommitment(recovered),f.binding.resultKeySHA256);}
    finally{recovered.fill(0);}
    const later=await createResultKeyCustody({releaseId:h(2),recipient:f.recipient});
    assert.notEqual(later.resultKeySHA256,f.custody.resultKeySHA256);
    assert.equal(JSON.stringify(f.custody).includes(f.key.toString('base64url')),false);
    assert.equal(JSON.stringify(f.custody).includes('AGE-SECRET-KEY-'),false);
    await assert.rejects(recoverResultKey(f.custody,await generateIdentity(),f.binding));
    for(const change of [{releaseId:h(2)},{resultKeySHA256:h(4)},{recipient:await identityToRecipient(await generateIdentity())}])
      await assert.rejects(recoverResultKey(f.custody,f.identity,{...f.binding,...change}));
    const altered={...f.custody,ciphertext:(f.custody.ciphertext[0]==='A'?'B':'A')+f.custody.ciphertext.slice(1)};
    await assert.rejects(recoverResultKey(altered,f.identity,f.binding));
    await assert.rejects(createResultKeyCustody({releaseId:h(0),recipient:f.recipient}));
  }finally{f.key.fill(0);}
});

test('private receipts are authenticated to the entire approval and repeat decryption grants no payment',async()=>{
  const f=await fixture();try {
    const envelope=await sealResultDelivery(f.receipt,f.key,f.approval);
    assert.equal(envelope.includes('private-task-name'),false);assert.equal(envelope.includes('private-result.txt'),false);
    const first=await openResultDelivery(envelope,f.key,f.approval),again=await openResultDelivery(envelope,f.key,f.approval);
    assert.deepEqual(first.receipt,f.receipt);assert.deepEqual(again.receipt,f.receipt);
    assert.equal(first.receiptAuthenticated,true);assert.equal(first.outputVerified,false);assert.equal(first.paymentAuthorized,false);
    assert.equal(JSON.stringify(first).includes('private-task-name'),false);
    for(const field of ['releaseId','leaseDigest','orderId','reservationId','packageSHA256','policySHA256','attestationPolicySHA256',
      'runtimeSHA256','taskSHA256','capsuleSHA256','channelKeySHA256','nonce']) {
      const changed=structuredClone(f.approval);changed.value[field]=h(999);
      changed.digest=TypedDataEncoder.hash(changed.domain,deliveryTypesV2,changed.value);
      await assert.rejects(openResultDelivery(envelope,f.key,changed));
    }
    for(const change of [{attempt:2},{rank:1,worldSize:2}]) {
      const changed=structuredClone(f.approval);Object.assign(changed.value,change);
      changed.digest=TypedDataEncoder.hash(changed.domain,deliveryTypesV2,changed.value);
      await assert.rejects(openResultDelivery(envelope,f.key,changed));
    }
    for(const change of [{chainId:1},{verifyingContract:'0x'+'33'.repeat(20)}]) {
      const changed=structuredClone(f.approval);Object.assign(changed.domain,change);
      changed.digest=TypedDataEncoder.hash(changed.domain,deliveryTypesV2,changed.value);
      await assert.rejects(openResultDelivery(envelope,f.key,changed));
    }
    await assert.rejects(openResultDelivery(envelope,f.key,{...f.approval,jobId:'other-job'}));
    await assert.rejects(openResultDelivery(envelope,f.key,{...f.approval,requester:'0x'+'33'.repeat(20)}));
  }finally{f.key.fill(0);}
});

test('tampering, old attempt secrets, altered receipt context and oversized return traffic fail',async()=>{
  const f=await fixture();try {
    const envelope=await sealResultDelivery(f.receipt,f.key,f.approval);
    const parts=envelope.split('.');parts[3]=(parts[3][0]==='A'?'B':'A')+parts[3].slice(1);
    await assert.rejects(openResultDelivery(parts.join('.'),f.key,f.approval));
    const oldKey=randomBytes(32);
    try {await assert.rejects(openResultDelivery(envelope,oldKey,f.approval));}
    finally {oldKey.fill(0);}
    for(const change of [{jobId:'other'},{packageSHA256:'ee'.repeat(32)},{attempt:2},{rank:1},{worldSize:2},{ciphertextBytes:0}])
      await assert.rejects(sealResultDelivery({...f.receipt,...change},f.key,f.approval));
    await assert.rejects(sealResultDelivery({...f.receipt,unbounded:'x'.repeat(4*1024*1024)},f.key,f.approval));
    await assert.rejects(openResultDelivery('x'.repeat(6*1024*1024+1),f.key,f.approval));
    await assert.rejects(openResultDelivery(envelope,f.key,{...f.approval,domain:{...f.approval.domain,version:'1'}}));
  }finally{f.key.fill(0);}
});
