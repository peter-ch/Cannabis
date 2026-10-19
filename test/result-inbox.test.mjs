import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { Wallet, TypedDataEncoder } from 'ethers';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { deliveryTypesV2 } from '../compute/key_delivery.mjs';
import { resultKeyCommitment } from '../compute/result_keys.mjs';
import { sealResultDelivery } from '../compute/result_delivery.mjs';
import { ResultInbox } from '../compute/result_inbox.mjs';

const h=n=>'0x'+n.toString(16).padStart(64,'0');
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
async function fixture(t,limits) {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-inbox-'));
  const file=path.join(directory,'inbox.sqlite'),wallet=Wallet.createRandom();
  const recipient=await identityToRecipient(await generateIdentity());
  const context={chainId:31337,escrow:'0x'+'11'.repeat(20),requester:wallet.address};
  const domain={name:'Cannabis confidential key delivery',version:'2',chainId:context.chainId,verifyingContract:context.escrow};
  const opened=new Set(),keys=[];
  const connect=()=>{const db=new ResultInbox(file,context,limits);opened.add(db);return db;};
  const close=db=>{db.close();opened.delete(db);};
  t.after(()=>{for(const db of opened)db.close();for(const key of keys)key.fill(0);
    assert.equal(path.dirname(path.resolve(directory)),path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('cannabis-inbox-'));fs.rmSync(directory,{recursive:true,force:true});});
  async function record(attempt=1,changes={}) {
    const key=randomBytes(32);keys.push(key);
    const value=Object.fromEntries(deliveryTypesV2.JobKeyDelivery.map(({name,type})=>[name,type==='bytes32'?h(3):type==='string'?recipient:1]));
    Object.assign(value,{releaseId:h(attempt+10),nonce:h(attempt+20),attempt,rank:0,worldSize:1,
      resultKeySHA256:resultKeyCommitment(key),notBefore:1000,expiresAt:1060},changes);
    const digest=TypedDataEncoder.hash(domain,deliveryTypesV2,value);
    const expectedApproval={domain,value,digest,requester:wallet.address,jobId:'owned-inbox-job',
      requesterSignature:await wallet.signTypedData(domain,deliveryTypesV2,value)};
    const journal={schema:'cannabis.key-delivery.record.v2',keyWrapped:true,releaseId:value.releaseId,approvalDigest:digest,expectedApproval};
    const receipt={schema:'cannabis.result.v1',jobId:expectedApproval.jobId,taskId:'private-task-name',packageSHA256:value.packageSHA256.slice(2),
      attempt,rank:value.rank,worldSize:value.worldSize,recipient,ciphertextSHA256:'ab'.repeat(32),ciphertextBytes:500,
      files:[{name:'private-result.txt',sha256:'cd'.repeat(32),bytes:20}]};
    const load=async binding=>{assert.deepEqual(binding,{releaseId:value.releaseId,recipient,resultKeySHA256:value.resultKeySHA256});return Buffer.from(key);};
    const envelope=await sealResultDelivery(receipt,key,expectedApproval);
    return {key,digest,journal,receipt,load,envelope,expectedApproval};
  }
  return {directory,file,wallet,context,recipient,connect,close,record};
}

test('requester inbox survives restart, keeps only encrypted receipts and treats repeat delivery as recovery',async t=>{
  const f=await fixture(t),r=await f.record();let db=f.connect();
  assert.equal(db.activate(r.journal,{resultRecipient:f.recipient}).newSelection,true);
  const reordered=structuredClone(r.journal);
  reordered.expectedApproval.value=Object.fromEntries(Object.entries(reordered.expectedApproval.value).reverse());
  assert.equal(db.activate(reordered,{resultRecipient:f.recipient}).newSelection,false);
  let returnedKey;
  const first=await db.receive(r.digest,r.envelope,async b=>(returnedKey=await r.load(b)));
  assert.equal(returnedKey.every(b=>b===0),true);assert.deepEqual(first.receipt,r.receipt);
  assert.equal(first.newDelivery,true);assert.equal(first.outputVerified,false);assert.equal(first.paymentAuthorized,false);
  assert.equal(JSON.stringify(first).includes('private-task-name'),false);
  f.close(db);db=f.connect();
  assert.equal(db.inspect(r.digest).receiptStored,true);
  const recovered=await db.recover(r.digest,r.load);assert.deepEqual(recovered.receipt,r.receipt);assert.equal(recovered.newDelivery,false);
  assert.equal((await db.receive(r.digest,r.envelope,r.load)).newDelivery,false);
  const different=await sealResultDelivery({...r.receipt,ciphertextSHA256:'ef'.repeat(32)},r.key,r.expectedApproval);
  await assert.rejects(db.receive(r.digest,different,()=>assert.fail('Conflicting receipt must fail before custody')),/Conflicting/);
  for(const filename of fs.readdirSync(f.directory)) {
    const raw=fs.readFileSync(path.join(f.directory,filename));
    for(const forbidden of ['private-task-name','private-result.txt',r.key.toString('base64url'),f.wallet.privateKey])
      assert.equal(raw.includes(Buffer.from(forbidden)),false);
    assert.equal(raw.includes(r.key),false);
  }
});

test('inbox rejects foreign context, modified approvals and unsigned attempt selection',async t=>{
  const f=await fixture(t),db=f.connect(),r=await f.record();
  for(const mutate of [j=>j.expectedApproval.value.attempt++,j=>j.expectedApproval.domain.chainId=1,
    j=>j.expectedApproval.requester=Wallet.createRandom().address,j=>j.expectedApproval.requesterSignature='0x'+'11'.repeat(65),
    j=>j.approvalDigest=h(99),j=>j.releaseId=h(99),j=>j.keyWrapped=false,j=>j.schema='cannabis.key-delivery.record.v1']) {
    const changed=structuredClone(r.journal);mutate(changed);
    assert.throws(()=>db.activate(changed,{resultRecipient:f.recipient}));
  }
  assert.throws(()=>db.inspect(r.digest),/Unknown/);
  db.activate(r.journal,{resultRecipient:f.recipient});
  assert.throws(()=>new ResultInbox(f.file,{...f.context,chainId:1}),/cannot change/);
  assert.throws(()=>new ResultInbox(':memory:',{...f.context,escrow:'0x'+'00'.repeat(20)}),/address/);
});

test('replacement is explicit, monotonic and workload-bound; retired and superseded receipts never open custody',async t=>{
  const f=await fixture(t),db=f.connect(),first=await f.record(),next=await f.record(2);
  db.activate(first.journal,{resultRecipient:f.recipient});
  assert.throws(()=>db.activate(next.journal,{resultRecipient:f.recipient}),/changed/);
  for(const changes of [{runtimeSHA256:h(55)},{policySHA256:h(55)},{worldSize:2},{inputRecipient:await identityToRecipient(await generateIdentity())}]) {
    const changed=await f.record(2,changes);
    assert.throws(()=>db.activate(changed.journal,{resultRecipient:f.recipient,previousApprovalDigest:first.digest}),/workload/);
  }
  const same=await f.record(1);
  assert.throws(()=>db.activate(same.journal,{resultRecipient:f.recipient,previousApprovalDigest:first.digest}),/increase/);
  db.activate(next.journal,{resultRecipient:f.recipient,previousApprovalDigest:first.digest});
  assert.equal(db.inspect(first.digest).active,false);
  await assert.rejects(db.receive(first.digest,first.envelope,()=>assert.fail('Superseded key must not open')),/superseded/);
  assert.throws(()=>db.activate(first.journal,{resultRecipient:f.recipient,previousApprovalDigest:next.digest}),/increase/);
  db.retire(next.digest);
  await assert.rejects(db.receive(next.digest,next.envelope,()=>assert.fail('Retired key must not open')),/retired/);
  assert.throws(()=>db.activate(next.journal,{resultRecipient:f.recipient}),/reactivate/);
  const third=await f.record(3);db.activate(third.journal,{resultRecipient:f.recipient,previousApprovalDigest:next.digest});
  assert.equal((await db.receive(third.digest,third.envelope,third.load)).newDelivery,true);
});

test('concurrent identical receipts create one delivery; conflicting receipts cannot overwrite it',async t=>{
  const f=await fixture(t),a=f.connect(),b=f.connect(),first=await f.record();
  a.activate(first.journal,{resultRecipient:f.recipient});
  async function pair(r,envelopes) {
    const gate=deferred(),entered=deferred();let n=0;
    const load=async expected=>{if(++n===2)entered.resolve();await gate.promise;return r.load(expected);};
    const work=[a.receive(r.digest,envelopes[0],load),b.receive(r.digest,envelopes[1],load)];
    await entered.promise;gate.resolve();return Promise.allSettled(work);
  }
  const repeated=await pair(first,[first.envelope,first.envelope]);
  assert.equal(repeated.every(r=>r.status==='fulfilled'),true);
  assert.deepEqual(repeated.map(r=>r.value.newDelivery).sort(),[false,true]);
  const next=await f.record(2);a.activate(next.journal,{resultRecipient:f.recipient,previousApprovalDigest:first.digest});
  const different=await sealResultDelivery({...next.receipt,ciphertextSHA256:'ef'.repeat(32)},next.key,next.expectedApproval);
  const raced=await pair(next,[next.envelope,different]);
  assert.equal(raced.filter(r=>r.status==='fulfilled').length,1);
  assert.match(raced.find(r=>r.status==='rejected').reason.message,/Conflicting/);
  const saved=await a.recover(next.digest,next.load);
  assert.deepEqual(saved.receipt,raced.find(r=>r.status==='fulfilled').value.receipt);
});

test('replacement or retirement while a local key opens prevents stale receive and recovery',async t=>{
  const f=await fixture(t),a=f.connect(),b=f.connect(),first=await f.record(),next=await f.record(2);
  a.activate(first.journal,{resultRecipient:f.recipient});
  const entered=deferred(),release=deferred();let key;
  const pending=a.receive(first.digest,first.envelope,async expected=>{entered.resolve();await release.promise;return key=await first.load(expected);});
  const rejected=assert.rejects(pending,/superseded/);
  await entered.promise;b.activate(next.journal,{resultRecipient:f.recipient,previousApprovalDigest:first.digest});
  release.resolve();await rejected;assert.equal(key.every(n=>n===0),true);assert.equal(a.inspect(first.digest).receiptStored,false);
  await a.receive(next.digest,next.envelope,next.load);
  const opening=deferred(),finish=deferred();
  const recovering=a.recover(next.digest,async expected=>{opening.resolve();await finish.promise;return next.load(expected);});
  const retired=assert.rejects(recovering,/retired/);await opening.promise;b.retire(next.digest);finish.resolve();await retired;
});

test('tampered return traffic, wrong recipient and corrupt saved ciphertext fail without recording success',async t=>{
  const f=await fixture(t),db=f.connect(),r=await f.record();db.activate(r.journal,{resultRecipient:f.recipient});
  const parts=r.envelope.split('.');parts[3]=(parts[3][0]==='A'?'B':'A')+parts[3].slice(1);
  await assert.rejects(db.receive(r.digest,parts.join('.'),r.load));
  await assert.rejects(db.receive(r.digest,'x'.repeat(6*1024*1024+1),()=>assert.fail('Oversize should not open')));
  const wrong=await sealResultDelivery({...r.receipt,recipient:await identityToRecipient(await generateIdentity())},r.key,r.expectedApproval);
  await assert.rejects(db.receive(r.digest,wrong,r.load),/recipient/);
  assert.equal(db.inspect(r.digest).receiptStored,false);
  await db.receive(r.digest,r.envelope,r.load);
  const raw=new DatabaseSync(f.file);try{raw.prepare('UPDATE result_releases SET envelope=? WHERE digest=?').run(parts.join('.'),r.digest);}finally{raw.close();}
  await assert.rejects(db.recover(r.digest,()=>assert.fail('Corrupt storage should not open')),/changed/);
});

test('release count and total encrypted receipt bounds are enforced across restart',async t=>{
  const f=await fixture(t,{maxReleases:1,maxReceiptBytes:1024}),db=f.connect(),r=await f.record();
  db.activate(r.journal,{resultRecipient:f.recipient});assert.ok(r.envelope.length>1024);
  await assert.rejects(db.receive(r.digest,r.envelope,r.load),/capacity/);
  assert.equal(db.inspect(r.digest).receiptStored,false);
  const next=await f.record(2);f.close(db);const reopened=f.connect();
  assert.throws(()=>reopened.activate(next.journal,{resultRecipient:f.recipient,previousApprovalDigest:r.digest}),/capacity/);
  assert.equal(reopened.inspect(r.digest).active,true);
});

test('reconstruction only uses current saved receipts under a synchronous selection lock',async t=>{
  const f=await fixture(t),db=f.connect(),r=await f.record();db.activate(r.journal,{resultRecipient:f.recipient});
  const received=await db.receive(r.digest,r.envelope,r.load),selection={approvalDigest:r.digest,receiptSHA256:received.receiptSHA256};
  const raw=new DatabaseSync(f.file);raw.exec('PRAGMA busy_timeout=1');
  try {
    const report=db.useCurrent([selection],approvals=>{
      assert.equal(approvals[0].digest,r.digest);
      assert.throws(()=>raw.prepare('UPDATE result_slots SET active=0').run(),/locked/);
      return {outputVerified:true,paymentAuthorized:false};
    });
    assert.equal(report.paymentAuthorized,false);
    assert.throws(()=>db.useCurrent([{...selection,receiptSHA256:'aa'.repeat(32)}],()=>assert.fail('Stale snapshot')),/changed/);
    let asyncRan=false;
    assert.throws(()=>db.useCurrent([selection],async()=>{asyncRan=true;}),/selection/);assert.equal(asyncRan,false);
    assert.throws(()=>db.useCurrent([selection],()=>({then(){}})),/synchronous/);
    const next=await f.record(2);db.activate(next.journal,{resultRecipient:f.recipient,previousApprovalDigest:r.digest});
    assert.throws(()=>db.useCurrent([selection],()=>assert.fail('Replaced snapshot')),/superseded/);
  }finally{raw.close();}
});
