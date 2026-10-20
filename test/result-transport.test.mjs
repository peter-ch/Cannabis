import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Transform } from 'node:stream';
import { createHash, randomBytes } from 'node:crypto';
import { Wallet, TypedDataEncoder } from 'ethers';
import { Encrypter, generateIdentity, identityToRecipient } from 'age-encryption';
import { deliveryApprovalTypes } from '../compute/key_delivery.mjs';
import { resultKeyCommitment } from '../compute/result_keys.mjs';
import { sealResultDelivery } from '../compute/result_delivery.mjs';
import { ResultInbox } from '../compute/result_inbox.mjs';
import { GuestWire, sendEncryptedResult, receiveEncryptedResult, resultStoredPayload, serveGuestSession, receiveGuestEvidence } from '../compute/result_transport.mjs';

const h=n=>'0x'+n.toString(16).padStart(64,'0');
const sha=value=>createHash('sha256').update(value).digest('hex');
async function fixture(t,version='2') {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-wire-'));
  const wallet=Wallet.createRandom(),identity=await generateIdentity(),recipient=await identityToRecipient(identity),key=randomBytes(32);
  const types=deliveryApprovalTypes(version),domain={name:'Cannabis confidential key delivery',version,chainId:31337,verifyingContract:'0x'+'11'.repeat(20)};
  const value=Object.fromEntries(types.JobKeyDelivery.map(({name,type})=>[name,type==='bytes32'?h(3):type==='string'?recipient:1]));
  Object.assign(value,{rank:0,notBefore:1000,expiresAt:1060,resultKeySHA256:resultKeyCommitment(key)});
  const expected={domain,value,digest:TypedDataEncoder.hash(domain,types,value),requester:wallet.address,jobId:'owned-transport'};
  expected.requesterSignature=await wallet.signTypedData(domain,types,value);
  const record={schema:'cannabis.key-delivery.record.v'+version,keyWrapped:true,approvalDigest:expected.digest,releaseId:value.releaseId,expectedApproval:expected};
  const plain=Buffer.concat([Buffer.from('owned-private-stream-content'),randomBytes(2*1024*1024)]),encrypter=new Encrypter();encrypter.addRecipient(recipient);
  const cipher=Buffer.from(await encrypter.encrypt(plain)),file=path.join(directory,'protected-output.age');fs.writeFileSync(file,cipher);
  const receipt={schema:'cannabis.result.v1',jobId:expected.jobId,taskId:'private-task',packageSHA256:value.packageSHA256.slice(2),
    attempt:1,rank:0,worldSize:1,recipient,ciphertextSHA256:sha(cipher),ciphertextBytes:cipher.length,files:[{name:'private-file'}]};
  const result={ciphertext:file,resultEnvelope:await sealResultDelivery(receipt,key,expected)};
  const inbox=new ResultInbox(path.join(directory,'inbox.sqlite'),{chainId:31337,escrow:domain.verifyingContract,requester:wallet.address});
  inbox.activate(record,{resultRecipient:recipient});
  const streams=[],wires=[];
  function pair(timeoutMs=5000) {
    const captured=[];
    const channel=()=>new Transform({highWaterMark:65536,transform(data,encoding,done){captured.push(Buffer.from(data));done(null,data);}});
    const forward=channel(),backward=channel();
    const guest=new GuestWire(backward,forward,{timeoutMs}),requester=new GuestWire(forward,backward,{timeoutMs});
    streams.push(forward,backward);wires.push(guest,requester);return {guest,requester,captured,forward,backward};
  }
  const options={inbox,approvalDigest:expected.digest,loadResultKey:async()=>Buffer.from(key),
    destination:path.join(directory,'received.age'),maxCiphertextBytes:4*1024*1024,
    signStored:payload=>wallet.signTypedData(payload.domain,payload.types,payload.value)};
  t.after(()=>{for(const stream of streams)stream.destroy();for(const wire of wires)wire.close();inbox.close();key.fill(0);
    assert.equal(path.dirname(path.resolve(directory)),path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('cannabis-wire-'));fs.rmSync(directory,{recursive:true,force:true});});
  return {directory,wallet,identity,key,expected,record,result,receipt,cipher,plain,inbox,pair,options};
}

for(const version of ['2','3'])test(`v${version} encrypted handoff stores ciphertext and authenticates a distinct nonpayment acknowledgement`,async t=>{
  const f=await fixture(t,version),p=f.pair();
  const [sent,received]=await Promise.all([
    sendEncryptedResult(p.guest,f.result,f.expected,{maxCiphertextBytes:f.options.maxCiphertextBytes}),
    receiveEncryptedResult(p.requester,f.options)]);
  assert.equal(sent.requesterAcknowledgedStorage,true);assert.equal(received.ciphertextStored,true);
  assert.equal(sent.paymentAuthorized,false);assert.equal(received.outputVerified,false);
  assert.deepEqual(fs.readFileSync(f.options.destination),f.cipher);
  const observed=Buffer.concat(p.captured);
  for(const secret of ['owned-private-stream-content','private-task','private-file',f.identity,f.key.toString('base64url'),f.result.ciphertext])
    assert.equal(observed.includes(Buffer.from(secret)),false);
  assert.equal(observed.includes(f.key),false);
  assert.equal((await f.inbox.recover(f.expected.digest,f.options.loadResultKey)).receipt.ciphertextSHA256,sha(f.cipher));
});

test('modified ciphertext fails its authenticated receipt and never becomes a published local artifact',async t=>{
  const f=await fixture(t),p=f.pair();const changed=Buffer.from(f.cipher);changed[changed.length-1]^=1;fs.writeFileSync(f.result.ciphertext,changed);
  const results=await Promise.allSettled([
    sendEncryptedResult(p.guest,f.result,f.expected,{maxCiphertextBytes:f.options.maxCiphertextBytes}),receiveEncryptedResult(p.requester,f.options)]);
  assert.equal(results.every(r=>r.status==='rejected'),true);assert.equal(fs.existsSync(f.options.destination),false);
  assert.equal(fs.readdirSync(f.directory).some(n=>n.startsWith('.cannabis-receive-')),false);
});

test('wrong acknowledgement signer or changed commitment cannot claim requester storage',async t=>{
  const f=await fixture(t);
  for(const variant of ['signer','attempt','ciphertext']) {
    const p=f.pair();const options={...f.options,destination:path.join(f.directory,variant+'.age'),signStored:async payload=>{
      const value=structuredClone(payload.value);if(variant==='attempt')value.approvalDigest=h(99);if(variant==='ciphertext')value.ciphertextSHA256=h(99);
      return (variant==='signer'?Wallet.createRandom():f.wallet).signTypedData(payload.domain,payload.types,value);
    }};
    const results=await Promise.allSettled([sendEncryptedResult(p.guest,f.result,f.expected,{maxCiphertextBytes:4*1024*1024}),receiveEncryptedResult(p.requester,options)]);
    assert.equal(results.every(r=>r.status==='rejected'),true);
    // Authenticated ciphertext is retained for an interrupted acknowledgement.
    assert.deepEqual(fs.readFileSync(options.destination),f.cipher);
  }
});

test('retirement during owner acknowledgement refuses a stale delivery while preserving recovered ciphertext',async t=>{
  const f=await fixture(t),p=f.pair();
  const options={...f.options,signStored:async payload=>{f.inbox.retire(f.expected.digest);return f.options.signStored(payload);}};
  const results=await Promise.allSettled([sendEncryptedResult(p.guest,f.result,f.expected,{maxCiphertextBytes:4*1024*1024}),receiveEncryptedResult(p.requester,options)]);
  assert.equal(results.every(r=>r.status==='rejected'),true);assert.deepEqual(fs.readFileSync(options.destination),f.cipher);
});

test('short, oversized and wrong-kind frames fail under a retained timeout',async t=>{
  const f=await fixture(t);
  for(const header of [Buffer.from([0,0,0,0,0]),Buffer.from([0,0xff,0xff,0xff,0xff]),Buffer.from([1,0,0,0,1,0])]) {
    const p=f.pair(150),read=p.requester.readJSON();p.forward.write(header);
    await assert.rejects(read);p.guest.close();p.requester.close();
  }
  const p=f.pair(50);p.forward.write(Buffer.from([0,0,0,0,10,123]));await assert.rejects(p.requester.readJSON());
});

test('existing destination is not overwritten and missing acknowledgement ends the sender',async t=>{
  const f=await fixture(t),p=f.pair(250);fs.writeFileSync(f.options.destination,'retained-owner-file');
  const results=await Promise.allSettled([sendEncryptedResult(p.guest,f.result,f.expected,{maxCiphertextBytes:4*1024*1024}),receiveEncryptedResult(p.requester,f.options)]);
  assert.equal(results.every(r=>r.status==='rejected'),true);assert.equal(fs.readFileSync(f.options.destination,'utf8'),'retained-owner-file');
  const isolated=f.pair(100);
  const sending=sendEncryptedResult(isolated.guest,f.result,f.expected,{maxCiphertextBytes:4*1024*1024});
  const refused=assert.rejects(sending);const header=await isolated.requester.readJSON();let total=0;
  while(total<header.ciphertextBytes)total+=(await isolated.requester.readChunk()).length;
  await isolated.requester.readJSON();await refused;
});

test('storage acknowledgement domain binds chain and escrow independently of payment approvals',async t=>{
  const f=await fixture(t),commitments={envelopeSHA256:sha(f.result.resultEnvelope),ciphertextSHA256:sha(f.cipher),ciphertextBytes:f.cipher.length};
  const base=resultStoredPayload(f.expected,commitments);
  for(const change of [{chainId:1},{verifyingContract:'0x'+'22'.repeat(20)}])
    assert.notEqual(resultStoredPayload({...f.expected,domain:{...f.expected.domain,...change}},commitments).digest,base.digest);
  assert.equal(base.domain.name,'Cannabis encrypted result stored');
});

test('guest independently rejects a forged storage acknowledgement sent by a relay',async t=>{
  const f=await fixture(t),p=f.pair();
  const sending=sendEncryptedResult(p.guest,f.result,f.expected,{maxCiphertextBytes:4*1024*1024});
  const rejected=assert.rejects(sending);const header=await p.requester.readJSON();let total=0;
  while(total<header.ciphertextBytes)total+=(await p.requester.readChunk()).length;
  const end=await p.requester.readJSON();
  const payload=resultStoredPayload(f.expected,{envelopeSHA256:sha(header.resultEnvelope),ciphertextSHA256:end.ciphertextSHA256,ciphertextBytes:total});
  const signature=await Wallet.createRandom().signTypedData(payload.domain,payload.types,payload.value);
  await p.requester.writeJSON({protocol:'cannabis.guest-wire.v1',operation:'stored',signature});await rejected;
});

test('retiring an attempt during streaming prevents ciphertext publication and owner signing',async t=>{
  const f=await fixture(t),p=f.pair(),write=p.guest.writeChunk.bind(p.guest);let retired=false;
  p.guest.writeChunk=async bytes=>{if(!retired){retired=true;f.inbox.retire(f.expected.digest);}return write(bytes);};
  const results=await Promise.allSettled([sendEncryptedResult(p.guest,f.result,f.expected,{maxCiphertextBytes:4*1024*1024}),
    receiveEncryptedResult(p.requester,{...f.options,signStored:()=>assert.fail('Stale result must not request a signature')})]);
  assert.equal(results.every(r=>r.status==='rejected'),true);assert.equal(fs.existsSync(f.options.destination),false);
  assert.equal(fs.readdirSync(f.directory).some(n=>n.startsWith('.cannabis-receive-')),false);
});

test('transport expiry cancels an executing session before a result or acknowledgement can escape',async t=>{
  const f=await fixture(t),p=f.pair(250);let stop,closed=0,started=false;
  // A lifecycle probe, not an attested execution fixture. The kernel integration
  // separately uses the actual GuestEvidenceSession and its native supervisor.
  const session={evidence:async()=>({ownedLifecycleProbe:true}),executeNative:async()=>{
    started=true;return new Promise((resolve,reject)=>stop=()=>reject(Error('stopped')));},
    close:()=>{closed++;stop?.();},serviceInterval:{end:Math.floor(Date.now()/1000)+10}};
  const serving=serveGuestSession(session,p.guest,{maxCiphertextBytes:4*1024*1024}),failed=assert.rejects(serving);
  await receiveGuestEvidence(p.requester);
  await p.requester.writeJSON({protocol:'cannabis.guest-wire.v1',operation:'execute',envelope:'owned-probe',expected:{}});
  await failed;assert.equal(started,true);assert.ok(closed>=1);
});

test('elapsed monotonic deadline rejects a frame even before a delayed timer callback runs',async t=>{
  const f=await fixture(t),p=f.pair(20);
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,60);
  await assert.rejects(p.guest.writeJSON({mustNotBeSent:true}));
  assert.equal(p.captured.length,0);assert.equal(p.guest.signal.aborted,true);
});
