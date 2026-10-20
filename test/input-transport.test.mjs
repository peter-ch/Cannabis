import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { Transform } from 'node:stream';
import { Encrypter, generateIdentity, identityToRecipient } from 'age-encryption';
import { GuestWire } from '../compute/result_transport.mjs';
import { sendEncryptedInput, receiveEncryptedInput } from '../compute/input_transport.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const protocol='cannabis.guest-wire.v1';
async function fixture(t) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-input-'));
  const encoder=new Encrypter();encoder.addRecipient(await identityToRecipient(await generateIdentity()));
  const plain=Buffer.concat([Buffer.from('owned private input content'),randomBytes(130000)]);
  const ciphertext=Buffer.from(await encoder.encrypt(plain));
  const source=path.join(root,'source.age'),destination=path.join(root,'workload.age');fs.writeFileSync(source,ciphertext);
  const options={packageSHA256:sha(ciphertext),maxCiphertextBytes:1024*1024};
  const wires=[],streams=[];
  function pair(timeoutMs=1000) {
    const captured=[];
    const channel=()=>new Transform({highWaterMark:65536,transform(data,encoding,done){captured.push(Buffer.from(data));done(null,data);}});
    const outgoing=channel(),incoming=channel();
    const guest=new GuestWire(outgoing,incoming,{timeoutMs}),requester=new GuestWire(incoming,outgoing,{timeoutMs});
    wires.push(guest,requester);streams.push(outgoing,incoming);return {guest,requester,captured};
  }
  t.after(()=>{for(const wire of wires){wire.fail();wire.close();}for(const stream of streams)stream.destroy();
    assert.equal(path.dirname(path.resolve(root)),path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('cannabis-input-'));fs.rmSync(root,{recursive:true,force:true});});
  return {root,source,destination,options,plain,ciphertext,pair};
}

test('encrypted input is committed before evidence without claiming key release or hardware acceptance',async t=>{
  const f=await fixture(t),p=f.pair();
  const [sent,received]=await Promise.all([
    sendEncryptedInput(p.requester,{...f.options,source:f.source}),
    receiveEncryptedInput(p.guest,{...f.options,destination:f.destination})]);
  assert.deepEqual(fs.readFileSync(f.destination),f.ciphertext);
  assert.equal(sent.peerReportedStorage,true);assert.equal(received.ciphertextVerified,true);
  for(const value of [sent,received])for(const field of ['keyReleased','paymentAuthorized','hardwareValidated'])assert.equal(value[field],false);
  assert.equal(Buffer.concat(p.captured).includes(f.plain.subarray(0,100)),false);
  if(process.platform!=='win32')assert.equal(fs.statSync(f.destination).mode&0o777,0o400);
  assert.deepEqual(fs.readdirSync(f.root).sort(),['source.age','workload.age']);
});

test('existing input and unexpected source contents never authorize or overwrite a package',async t=>{
  for(const mode of ['existing','changed','oversized']) {
    const f=await fixture(t),p=f.pair();
    if(mode==='existing')fs.writeFileSync(f.destination,'retained');
    if(mode==='changed')fs.writeFileSync(f.source,'changed owned input');
    if(mode==='oversized')f.options.maxCiphertextBytes=16;
    const settled=await Promise.allSettled([
      sendEncryptedInput(p.requester,{...f.options,source:f.source}),
      receiveEncryptedInput(p.guest,{...f.options,destination:f.destination})]);
    assert.equal(settled.every(v=>v.status==='rejected'),true,mode);
    if(mode==='existing')assert.equal(fs.readFileSync(f.destination,'utf8'),'retained');
    else assert.equal(fs.existsSync(f.destination),false);
    assert.equal(fs.readdirSync(f.root).some(n=>n.startsWith('.input-')),false);
  }
});

test('wrong commitments, overflow, wrong endings and truncated input leave no accepted file',async t=>{
  for(const mode of ['hash','extra','overflow','end','content','truncated']) {
    const f=await fixture(t),p=f.pair(200);
    const receiving=receiveEncryptedInput(p.guest,{...f.options,destination:f.destination});
    const failed=assert.rejects(receiving);
    assert.equal((await p.requester.readJSON()).operation,'input-ready');
    const header={protocol,operation:'input',packageSHA256:f.options.packageSHA256,ciphertextBytes:4};
    if(mode==='hash')header.packageSHA256='ff'.repeat(32);
    if(mode==='extra')header.command='forbidden';
    await p.requester.writeJSON(header);
    if(['overflow','end','content','truncated'].includes(mode)) {
      await p.requester.writeChunk(Buffer.from(mode==='overflow'?'12345':mode==='truncated'?'12':'1234'));
      if(mode==='end'||mode==='content')await p.requester.writeJSON({protocol,
        operation:mode==='end'?'unexpected-end':'input-end',packageSHA256:f.options.packageSHA256});
    }
    await failed;
    assert.equal(fs.existsSync(f.destination),false);
    assert.equal(fs.readdirSync(f.root).some(n=>n.startsWith('.input-')),false);
  }
});

test('caller paths reject symlink destinations and parents before intake',{skip:process.platform==='win32'},async t=>{
  const f=await fixture(t),link=path.join(f.root,'link');fs.symlinkSync(f.root,link);
  for(const destination of [path.join(link,'workload.age'),path.join(f.root,'linked.age')]) {
    if(destination.endsWith('linked.age'))fs.symlinkSync(f.source,destination);
    const p=f.pair();await assert.rejects(receiveEncryptedInput(p.guest,{...f.options,destination}));
    assert.deepEqual(fs.readFileSync(f.source),f.ciphertext);
  }
});
