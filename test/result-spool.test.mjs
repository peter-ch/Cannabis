import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash,randomBytes } from 'node:crypto';
import { TypedDataEncoder,Wallet } from 'ethers';
import { ResultSpool,RESULT_SPOOL_OVERHEAD } from '../operator/result-spool.mjs';
import { resultStoredPayload } from '../compute/result_transport.mjs';
import { deliveryApprovalTypes } from '../compute/key_delivery.mjs';
import { approvedBrowserFixture } from './fixtures/approved-browser.mjs';
const DAY=86400000,MAX=1024*1024,hash=v=>createHash('sha256').update(v).digest('hex');
async function fixture(t,options={}) {
  const parent=fs.realpathSync(os.tmpdir()),root=fs.mkdtempSync(path.join(parent,'cannabis-spool-test-'));
  const directory=path.join(root,'spool');fs.mkdirSync(directory);
  const f=await approvedBrowserFixture(),expected=f.bundle.entries[0].approval,envelope=f.bundle.entries[0].envelope,bytes=Buffer.from(f.encrypted[0]);
  let clock=Date.now(),spool=new ResultSpool(directory,{create:true,maxBytes:MAX+RESULT_SPOOL_OVERHEAD,now:()=>clock,...options});
  const request={expected,maxCiphertextBytes:MAX,serviceEnd:Math.floor(clock/1000)+60};
  t.after(()=>{spool.close();assert.equal(path.dirname(fs.realpathSync(root)),parent);fs.rmSync(root,{recursive:true});});
  const complete=()=>{
    const r=spool.reserve(request);spool.dispatch(r);spool.begin(r,{resultEnvelope:envelope,ciphertextBytes:bytes.length});
    for(let i=0;i<bytes.length;i+=65536)spool.append(r,bytes.subarray(i,i+65536));
    spool.seal(r,hash(bytes));return r;
  };
  const another=async()=>{
    const e=structuredClone(expected),types=deliveryApprovalTypes(e.domain.version);e.value.nonce='0x'+randomBytes(32).toString('hex');
    e.digest=TypedDataEncoder.hash(e.domain,types,e.value);e.requesterSignature=await f.owner.signTypedData(e.domain,types,e.value);return e;
  };
  return {...f,root,directory,expected,envelope,bytes,request,complete,another,get spool(){return spool;},
    advance:ms=>clock+=ms,reopen:()=>{spool.close();clock=Math.max(clock,Date.now());spool=new ResultSpool(directory,{now:()=>clock});return spool;},
    payload:()=>resultStoredPayload(expected,{envelopeSHA256:hash(envelope),ciphertextSHA256:hash(bytes),ciphertextBytes:bytes.length})};
}
function child(config,file) {
  fs.writeFileSync(file,JSON.stringify(config),{flag:'wx',mode:0o600});
  return new Promise((resolve,reject)=>{
    const p=spawn(process.execPath,['--disable-warning=ExperimentalWarning','test/helpers/result_spool_process.mjs',file],{windowsHide:true,stdio:['ignore','pipe','pipe']});
    // Allow bounded module startup on WSL-mounted source; production service
    // deadlines and SQLite lock timeouts remain unchanged.
    let out='',err='';const timer=setTimeout(()=>{p.kill();reject(Error('Spool fixture timeout'));},30000);
    p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('error',reject);
    p.on('exit',code=>{clearTimeout(timer);try{assert.equal(err,'');resolve({code,...JSON.parse(out)});}catch(e){reject(e);}});
  });
}
test('aggregate local reservation survives reopen and refuses overbooking across processes',async t=>{
  const f=await fixture(t);f.spool.close();
  const configs=[f.request,{...f.request,expected:await f.another()}];
  const results=await Promise.all(configs.map((request,i)=>child({directory:f.directory,request,stage:'reserved'},path.join(f.root,`child-${i}.json`))));
  assert.equal(results.filter(r=>r.ok).length,1);assert.equal(results.filter(r=>r.code===1).length,1);
  f.reopen();assert.equal(f.spool.usage().reservedBytes,MAX+RESULT_SPOOL_OVERHEAD);assert.equal(f.spool.usage().records,1);
  assert.throws(()=>f.spool.reserve({...f.request,expected:configs[1].expected}));
});
test('cancelling unused space revokes the handle, while dispatch uncertainty stays charged after expiry',async t=>{
  const f=await fixture(t),r=f.spool.reserve(f.request);
  assert.equal(f.spool.cancelUnused(r),true);assert.throws(()=>f.spool.dispatch(r));assert.equal(f.spool.usage().records,0);
  const uncertain=f.spool.reserve(f.request);f.spool.dispatch(uncertain);assert.equal(f.spool.cancelUnused(uncertain),false);
  f.advance(40*DAY);f.spool.cleanup();assert.equal(f.spool.status(uncertain.id).state,'dispatched');
  assert.equal(f.spool.usage().reservedBytes,MAX+RESULT_SPOOL_OVERHEAD);
});
test('expired unused reservation cannot forward execution after cleanup or a backwards clock',async t=>{
  const f=await fixture(t),r=f.spool.reserve(f.request);f.advance(61000);assert.equal(f.spool.cleanup().records,0);
  assert.throws(()=>f.spool.dispatch(r));f.advance(-62000);assert.throws(()=>f.spool.reserve(f.request));
});
test('process termination preserves each durable state and reconstructs sealed metadata without a key or rerun',async t=>{
  for(const stage of ['reserved','dispatched','receiving','sealed','complete']){
    const f=await fixture(t);f.spool.close();
    const result=await child({directory:f.directory,request:f.request,stage,crash:true,envelope:f.envelope,ciphertext:f.bytes.toString('base64')},path.join(f.root,'crash.json'));
    assert.equal(result.code,86);assert.equal(result.ok,true);f.reopen();assert.equal(f.spool.status(result.id).state,stage);
    assert.equal(f.spool.usage().records,1);assert.throws(()=>f.spool.reserve(f.request));
    if(['sealed','complete'].includes(stage)){
      const recovered=f.spool.recover(result.id);assert.deepEqual(fs.readFileSync(recovered.source.ciphertext),f.bytes);
      assert.equal(recovered.source.resultEnvelope,f.envelope);assert.deepEqual(JSON.parse(fs.readFileSync(recovered.sourceFile)),recovered.source);
      assert.equal(f.spool.status(result.id).state,'complete');
    }else assert.throws(()=>f.spool.recover(result.id));
  }
});
test('complete unacknowledged output never expires; only a genuine storage signature starts retention',async t=>{
  const f=await fixture(t),r=f.complete(),p=f.payload();
  const wrong=await Wallet.createRandom().signTypedData(p.domain,p.types,p.value);
  assert.throws(()=>f.spool.acknowledge(r.id,wrong));assert.throws(()=>f.spool.acknowledge(r.id,{complete:true}));
  f.advance(40*DAY);f.spool.cleanup();assert.equal(f.spool.status(r.id).state,'complete');
  assert.deepEqual(fs.readFileSync(f.spool.recover(r.id).source.ciphertext),f.bytes);
  const signature=await f.owner.signTypedData(p.domain,p.types,p.value);f.spool.acknowledge(r.id,signature);
  f.advance(7*DAY-1);f.spool.cleanup();assert.equal(f.spool.status(r.id).state,'acknowledged');
  f.advance(1);assert.equal(f.spool.cleanup().records,0);assert.equal(fs.existsSync(path.join(f.directory,r.id)),false);
});
test('interrupted deletion retains its charge and resumes without erasing other files',async t=>{
  const f=await fixture(t),r=f.complete(),p=f.payload();f.spool.acknowledge(r.id,await f.owner.signTypedData(p.domain,p.types,p.value));f.advance(7*DAY);
  const remove=fs.unlinkSync;let once=false;
  fs.unlinkSync=file=>{if(path.basename(file)==='source.json'&&!once){once=true;throw Error('Owned disk fault');}return remove(file);};
  try{assert.throws(()=>f.spool.cleanup());}finally{fs.unlinkSync=remove;}
  assert.equal(once,true);assert.equal(f.spool.status(r.id).state,'purging');assert.equal(f.spool.usage().records,1);
  const sentinel=path.join(f.directory,'operator-note.txt');fs.writeFileSync(sentinel,'keep');
  f.reopen();assert.equal(f.spool.cleanup().records,0);assert.equal(fs.readFileSync(sentinel,'utf8'),'keep');
});
test('changed complete ciphertext or published recovery metadata fails closed without releasing capacity',async t=>{
  for(const target of ['ciphertext','metadata']){
    const f=await fixture(t),r=f.complete(),recovered=f.spool.recover(r.id);
    const file=target==='ciphertext'?recovered.source.ciphertext:recovered.sourceFile;
    const bytes=fs.readFileSync(file);bytes[0]^=1;fs.writeFileSync(file,bytes);
    assert.throws(()=>f.spool.recover(r.id));assert.equal(f.spool.usage().records,1);assert.equal(fs.existsSync(file),true);
  }
});
test('a partial disk write remains charged and cannot be mistaken for a completed archive',async t=>{
  const f=await fixture(t),r=f.spool.reserve(f.request);f.spool.dispatch(r);f.spool.begin(r,{resultEnvelope:f.envelope,ciphertextBytes:f.bytes.length});
  const write=fs.writeSync;let injected=false;
  fs.writeSync=(fd,bytes,...args)=>{if(!injected&&Buffer.isBuffer(bytes)){injected=true;write(fd,bytes,0,1,0);throw Error('Owned ENOSPC');}return write(fd,bytes,...args);};
  try{assert.throws(()=>f.spool.append(r,f.bytes.subarray(0,65536)));}finally{fs.writeSync=write;}
  assert.equal(injected,true);assert.throws(()=>f.spool.append(r,f.bytes.subarray(0,65536)));assert.throws(()=>f.spool.seal(r,hash(f.bytes)));
  f.advance(40*DAY);f.spool.cleanup();assert.equal(f.spool.status(r.id).state,'receiving');assert.equal(f.spool.usage().records,1);
});
test('a missing ledger or changed limits cannot silently reset reservations',async t=>{
  const f=await fixture(t);f.spool.reserve(f.request);
  assert.throws(()=>new ResultSpool(f.directory,{create:true}));assert.throws(()=>new ResultSpool(f.directory,{maxBytes:2*(MAX+RESULT_SPOOL_OVERHEAD)}));
  const empty=path.join(f.root,'missing');fs.mkdirSync(empty);assert.throws(()=>new ResultSpool(empty));
});
