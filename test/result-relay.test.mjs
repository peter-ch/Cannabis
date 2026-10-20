import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { execFileSync } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { ResultRelay, RESULT_CHUNK_BYTES as chunkSize } from '../service/result-relay.mjs';
import { createWorkServer } from '../service/work-server.mjs';
import { approvedBrowserFixture } from './fixtures/approved-browser.mjs';
import { openApprovedResults } from '../web/work-approvals.js';
const hash=b=>createHash('sha256').update(b).digest('hex');
const h='0x'+'11'.repeat(32),envelope='e30..AAAA.BBBB.CCCC';
const manifest=bytes=>({resultEnvelope:envelope,ciphertextSHA256:hash(bytes),ciphertextBytes:bytes.length});
const temp=()=>fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-relay-'));
const reserve=(s,bytes,extra={})=>s.reserve({approvalDigest:h,maxCiphertextBytes:bytes,expiresAt:Date.now()+60000,...extra});
const putAll=(s,a,bytes)=>{for(let i=0;i<Math.ceil(bytes.length/chunkSize);i++)s.put(a.id,a.uploadToken,i,bytes.subarray(i*chunkSize,(i+1)*chunkSize));};

test('resumable out-of-order encrypted chunks survive restart, remain immutable and require full hash verification',()=>{
  const dir=temp(),file=path.join(dir,'relay.sqlite'),bytes=randomBytes(chunkSize*2+7);
  let s=new ResultRelay(file);
  try {
    const a=reserve(s,bytes.length);
    assert.throws(()=>s.put(a.id,a.uploadToken,0,bytes.subarray(0,chunkSize)),/manifest/);
    s.begin(a.id,a.uploadToken,manifest(bytes));
    s.put(a.id,a.uploadToken,2,bytes.subarray(chunkSize*2));
    assert.throws(()=>s.finish(a.id,a.uploadToken),/incomplete/);
    assert.throws(()=>s.manifest(a.id,a.readToken),/not complete/);
    s.close();s=new ResultRelay(file);
    assert.deepEqual(s.status(a.id,a.uploadToken).received,[2]);
    putAll(s,a,bytes);assert.deepEqual(s.begin(a.id,a.uploadToken,manifest(bytes)).received,[0,1,2]);
    assert.throws(()=>s.begin(a.id,a.uploadToken,{...manifest(bytes),resultEnvelope:'e30..BBBB.CCCC.DDDD'}),/already fixed/);
    assert.throws(()=>s.put(a.id,a.uploadToken,0,randomBytes(chunkSize)),/cannot change/);
    assert.throws(()=>s.put(a.id,a.uploadToken,1,bytes.subarray(0,1)),/does not match/);
    assert.throws(()=>s.put(a.id,a.uploadToken,3,bytes.subarray(0,7)),/does not match/);
    const done=s.finish(a.id,a.uploadToken);assert.equal(done.complete,true);assert.equal(done.paymentAuthorized,false);
    assert.deepEqual(s.finish(a.id,a.uploadToken),done);putAll(s,a,bytes);
    const recovered=Buffer.concat([0,1,2].map(i=>s.chunk(a.id,a.readToken,i)));assert.deepEqual(recovered,bytes);
    assert.equal(s.manifest(a.id,a.readToken).ciphertextSHA256,hash(recovered));
    assert.throws(()=>s.chunk(a.id,a.readToken,3),/not found/);
  }finally{s.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('read/upload capabilities are separate, expiry and revocation deny every operation',()=>{
  let now=Date.now();const s=new ResultRelay(':memory:',{now:()=>now});
  try {
    const a=reserve(s,10,{expiresAt:now+100});
    for(const [token,role] of [[a.uploadToken,'read'],[a.readToken,'upload'],['0'.repeat(64),'read']])
      assert.throws(()=>s.authorize(a.id,token,role),/not found/);
    assert.throws(()=>s.authorize(randomUUID(),a.uploadToken,'upload'),/not found/);
    assert.throws(()=>s.remove(a.id,a.uploadToken),/not found/);
    now+=100;assert.throws(()=>s.begin(a.id,a.uploadToken,manifest(Buffer.alloc(10))),/not found/);
    assert.throws(()=>s.status(a.id,a.uploadToken),/not found/);assert.equal(s.cleanup(),1);
    const b=reserve(s,10,{expiresAt:now+100});s.remove(b.id,b.readToken);
    assert.throws(()=>s.status(b.id,b.uploadToken),/not found/);
  }finally{s.close();}
});

test('reservations bound ciphertext plus receipts across connections and release expired capacity',()=>{
  const dir=temp(),file=path.join(dir,'relay.sqlite');let now=Date.now();
  const limits={maxStorageBytes:4096,maxObjects:2,maxEnvelopeBytes:1024,now:()=>now};
  const s=new ResultRelay(file,limits),other=new ResultRelay(file,limits);
  try {
    reserve(s,1024,{expiresAt:now+100});reserve(other,1024,{expiresAt:now+100});
    assert.throws(()=>reserve(s,1),/full/);now+=100;
    const a=reserve(other,2048,{expiresAt:now+100});
    assert.throws(()=>reserve(s,1),/full/);
    assert.throws(()=>s.begin(a.id,a.uploadToken,manifest(Buffer.alloc(2049))),/reservation/);
    assert.throws(()=>s.begin(a.id,a.uploadToken,{...manifest(Buffer.alloc(1)),contentKey:'private'}),/Unexpected/);
    assert.throws(()=>new ResultRelay(file,{...limits,maxObjects:3}),/cannot change/);
  }finally{s.close();other.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('complete-sized corrupted bytes never become readable, including after retry',()=>{
  const s=new ResultRelay(':memory:');try {
    const a=reserve(s,5);s.begin(a.id,a.uploadToken,manifest(Buffer.from('abcde')));
    s.put(a.id,a.uploadToken,0,Buffer.from('xxxxx'));
    for(let n=0;n<2;n++)assert.throws(()=>s.finish(a.id,a.uploadToken),/do not match/);
    assert.equal(s.status(a.id,a.uploadToken).complete,false);
    assert.throws(()=>s.chunk(a.id,a.readToken,0),/not complete/);
  }finally{s.close();}
});

test('concurrent writers cannot replace a previously chosen result chunk',async()=>{
  const dir=temp(),file=path.join(dir,'relay.sqlite'),s=new ResultRelay(file);
  const run=(a,value)=>new Promise((resolve,reject)=>{
    const source=`import {parentPort,workerData as d} from 'node:worker_threads';
      import {ResultRelay} from ${JSON.stringify(new URL('../service/result-relay.mjs',import.meta.url).href)};
      const s=new ResultRelay(d.file);try{s.put(d.a.id,d.a.uploadToken,0,Buffer.from(d.value));parentPort.postMessage('stored');}
      catch(e){parentPort.postMessage(e.status);}finally{s.close();}`;
    const w=new Worker(new URL('data:text/javascript,'+encodeURIComponent(source)),{workerData:{file,a,value}});
    let result;w.on('message',v=>result=v);w.on('error',reject);w.on('exit',code=>code?reject(Error('Worker failed')):resolve(result));
  });
  try {
    const a=reserve(s,5);s.begin(a.id,a.uploadToken,manifest(Buffer.from('abcde')));
    const results=await Promise.all([run(a,'abcde'),run(a,'xxxxx')]);
    assert.deepEqual(results.sort((a,b)=>String(a).localeCompare(String(b))),[409,'stored']);
    assert.equal(s.status(a.id,a.uploadToken).received.length,1);
  }finally{s.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('local reservation CLI writes distinct private access files without emitting credentials or changing existing files',()=>{
  const dir=temp(),config=path.join(dir,'config.json'),input=path.join(dir,'input.json'),out=path.join(dir,'access');
  try {
    fs.writeFileSync(config,JSON.stringify({database:path.join(dir,'relay.sqlite'),origin:'https://example.invalid'}));
    fs.writeFileSync(input,JSON.stringify({approvalDigest:h,maxCiphertextBytes:100,expiresAt:Date.now()+60000}));
    const stdout=execFileSync(process.execPath,['scripts/reserve-result-storage.mjs',config,input,out],{encoding:'utf8',windowsHide:true});
    const upload=JSON.parse(fs.readFileSync(path.join(out,'upload.json'))),read=JSON.parse(fs.readFileSync(path.join(out,'read.json')));
    assert.equal(upload.role,'upload');assert.equal(read.role,'read');assert.notEqual(upload.token,read.token);
    assert.equal(upload.id,read.id);assert.ok(!stdout.includes(upload.token)&&!stdout.includes(read.token));
    const before=fs.readFileSync(path.join(out,'read.json'));
    assert.throws(()=>execFileSync(process.execPath,['scripts/reserve-result-storage.mjs',config,input,out],{windowsHide:true,stdio:'pipe'}));
    assert.deepEqual(fs.readFileSync(path.join(out,'read.json')),before);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

test('HTTP ciphertext delivery verifies in the requester flow; credentials, origin, bounds and closed payments are enforced',async()=>{
  const reservation=net.createServer();await new Promise(r=>reservation.listen(0,'127.0.0.1',r));
  const port=reservation.address().port;await new Promise(r=>reservation.close(r));
  const origin='http://127.0.0.1:'+port,{server,relay}=createWorkServer({file:':memory:',resultFile:':memory:',origin});
  await new Promise(r=>server.listen(port,'127.0.0.1',r));
  const f=await approvedBrowserFixture(),bytes=Buffer.from(f.encrypted[0]);
  const a=relay.reserve({approvalDigest:f.bundle.entries[0].approval.digest,maxCiphertextBytes:bytes.length,expiresAt:Date.now()+60000});
  const route='/api/work/results/'+a.id;
  const call=(action,method='GET',body,token=a.uploadToken,headers={})=>fetch(origin+route+action,{method,body,
    headers:{Origin:origin,'Content-Type':'application/json',Authorization:'Bearer '+token,...headers}});
  try {
    assert.equal((await call('/status','GET',undefined,a.readToken)).status,404);
    assert.equal((await call('/status?token='+a.uploadToken)).status,400);
    assert.equal((await call('/manifest','POST','{}',a.uploadToken,{Origin:'https://evil.invalid'})).status,403);
    assert.equal((await call('/manifest','POST','{}',a.uploadToken,{'Content-Encoding':'gzip'})).status,415);
    const m={...manifest(bytes),resultEnvelope:f.bundle.entries[0].envelope};
    assert.equal((await call('/manifest','POST',JSON.stringify(m))).status,200);
    assert.equal((await call('/chunks/0','POST',Buffer.alloc(chunkSize+1),a.uploadToken,{'Content-Type':'application/octet-stream'})).status,413);
    assert.equal((await call('/chunks/0','POST',bytes,a.uploadToken,{'Content-Type':'application/octet-stream'})).status,200);
    assert.equal((await call('/finish','POST','{}')).status,200);
    const response=await call('/manifest','GET',undefined,a.readToken),hosted=await response.json();
    assert.equal(response.headers.get('cache-control'),'no-store');assert.equal(hosted.approvalDigest,a.approvalDigest);
    const download=await call('/chunks/0','GET',undefined,a.readToken),recovered=new Uint8Array(await download.arrayBuffer());
    assert.equal(hash(recovered),f.receipt.ciphertextSHA256);
    const bundle=structuredClone(f.bundle);bundle.entries[0].envelope=hosted.resultEnvelope;
    const files=await openApprovedResults({...f,bundle,encrypted:[recovered]});
    assert.equal(new TextDecoder().decode(files.get('finished/answer.txt')),'owned verification result\n');
    const tampered=recovered.slice();tampered[42]^=1;await assert.rejects(openApprovedResults({...f,bundle,encrypted:[tampered]}));
    const status=await(await fetch(origin+'/api/work/status')).json();assert.equal(status.paymentsAvailable,false);assert.equal(status.executionAvailable,false);
    assert.equal((await call('/reserve','POST','{}')).status,404);
    assert.equal((await call('','DELETE',undefined,a.readToken)).status,200);
    assert.equal((await call('/manifest','GET',undefined,a.readToken)).status,404);
  }finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});

test('authenticated stalled transfers cannot allocate unbounded bodies and abort releases their slots',async()=>{
  const reservation=net.createServer();await new Promise(r=>reservation.listen(0,'127.0.0.1',r));
  const port=reservation.address().port;await new Promise(r=>reservation.close(r));
  const origin='http://127.0.0.1:'+port,{server,relay}=createWorkServer({file:':memory:',resultFile:':memory:',origin});
  await new Promise(r=>server.listen(port,'127.0.0.1',r));
  const bytes=Buffer.alloc(chunkSize),a=reserve(relay,bytes.length);relay.begin(a.id,a.uploadToken,manifest(bytes));
  const url=origin+'/api/work/results/'+a.id+'/chunks/0';
  const headers={Origin:origin,'Content-Type':'application/octet-stream',Authorization:'Bearer '+a.uploadToken};
  const streams=[],controllers=[],pending=[];let seen=0,notify;
  const ready=new Promise(r=>notify=r),authorize=relay.authorize.bind(relay);
  relay.authorize=(...args)=>{authorize(...args);if(++seen===2)setImmediate(notify);};
  try {
    for(let i=0;i<2;i++) {
      const stream=new PassThrough(),controller=new AbortController();streams.push(stream);controllers.push(controller);
      pending.push(fetch(url,{method:'POST',headers:{...headers,'Content-Length':String(chunkSize)},body:stream,duplex:'half',signal:controller.signal}).catch(()=>null));
      stream.write(bytes.subarray(0,1));
    }
    await ready;
    assert.equal((await fetch(url,{method:'POST',headers,body:bytes})).status,503);
    for(const c of controllers)c.abort();for(const s of streams)s.destroy();await Promise.all(pending);
    let response;
    for(let i=0;i<10;i++) {
      response=await fetch(url,{method:'POST',headers,body:bytes});
      if(response.status!==503)break;
      await new Promise(r=>setTimeout(r,10));
    }
    assert.equal(response.status,200);assert.deepEqual(relay.status(a.id,a.uploadToken).received,[0]);
  }finally{for(const c of controllers)c.abort();for(const s of streams)s.destroy();server.closeAllConnections();await new Promise(r=>server.close(r));}
});
