import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash,randomBytes,randomUUID } from 'node:crypto';
import { uploadEncryptedResult } from '../operator/result-upload.mjs';
import { createWorkServer } from '../service/work-server.mjs';
import { approvedBrowserFixture } from './fixtures/approved-browser.mjs';
import { approvedArchiveDescriptors,openApprovedResults } from '../web/work-approvals.js';
import { downloadApprovedArchives } from '../web/work-relay.js';
const execute=promisify(execFile),CHUNK=65536,origin='https://example.invalid',h='0x'+'11'.repeat(32);
const hash=b=>createHash('sha256').update(b).digest('hex');
const json=value=>new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
function directory(t) {
  const root=fs.realpathSync(os.tmpdir()),dir=fs.mkdtempSync(path.join(root,'cannabis-upload-'));
  t.after(()=>{assert.equal(path.dirname(fs.realpathSync(dir)),root);fs.rmSync(dir,{recursive:true,force:true});});
  return dir;
}
// Framing-only owned fixture for transport failures. This is not an encrypted
// customer result or evidence of confidential execution. The HTTP case below
// uses actual age encryption and authenticated JWE receipts instead.
function synthetic(t) {
  const dir=directory(t),bytes=Buffer.concat([Buffer.from('age-encryption.org/v1\n'),randomBytes(CHUNK*2)]);
  const header=Buffer.from(JSON.stringify({alg:'dir',enc:'A256GCM',typ:'cannabis-result+jwe',kid:h})).toString('base64url');
  const source={approvalDigest:h,resultEnvelope:header+'..AAAA.BBBB.CCCC',ciphertextSHA256:hash(bytes),ciphertextBytes:bytes.length,
    ciphertext:path.join(dir,'result.age')};fs.writeFileSync(source.ciphertext,bytes);
  const access={schema:'cannabis.result-relay-access.v1',id:randomUUID(),approvalDigest:h,expiresAt:Date.now()+60000,
    chunkBytes:CHUNK,origin,role:'upload',token:randomBytes(32).toString('hex')};
  const state={schema:'cannabis.result-relay-state.v1',id:access.id,approvalDigest:h,expiresAt:access.expiresAt,
    chunkBytes:CHUNK,ciphertextSHA256:source.ciphertextSHA256,ciphertextBytes:bytes.length,received:[],complete:false,
    outputVerified:false,qualityAccepted:false,paymentAuthorized:false};
  const calls=[],stored=new Set();
  const fetchImpl=async(url,options)=>{
    calls.push(url);assert.equal(options.redirect,'error');assert.equal(options.credentials,'omit');
    assert.equal(options.headers.Authorization,'Bearer '+access.token);assert.equal(options.headers.Origin,origin);
    assert.equal(options.referrerPolicy,'no-referrer');assert.equal(options.cache,'no-store');assert.equal(options.method,'POST');
    if(url.endsWith('/manifest'))return json({...state,received:[...stored]});
    if(url.endsWith('/finish'))return json({...state,received:[...stored],complete:true});
    const index=Number(url.split('/').pop());assert.deepEqual(options.body,bytes.subarray(index*CHUNK,(index+1)*CHUNK));
    stored.add(index);return json({stored:true,index,complete:false});
  };
  return {dir,bytes,source,access,state,calls,stored,fetchImpl,input:{source,access,origin,fetchImpl,wait:async()=>{}}};
}

test('real HTTP upload resumes an ambiguous stored chunk, then requester authenticates and reconstructs the actual age/JWE result',async t=>{
  const dir=directory(t),reservation=net.createServer();await new Promise(r=>reservation.listen(0,'127.0.0.1',r));
  const port=reservation.address().port;await new Promise(r=>reservation.close(r));
  const origin='http://127.0.0.1:'+port,{server,relay}=createWorkServer({file:':memory:',resultFile:':memory:',origin});
  await new Promise(r=>server.listen(port,'127.0.0.1',r));
  try {
    const f=await approvedBrowserFixture({repetitions:6000}),descriptors=await approvedArchiveDescriptors(f),d=descriptors[0];
    assert.ok(d.ciphertextBytes>2*CHUNK);
    const a=relay.reserve({approvalDigest:d.approvalDigest,maxCiphertextBytes:d.ciphertextBytes,expiresAt:Date.now()+60000});
    const {uploadToken,readToken,...context}=a,access={...context,origin,role:'upload',token:uploadToken};
    const source={approvalDigest:d.approvalDigest,resultEnvelope:f.bundle.entries[0].envelope,ciphertextSHA256:d.ciphertextSHA256,
      ciphertextBytes:d.ciphertextBytes,ciphertext:path.join(dir,'result.age')};fs.writeFileSync(source.ciphertext,f.encrypted[0]);
    const calls=[],waits=[];
    const input={source,access,origin,wait:async ms=>waits.push(ms),fetchImpl:async(url,options)=>{
      calls.push({url,headers:options.headers,body:typeof options.body==='string'?options.body:Buffer.from(options.body).toString('base64')});const response=await fetch(url,options);
      if(url.endsWith('/chunks/1')){assert.equal(response.status,200);await response.arrayBuffer();throw new TypeError('Lost response after storage');}
      return response;
    }};
    await assert.rejects(uploadEncryptedResult(input),/resume/);
    assert.deepEqual(waits,[1000,1000]);assert.deepEqual(relay.status(a.id,uploadToken).received,[0,1]);
    const report=await uploadEncryptedResult({...input,fetchImpl:async(url,options)=>{
      calls.push({url,headers:options.headers,body:typeof options.body==='string'?options.body:Buffer.from(options.body).toString('base64')});return fetch(url,options);}});
    assert.equal(report.reusedBytes,2*CHUNK);assert.equal(report.uploadedBytes,d.ciphertextBytes-2*CHUNK);
    assert.equal(report.relayReportedComplete,true);
    for(const flag of ['requesterAcknowledgedStorage','outputVerified','qualityAccepted','paymentAuthorized'])assert.equal(report[flag],false);
    assert.equal(calls.filter(c=>c.url.endsWith('/chunks/0')).length,1);assert.equal(calls.filter(c=>c.url.endsWith('/chunks/1')).length,3);
    const recovered=await downloadApprovedArchives({descriptors,accessFiles:[{...context,origin,role:'read',token:readToken}],origin,assertCurrent:async()=>{}});
    const files=await openApprovedResults({...f,encrypted:recovered});
    assert.equal(new TextDecoder().decode(files.get('finished/answer.txt')),'owned verification result\n'.repeat(6000));
    assert.deepEqual(fs.readFileSync(source.ciphertext),Buffer.from(f.encrypted[0]));
    const configFile=path.join(dir,'config.json'),accessFile=path.join(dir,'access.json'),sourceFile=path.join(dir,'source.json');
    for(const [file,value] of [[configFile,{origin,timeoutMs:60000}],[accessFile,access],[sourceFile,source]])fs.writeFileSync(file,JSON.stringify(value));
    const cli=await execute(process.execPath,['scripts/upload-result.mjs',configFile,accessFile,sourceFile],{windowsHide:true});
    assert.equal(cli.stderr,'');const again=JSON.parse(cli.stdout);assert.equal(again.uploadedBytes,0);assert.equal(again.reusedBytes,d.ciphertextBytes);
    assert.ok(!cli.stdout.includes(uploadToken)&&!cli.stdout.includes(readToken)&&!cli.stdout.includes(source.ciphertext));
    for(const secret of [f.identity,f.owner.privateKey,'answer.txt','owned verification result',readToken])assert.ok(!JSON.stringify(calls).includes(secret));
    assert.ok(calls.every(c=>!c.url.includes(uploadToken)));
  }finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});

test('invalid capability, receipt, file size/hash or format fails before any network request',async t=>{
  const f=synthetic(t);
  for(const change of [a=>a.origin='https://elsewhere.invalid',a=>a.role='read',a=>a.approvalDigest='0x'+'22'.repeat(32),
    a=>a.expiresAt=1,a=>a.id='../escape',a=>a.extra='forbidden',a=>a.token='short']) {
    const access=structuredClone(f.access);change(access);await assert.rejects(uploadEncryptedResult({...f.input,access}));
  }
  for(const change of [s=>s.ciphertextSHA256='0'.repeat(64),s=>s.ciphertextBytes++,s=>s.ciphertext='relative.age',
    s=>s.ciphertextBytes=64*1024*1024+1,s=>s.resultEnvelope='plaintext',s=>s.resultEnvelope='e30..AAAA.BBBB.CCCC',s=>s.secret='forbidden']) {
    const source=structuredClone(f.source);change(source);await assert.rejects(uploadEncryptedResult({...f.input,source}));
  }
  const plain=Buffer.alloc(f.bytes.length,65);fs.writeFileSync(f.source.ciphertext,plain);
  await assert.rejects(uploadEncryptedResult({...f.input,source:{...f.source,ciphertextSHA256:hash(plain)}}),/binary age/);
  assert.equal(f.calls.length,0);
});

test('source mutation after checking cannot send replacement chunks or report completion',async t=>{
  for(const phase of ['checked','upload','finish']) {
    const f=synthetic(t);let changed=false;
    const mutate=()=>{if(changed)return;changed=true;const fd=fs.openSync(f.source.ciphertext,'r+');
      try{fs.writeSync(fd,Buffer.from('replaced'),0,8,CHUNK);}finally{fs.closeSync(fd);}};
    await assert.rejects(uploadEncryptedResult({...f.input,onProgress:p=>{if(p.phase===phase)mutate();},
      fetchImpl:async(url,options)=>{const r=await f.fetchImpl(url,options);if(phase==='finish'&&url.endsWith('/finish'))mutate();return r;}}),/changed/);
    assert.ok(changed);assert.ok(fs.existsSync(f.source.ciphertext));
    if(phase!=='finish')assert.ok(!f.calls.some(u=>u.endsWith('/chunks/1')||u.endsWith('/finish')));
  }
});

test('malformed relay state and chunk acknowledgements cannot advance the transfer',async t=>{
  const f=synthetic(t);
  for(const change of [s=>s.received=[0,0],s=>s.received=[3],s=>s.received=[1,0],s=>s.complete=true,
    s=>s.ciphertextSHA256='0'.repeat(64),s=>s.expiresAt++,s=>s.paymentAuthorized=true,s=>s.outputVerified=true,
    s=>s.approvalDigest='0x'+'22'.repeat(32),s=>s.extra=1]) {
    const state=structuredClone(f.state);change(state);
    await assert.rejects(uploadEncryptedResult({...f.input,fetchImpl:async()=>json(state)}),/differs/);
  }
  for(const answer of [{stored:false,index:0,complete:false},{stored:true,index:1,complete:false},{stored:true,index:0,complete:false,paid:true}]) {
    await assert.rejects(uploadEncryptedResult({...f.input,fetchImpl:async url=>json(url.endsWith('/manifest')?f.state:answer)}),/acknowledgement/);
  }
});

test('redirects, unexpected types, excessive or truncated response bodies are refused',async t=>{
  const f=synthetic(t);
  const cases=[()=>{const r=json(f.state);Object.defineProperty(r,'redirected',{value:true});return r;},
    ()=>{const r=json(f.state);Object.defineProperty(r,'url',{value:'https://elsewhere.invalid/'});return r;},
    ()=>new Response('{}',{headers:{'Content-Type':'text/html'}}),
    ()=>new Response('{}',{headers:{'Content-Type':'application/json','Content-Encoding':'gzip'}}),
    ()=>new Response('{}',{headers:{'Content-Type':'application/json','Content-Length':'32769'}}),
    ()=>new Response(' '.repeat(32769),{headers:{'Content-Type':'application/json'}}),
    ()=>new Response('{}',{headers:{'Content-Type':'application/json','Content-Length':'3'}}),
    ()=>new Response('{',{headers:{'Content-Type':'application/json'}})];
  for(const make of cases)await assert.rejects(uploadEncryptedResult({...f.input,fetchImpl:async()=>make()}));
  assert.equal(f.calls.length,0);
});

test('retry count, backoff, expiry and cancellation are bounded without discarding local ciphertext',async t=>{
  const f=synthetic(t),waits=[];let calls=0;
  await assert.rejects(uploadEncryptedResult({...f.input,timeoutMs:180000,access:{...f.access,expiresAt:Date.now()+180000},
    fetchImpl:async()=>{calls++;return new Response('',{status:429});},wait:async ms=>waits.push(ms)}),/resume/);
  assert.equal(calls,3);assert.deepEqual(waits,[60000,60000]);
  calls=0;await assert.rejects(uploadEncryptedResult({...f.input,timeoutMs:500,
    fetchImpl:async()=>{calls++;return new Response('',{status:503});}}),/Insufficient time/);assert.equal(calls,1);
  const controller=new AbortController();
  await assert.rejects(uploadEncryptedResult({...f.input,signal:controller.signal,onProgress:p=>{if(p.phase==='checked')controller.abort();}}),/cancelled/);
  assert.equal(f.calls.length,0);assert.deepEqual(fs.readFileSync(f.source.ciphertext),f.bytes);
});

test('actual held HTTP replies abort on cancellation and expiry',async t=>{
  const f=synthetic(t),server=http.createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const origin='http://127.0.0.1:'+server.address().port;let requests=0,closed=0,onRequest=()=>{};
  server.on('request',(req,res)=>{requests++;req.resume();res.on('close',()=>closed++);onRequest();});
  try {
    for(const cancel of [true,false]) {
      const controller=new AbortController();onRequest=()=>{if(cancel)controller.abort();};
      const pending=uploadEncryptedResult({...f.input,origin,access:{...f.access,origin,expiresAt:Date.now()+5000},
        timeoutMs:cancel?5000:1000,signal:controller.signal,fetchImpl:fetch});
      await assert.rejects(pending,cancel?/cancelled/:/expired|deadline|Insufficient time/);
    }
    for(let i=0;i<20&&closed<2;i++)await new Promise(r=>setTimeout(r,10));
    assert.equal(requests,2);assert.equal(closed,2);
  }finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});

test('CLI failure reveals no input paths or bearer credentials and preserves its sources',async t=>{
  const f=synthetic(t),config=path.join(f.dir,'private-config.json'),access=path.join(f.dir,'private-access.json'),source=path.join(f.dir,'private-source.json');
  fs.writeFileSync(config,JSON.stringify({origin,timeoutMs:1000}));fs.writeFileSync(access,JSON.stringify({...f.access,role:'read'}));
  fs.writeFileSync(source,JSON.stringify(f.source));
  let failure;try{await execute(process.execPath,['scripts/upload-result.mjs',config,access,source],{windowsHide:true});}catch(e){failure=e;}
  assert.equal(failure.code,1);assert.equal(failure.stdout,'');const error=JSON.parse(failure.stderr);assert.match(error.error,/Retain/);
  for(const privateValue of [f.access.token,f.dir,f.source.resultEnvelope])assert.ok(!failure.stderr.includes(privateValue));
  assert.deepEqual(fs.readFileSync(f.source.ciphertext),f.bytes);assert.ok(fs.existsSync(access)&&fs.existsSync(source));
});
