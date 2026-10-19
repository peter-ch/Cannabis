import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createHash,randomBytes,randomUUID } from 'node:crypto';
import { createWorkServer } from '../service/work-server.mjs';
import { approvedBrowserFixture } from './fixtures/approved-browser.mjs';
import { approvedArchiveDescriptors,openApprovedResults } from '../web/work-approvals.js';
import { downloadApprovedArchives,EncryptedDownloadCache } from '../web/work-relay.js';
const hash=v=>createHash('sha256').update(v).digest('hex'),h='0x'+'11'.repeat(32),CHUNK=65536;
const origin='https://example.invalid';
function synthetic() {
  const bytes=randomBytes(CHUNK*2+19),envelope='e30..AAAA.BBBB.CCCC';
  const descriptor={approvalDigest:h,envelopeSHA256:hash(envelope),ciphertextSHA256:hash(bytes),ciphertextBytes:bytes.length};
  const access={schema:'cannabis.result-relay-access.v1',id:randomUUID(),approvalDigest:h,expiresAt:Date.now()+60000,
    chunkBytes:CHUNK,origin,role:'read',token:randomBytes(32).toString('hex')};
  const manifest={schema:'cannabis.result-relay-manifest.v1',id:access.id,approvalDigest:h,expiresAt:access.expiresAt,
    chunkBytes:CHUNK,resultEnvelope:envelope,ciphertextSHA256:hash(bytes),ciphertextBytes:bytes.length};
  const calls=[];
  const fetchImpl=async(url,options)=>{
    calls.push(url);assert.equal(options.redirect,'error');assert.equal(options.credentials,'omit');
    assert.equal(options.headers.Authorization,'Bearer '+access.token);assert.equal(options.body,undefined);
    assert.equal(options.referrerPolicy,'no-referrer');assert.equal(options.cache,'no-store');
    if(url.endsWith('/manifest'))return new Response(JSON.stringify(manifest),{headers:{'Content-Type':'application/json'}});
    const index=Number(url.split('/').pop());return new Response(bytes.subarray(index*CHUNK,(index+1)*CHUNK),{headers:{'Content-Type':'application/octet-stream'}});
  };
  return {bytes,access,descriptor,manifest,calls,fetchImpl,input:{descriptors:[descriptor],accessFiles:[access],origin,assertCurrent:async()=>{},fetchImpl,delay:async()=>{}}};
}

test('requester authenticates archive commitments before HTTP retrieval and reconstructs the encrypted delivery',async()=>{
  const reservation=net.createServer();await new Promise(r=>reservation.listen(0,'127.0.0.1',r));
  const port=reservation.address().port;await new Promise(r=>reservation.close(r));
  const origin='http://127.0.0.1:'+port,{server,relay}=createWorkServer({file:':memory:',resultFile:':memory:',origin});
  await new Promise(r=>server.listen(port,'127.0.0.1',r));
  try {
    const f=await approvedBrowserFixture(),descriptors=await approvedArchiveDescriptors(f),d=descriptors[0];
    assert.deepEqual(d,{approvalDigest:f.bundle.entries[0].approval.digest,envelopeSHA256:hash(f.bundle.entries[0].envelope),
      ciphertextSHA256:f.receipt.ciphertextSHA256,ciphertextBytes:f.encrypted[0].length});
    const a=relay.reserve({approvalDigest:d.approvalDigest,maxCiphertextBytes:d.ciphertextBytes,expiresAt:Date.now()+60000});
    relay.begin(a.id,a.uploadToken,{resultEnvelope:f.bundle.entries[0].envelope,ciphertextSHA256:d.ciphertextSHA256,ciphertextBytes:d.ciphertextBytes});
    relay.put(a.id,a.uploadToken,0,f.encrypted[0]);relay.finish(a.id,a.uploadToken);
    const {uploadToken,readToken,...context}=a,access={...context,origin,role:'read',token:readToken};
    const requests=[];
    const encrypted=await downloadApprovedArchives({descriptors,accessFiles:[access],origin,assertCurrent:async()=>{},
      fetchImpl:(url,options)=>{requests.push({url,method:options.method,headers:options.headers,body:options.body});return fetch(url,options);}});
    const files=await openApprovedResults({...f,encrypted});
    assert.equal(new TextDecoder().decode(files.get('finished/answer.txt')),'owned verification result\n');
    assert.equal(requests.length,2);
    for(const secret of [f.identity,f.owner.privateKey,'answer.txt','owned verification result'])assert.ok(!JSON.stringify(requests).includes(secret));
    assert.ok(requests.every(r=>r.method==='GET'&&r.body===undefined&&!r.url.includes(readToken)));
    const invalid=structuredClone(f.bundle);invalid.entries[0].custody.ciphertext='not-custody';
    await assert.rejects(approvedArchiveDescriptors({...f,bundle:invalid}));
    const original=structuredClone(f.spec),pending=approvedArchiveDescriptors(f);f.spec.tasks[0].runtime.digestSHA256='f'.repeat(64);
    assert.deepEqual(await pending,descriptors);f.spec=original;
  }finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});

test('bounded retries retain completed encrypted chunks and resume without downloading them twice',async()=>{
  const f=synthetic(),cache=new EncryptedDownloadCache(),failed=[],delays=[];
  await assert.rejects(downloadApprovedArchives({...f.input,cache,delay:async ms=>delays.push(ms),fetchImpl:async(url,options)=>{
    if(url.endsWith('/chunks/1')){failed.push(url);throw new TypeError('Transport interrupted');}return f.fetchImpl(url,options);
  }}),/resume/);
  assert.equal(failed.length,3);assert.deepEqual(delays,[1000,1000]);
  const result=await downloadApprovedArchives({...f.input,cache});assert.deepEqual(Buffer.from(result[0]),f.bytes);
  assert.equal(f.calls.filter(url=>url.endsWith('/chunks/0')).length,1);
  assert.equal(f.calls.filter(url=>url.endsWith('/manifest')).length,2);
  cache.clear();assert.ok(result[0].every(b=>b===0));
});

test('origin, role, expiry and selected approval are checked before exposing a read capability',async()=>{
  const f=synthetic();
  for(const change of [a=>a.origin='https://elsewhere.invalid',a=>a.role='upload',a=>a.approvalDigest='0x'+'22'.repeat(32),
    a=>a.expiresAt=1,a=>a.id='../escape',a=>a.contentKey='forbidden',a=>a.token='short']) {
    const access=structuredClone(f.access);change(access);
    await assert.rejects(downloadApprovedArchives({...f.input,accessFiles:[access]}));
  }
  await assert.rejects(downloadApprovedArchives({...f.input,descriptors:[{...f.descriptor,ciphertextBytes:64*1024*1024+1}]}));
  assert.equal(f.calls.length,0);
});

test('the relay cannot replace authenticated manifests, return redirects, compress or exceed response bounds',async()=>{
  for(const change of [m=>m.approvalDigest='0x'+'33'.repeat(32),m=>m.resultEnvelope+='A',m=>m.ciphertextSHA256='a'.repeat(64),
    m=>m.ciphertextBytes++,m=>m.expiresAt++,m=>m.chunkBytes++,m=>m.extra=true]) {
    const f=synthetic(),m=structuredClone(f.manifest);change(m);
    await assert.rejects(downloadApprovedArchives({...f.input,fetchImpl:async()=>new Response(JSON.stringify(m),{headers:{'Content-Type':'application/json'}})}),/metadata/);
  }
  for(const kind of ['redirect','encoding','oversize','stream-overflow','wrong-type']) {
    const f=synthetic();
    const fetchImpl=async(url,options)=>{
      if(url.endsWith('/manifest'))return f.fetchImpl(url,options);
      const headers={'Content-Type':'application/octet-stream'};
      if(kind==='encoding')headers['Content-Encoding']='gzip';if(kind==='oversize')headers['Content-Length']=String(CHUNK+1);
      if(kind==='wrong-type')headers['Content-Type']='text/html';
      const response=new Response(Buffer.alloc(kind==='stream-overflow'?CHUNK+1:CHUNK),{headers});
      if(kind==='redirect')Object.defineProperty(response,'redirected',{value:true});return response;
    };
    await assert.rejects(downloadApprovedArchives({...f.input,fetchImpl}));
  }
});

test('corrupt ciphertext discards the entire cached archive before a fresh retry',async()=>{
  const f=synthetic(),cache=new EncryptedDownloadCache();
  await assert.rejects(downloadApprovedArchives({...f.input,cache,fetchImpl:async(url,options)=>{
    const response=await f.fetchImpl(url,options);
    if(!url.endsWith('/chunks/2'))return response;
    const bytes=new Uint8Array(await response.arrayBuffer());bytes[0]^=1;
    return new Response(bytes,{headers:{'Content-Type':'application/octet-stream'}});
  }}),/ciphertext differs/);
  const result=await downloadApprovedArchives({...f.input,cache});assert.deepEqual(Buffer.from(result[0]),f.bytes);
  assert.equal(f.calls.filter(url=>url.endsWith('/chunks/0')).length,2);
});

test('cancellation and selection changes stop further downloads and never return a result',async()=>{
  const f=synthetic(),controller=new AbortController();
  await assert.rejects(downloadApprovedArchives({...f.input,signal:controller.signal,onProgress:()=>controller.abort()}),/cancelled/);
  assert.equal(f.calls.filter(url=>url.includes('/chunks/')).length,1);
  const other=synthetic();let selected=true;
  await assert.rejects(downloadApprovedArchives({...other.input,assertCurrent:async()=>assert.ok(selected,'Selection changed'),fetchImpl:async(url,options)=>{
    const response=await other.fetchImpl(url,options);selected=false;return response;
  }}),/Selection changed/);
  assert.equal(other.calls.length,1);
});

test('rate-limit retries are bounded and an expired grant is not used again after waiting',async()=>{
  const f=synthetic(),delays=[];let attempts=0;
  await assert.rejects(downloadApprovedArchives({...f.input,delay:async ms=>delays.push(ms),fetchImpl:async()=>{
    attempts++;return new Response('busy',{status:429});
  }}),/resume/);
  assert.equal(attempts,3);assert.deepEqual(delays,[60000,60000]);
  const expired=synthetic(),originalNow=Date.now;let calls=0;
  try {await assert.rejects(downloadApprovedArchives({...expired.input,fetchImpl:async()=>{calls++;return new Response('busy',{status:503});},
    delay:async()=>{Date.now=()=>originalNow()+120000;}}),/expired/);}
  finally{Date.now=originalNow;}
  assert.equal(calls,1);
});
