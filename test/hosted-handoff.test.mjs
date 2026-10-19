import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { Transform } from 'node:stream';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { Wallet } from 'ethers';
import { createWorkServer } from '../service/work-server.mjs';
import { approvedBrowserFixture } from './fixtures/approved-browser.mjs';
import { recoverResultKey } from '../compute/result_keys.mjs';
import { ResultInbox } from '../compute/result_inbox.mjs';
import { GuestWire,sendEncryptedResult,resultStoredPayload } from '../compute/result_transport.mjs';
import { bridgeEncryptedResult } from '../operator/result-bridge.mjs';
import { receiveHostedResult } from '../requester/hosted-result.mjs';
import { openApprovedResults } from '../web/work-approvals.js';
import { createHash } from 'node:crypto';
const hash=v=>createHash('sha256').update(v).digest('hex'),CHUNK=65536;
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
async function fixture(t) {
  const root=fs.realpathSync(os.tmpdir()),dir=fs.mkdtempSync(path.join(root,'cannabis-hosted-handoff-'));
  const f=await approvedBrowserFixture({repetitions:6000}),entry=f.bundle.entries[0],expected=entry.approval,bytes=Buffer.from(f.encrypted[0]);
  const spoolDirectory=path.join(dir,'operator');fs.mkdirSync(spoolDirectory);
  const ciphertext=path.join(dir,'owned-guest.age'),destination=path.join(dir,'requester.age');fs.writeFileSync(ciphertext,bytes);
  const result={ciphertext,resultEnvelope:entry.envelope},inbox=new ResultInbox(path.join(dir,'inbox.sqlite'),f.bundle.context);
  inbox.activate({schema:'cannabis.key-delivery.record.v2',keyWrapped:true,approvalDigest:expected.digest,
    releaseId:expected.value.releaseId,expectedApproval:expected},{resultRecipient:entry.recipient});
  const reserved=net.createServer();await new Promise(r=>reserved.listen(0,'127.0.0.1',r));
  const port=reserved.address().port;await new Promise(r=>reserved.close(r));
  const origin='http://127.0.0.1:'+port,{server,relay}=createWorkServer({file:':memory:',resultFile:':memory:',origin});
  await new Promise(r=>server.listen(port,'127.0.0.1',r));
  const {uploadToken,readToken,...grant}=relay.reserve({approvalDigest:expected.digest,maxCiphertextBytes:bytes.length,expiresAt:Date.now()+60000});
  const upload={...grant,origin,role:'upload',token:uploadToken},read={...grant,origin,role:'read',token:readToken};
  const captures=[],streams=[],wires=[],requests=[];
  const pair=()=>{
    const channel=()=>{const stream=new Transform({highWaterMark:CHUNK,transform(data,encoding,done){captures.push(Buffer.from(data));done(null,data);}});streams.push(stream);return stream;};
    const a=channel(),b=channel(),left=new GuestWire(a,b,{timeoutMs:5000}),right=new GuestWire(b,a,{timeoutMs:5000});
    wires.push(left,right);return [left,right];
  };
  const [guest,bridgeGuest]=pair(),[bridgeRequester,requester]=pair();
  const fetchImpl=(url,options)=>{requests.push({url,headers:options.headers,method:options.method});return fetch(url,options);};
  const bridgeOptions={expected,access:upload,origin,spoolDirectory,maxCiphertextBytes:1024*1024,timeoutMs:5000,fetchImpl,wait:async()=>{}};
  const requesterOptions={inbox,approvalDigest:expected.digest,loadResultKey:binding=>recoverResultKey(entry.custody,f.identity,binding),
    destination,maxCiphertextBytes:1024*1024,signStored:payload=>f.owner.signTypedData(payload.domain,payload.types,payload.value),
    access:read,origin,timeoutMs:5000,fetchImpl,wait:async()=>{}};
  const run=(bridgeChanges={},requesterChanges={})=>Promise.allSettled([
    sendEncryptedResult(guest,result,expected,{maxCiphertextBytes:1024*1024}),
    bridgeEncryptedResult(bridgeGuest,bridgeRequester,{...bridgeOptions,...bridgeChanges}),
    receiveHostedResult(requester,{...requesterOptions,...requesterChanges})]);
  t.after(async()=>{
    for(const wire of wires){wire.fail();wire.close();}for(const stream of streams)stream.destroy();
    server.closeAllConnections();await new Promise(r=>server.close(r));inbox.close();
    assert.equal(path.dirname(fs.realpathSync(dir)),root);fs.rmSync(dir,{recursive:true,force:true});
  });
  return {...f,dir,bytes,result,expected,spoolDirectory,destination,inbox,server,relay,grant,upload,read,
    guest,bridgeGuest,bridgeRequester,requester,bridgeOptions,requesterOptions,run,requests,captures};
}
function failed(results) {assert.equal(results.length,3);for(const r of results)assert.equal(r.status,'rejected');}
function retained(f) {
  const dirs=fs.readdirSync(f.spoolDirectory);assert.equal(dirs.length,1);
  const dir=path.join(f.spoolDirectory,dirs[0]);assert.deepEqual(fs.readdirSync(dir).sort(),['result.age','source.json']);
  assert.deepEqual(fs.readFileSync(path.join(dir,'result.age')),f.bytes);return dir;
}

test('guest to HTTP relay to requester preserves the genuine storage signature after local durable publication',async t=>{
  const f=await fixture(t);let lost=false,busy=false,signed=false;const waits=[],downloadWaits=[];
  const results=await f.run({wait:async ms=>waits.push(ms),fetchImpl:async(url,options)=>{
    const response=await f.bridgeOptions.fetchImpl(url,options);
    if(!lost&&url.endsWith('/chunks/0')){lost=true;assert.equal(response.status,200);await response.arrayBuffer();throw new TypeError('Lost stored response');}
    return response;
  }},{wait:async ms=>downloadWaits.push(ms),fetchImpl:async(url,options)=>{
    const response=await f.requesterOptions.fetchImpl(url,options);
    if(!busy&&url.endsWith('/chunks/1')){busy=true;await response.arrayBuffer();return new Response('',{status:503});}
    return response;
  },signStored:async payload=>{
    signed=true;assert.deepEqual(fs.readFileSync(f.destination),f.bytes);
    assert.equal(f.inbox.inspect(f.expected.digest).active,true);assert.equal(payload.domain.name,'Cannabis encrypted result stored');
    return f.requesterOptions.signStored(payload);
  }});
  for(const r of results)assert.equal(r.status,'fulfilled',r.reason?.message);
  assert.equal(signed,true);assert.deepEqual(waits,[1000]);assert.deepEqual(downloadWaits,[1000]);
  assert.equal(results[0].value.requesterAcknowledgedStorage,true);
  assert.equal(results[1].value.requesterStorageSignatureVerified,true);assert.equal(results[1].value.guestCompletionObserved,false);
  assert.equal(results[2].value.storageAcknowledged,true);assert.equal(results[2].value.outputVerified,false);
  for(const r of results)assert.equal(r.value.paymentAuthorized,false);
  retained(f);assert.deepEqual(fs.readFileSync(f.destination),f.bytes);
  const files=await openApprovedResults({...f,encrypted:[new Uint8Array(fs.readFileSync(f.destination))]});
  assert.equal(new TextDecoder().decode(files.get('finished/answer.txt')),'owned verification result\n'.repeat(6000));
  const seen=Buffer.concat(f.captures);
  for(const secret of [f.identity,f.owner.privateKey,f.result.ciphertext,f.destination,f.read.token,f.upload.token,'answer.txt','owned verification result'])
    assert.equal(seen.includes(Buffer.from(secret)),false);
  assert.ok(f.requests.every(r=>!r.url.includes(f.read.token)&&!r.url.includes(f.upload.token)));
});

test('altered hosted receipt or archive commitment fails before disclosing a read capability',async t=>{
  for(const kind of ['receipt','hash']) {
    const f=await fixture(t),write=f.bridgeRequester.writeJSON.bind(f.bridgeRequester);
    f.bridgeRequester.writeJSON=async value=>{
      const v=structuredClone(value);
      if(kind==='hash')v.ciphertextSHA256='0'.repeat(64);
      else {const parts=v.resultEnvelope.split('.');parts[3]=(parts[3][0]==='A'?'B':'A')+parts[3].slice(1);v.resultEnvelope=parts.join('.');}
      return write(v);
    };
    failed(await f.run({}, {signStored:()=>assert.fail('No invalid result signature')}));
    assert.equal(f.requests.some(r=>r.method==='GET'),false);assert.equal(fs.existsSync(f.destination),false);retained(f);
  }
});

test('changed download bytes never publish or request a signature',async t=>{
  const f=await fixture(t);
  failed(await f.run({}, {fetchImpl:async(url,options)=>{
    const r=await f.requesterOptions.fetchImpl(url,options);
    if(!url.endsWith('/chunks/1'))return r;
    const bytes=Buffer.from(await r.arrayBuffer());bytes[42]^=1;
    return new Response(bytes,{headers:{'Content-Type':'application/octet-stream'}});
  },signStored:()=>assert.fail('Corrupted ciphertext must not reach signing')}));
  assert.equal(fs.existsSync(f.destination),false);assert.equal(fs.readdirSync(f.dir).some(n=>n.startsWith('.cannabis-receive-')),false);retained(f);
});

test('retirement during HTTP retrieval stops subsequent chunks and owner signing',async t=>{
  const f=await fixture(t);
  failed(await f.run({}, {fetchImpl:async(url,options)=>{
    const r=await f.requesterOptions.fetchImpl(url,options);if(url.endsWith('/chunks/0'))f.inbox.retire(f.expected.digest);return r;
  },signStored:()=>assert.fail('Retired result must not reach signing')}));
  assert.equal(f.requests.some(r=>r.method==='GET'&&r.url.endsWith('/chunks/1')),false);
  assert.equal(fs.existsSync(f.destination),false);retained(f);
});

test('wrong owner signature is refused while already published requester ciphertext remains recoverable',async t=>{
  const f=await fixture(t),wrong=Wallet.createRandom();
  failed(await f.run({}, {signStored:p=>wrong.signTypedData(p.domain,p.types,p.value)}));
  assert.deepEqual(fs.readFileSync(f.destination),f.bytes);retained(f);
});

test('bridge independently refuses a forged storage signature and never forwards it to the guest',async t=>{
  const f=await fixture(t);let forwarded=false;const write=f.bridgeGuest.writeJSON.bind(f.bridgeGuest);
  f.bridgeGuest.writeJSON=async v=>{if(v.operation==='stored')forwarded=true;return write(v);};
  const sending=sendEncryptedResult(f.guest,f.result,f.expected,{maxCiphertextBytes:1024*1024});
  const bridging=bridgeEncryptedResult(f.bridgeGuest,f.bridgeRequester,f.bridgeOptions);
  const forged=(async()=>{
    const header=await f.requester.readJSON();const p=resultStoredPayload(f.expected,{envelopeSHA256:hash(header.resultEnvelope),
      ciphertextSHA256:header.ciphertextSHA256,ciphertextBytes:header.ciphertextBytes});
    const signature=await Wallet.createRandom().signTypedData(p.domain,p.types,p.value);
    await f.requester.writeJSON({protocol:'cannabis.guest-wire.v1',operation:'stored',signature});
  })();
  const results=await Promise.allSettled([sending,bridging,forged]);
  assert.equal(results[0].status,'rejected');assert.equal(results[1].status,'rejected');assert.equal(results[2].status,'fulfilled');
  assert.equal(forwarded,false);assert.equal(fs.existsSync(f.destination),false);retained(f);
});

test('cancelling while owner signing is pending finishes promptly and cannot forward a late signature',async t=>{
  const f=await fixture(t),entered=deferred(),answer=deferred(),controller=new AbortController();let forwarded=0;
  const write=f.requester.writeJSON.bind(f.requester);f.requester.writeJSON=async v=>{if(v.operation==='stored')forwarded++;return write(v);};
  let payload;const running=f.run({}, {signal:controller.signal,signStored:p=>{payload=p;entered.resolve();return answer.promise;}});
  await entered.promise;controller.abort();failed(await running);
  assert.deepEqual(fs.readFileSync(f.destination),f.bytes);answer.resolve(await f.requesterOptions.signStored(payload));
  await new Promise(r=>setImmediate(r));assert.equal(forwarded,0);retained(f);
});

test('incomplete guest streams expire, remove only their partial spool and never contact storage',async t=>{
  const f=await fixture(t),sentinel=path.join(f.spoolDirectory,'keep.txt');fs.writeFileSync(sentinel,'retained operator file');
  const running=Promise.allSettled([
    bridgeEncryptedResult(f.bridgeGuest,f.bridgeRequester,{...f.bridgeOptions,timeoutMs:150}),
    receiveHostedResult(f.requester,f.requesterOptions)]);
  await f.guest.writeJSON({protocol:'cannabis.guest-wire.v1',operation:'result',approvalDigest:f.expected.digest,
    resultEnvelope:f.result.resultEnvelope,ciphertextBytes:f.bytes.length});
  await f.guest.writeChunk(f.bytes.subarray(0,CHUNK));
  const results=await running;assert.ok(results.every(r=>r.status==='rejected'));
  assert.deepEqual(fs.readdirSync(f.spoolDirectory),['keep.txt']);assert.equal(fs.readFileSync(sentinel,'utf8'),'retained operator file');
  assert.equal(f.requests.length,0);assert.equal(fs.existsSync(f.destination),false);
});

test('existing requester files remain unchanged and read grants are bound to local role and origin',async t=>{
  const f=await fixture(t);fs.writeFileSync(f.destination,'retained owner file');
  failed(await f.run());assert.equal(fs.readFileSync(f.destination,'utf8'),'retained owner file');
  assert.equal(f.requests.some(r=>r.method==='GET'),false);
  for(const change of [{role:'upload'},{origin:'https://elsewhere.invalid'},{approvalDigest:'0x'+'22'.repeat(32)}]) {
    const g=await fixture(t);failed(await g.run({}, {access:{...g.read,...change}}));assert.equal(g.requests.some(r=>r.method==='GET'),false);
  }
});

test('streaming requester rejects redirected, encoded and excessive HTTP responses without signing',async t=>{
  for(const kind of ['redirect','encoding','oversize','truncated','manifest']) {
    const f=await fixture(t);
    failed(await f.run({}, {fetchImpl:async(url,options)=>{
      const r=await f.requesterOptions.fetchImpl(url,options);
      if(!url.endsWith('/manifest'))return r;
      const m=await r.json();
      if(kind==='manifest')m.resultEnvelope+='A';
      const changed=new Response(JSON.stringify(m),{headers:{'Content-Type':'application/json',
        ...(kind==='encoding'?{'Content-Encoding':'gzip'}:{}),...(kind==='oversize'?{'Content-Length':String(7*1024*1024)}:{}),
        ...(kind==='truncated'?{'Content-Length':'1'}:{})}});
      if(kind==='redirect')Object.defineProperty(changed,'redirected',{value:true});return changed;
    },signStored:()=>assert.fail('Untrusted response must not reach signing')}));
    assert.equal(fs.existsSync(f.destination),false);
  }
});

test('separate operator process bridges only public approval and encrypted artifacts without requester custody',async t=>{
  const f=await fixture(t),listener=net.createServer();let child,socket,guest,requester,timer;
  await new Promise(r=>listener.listen(0,'127.0.0.1',r));
  const configFile=path.join(f.dir,'operator-config.json'),report=path.join(f.dir,'operator-report.json');
  const {fetchImpl,wait,...bridge}=f.bridgeOptions;
  const config=JSON.stringify({bridge,requesterPort:listener.address().port,report});
  for(const secret of [f.identity,f.owner.privateKey,f.read.token])assert.ok(!config.includes(secret));
  fs.writeFileSync(configFile,config,{flag:'wx',mode:0o600});
  let exited;
  try {
    const connected=once(listener,'connection');
    child=spawn(process.execPath,['--disable-warning=ExperimentalWarning','test/helpers/hosted_result_bridge.mjs',configFile],{windowsHide:true,stdio:['pipe','pipe','pipe']});
    let errors='';child.stderr.on('data',b=>{errors+=b.toString();assert.ok(errors.length<8192);});
    exited=once(child,'exit');timer=setTimeout(()=>child.kill(),7000);
    [socket]=await Promise.race([connected,exited.then(()=>{throw Error('Operator exited before connecting');})]);
    guest=new GuestWire(child.stdout,child.stdin,{timeoutMs:5000});requester=new GuestWire(socket,socket,{timeoutMs:5000});
    const [sent,received]=await Promise.all([
      sendEncryptedResult(guest,f.result,f.expected,{maxCiphertextBytes:1024*1024}),
      receiveHostedResult(requester,f.requesterOptions)]);
    const [code]=await exited;assert.equal(code,0,errors);assert.equal(errors,'');
    assert.equal(sent.requesterAcknowledgedStorage,true);assert.equal(received.storageAcknowledged,true);
    assert.equal(JSON.parse(fs.readFileSync(report)).requesterStorageSignatureVerified,true);
    assert.deepEqual(fs.readFileSync(f.destination),f.bytes);retained(f);
  } finally {
    clearTimeout(timer);guest?.fail();guest?.close();requester?.fail();requester?.close();socket?.destroy();
    if(child&&child.exitCode===null&&child.signalCode===null){child.kill();await exited;}
    await new Promise(r=>listener.close(r));
  }
});

test('a metadata-write failure preserves the complete encrypted spool for local recovery',async t=>{
  const f=await fixture(t),open=fs.openSync;let injected=false;
  fs.openSync=(file,...args)=>{
    if(typeof file==='string'&&file.startsWith(f.spoolDirectory+path.sep)&&path.basename(file)==='source.json') {
      injected=true;throw Object.assign(Error('Owned metadata storage fault'),{code:'ENOSPC'});
    }
    return open(file,...args);
  };
  let results;try{results=await f.run();}finally{fs.openSync=open;}
  failed(results);assert.equal(injected,true);
  const directories=fs.readdirSync(f.spoolDirectory);assert.equal(directories.length,1);
  const saved=path.join(f.spoolDirectory,directories[0]);assert.deepEqual(fs.readFileSync(path.join(saved,'result.age')),f.bytes);
  assert.equal(results[1].reason.recoveryDirectory,saved);assert.equal(JSON.stringify(results[1].reason).includes(saved),false);
  assert.equal(f.requests.length,0);assert.equal(fs.existsSync(f.destination),false);
});

test('cancelling an actual partially delivered HTTP chunk closes its socket and discards only the incomplete requester file',async t=>{
  const f=await fixture(t),entered=deferred(),controller=new AbortController(),handler=f.server.listeners('request')[0];let closed=false;
  f.server.removeListener('request',handler);
  f.server.on('request',(req,res)=>{
    if(req.method==='GET'&&req.url.endsWith('/chunks/0')) {
      res.on('close',()=>closed=true);res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':String(CHUNK)});
      res.write(f.bytes.subarray(0,1));entered.resolve();return;
    }
    return handler(req,res);
  });
  const running=f.run({}, {signal:controller.signal,signStored:()=>assert.fail('Interrupted retrieval must not reach signing')});
  await entered.promise;controller.abort();failed(await running);
  for(let i=0;i<20&&!closed;i++)await new Promise(r=>setTimeout(r,10));assert.equal(closed,true);
  assert.equal(fs.existsSync(f.destination),false);assert.equal(fs.readdirSync(f.dir).some(n=>n.startsWith('.cannabis-receive-')),false);retained(f);
});
