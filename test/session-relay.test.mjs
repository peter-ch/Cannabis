import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { Transform } from 'node:stream';
import { createHash,generateKeyPairSync,randomBytes } from 'node:crypto';
import { CompactEncrypt,compactDecrypt,calculateJwkThumbprint } from 'jose';
import { TypedDataEncoder } from 'ethers';
import { Encrypter } from 'age-encryption';
import { guestInitialization } from '../compute/guest_initialization.mjs';
import { validateAttestationPolicy } from '../compute/attestation.mjs';
import { deliveryApprovalTypes } from '../compute/key_delivery.mjs';
import { recoverResultKey } from '../compute/result_keys.mjs';
import { sealResultDelivery } from '../compute/result_delivery.mjs';
import { ResultInbox } from '../compute/result_inbox.mjs';
import { GuestWire,serveGuestSession,sendGuestExecution,receiveGuestEvidence } from '../compute/result_transport.mjs';
import { sendEncryptedInput,receiveEncryptedInput } from '../compute/input_transport.mjs';
import { relayConfiguredSession } from '../operator/session-relay.mjs';
import { receiveSessionResultAccess } from '../requester/session-access.mjs';
import { receiveHostedResult } from '../requester/hosted-result.mjs';
import { createWorkServer } from '../service/work-server.mjs';
import { approvedBrowserFixture } from './fixtures/approved-browser.mjs';
import { openApprovedResults } from '../web/work-approvals.js';
const hash=v=>createHash('sha256').update(v).digest('hex'),deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
async function fixture(t,version='2') {
  const types=deliveryApprovalTypes(version);
  const root=fs.realpathSync(os.tmpdir()),dir=fs.mkdtempSync(path.join(root,'cannabis-session-relay-'));
  const base=await approvedBrowserFixture(),enc=new Encrypter();enc.addRecipient(base.receipt.recipient);
  const inputBytes=Buffer.from(await enc.encrypt(randomBytes(140000))),packageSHA256=hash(inputBytes);
  const f=await approvedBrowserFixture({owner:base.owner,identity:base.identity,repetitions:6000,packageSHA256,version}),entry=f.bundle.entries[0],initialValue=entry.approval.value;
  const input=path.join(dir,'input.age'),guestInput=path.join(dir,'guest-input.age'),guestResult=path.join(dir,'guest-result.age'),destination=path.join(dir,'requester-result.age');
  fs.writeFileSync(input,inputBytes);fs.writeFileSync(guestResult,f.encrypted[0]);const spoolDirectory=path.join(dir,'spool');fs.mkdirSync(spoolDirectory);
  const binding={chainId:31337,escrow:f.bundle.context.escrow,
    ...Object.fromEntries(['orderId','leaseDigest','reservationId','attempt','rank','worldSize'].map(k=>[k,initialValue[k]])),
    ...Object.fromEntries(['packageSHA256','policySHA256','runtimeSHA256','taskSHA256'].map(k=>[k,initialValue[k].slice(2)])),acceleratorClass:'cpu'};
  const initialization={schema:'cannabis.guest-initialization.v1',tee:'snp',requester:f.owner.address,jobId:f.spec.id,binding};
  if(version==='3'){initialization.schema='cannabis.guest-initialization.v2';binding.configurationSHA256=initialValue.configurationSHA256;}
  const now=Math.floor(Date.now()/1000),verifier=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const policy={schema:'cannabis.attestation.trustee-policy.v1',issuer:'Owned protocol fixture',signingJwk:verifier.publicKey.export({format:'jwk'}),
    verifierBuild:'Synthetic protocol only',appraisalPolicyId:'owned-fixture',maxTokenAgeSeconds:90,maxTokenLifetimeSeconds:120,challengeTTLSeconds:90,tee:'snp',
    measurements:{launch:'11'.repeat(48),initData:guestInitialization(initialization).digest,minimumTCB:{bootloader:1,tee:1,snp:1,microcode:1}}};
  const challenge={schema:'cannabis.attestation.challenge.v1',nonce:randomBytes(32).toString('hex'),issuedAt:now-1,expiresAt:now+60,
    attestationPolicySHA256:validateAttestationPolicy(policy),binding};
  // A transport fixture plan only. It supplies no launch signatures, actual
  // funding or hardware admission. The kernel integration checks those separately.
  const launch={initialization,policy,challenge,interval:{start:now-1,end:now+90},
    transport:{timeoutMs:15000,maxCiphertextBytes:1024*1024},execution:{profile:{ciphertext:{inputBytes:1024*1024,outputBytes:1024*1024}}}};
  const portServer=net.createServer();await new Promise(r=>portServer.listen(0,'127.0.0.1',r));const port=portServer.address().port;await new Promise(r=>portServer.close(r));
  const origin='http://127.0.0.1:'+port,{server,relay}=createWorkServer({file:':memory:',resultFile:':memory:',origin});await new Promise(r=>server.listen(port,'127.0.0.1',r));
  const inbox=new ResultInbox(path.join(dir,'inbox.sqlite'),f.bundle.context),wires=[],streams=[],captured=[];
  const pair=()=>{
    const stream=()=>{const s=new Transform({highWaterMark:65536,transform(b,e,done){captured.push(Buffer.from(b));done(null,b);}});streams.push(s);return s;};
    const a=stream(),b=stream(),left=new GuestWire(a,b,{timeoutMs:18000}),right=new GuestWire(b,a,{timeoutMs:18000});wires.push(left,right);return [left,right];
  };
  const [guest,operatorGuest]=pair(),[operatorRequester,requester]=pair();
  let channel,evidence,expected,resultEnvelope,executions=0,reservations=0;
  const guestRun=async()=>{
    try {
      await receiveEncryptedInput(guest,{destination:guestInput,packageSHA256,maxCiphertextBytes:1024*1024});
      assert.deepEqual(fs.readFileSync(guestInput),inputBytes);
      channel=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
      const raw=Buffer.from(JSON.stringify({syntheticOwnedProtocolEvidence:true}));
      evidence={schema:'cannabis.guest-evidence.v1',nonce:challenge.nonce,channelJwk:channel.publicKey.export({format:'jwk'}),
        evidence:raw.toString('base64url'),agent:{ownedFixtureOnly:true},evidenceSHA256:hash(raw),hardwareVerified:false,executionAuthorized:false};
      const session={evidence:async()=>evidence,executeNative:async(envelope,approval)=>{
        executions++;assert.equal(approval.digest,expected.digest);
        const opened=await compactDecrypt(envelope,channel.privateKey);assert.equal(new TextDecoder().decode(opened.plaintext),'OWNED WRAPPED FIXTURE INPUT KEY');
        return {ciphertext:guestResult,resultEnvelope};
      },close:()=>{},serviceInterval:launch.interval};
      return await serveGuestSession(session,guest,{maxCiphertextBytes:1024*1024});
    }catch(e){guest.fail();throw e;}
  };
  const prepare=async received=>{
    assert.equal(received.evidence,evidence.evidence);const value={...initialValue,nonce:'0x'+challenge.nonce,
      attestationPolicySHA256:'0x'+challenge.attestationPolicySHA256,channelKeySHA256:'0x'+hash(canonical(received.channelJwk)),notBefore:now,expiresAt:now+55};
    const domain=entry.approval.domain;
    expected={domain,value,digest:TypedDataEncoder.hash(domain,types,value),requester:f.owner.address,jobId:f.spec.id,
      requesterSignature:await f.owner.signTypedData(domain,types,value)};
    const key=await recoverResultKey(entry.custody,f.identity,{releaseId:value.releaseId,recipient:entry.recipient,resultKeySHA256:value.resultKeySHA256});
    try{resultEnvelope=await sealResultDelivery(f.receipt,key,expected);}finally{key.fill(0);}
    f.bundle.entries[0]={...entry,approval:expected,envelope:resultEnvelope};
    inbox.activate({schema:'cannabis.key-delivery.record.v'+version,keyWrapped:true,approvalDigest:expected.digest,releaseId:value.releaseId,expectedApproval:expected},
      {resultRecipient:entry.recipient});
    const envelope=await new CompactEncrypt(Buffer.from('OWNED WRAPPED FIXTURE INPUT KEY')).setProtectedHeader({alg:'ECDH-ES+A256KW',enc:'A256GCM',
      typ:'cannabis-job-key+jwe',kid:await calculateJwkThumbprint(received.channelJwk),'cannabis-approval':expected.digest}).encrypt(channel.publicKey);
    return {schema:'cannabis.key-delivery.record.v'+version,expectedApproval:expected,envelope};
  };
  const reserveResult=({approvalDigest,maxCiphertextBytes},signal)=>{
    assert.equal(signal.aborted,false);reservations++;
    const {uploadToken,readToken,...common}=relay.reserve({approvalDigest,maxCiphertextBytes,expiresAt:Date.now()+60000});
    return {upload:{...common,origin,role:'upload',token:uploadToken},read:{...common,origin,role:'read',token:readToken}};
  };
  const options={launch,origin,spoolDirectory,reserveResult,wait:async()=>{}};
  const requesterRun=async({changeRecord=r=>r,changeAccess=a=>a}={})=>{
    try {
      await sendEncryptedInput(requester,{source:input,packageSHA256,maxCiphertextBytes:1024*1024});
      const record=await prepare(await receiveGuestEvidence(requester));await sendGuestExecution(requester,await changeRecord(record));
      const access=changeAccess(await receiveSessionResultAccess(requester,{approvalDigest:expected.digest,origin}));
      return await receiveHostedResult(requester,{inbox,approvalDigest:expected.digest,loadResultKey:b=>recoverResultKey(entry.custody,f.identity,b),
        destination,maxCiphertextBytes:1024*1024,signStored:p=>f.owner.signTypedData(p.domain,p.types,p.value),access,origin,timeoutMs:15000,wait:async()=>{}});
    }catch(e){requester.fail();throw e;}
  };
  const run=(operator={},client={})=>Promise.allSettled([guestRun(),relayConfiguredSession(operatorGuest,operatorRequester,{...options,...operator}),requesterRun(client)]);
  t.after(async()=>{
    for(const wire of wires){wire.fail();wire.close();}for(const stream of streams)stream.destroy();
    server.closeAllConnections();await new Promise(r=>server.close(r));inbox.close();
    assert.equal(path.dirname(fs.realpathSync(dir)),root);fs.rmSync(dir,{recursive:true,force:true});
  });
  return {...f,dir,input,guestInput,destination,spoolDirectory,guest,requester,operatorGuest,operatorRequester,options,run,reserveResult,captured,
    get executions(){return executions;},get reservations(){return reservations;}};
}
const failed=r=>{for(const item of r)assert.equal(item.status,'rejected');};

test('configuration-bound session refuses downgrade or substitution before execution or relay reservation',async t=>{
  for(const variant of ['version','configuration']) {
    const f=await fixture(t,'3');
    const results=await f.run({}, {changeRecord:r=>{
      if(variant==='version'){r.schema='cannabis.key-delivery.record.v2';r.expectedApproval.domain.version='2';delete r.expectedApproval.value.configurationSHA256;}
      else r.expectedApproval.value.configurationSHA256='0x'+'ff'.repeat(32);
      return r;
    }});
    failed(results);assert.equal(f.executions,0);assert.equal(f.reservations,0);
  }
});

for(const version of ['2','3'])test(`v${version} session preserves input/evidence ordering, sealed execution, role-specific access and requester acknowledgement`,async t=>{
  const f=await fixture(t,version),results=await f.run();for(const r of results)assert.equal(r.status,'fulfilled',results.map(x=>x.reason?.message).join(' | '));
  assert.equal(f.executions,1);assert.equal(f.reservations,1);assert.equal(results[0].value.requesterAcknowledgedStorage,true);
  assert.equal(results[1].value.hardwareValidated,false);assert.equal(results[1].value.guestCompletionObserved,false);
  assert.equal(results[2].value.paymentAuthorized,false);
  const files=await openApprovedResults({...f,encrypted:[new Uint8Array(fs.readFileSync(f.destination))]});
  assert.equal(new TextDecoder().decode(files.get('finished/answer.txt')),'owned verification result\n'.repeat(6000));
  const seen=Buffer.concat(f.captured);
  for(const secret of [f.identity,f.owner.privateKey,'OWNED WRAPPED FIXTURE INPUT KEY','owned verification result',f.input,f.destination])
    assert.equal(seen.includes(Buffer.from(secret)),false);
});

test('changed encrypted input cannot reach evidence, reservation or execution',async t=>{
  const f=await fixture(t),write=f.requester.writeChunk.bind(f.requester);let changed=false;
  f.requester.writeChunk=async bytes=>{const b=Buffer.from(bytes);if(!changed){changed=true;b[42]^=1;}return write(b);};
  failed(await f.run());assert.equal(f.executions,0);assert.equal(f.reservations,0);assert.equal(fs.existsSync(f.guestInput),false);
});

test('changed signed workload, channel header and approval signature fail before reservation or guest forwarding',async t=>{
  for(const variant of ['workload','channel','signature','ephemeral-key']) {
    const f=await fixture(t);failed(await f.run({}, {changeRecord:record=>{
      const r=structuredClone(record);
      if(variant==='workload')r.expectedApproval.value.runtimeSHA256='0x'+'ab'.repeat(32);
      else if(variant==='signature')r.expectedApproval.requesterSignature='0x'+'11'.repeat(65);
      else {const parts=r.envelope.split('.'),header=JSON.parse(Buffer.from(parts[0],'base64url'));
        if(variant==='channel')header.kid='another-channel';else header.epk.d='unexpected-private-field';
        parts[0]=Buffer.from(JSON.stringify(header)).toString('base64url');r.envelope=parts.join('.');}
      return r;
    }}));assert.equal(f.executions,0);assert.equal(f.reservations,0);
  }
});

test('storage refusal, mixed grants and a wrong configured origin prevent execution',async t=>{
  for(const variant of ['full','mixed','origin']) {
    const f=await fixture(t);failed(await f.run({reserveResult:(request,signal)=>{
      if(variant==='full')throw Error('Owned full storage');const grants=f.reserveResult(request,signal);
      if(variant==='mixed')grants.read.id='00000000-0000-4000-8000-000000000000';else grants.read.origin='https://elsewhere.invalid';return grants;
    }}));assert.equal(f.executions,0);assert.equal(fs.existsSync(f.destination),false);
  }
});

test('cancellation during reservation prevents a late callback from forwarding execution or read access',async t=>{
  const f=await fixture(t),entered=deferred(),response=deferred(),controller=new AbortController();let accessMessages=0;
  const write=f.operatorRequester.writeJSON.bind(f.operatorRequester);f.operatorRequester.writeJSON=async v=>{if(v.operation==='result-access')accessMessages++;return write(v);};
  const running=f.run({signal:controller.signal,reserveResult:()=>{entered.resolve();return response.promise;}});
  await Promise.race([entered.promise,running.then(()=>{throw Error('Session ended before reservation');})]);
  controller.abort();failed(await running);response.resolve({late:true});await new Promise(r=>setImmediate(r));
  assert.equal(f.executions,0);assert.equal(accessMessages,0);
});

test('requester rejects altered access and the operator waits for matching readiness before execution',async t=>{
  const f=await fixture(t),write=f.operatorRequester.writeJSON.bind(f.operatorRequester);
  f.operatorRequester.writeJSON=async v=>{const value=structuredClone(v);if(value.operation==='result-access')value.access.role='upload';return write(value);};
  failed(await f.run());assert.equal(f.executions,0);assert.equal(fs.existsSync(f.destination),false);
});

test('changed evidence is refused before the requester can prepare a key delivery',async t=>{
  const f=await fixture(t),write=f.guest.writeJSON.bind(f.guest);let evidenceForwarded=false;
  const forward=f.operatorRequester.writeJSON.bind(f.operatorRequester);
  f.operatorRequester.writeJSON=async v=>{if(v.operation==='evidence')evidenceForwarded=true;return forward(v);};
  f.guest.writeJSON=async v=>{const value=structuredClone(v);if(value.operation==='evidence')value.evidence.nonce='ab'.repeat(32);return write(value);};
  failed(await f.run());assert.equal(evidenceForwarded,false);assert.equal(f.reservations,0);assert.equal(f.executions,0);
});

test('mismatched requester readiness cannot forward the sealed execution command',async t=>{
  const f=await fixture(t),write=f.requester.writeJSON.bind(f.requester);
  f.requester.writeJSON=async v=>{const value=structuredClone(v);
    if(value.operation==='result-access-ready')value.relayId='00000000-0000-4000-8000-000000000000';return write(value);};
  failed(await f.run());assert.equal(f.reservations,1);assert.equal(f.executions,0);
});
