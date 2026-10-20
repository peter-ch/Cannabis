import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import {PassThrough} from 'node:stream';
import {setImmediate as nextTurn} from 'node:timers/promises';
import {groupFixture} from './helpers/group_fixture.mjs';
import {GuestGroupMesh,RequesterGroupReadiness,validateGroupPacket} from '../compute/group_mesh.mjs';
import {GroupPacketPipe} from '../compute/group_packet_pipe.mjs';
import {verifyGroupAdmission,groupDeliveryBinding} from '../compute/group_admission.mjs';
import {WorkflowStore} from '../requester/workflow-store.mjs';
import {workflowSigningSchema} from '../requester/workflow-wallet-schema.mjs';
import {groupAdmissionTypes,groupStartTypes} from '../compute/group_admission.mjs';
import {deliveryTypesV5,deliveryTypesV6} from '../compute/key_delivery.mjs';
import {approvalTypesV5,approvalTypesV6} from '../web/work-approvals.js';
function packet(from,to,text='private rank message') {
  const content=Buffer.from(text),p=Buffer.alloc(28+content.length);p[0]=0x45;p.writeUInt16BE(p.length,2);p[8]=64;p[9]=17;
  p.set([10,211,0,from+1,10,211,0,to+1],12);p.writeUInt16BE(20000,20);p.writeUInt16BE(20001,22);p.writeUInt16BE(content.length+8,24);content.copy(p,28);return p;
}
async function prepared(t,nodes) {
  const f=await groupFixture({nodes});t.after(f.close);
  const meshes=[],received=Array.from({length:nodes},()=>[]),signal=AbortSignal.timeout(10000);
  t.after(()=>Promise.all(meshes.map(m=>m.close())));
  for(let rank=0;rank<nodes;rank++)meshes.push(await GuestGroupMesh.create(
    await verifyGroupAdmission(f.proof,f.network,f.approval,{clock:f.clock}),rank,f.keys[rank],{
      onPacket:(peer,p)=>{received[rank].push({peer,packet:Buffer.from(p)});},signal}));
  await Promise.all(meshes.map(m=>m.listen()));
  const readiness=await Promise.all(meshes.map(m=>m.connect()));
  const reviewer=await RequesterGroupReadiness.create(f.admission,f.requesterKey);t.after(()=>reviewer.close());
  const payload=reviewer.review(readiness),start={schema:'cannabis.protected-group-start.v1',readiness,payload,
    requesterSignature:await f.requester.signTypedData(payload.domain,payload.types,payload.value)};
  return {...f,meshes,received,reviewer,start};
}
for(const nodes of [2,4])test(`${nodes} ranks authenticate one roster/start and retain protected transport until every rank completes`,async t=>{
  const f=await prepared(t,nodes);
  assert.equal(f.admission.chainVerified,false);assert.equal(f.admission.executionAuthorized,false);
  for(const m of f.meshes)assert.throws(()=>m.assertActive());
  await Promise.all(f.meshes.map(m=>m.start(f.start)));
  for(let rank=0;rank<nodes;rank++) {
    f.meshes[rank].assertActive();
    const entry=f.approval.group.peers[rank];
    assert.deepEqual(groupDeliveryBinding(f.admission,{approval:f.approval,start:f.start},entry.initialization.binding,entry.channelJwk,f.clock()),
      {groupDigest:f.admission.groupDigest,groupStartDigest:f.start.payload.digest});
    await f.meshes[rank].sendPacket((rank+1)%nodes,packet(rank,(rank+1)%nodes));
  }
  // DONE shares the ordered authenticated channel with preceding packets.
  await Promise.all(f.meshes.map(m=>m.finish()));
  for(let rank=0;rank<nodes;rank++) {
    assert.equal(f.received[rank].length,1);
    assert.equal(f.received[rank][0].peer,(rank+nodes-1)%nodes);
    assert.equal(f.received[rank][0].packet.subarray(28).toString(),'private rank message');
  }
  await Promise.all(f.meshes.map(m=>m.close()));assert.ok(f.meshes.every(m=>m.status.state==='complete'));
});

test('packet write completion during successful group retirement does not abort the result',async t=>{
  const f=await prepared(t,2);
  await Promise.all(f.meshes.map(m=>m.start(f.start)));
  const input=new PassThrough(),output=new PassThrough(),pipe=new GroupPacketPipe(131072),failures=[];
  pipe.bind(f.meshes[0]);pipe.attach(input,output,()=>failures.push('aborted'));
  t.after(()=>pipe.close());
  const original=tls.TLSSocket.prototype.write;
  let release,forwarded;
  const sent=new Promise(resolve=>{forwarded=resolve;});
  t.mock.method(tls.TLSSocket.prototype,'write',function(bytes,...args){
    // Forward the actual authenticated packet but hold its local completion.
    // The all-rank DONE barrier may legitimately finish before this callback.
    if(Buffer.isBuffer(bytes)&&bytes[0]===4&&bytes.subarray(5).equals(packet(0,1))){
      const done=args.pop();
      return original.call(this,bytes,...args,error=>{release=()=>done(error);forwarded();});
    }
    return original.call(this,bytes,...args);
  });
  const payload=packet(0,1),frame=Buffer.alloc(4+payload.length);
  frame.writeUInt32BE(payload.length);payload.copy(frame,4);output.write(frame);
  await sent;
  await Promise.all([pipe.finish(),f.meshes[1].finish()]);
  release();await nextTurn();
  assert.equal(f.received[1].length,1);
  assert.equal(f.meshes[0].status.state,'complete');
  assert.deepEqual(failures,[]);
});

for(const fault of ['input-error','output-error','output-eof'])test(`packet bridge ${fault} before all ranks finish still aborts`,async t=>{
  const f=await prepared(t,2);
  await Promise.all(f.meshes.map(m=>m.start(f.start)));
  const input=new PassThrough(),output=new PassThrough(),pipe=new GroupPacketPipe(131072),failures=[];
  pipe.bind(f.meshes[0]);pipe.attach(input,output,()=>{
    failures.push('aborted');f.meshes[0].close(Error('Owned premature bridge failure'));
  });
  t.after(()=>pipe.close());
  const finishing=pipe.finish(),rejected=assert.rejects(finishing,/Protected group/);
  assert.equal(f.meshes[0].status.state,'finishing');
  if(fault==='input-error')input.destroy(Error('Owned premature input failure'));
  else if(fault==='output-error')output.destroy(Error('Owned premature output failure'));
  else output.end();
  await rejected;
  assert.ok(failures.length>0);
  assert.equal(f.meshes[0].status.state,'failed');
});

test('changed peers, missing ranks, forged readiness, replayed starts and non-peer packets fail closed',async t=>{
  const f=await prepared(t,2);
  for(const mutate of [g=>g.peers.pop(),g=>g.peers.reverse(),g=>g.peers[1].channelJwk=g.peers[0].channelJwk,
    g=>g.peers[1].endpoint=g.peers[0].endpoint,g=>g.peers[0].challenge.nonce='11'.repeat(32)]) {
    const changed=structuredClone(f.approval);mutate(changed.group);
    await assert.rejects(verifyGroupAdmission(f.proof,f.network,changed,{clock:f.clock}));
  }
  const forged=structuredClone(f.start.readiness);forged[1].authenticator='A'.repeat(43);assert.throws(()=>f.reviewer.review(forged));
  await Promise.all(f.meshes.map(m=>m.start(f.start)));
  await assert.rejects(f.meshes[0].start(f.start));
  for(const mutate of [p=>p[16]=169,p=>p[15]=2,p=>p[9]=1,p=>p.writeUInt16BE(0x2000,6),p=>p[0]=0x65]) {
    const p=packet(0,1);mutate(p);assert.throws(()=>validateGroupPacket(p,0,1,2));
  }
  await assert.rejects(f.meshes[0].sendPacket(1,packet(1,0)));
  assert.equal(f.meshes[0].status.state,'failed');
});

test('group dispatch is atomic and remains consumed across requester restart',t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-group-store-')),file=path.join(root,'workflow.sqlite');
  t.after(()=>fs.rmSync(root,{recursive:true}));
  const ids=[1,2].map(n=>'0x'+String(n).padStart(64,'0')),
    manifest={reservations:ids.map(reservationId=>({reservationId,task:0}))};
  let store=new WorkflowStore(file,manifest,{create:true,clock:()=>1000});
  try {
    assert.throws(()=>store.claimGroup([...ids,'0x'+'3'.repeat(64)]));assert.ok(store.snapshot().every(r=>r.state==='queued'));
    const tokens=store.claimGroup(ids);assert.equal(tokens.length,2);assert.ok(store.snapshot().every(r=>r.state==='uncertain'));
    assert.throws(()=>store.claim(ids[0]));store.close();store=new WorkflowStore(file,manifest,{clock:()=>1000});
    assert.ok(store.snapshot().every(r=>r.state==='uncertain'));assert.throws(()=>store.claimGroup(ids));
  }finally{store.close();}
});

test('equivalent typed-data domain encodings cannot hide inconsistent group results',async()=>{
  const {assertCompatibleGroupResults}=await import('../compute/group_results.mjs'),h=n=>'0x'+n.toString(16).padStart(64,'0');
  const first={domain:{version:'5',chainId:31337,verifyingContract:'0x'+'Ab'.repeat(20)},
    value:{orderId:h(1),packageSHA256:h(2),taskSHA256:h(3),attempt:1,worldSize:2,rank:0,groupDigest:h(4),groupStartDigest:h(5)}},
    second=structuredClone(first);
  second.domain.chainId='0x7a69';second.domain.verifyingContract=second.domain.verifyingContract.toLowerCase();second.value.rank=1;
  assert.doesNotThrow(()=>assertCompatibleGroupResults([first,second]));
  second.value.groupStartDigest=h(6);assert.throws(()=>assertCompatibleGroupResults([first,second]),/same|share/);
  second.domain.chainId='31337';assert.throws(()=>assertCompatibleGroupResults([first,second]),/same|share/);
  second.domain.version='3';assert.throws(()=>assertCompatibleGroupResults([first,second]),/same|share/);
});

test('wallet and browser recovery preserve the exact group authorization schemas',()=>{
  assert.deepEqual(workflowSigningSchema('group','1').types,groupAdmissionTypes);
  assert.deepEqual(workflowSigningSchema('group-start','1').types,groupStartTypes);
  assert.deepEqual(workflowSigningSchema('key-release','5').types,deliveryTypesV5);
  assert.deepEqual(workflowSigningSchema('key-release','6').types,deliveryTypesV6);
  assert.deepEqual(approvalTypesV5,deliveryTypesV5);assert.deepEqual(approvalTypesV6,deliveryTypesV6);
});
