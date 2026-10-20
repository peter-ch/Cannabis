import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {TypedDataEncoder} from 'ethers';
import {WorkflowStore} from '../requester/workflow-store.mjs';
import {createWorkflowApprovalServer} from '../requester/approval-server.mjs';
import {WorkflowWallet} from '../requester/workflow-wallet.js';
import {validateWorkflowReview} from '../requester/workflow-wallet-schema.mjs';
import {workflowApprovals} from './helpers/workflow_approvals.mjs';
const h=n=>'0x'+n.toString(16).padStart(64,'0');

test('workflow durable consume survives concurrent clients, restart and unknown execution',()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-workflow-store-')),file=path.join(root,'workflow.sqlite');let now=100;
  const manifest={workflowSHA256:'11'.repeat(32),reservations:[{reservationId:h(1),task:0},{reservationId:h(2),task:1}]};
  let a,b;
  try {
    a=new WorkflowStore(file,manifest,{create:true,clock:()=>now});b=new WorkflowStore(file,manifest,{clock:()=>now});
    const claim=a.claim(h(1));assert.throws(()=>b.claim(h(1)));claim.approval(h(3));a.close();a=null;b.close();b=null;
    a=new WorkflowStore(file,manifest,{clock:()=>now});assert.equal(a.snapshot()[0].state,'uncertain');assert.throws(()=>a.claim(h(1)));
    assert.throws(()=>new WorkflowStore(file,{...manifest,workflowSHA256:'22'.repeat(32)},{clock:()=>now}));
    assert.throws(()=>a.stored(h(1),h(9),h(3),'33'.repeat(32)));
    a.stored(h(1),claim.releaseId,h(3),'33'.repeat(32));assert.equal(a.snapshot()[0].state,'stored');assert.throws(()=>a.claim(h(1)));
    assert.throws(()=>a.stored(h(1),claim.releaseId,h(4),'33'.repeat(32)));
    now=99;assert.throws(()=>a.snapshot());now=101;assert.equal(a.snapshot()[1].state,'queued');
    a.close();a=null;fs.unlinkSync(file);assert.throws(()=>new WorkflowStore(file,manifest,{clock:()=>now}));
  }finally{a?.close();b?.close();assert.equal(path.dirname(fs.realpathSync(root)),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});}
});

function walletProvider(owner,item,{duringSign}={}) {
  const listeners=new Map(),calls=[];
  return {calls,on:(name,fn)=>listeners.set(name,fn),removeListener:name=>listeners.delete(name),
    request:async({method,params})=>{calls.push(method);
      if(['eth_accounts','eth_requestAccounts'].includes(method))return [owner.address];
      if(method==='eth_chainId')return '0x7a69';
      if(method==='eth_getBlockByNumber')return {hash:item.input.genesisHash};
      if(method==='eth_signTypedData_v4'){assert.equal(params[0],owner.address);duringSign?.(listeners);return item.signature;}
      throw Error('Unexpected wallet operation');
    }};
}
test('workflow wallet accepts exact protocol schemas and rejects transaction-like or changed wallet requests',async()=>{
  const {owner,items}=await workflowApprovals();
  for(const item of items) {
    const {input}=item,review={id:'55'.repeat(32),kind:input.kind,reservationId:input.reservationId,requester:owner.address,
      genesisHash:input.genesisHash,expiresAt:input.expiresAt*1000,digest:input.payload.digest,
      typedData:TypedDataEncoder.getPayload(input.payload.domain,input.payload.types,input.payload.value)};
    validateWorkflowReview(review);const wallet=new WorkflowWallet(),provider=walletProvider(owner,item);wallet.select(provider);await wallet.connect();
    assert.equal(await wallet.sign(review),item.signature);assert.equal(provider.calls.filter(v=>v==='eth_signTypedData_v4').length,1);
    const changed=structuredClone(review);changed.typedData.domain.name='Permit';assert.throws(()=>validateWorkflowReview(changed));
    const substituted=structuredClone(review);substituted.typedData.message.approveSpending=true;assert.throws(()=>validateWorkflowReview(substituted));
    wallet.clear();const switcher=walletProvider(owner,item,{duringSign:listeners=>listeners.get('chainChanged')()});
    wallet.select(switcher);await wallet.connect();await assert.rejects(wallet.sign(review));wallet.clear();
    assert.ok(provider.calls.every(v=>['eth_requestAccounts','eth_accounts','eth_chainId','eth_getBlockByNumber','eth_signTypedData_v4'].includes(v)));
  }
});

test('local workflow review requires its capability, exact origin, owner signature and live request',async()=>{
  const {items}=await workflowApprovals(),controller=new AbortController();let starts=0;
  const server=await createWorkflowApprovalServer({snapshot:()=>({slots:[]}),start:async()=>{starts++;return {};}});
  const token=new URL(server.url).hash.slice(1),headers={Authorization:'Bearer '+token,Origin:server.origin,'Content-Type':'application/json'};
  try {
    assert.equal((await fetch(server.origin+'/api/state')).status,400);
    assert.equal((await fetch(server.origin+'/api/start',{method:'POST',headers:{...headers,Origin:'https://outside.invalid'},body:'{}'})).status,400);
    assert.equal(starts,0);
    const pending=server.signApproval(items[0].input,controller.signal),state=await (await fetch(server.origin+'/api/state',{headers})).json(),id=state.requests[0].id;
    assert.equal((await fetch(server.origin+'/api/approve',{method:'POST',headers,body:JSON.stringify({id,signature:items[1].signature})})).status,400);
    assert.equal((await fetch(server.origin+'/api/approve',{method:'POST',headers,body:JSON.stringify({id,signature:items[0].signature})})).status,200);
    assert.equal(await pending,items[0].signature);
    assert.equal((await fetch(server.origin+'/api/approve',{method:'POST',headers,body:JSON.stringify({id,signature:items[0].signature})})).status,400);
    const cancelled=server.signApproval(items[1].input,controller.signal);controller.abort();await assert.rejects(cancelled);
    assert.equal((await (await fetch(server.origin+'/api/state',{headers})).json()).requests.length,0);
  }finally{controller.abort();await server.close();}
});
