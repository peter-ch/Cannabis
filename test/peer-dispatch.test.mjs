import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { PeerDispatchJournal,assertPeerDispatchJournal } from '../compute/peer_dispatch.mjs';

const id=n=>'0x'+n.toString(16).padStart(64,'0'),DAY=86400000;
function fixture(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-peer-dispatch-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return path.join(dir,'dispatch.sqlite');}
const moduleURL=new URL('../compute/peer_dispatch.mjs',import.meta.url).href;
function child(file,routeId,linger=false) {
  const code=`import {PeerDispatchJournal} from ${JSON.stringify(moduleURL)};
    const j=new PeerDispatchJournal(process.argv[1]);
    try {j.consume(process.argv[2],Date.now()+60000);process.stdout.write('consumed\\n');}
    catch {process.stdout.write('refused\\n');}
    if(process.argv[3]==='linger')setInterval(()=>{},1000);else j.close();`;
  const proc=spawn(process.execPath,['--input-type=module','-e',code,file,routeId,linger?'linger':'exit'],
    {stdio:['ignore','pipe','pipe'],windowsHide:true});
  let output='',errors='';proc.stderr.on('data',b=>{errors+=b;});
  const line=new Promise((resolve,reject)=>{proc.stdout.on('data',b=>{output+=b;if(output.includes('\n'))resolve(output.trim());});
    proc.once('error',reject);proc.once('exit',()=>{if(!output.includes('\n'))reject(Error('No child journal result: '+errors));});});
  const exited=new Promise((resolve,reject)=>{proc.once('error',reject);proc.once('exit',(code,signal)=>resolve({code,signal}));});
  return {proc,line,exited};
}

test('peer dispatch requires explicit first creation, rejects changed settings and never silently resets state',t=>{
  const file=fixture(t);assert.throws(()=>new PeerDispatchJournal(file));assert.equal(fs.existsSync(file),false);
  assert.throws(()=>new PeerDispatchJournal(':memory:',{create:true}));
  let j=new PeerDispatchJournal(file,{create:true});assertPeerDispatchJournal(j);
  assert.throws(()=>new PeerDispatchJournal(file,{create:true}));
  assert.throws(()=>new PeerDispatchJournal(file,{maxRecords:2}));
  j.consume(id(1),Date.now()+60000);j.close();assert.throws(()=>assertPeerDispatchJournal(j));
  j=new PeerDispatchJournal(file);assert.equal(j.status(id(1)).state,'consumed');j.close();
  const empty=path.join(path.dirname(file),'empty.sqlite');fs.writeFileSync(empty,'');
  assert.throws(()=>new PeerDispatchJournal(empty));assert.throws(()=>assertPeerDispatchJournal({}));
});

test('peer dispatch survives process termination before handler outcome and refuses replay in another process',async t=>{
  const file=fixture(t);new PeerDispatchJournal(file,{create:true}).close();
  const active=child(file,id(2),true);t.after(()=>active.proc.kill());
  assert.equal(await active.line,'consumed');active.proc.kill('SIGKILL');await active.exited;
  const retry=child(file,id(2));assert.equal(await retry.line,'refused');assert.equal((await retry.exited).code,0);
  const j=new PeerDispatchJournal(file);
  try{assert.equal(j.status(id(2)).state,'consumed');assert.equal(j.status(id(2)).recoveryRequired,true);}
  finally{j.close();}
});

test('peer dispatch commits exactly one handoff across concurrent independent processes',async t=>{
  const file=fixture(t);new PeerDispatchJournal(file,{create:true}).close();
  const children=[child(file,id(3)),child(file,id(3))];t.after(()=>children.forEach(c=>c.proc.kill()));
  assert.deepEqual((await Promise.all(children.map(c=>c.line))).sort(),['consumed','refused']);
  for(const result of await Promise.all(children.map(c=>c.exited)))assert.equal(result.code,0);
});

test('peer dispatch outcomes are terminal local observations and cannot reopen an assignment',t=>{
  const file=fixture(t),j=new PeerDispatchJournal(file,{create:true});
  try {
    for(const [n,state] of [[4,'completed'],[5,'failed']]) {
      const dispatch=j.consume(id(n),Date.now()+60000);dispatch.finish(state);
      assert.equal(j.status(id(n)).state,state);assert.equal(j.status(id(n)).executionVerified,false);
      assert.throws(()=>dispatch.finish('completed'));assert.throws(()=>j.consume(id(n),Date.now()+60000));
    }
    assert.equal(j.status(id(6)),null);assert.throws(()=>j.consume(id(0),Date.now()+60000));
    assert.throws(()=>j.consume(id(6),Date.now()-1));assert.equal(j.status(id(6)),null);
  }finally{j.close();}
});

test('peer dispatch capacity and expiry survive reopen; cleanup never removes retained result files',t=>{
  const file=fixture(t);let now=Date.now();const options={maxRecords:1,retentionMs:DAY,now:()=>now};
  let j=new PeerDispatchJournal(file,{create:true,...options});
  const result=path.join(path.dirname(file),'result.age');fs.writeFileSync(result,'owned encrypted-result placeholder');
  try {
    j.consume(id(7),now+100);assert.throws(()=>j.consume(id(8),now+100));j.close();j=new PeerDispatchJournal(file,options);
    now+=100;assert.equal(j.cleanup(),0);assert.throws(()=>j.consume(id(8),now+100));
    now+=DAY-1;assert.equal(j.cleanup(),0);now++;assert.equal(j.cleanup(),1);
    j.consume(id(8),now+100);assert.equal(j.status(id(8)).state,'consumed');assert.ok(fs.existsSync(result));
  }finally{j.close();}
});

test('peer dispatch refuses backward clocks across restarts and preserves the original marker',t=>{
  const file=fixture(t);let now=Date.now();const options={now:()=>now};
  let j=new PeerDispatchJournal(file,{create:true,...options});j.consume(id(9),now+60000);j.close();
  now--;assert.throws(()=>new PeerDispatchJournal(file,options));now++;
  j=new PeerDispatchJournal(file,options);try{assert.equal(j.status(id(9)).state,'consumed');now--;assert.throws(()=>j.cleanup());}
  finally{j.close();}
});
