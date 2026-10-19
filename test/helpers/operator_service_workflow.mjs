// Isolated composition fixture. Mocked SNP/peer/volume/approval adapters grant
// NO hardware, transport, person, paid-work or deployment evidence.
import { mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { PeerDispatchJournal } from '../../compute/peer_dispatch.mjs';
import { WorkStore } from '../../service/work-store.mjs';
import { ResultRelay } from '../../service/result-relay.mjs';

assert.equal(process.platform,'linux');assert.equal(process.geteuid(),0);
const root=fs.mkdtempSync('/run/cannabis-operator-check-'),id='a'.repeat(64),routeId='0x'+id;
const marked=new WeakSet();let scenario='refuse',listener,inspectRelease,checks=0;
const observed=[];
const ok=value=>{assert.ok(value);checks++;};
async function until(predicate){for(let i=0;i<200;i++){if(predicate())return;await delay(10);}throw Error('Fixture stage timeout');}
async function freePort(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
mock.module('../../operator/provider-approvals.mjs',{namedExports:{readProviderCatalog:()=>({}),ProviderApprovals:class {
  snapshot(){return {assignments:[{id,consentRetained:true,validUntil:Math.floor(Date.now()/1000)+120}]};}
  retainedOrigin(){return 'https://peer.invalid:4443';}peerRoute(key,handle){assert.equal(key,id);return {handle};}
  async close(){observed.push('provider-closed');}
}}});
mock.module('../../operator/physical-spool.mjs',{namedExports:{assertPhysicalResultSpool:v=>assert.ok(marked.has(v)),PhysicalResultSpool:class {
  constructor(){marked.add(this);}checkCapacity(){observed.push('capacity');return {};}
  close(){observed.push('spool-closed');marked.delete(this);}
}}});
mock.module('../../operator/snp-vm.mjs',{namedExports:{
  inspectSnpHost:async(file,{signal})=>{observed.push('inspect');if(scenario==='refuse')throw Error('PRIVATE PATH '+file);
    if(scenario==='slow-inspection')await new Promise(resolve=>{inspectRelease=resolve;signal.addEventListener('abort',resolve,{once:true});});
    if(signal.aborted)throw Error('Cancelled');return {hardwareValidated:false};},
  runSnpBookedSession:async(channel,local,options)=>{
    assert.equal(typeof options.reserveResult,'function');observed.push('session');
    options.onStage({phase:'starting-vm'});options.onStage({phase:'relaying-encrypted-session'});
    const grants=await options.reserveResult({approvalDigest:'0x'+'b'.repeat(64),maxCiphertextBytes:256,
      serviceEnd:Math.floor(Date.now()/1000)+60},options.signal);
    ok(grants.upload.role==='upload'&&grants.read.role==='read'&&grants.upload.token!==grants.read.token&&grants.upload.id===grants.read.id);
    if(scenario==='complete'){options.onStage({phase:'local-session-finished',localTreeStopped:true});return;}
    if(scenario==='unknown'){options.onStage({phase:'failed-cleanup-unknown'});throw Error('Fixture failed before cleanup report');}
    await new Promise(resolve=>{options.signal.addEventListener('abort',resolve,{once:true});});
    options.onStage({phase:'failed-local-tree-stopped',localTreeStopped:true});throw Error('Fixture cancelled after local cleanup');
  }
}});
mock.module('../../compute/peer_network.mjs',{namedExports:{listenBookedPeers:async options=>{
  observed.push('listen');assert.equal(options.maxConnections,1);assert.equal(options.maxHandshakes,1);
  let closed=false,active=0,task;
  listener={trigger:()=>{const consumed=options.dispatchJournal.consume(routeId,Date.now()+120000);active++;
    task=options.routes[0].handle({},{}).then(()=>consumed.finish('completed'),()=>consumed.finish('failed')).finally(()=>active--);return task;},
    close:async()=>{closed=true;observed.push('listener-close');await task;return {closed:true,liveSockets:0,pendingHandlers:0,pendingTasks:0};},
    snapshot:()=>({closed,connections:active,pendingHandshakes:0,admittedChannels:active,routes:[]})};return listener;
}}});
const {openOperatorService,readOperatorConfiguration}=await import('../../operator/service.mjs');
async function fixture(name){
  const directory=path.join(root,name);fs.mkdirSync(directory,{mode:0o700});const p=n=>path.join(directory,n);
  for(const f of ['profile','catalog','key','cert'])fs.writeFileSync(p(f),'{}',{mode:0o600});
  fs.mkdirSync(p('approvals'),{mode:0o700});fs.mkdirSync(p('spool'),{mode:0o700});
  new PeerDispatchJournal(p('dispatch'),{create:true}).close();
  new WorkStore(p('orders'),'https://results.invalid').close();new ResultRelay(p('results')).close();
  for(const f of ['orders','results'])fs.chmodSync(p(f),0o600);
  const config={schema:'cannabis.operator-service.v1',profile:p('profile'),catalog:p('catalog'),approvals:p('approvals'),spool:p('spool'),dispatch:p('dispatch'),
    peer:{origin:'https://peer.invalid:4443',listenHost:'127.0.0.1',cert:p('cert'),key:p('key')},
    relay:{origin:'https://results.invalid',port:await freePort(),orders:p('orders'),results:p('results')}};
  fs.writeFileSync(p('config'),JSON.stringify(config),{mode:0o600});
  return {config,file:p('config'),opened:await openOperatorService(p('config'))};
}
try {
  const f=await fixture('refuse'),s=f.opened.service;ok(s.snapshot().canStart);s.start();assert.throws(()=>s.start());
  await until(()=>s.snapshot().state==='failed');ok(!observed.includes('listen'));ok(!s.snapshot().relayListening);
  ok(!JSON.stringify(s.snapshot()).includes(root));await s.close();ok(observed.includes('spool-closed'));
  fs.chmodSync(f.file,0o644);assert.throws(()=>readOperatorConfiguration(f.file));checks++;
  fs.chmodSync(f.file,0o600);fs.symlinkSync(f.file,f.file+'-link');assert.throws(()=>readOperatorConfiguration(f.file+'-link'));checks++;

  scenario='slow-inspection';const slow=(await fixture('slow')).opened.service;slow.start();await until(()=>inspectRelease);
  slow.stop();await until(()=>slow.snapshot().state==='stopped');ok(!slow.snapshot().relayListening);await slow.close();

  scenario='cancel';const live=await fixture('cancel'),service=live.opened.service;service.start();
  await until(()=>service.snapshot().state==='listening');ok(service.snapshot().relayListening);const task=listener.trigger();
  await until(()=>service.snapshot().sessions[0]?.phase==='relaying-encrypted-session');
  const report=service.snapshot();ok(report.hardwareValidated===false&&report.paidAcceptanceVerified===false&&report.protectedKeyRetirementVerified===false);
  service.stop();await task;await until(()=>service.snapshot().state==='stopped');ok(service.snapshot().sessions[0].localTreeStopped);
  ok(service.snapshot().relayListening);ok(!service.snapshot().canStart);await service.close();
  const reopened=await openOperatorService(live.file);ok(!reopened.service.snapshot().canStart);await reopened.service.close();

  scenario='complete';const complete=(await fixture('complete')).opened.service;complete.start();
  await until(()=>complete.snapshot().state==='listening');await listener.trigger();
  ok(complete.snapshot().sessions[0].phase==='local-session-finished'&&complete.snapshot().sessions[0].localTreeStopped);
  ok(complete.snapshot().assignments[0].dispatch==='completed'&&!complete.snapshot().canStart);
  complete.stop();await until(()=>complete.snapshot().state==='stopped');await complete.close();

  scenario='unknown';const unknown=(await fixture('unknown')).opened.service;unknown.start();
  await until(()=>unknown.snapshot().state==='listening');await listener.trigger();
  await until(()=>unknown.snapshot().state==='reconciliation-required');ok(unknown.snapshot().cleanupUnknown&&!unknown.snapshot().canStart);
  assert.throws(()=>unknown.start());checks++;await unknown.close();
  console.log(JSON.stringify({schema:'cannabis.operator-composition-fixture.v1',checks,mockedAdapters:true,realSQLiteAndLoopbackRelay:true,
    hardwareValidated:false,paidAcceptanceVerified:false}));
}finally{mock.restoreAll();assert.ok(root.startsWith('/run/cannabis-operator-check-'));fs.rmSync(root,{recursive:true});}
