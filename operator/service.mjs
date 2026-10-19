// One independently operated provider. Configuration is local, immutable for
// this process, and never supplied by a browser or a remote requester.
import fs from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { ProviderApprovals,readProviderCatalog } from './provider-approvals.mjs';
import { PhysicalResultSpool } from './physical-spool.mjs';
import { ResultConsole } from './storage-console.mjs';
import { PeerDispatchJournal } from '../compute/peer_dispatch.mjs';
import { listenBookedPeers } from '../compute/peer_network.mjs';
import { createWorkServer } from '../service/work-server.mjs';
import { inspectSnpHost,runSnpBookedSession } from './snp-vm.mjs';
import { openOperatorBoundary } from './boundary.mjs';

const check=v=>{if(!v)throw Error('Operator configuration or lifecycle unavailable; retain recovery state');};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const origin=v=>{const u=new URL(v);check(u.origin===v&&u.protocol==='https:'&&!u.username&&!u.password&&v.length<=512);return v;};
function protectedPath(file,{directory=false,privateFile=false,limit=16*1024*1024}={}) {
  check(typeof file==='string'&&path.isAbsolute(file)&&path.resolve(file)===file&&!file.includes('\0'));
  let current=file,first=true;
  for(;;){const s=fs.lstatSync(current);check(!s.isSymbolicLink()&&s.uid===0&&(s.mode&0o022)===0);
    if(first){check(directory?s.isDirectory():s.isFile()&&s.nlink===1&&s.size>0&&s.size<=limit);
      if(privateFile)check((s.mode&0o077)===0);first=false;}else check(s.isDirectory());
    const parent=path.dirname(current);if(parent===current)break;current=parent;}
  return file;
}
function read(file,options) {protectedPath(file,options);const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {const s=fs.fstatSync(fd);check(s.isFile()&&s.uid===0&&(s.mode&0o022)===0&&s.size<=(options?.limit??16*1024*1024));return fs.readFileSync(fd);}
  finally{fs.closeSync(fd);}}

export function readOperatorConfiguration(file) {
  check(process.platform==='linux'&&process.geteuid()===0);
  const raw=read(file,{privateFile:true,limit:16384}),c=JSON.parse(raw);
  exact(c,['schema','resources','profile','catalog','approvals','spool','dispatch','peer','relay',...(Object.hasOwn(c,'market')?['market']:[])]);
  check(c.schema==='cannabis.operator-service.v1');
  exact(c.peer,['origin','listenHost','cert','key']);exact(c.relay,['origin','port','orders','results']);
  origin(c.peer.origin);origin(c.relay.origin);check(c.peer.origin!==c.relay.origin&&isIP(c.peer.listenHost));
  const peerPort=Number(new URL(c.peer.origin).port||443);
  check(peerPort>=1024&&peerPort<=65535&&Number.isSafeInteger(c.relay.port)&&c.relay.port>=1024&&c.relay.port<=65535&&peerPort!==c.relay.port);
  for(const key of ['resources','profile','catalog','dispatch'])protectedPath(c[key],{privateFile:key!=='catalog'});
  for(const key of ['approvals','spool'])protectedPath(c[key],{directory:true});
  for(const key of ['orders','results'])protectedPath(c.relay[key],{privateFile:true,limit:512*1024*1024});
  check(new Set([c.dispatch,c.relay.orders,c.relay.results]).size===3);
  if(Object.hasOwn(c,'market')&&c.market!==null){exact(c.market,['configuration','journal']);protectedPath(c.market.journal,{privateFile:true,limit:64*1024*1024});
    check(![c.dispatch,c.relay.orders,c.relay.results].includes(c.market.journal));}
  return {configuration:structuredClone(c),configurationSHA256:createHash('sha256').update(raw).digest('hex'),
    tlsCredentials:{key:read(c.peer.key,{privateFile:true,limit:262144}),cert:read(c.peer.cert,{limit:262144})}};
}

class OperatorService {
  #c;#tls;#provider;#spool;#journal;#results;#relay;#listener;#controller;#operation;#stopTask;
  #phase='stopped';#reason='Select Start booked listener after reviewing the retained provider approvals.';#sessions=new Map();#closed=false;
  #hostObserved=false;#cleanupUnknown=false;#closeTask;#boundary;#market;
  constructor(c,tls,provider,spool,journal,results,boundary,market=null) {this.#c=c;this.#tls=tls;this.#provider=provider;this.#spool=spool;this.#journal=journal;this.#results=results;this.#boundary=boundary;this.#market=market;}
  snapshot() {
    const listener=this.#listener?.snapshot();
    if(this.#phase==='listening'&&listener?.closed)this.stop();
    const now=Math.floor(Date.now()/1000),assignments=this.#provider.snapshot().assignments.map(r=>({id:r.id,
      consentRetained:r.consentRetained,expired:r.validUntil<=now,dispatch:this.#journal.status('0x'+r.id)?.state??'unused'}));
    return {schema:'cannabis.operator-service-state.v1',state:this.#phase,reason:this.#reason,
      peerOrigin:this.#c.peer.origin,relayOrigin:this.#c.relay.origin,relayListening:Boolean(this.#relay?.server.listening),
      hostCapabilityObserved:this.#hostObserved,canStart:!this.#closed&&!this.#cleanupUnknown&&!listener?.connections&&![...this.#sessions.values()].some(r=>r.active)&&['stopped','failed'].includes(this.#phase)&&
        assignments.some(r=>r.consentRetained&&!r.expired&&r.dispatch==='unused'),
      canStop:['starting','listening','failed'].includes(this.#phase),assignments,sessions:[...this.#sessions.values()].map(r=>({...r})),
      listener:listener?{closed:listener.closed,connections:listener.connections,pendingHandshakes:listener.pendingHandshakes,
        authenticatedChannels:listener.admittedChannels,routes:listener.routes}:null,
      resourceBoundary:this.#boundary.snapshot(),cleanupUnknown:this.#cleanupUnknown,
      hardwareValidated:false,paidAcceptanceVerified:false,protectedKeyRetirementVerified:false};
  }
  start() {
    check(this.snapshot().canStart);this.#phase='starting';this.#reason='Checking the selected SNP host and retained assignments.';
    const controller=this.#controller=new AbortController();this.#stopTask=undefined;
    this.#operation=this.#start(controller).catch(()=>{if(this.#phase==='starting'){
      this.#phase='failed';this.#reason='Startup refused: review the selected SNP host, approvals, capacity and listener configuration.';}});
    return {state:this.#phase};
  }
  async #start(controller) {
    await this.#boundary.check();check(!controller.signal.aborted);
    await inspectSnpHost(this.#c.profile,{signal:controller.signal});check(!controller.signal.aborted);this.#hostObserved=true;
    this.#spool.checkCapacity();const now=Math.floor(Date.now()/1000);
    const ids=this.#provider.snapshot().assignments.filter(r=>r.consentRetained&&r.validUntil>now&&!this.#journal.status('0x'+r.id)).map(r=>r.id);
    check(ids.length>0);
    const routes=ids.map(id=>{check(this.#provider.retainedOrigin(id)===this.#c.peer.origin);
      return this.#provider.peerRoute(id,async(channel,local)=>{
        await this.#boundary.check({minimumFreeBytes:4*local.signed.configuration.transport.maxCiphertextBytes+32*1024**2});
        check(!controller.signal.aborted&&![...this.#sessions.values()].some(r=>r.active));
        const row={assignmentId:id,phase:'awaiting-requester',active:true,startedAt:Date.now(),endedAt:null,
          localTreeStopped:false,hardwareValidated:false,paidAcceptanceVerified:false};this.#sessions.set(id,row);
        try {
          await runSnpBookedSession(channel,local,{profileFile:this.#c.profile,origin:this.#c.relay.origin,spool:this.#spool,
            signal:controller.signal,onStage:value=>{row.phase=value.phase;if('localTreeStopped' in value)row.localTreeStopped=value.localTreeStopped;},
            reserveResult:({approvalDigest,maxCiphertextBytes,serviceEnd},signal)=>{
              check(!signal.aborted&&!controller.signal.aborted&&this.#relay?.server.listening);
              const {uploadToken,readToken,...access}=this.#relay.relay.reserve({approvalDigest,maxCiphertextBytes,expiresAt:serviceEnd*1000});
              return {upload:{...access,origin:this.#c.relay.origin,role:'upload',token:uploadToken},
                read:{...access,origin:this.#c.relay.origin,role:'read',token:readToken}};
            }});
        }finally {
          row.active=false;row.endedAt=Date.now();
          if(!row.localTreeStopped){this.#cleanupUnknown=true;row.phase='failed-cleanup-unknown';
            this.#reason='Local cleanup is unverified. Intake stays stopped; retain dispatch and encrypted results.';
            // Do not await this handler from inside itself.
            queueMicrotask(()=>this.stop());}
        }
      });});
    if(!this.#relay) {
      const relay=createWorkServer({file:this.#c.relay.orders,resultFile:this.#c.relay.results,origin:this.#c.relay.origin});
      try{await new Promise((resolve,reject)=>{relay.server.once('error',reject);relay.server.listen(this.#c.relay.port,'127.0.0.1',resolve);});}
      catch(error){relay.server.close();throw error;}
      relay.server.removeAllListeners('error');relay.server.on('error',()=>{
        if(['starting','listening','failed'].includes(this.#phase))this.stop();
        else if(this.#phase==='stopped')this.#phase='reconciliation-required';
        this.#reason='Encrypted result relay unavailable; retain local results and reconcile the selected relay.';
      });
      this.#relay=relay;
    }
    check(!controller.signal.aborted&&this.#relay.server.listening);
    this.#listener=await listenBookedPeers({origin:this.#c.peer.origin,listenHost:this.#c.peer.listenHost,tlsCredentials:this.#tls,
      routes,dispatchJournal:this.#journal,maxConnections:1,maxHandshakes:1,signal:controller.signal});
    check(!controller.signal.aborted);this.#phase='listening';
    this.#reason='Listening for the retained booked assignments. Each connection still requires wallet approval and requester attestation.';
  }
  stop() {
    if(this.#stopTask)return {state:this.#phase};
    check(['starting','listening','failed'].includes(this.#phase));this.#phase='stopping';
    this.#reason='Stopping peer intake and awaiting owned session cleanup. Retained results are preserved.';
    // close with the full cleanup budget BEFORE aborting the listener signal.
    const closing=this.#listener?.close(30000);this.#controller?.abort();
    this.#stopTask=(async()=>{
      await this.#operation;const report=await(closing??this.#listener?.close(30000));
      if(report&&(report.liveSockets||report.pendingHandlers||report.pendingTasks))this.#cleanupUnknown=true;
      this.#phase=this.#cleanupUnknown?'reconciliation-required':'stopped';
      this.#reason=this.#cleanupUnknown?'Cleanup is unverified. Retain dispatch and result storage for local reconciliation.':
        'Peer intake is stopped. Encrypted results and dispatch history are retained; the result relay remains available.';
    })().catch(()=>{this.#cleanupUnknown=true;this.#phase='reconciliation-required';this.#reason='Shutdown could not be verified. Preserve all recovery state.';});
    return {state:this.#phase};
  }
  close() {
    if(this.#closeTask)return this.#closeTask;this.#closed=true;
    this.#closeTask=(async()=>{
      if(['starting','listening','failed'].includes(this.#phase))this.stop();await this.#stopTask;
      // Never close shared stores while a surviving handler can still use them.
      if(this.#listener?.snapshot().connections||[...this.#sessions.values()].some(r=>r.active))throw Error('Operator session cleanup remains pending');
      await this.#market?.close();await this.#results.close();await this.#provider.close();
      if(this.#relay){this.#relay.server.closeAllConnections();await new Promise(resolve=>this.#relay.server.close(resolve));}
      this.#spool.close();this.#journal.close();await this.#boundary.close();this.#tls=undefined;
    })();return this.#closeTask;
  }
}

export async function openOperatorService(file) {
  const {configuration:c,configurationSHA256,tlsCredentials}=readOperatorConfiguration(file);let provider,spool,journal,results,boundary,market=null;
  try {
    boundary=await openOperatorBoundary(c.resources,configurationSHA256);
    provider=new ProviderApprovals(readProviderCatalog(c.catalog),c.approvals);
    check(provider.snapshot().assignments.length>0&&provider.snapshot().assignments.every(r=>provider.retainedOrigin(r.id)===c.peer.origin));
    spool=new PhysicalResultSpool(c.spool);journal=new PeerDispatchJournal(c.dispatch);
    results=new ResultConsole(spool,{relayOrigins:[c.relay.origin]});
    if(c.market){const {MarketConsole}=await import('./market-console.mjs');market=new MarketConsole(c.market.configuration,c.market.journal,{guard:()=>boundary.check()});}
    const service=new OperatorService(c,tlsCredentials,provider,spool,journal,results,boundary,market);boundary.monitor();
    return {service,provider,results,market};
  }catch(error){await market?.close();await results?.close();await provider?.close();spool?.close();journal?.close();await boundary?.close();throw error;}
}
