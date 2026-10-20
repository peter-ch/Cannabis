// Independent direct peer connections. Routes are retained operator assignments,
// never configurations or executable requests supplied by a network client.
import net from 'node:net';
import { connect, createSecureContext, TLSSocket } from 'node:tls';
import { performance } from 'node:perf_hooks';
import { inspectLaunchConsent, launchConsentPayload } from './guest_consent.mjs';
import { authenticatePeerChannel, peerALPN } from './peer_channel.mjs';
import { assertPeerDispatchJournal } from './peer_dispatch.mjs';

const magic=Buffer.from('CANPEER1'),maxRoutes=64;
const seconds=()=>Math.floor(Date.now()/1000);
const error=()=>Error('Selected booked peer connection is unavailable');
const check=v=>{if(!v)throw error();};
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
function endpoint(origin) {
  check(typeof origin==='string'&&origin.length<=512);const u=new URL(origin);
  check(u.protocol==='https:'&&u.origin===origin&&!u.username&&!u.password);return u;
}
function host(url){return url.hostname.replace(/^\[|\]$/g,'');}
function retained(signed,initialization,proof) {
  signed=structuredClone(signed);initialization=structuredClone(initialization);proof=structuredClone(proof);
  // Registration/preparation can precede the reserved interval. This offline
  // check grants no live admission; authentication checks the actual clock/state.
  const p=launchConsentPayload(signed.configuration,initialization,proof,'requester');
  const d=inspectLaunchConsent(signed,initialization,proof,p.value.validFrom);
  return {signed,initialization,proof,d,routeId:d.assignmentSHA256};
}
export function peerRouteId(signed,initialization,proof) {return retained(signed,initialization,proof).routeId;}

function waitFor(socket,event,signal) {
  return new Promise((resolve,reject)=>{
    const finish=ok=>{socket.off(event,ready);socket.off('error',failed);socket.off('close',failed);signal.removeEventListener('abort',failed);ok?resolve():reject(error());};
    const ready=()=>finish(true),failed=()=>finish(false);
    socket.once(event,ready);socket.once('error',failed);socket.once('close',failed);signal.addEventListener('abort',failed,{once:true});
    if(signal.aborted||socket.destroyed)failed();
  });
}
function readRoute(socket,signal) {
  return new Promise((resolve,reject)=>{
    const finish=(value)=>{socket.off('readable',read);socket.off('error',failed);socket.off('end',failed);socket.off('close',failed);
      signal.removeEventListener('abort',failed);value?resolve(value):reject(error());};
    const failed=()=>finish();
    const read=()=>{
      if(signal.aborted||socket.destroyed||socket.readableLength>65536)return failed();
      // Consume exactly the fixed preface. Pipelined authentication bytes remain
      // in the socket for the single GuestWire parser; no second iterator exists.
      const bytes=socket.read(40);if(!bytes)return;
      if(!bytes.subarray(0,8).equals(magic))return failed();
      finish('0x'+bytes.subarray(8).toString('hex'));
    };
    socket.on('readable',read);socket.once('error',failed);socket.once('end',failed);socket.once('close',failed);
    signal.addEventListener('abort',failed,{once:true});read();
  });
}
function writeRoute(socket,id,signal) {
  return new Promise((resolve,reject)=>{
    const finish=ok=>{socket.off('error',failed);socket.off('close',failed);signal.removeEventListener('abort',failed);ok?resolve():reject(error());};
    const failed=()=>finish(false);socket.once('error',failed);socket.once('close',failed);signal.addEventListener('abort',failed,{once:true});
    if(signal.aborted||socket.destroyed)return failed();
    socket.write(Buffer.concat([magic,Buffer.from(id.slice(2),'hex')]),e=>finish(!e));
  });
}

// No redirects, alternate origins, disabled certificate validation or automatic
// wallet access. ca optionally selects the caller's TLS trust store.
export async function connectBookedPeer({origin,signed,initialization,proof,signApproval,ca,
  timeoutMs=60000,signal,clock=seconds}={}) {
  const began=performance.now();let socket,timer,channel,handedOff=false;
  const controller=new AbortController(),abort=()=>{controller.abort();socket?.destroy();};
  try {
    const url=endpoint(origin),r=retained(signed,initialization,proof);
    check(typeof signApproval==='function'&&integer(timeoutMs,1,60000)&&(!signal||signal instanceof AbortSignal));
    check(ca===undefined||typeof ca==='string'&&Buffer.byteLength(ca)<=262144||Buffer.isBuffer(ca)&&ca.length<=262144);
    const start=clock(),d=inspectLaunchConsent(r.signed,r.initialization,r.proof,start);let last=start;
    const totalMs=Math.min(d.configuration.transport.timeoutMs,(d.reservation.end-start)*1000);
    const remaining=limit=>Math.floor(limit-(performance.now()-began));
    const active=()=>{const now=clock();check(!signal?.aborted&&!controller.signal.aborted&&integer(now,last,d.reservation.end-1)&&remaining(totalMs)>0);last=now;return now;};
    signal?.addEventListener('abort',abort,{once:true});active();
    const budget=Math.min(timeoutMs,totalMs);check(remaining(budget)>0);timer=setTimeout(abort,remaining(budget));
    const hostname=host(url),port=Number(url.port||443);check(integer(port,1,65535));
    socket=connect({host:hostname,port,servername:net.isIP(hostname)?undefined:hostname,ca,
      rejectUnauthorized:true,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:[peerALPN],highWaterMark:16384});
    socket.on('error',abort);await waitFor(socket,'secureConnect',controller.signal);active();
    check(socket.authorized&&socket.alpnProtocol===peerALPN&&remaining(budget)>0);
    await writeRoute(socket,r.routeId,controller.signal);active();check(remaining(budget)>0);
    channel=await authenticatePeerChannel(socket,{role:'requester',origin,signed:r.signed,initialization:r.initialization,proof:r.proof,
      signApproval,timeoutMs:remaining(budget),sessionTimeoutMs:remaining(totalMs),signal:controller.signal,clock:active});
    active();check(remaining(budget)>0);clearTimeout(timer);
    // Retain external cancellation through the complete session, not merely TCP
    // connection setup. Remove the link when the owned socket is disposed.
    socket.once('close',()=>signal?.removeEventListener('abort',abort));
    handedOff=true;
    return channel;
  } catch {channel?.close();abort();throw error();}
  finally {clearTimeout(timer);if(!handedOff)signal?.removeEventListener('abort',abort);}
}

function credentials(value) {
  const keys=['key','cert',...(Object.hasOwn(value??{},'passphrase')?['passphrase']:[])];exact(value,keys);
  for(const key of ['key','cert'])check((typeof value[key]==='string'||Buffer.isBuffer(value[key]))&&Buffer.byteLength(value[key])>0&&Buffer.byteLength(value[key])<=262144);
  if(Object.hasOwn(value,'passphrase'))check(typeof value.passphrase==='string'&&value.passphrase.length<=4096);
  return createSecureContext({...value,minVersion:'TLSv1.3',maxVersion:'TLSv1.3'});
}

// The operator supplies signing/handling callbacks for each immutable local route.
// This module does not spawn workers, reserve physical capacity, release keys or
// attest hardware. A handler must use the sealed launcher and checked cleanup.
export async function listenBookedPeers({origin,listenHost,tlsCredentials,routes,dispatchJournal,maxConnections=8,maxHandshakes=4,
  maxAttemptsPerRoute=3,timeoutMs=60000,signal,clock=seconds}={}) {
  const url=endpoint(origin),hostname=host(url),port=Number(url.port||443),context=credentials(tlsCredentials);
  assertPeerDispatchJournal(dispatchJournal);
  check(net.isIP(listenHost)&&integer(port,0,65535)&&integer(maxConnections,1,32)&&integer(maxHandshakes,1,maxConnections)&&
    integer(maxAttemptsPerRoute,1,32)&&integer(timeoutMs,1,60000)&&(!signal||signal instanceof AbortSignal)&&!signal?.aborted);
  if(port===0)check(['127.0.0.1','::1'].includes(listenHost)&&['localhost','127.0.0.1','::1'].includes(hostname));
  check(Array.isArray(routes)&&routes.length>=1&&routes.length<=maxRoutes);
  const catalog=new Map();let bytes=0,lastClock=clock();check(integer(lastClock,1,Number.MAX_SAFE_INTEGER));
  for(const input of routes) {
    exact(input,['signed','initialization','proof','signApproval','handle']);
    check(typeof input.signApproval==='function'&&typeof input.handle==='function');
    const r=retained(input.signed,input.initialization,input.proof);
    bytes+=Buffer.byteLength(JSON.stringify([r.signed,r.initialization,r.proof]));
    check(bytes<=16*1024*1024&&!catalog.has(r.routeId)&&r.d.reservation.end>lastClock);
    const prior=dispatchJournal.status(r.routeId);
    catalog.set(r.routeId,{...r,signApproval:input.signApproval,handle:input.handle,attempts:0,state:prior?.state??'idle'});
  }
  const entries=new Set(),tasks=new Set(),listening=new AbortController();let closed=false,closing,pending=0,rejected=0,failed=0,admitted=0,originUsed;
  const readClock=()=>{const now=clock();check(integer(now,lastClock,Number.MAX_SAFE_INTEGER));lastClock=now;return now;};
  const abortAll=()=>{for(const e of entries){e.controller.abort();e.socket?.destroy();e.raw.destroy();}};
  const server=net.createServer(raw=>{
    raw.on('error',()=>{});
    if(closed||entries.size>=maxConnections||pending>=maxHandshakes){rejected++;raw.destroy();return;}
    const entry={raw,controller:new AbortController(),started:performance.now(),handshake:true};entries.add(entry);pending++;
    const stop=()=>{entry.controller.abort();entry.socket?.destroy();raw.destroy();};
    const timer=setTimeout(stop,timeoutMs);raw.once('close',stop);
    const task=(async()=>{
      let route,channel,dispatch,invoked=false;
      try {
        const remaining=limit=>Math.floor(limit-(performance.now()-entry.started));
        check(!closed&&!entry.controller.signal.aborted);readClock();
        const socket=entry.socket=new TLSSocket(raw,{isServer:true,secureContext:context,ALPNProtocols:[peerALPN],requestCert:false});
        socket.on('error',stop);await waitFor(socket,'secure',entry.controller.signal);
        check(!closed&&socket.getProtocol()==='TLSv1.3'&&socket.alpnProtocol===peerALPN&&
          (net.isIP(hostname)?!socket.servername:socket.servername===hostname));
        const id=await readRoute(socket,entry.controller.signal);route=catalog.get(id);
        check(route&&route.state==='idle'&&route.attempts<maxAttemptsPerRoute&&dispatchJournal.status(id)===null);readClock();
        route.attempts++;route.state='authenticating';entry.route=route;
        const d=inspectLaunchConsent(route.signed,route.initialization,route.proof,readClock());
        const totalMs=Math.min(d.configuration.transport.timeoutMs,(d.reservation.end-readClock())*1000);
        check(remaining(timeoutMs)>0&&remaining(totalMs)>0);
        channel=await authenticatePeerChannel(socket,{role:'provider',origin:originUsed,signed:route.signed,initialization:route.initialization,proof:route.proof,
          signApproval:route.signApproval,timeoutMs:Math.min(remaining(timeoutMs),remaining(totalMs)),sessionTimeoutMs:remaining(totalMs),
          signal:entry.controller.signal,clock:readClock});
        check(!closed&&!entry.controller.signal.aborted&&remaining(timeoutMs)>0);channel.assertActive();clearTimeout(timer);
        // Commit before callback handoff. Another listener or a process restart
        // sees this tombstone, even if this process dies before invoking handle.
        dispatch=dispatchJournal.consume(route.routeId,d.reservation.end*1000);
        entry.handshake=false;pending--;invoked=true;route.state='consumed';admitted++;
        check(!closed&&!entry.controller.signal.aborted);channel.assertActive();
        await route.handle(channel,{signed:structuredClone(route.signed),initialization:structuredClone(route.initialization),
          proof:structuredClone(route.proof),signal:channel.signal,routeId:route.routeId});
        route.state=entry.controller.signal.aborted?'failed':'completed';
        dispatch.finish(route.state);dispatch=undefined;
      } catch {failed++;if(invoked){route.state='failed';try{dispatch?.finish('failed');}catch{/* Retain uncertain consumed marker. */}}}
      finally {
        clearTimeout(timer);if(entry.handshake)pending--;
        if(entry.route&&!invoked)entry.route.state=entry.route.attempts>=maxAttemptsPerRoute?'exhausted':'idle';
        channel?.close();stop();entries.delete(entry);
      }
    })();tasks.add(task);task.finally(()=>tasks.delete(task));
  });
  server.maxConnections=maxConnections;server.on('error',()=>{void close();});
  const close=(waitMs=2000)=>{
    check(integer(waitMs,1,30000));if(closing)return closing;closed=true;signal?.removeEventListener('abort',onAbort);listening.abort();abortAll();
    closing=(async()=>{
      let timer;const stopped=new Promise(resolve=>server.close(()=>resolve()));
      try {await Promise.race([Promise.all([stopped,...tasks]),new Promise(resolve=>{timer=setTimeout(resolve,waitMs);})]);}
      finally {clearTimeout(timer);}
      return {closed:true,liveSockets:[...entries].filter(e=>!e.raw.destroyed||e.socket&&!e.socket.destroyed).length,
        pendingHandlers:[...entries].filter(e=>!e.handshake).length,pendingTasks:tasks.size};
    })();return closing;
  };
  const onAbort=()=>{void close();};signal?.addEventListener('abort',onAbort,{once:true});
  try {
    await new Promise((resolve,reject)=>{const clean=()=>{server.off('listening',ready);server.off('error',fail);listening.signal.removeEventListener('abort',fail);};
      const fail=()=>{clean();reject(error());},ready=()=>{clean();resolve();};
      server.once('error',fail);server.once('listening',ready);listening.signal.addEventListener('abort',fail,{once:true});
      if(listening.signal.aborted)return fail();server.listen({port,host:listenHost,signal:listening.signal});});
    check(!signal?.aborted&&!closed);if(port===0)url.port=String(server.address().port);originUsed=url.origin;
  } catch {await close();throw error();}
  return Object.freeze({origin:originUsed,address:Object.freeze({...server.address()}),close,
    snapshot:()=>({schema:'cannabis.peer-listener-state.v1',closed,connections:entries.size,pendingHandshakes:pending,
      admittedChannels:admitted,rejectedConnections:rejected,failedConnections:failed,
      routes:[...catalog.values()].map(r=>({routeId:r.routeId,state:dispatchJournal.status(r.routeId)?.state??r.state,attempts:r.attempts})),
      hardwareValidated:false,executionAuthorized:false,keyReleaseAuthorized:false})});
}
