// TLS 1.3 peer keys are derived inside protected guests from attested ephemeral
// P-256 keys. The requester verifies readiness with its own ephemeral key. No
// certificate, host-provided secret or anonymous plaintext fallback is accepted.
import tls from 'node:tls';
import {constants,webcrypto,hkdfSync,createHmac,timingSafeEqual} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {groupCanonical,groupHash,groupPublicKey,groupEndpoint,inspectGroupAdmission,
  groupStartPayload,verifyGroupStart} from './group_admission.mjs';

export const groupALPN='cannabis-group/1';
const cipher='TLS_AES_128_GCM_SHA256',construction=Symbol(),MAX_FRAME=2048,HIGH_WATER=65536;
const fail=()=>Error('Protected group connection failed; retire this group attempt');
const check=v=>{if(!v)throw fail();};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const same=(a,b)=>groupCanonical(a)===groupCanonical(b);
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});promise.catch(()=>{});return {promise,resolve,reject};};
const K={HELLO:1,READY:2,START:3,PACKET:4,DONE:5,ABORT:6};
const tlsOptions={minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ciphers:cipher,ALPNProtocols:[groupALPN],
  secureOptions:constants.SSL_OP_NO_TICKET,highWaterMark:HIGH_WATER};

function privateKey(key) {
  check(key?.type==='private'&&key.extractable===false&&key.algorithm?.name==='ECDH'&&
    key.algorithm.namedCurve==='P-256'&&key.usages.length===1&&key.usages[0]==='deriveBits');
}
async function secret(key,publicJwk,digest,label) {
  privateKey(key);const publicKey=await groupPublicKey(publicJwk);
  const raw=Buffer.from(await webcrypto.subtle.deriveBits({name:'ECDH',public:publicKey},key,256));
  try{return Buffer.from(hkdfSync('sha256',raw,Buffer.from(digest.slice(2),'hex'),Buffer.from('Cannabis group v1\0'+label),32));}
  finally{raw.fill(0);}
}
function readyContent(value) {
  exact(value,['schema','groupDigest','rank','meshDigest','readyAt','authenticator']);
  const {authenticator,...message}=value;return message;
}
function authenticator(key,message) {return createHmac('sha256',key).update(groupCanonical(message)).digest('base64url');}
function identity(digest,from,to) {return 'cg1:'+digest.slice(2)+':'+from+':'+to;}

// Only TCP/UDP IPv4 packets between the actual retained ranks cross a mesh.
// No raw headers, fragments, multicast, metadata address or default route escapes.
export function validateGroupPacket(packet,from,to,worldSize) {
  check(Buffer.isBuffer(packet)&&packet.length>=20&&packet.length<=1280&&packet[0]===0x45&&
    packet.readUInt16BE(2)===packet.length&&(packet.readUInt16BE(6)&0xbfff)===0&&packet[8]>0&&
    [6,17].includes(packet[9])&&Number.isInteger(from)&&Number.isInteger(to)&&from>=0&&to>=0&&
    from<worldSize&&to<worldSize&&from!==to&&worldSize>=2&&worldSize<=64);
  check(packet[12]===10&&packet[13]===211&&packet[14]===0&&packet[15]===from+1&&
    packet[16]===10&&packet[17]===211&&packet[18]===0&&packet[19]===to+1);
  if(packet[9]===6)check(packet.length>=40&&(packet[32]>>>4)>=5&&20+(packet[32]>>>4)*4<=packet.length);
  else check(packet.length>=28&&packet.readUInt16BE(24)===packet.length-20);
  return packet;
}

class Frames {
  #socket;#pending=Buffer.alloc(0);#queued=0;#limit;#closed=false;
  constructor(socket,limit){this.#socket=socket;this.#limit=limit;}
  async read(accept) {
    try {
      for await(const chunk of this.#socket) {
        check(!this.#closed&&this.#pending.length+chunk.length<=2*HIGH_WATER+MAX_FRAME+5);
        const combined=Buffer.concat([this.#pending,chunk]);this.#pending.fill(0);this.#pending=combined;
        while(this.#pending.length>=5) {
          const kind=this.#pending[0],length=this.#pending.readUInt32BE(1);
          check(Object.values(K).includes(kind)&&length>0&&length<=MAX_FRAME);
          if(this.#pending.length<5+length)break;
          const bytes=Buffer.from(this.#pending.subarray(5,5+length)),rest=Buffer.from(this.#pending.subarray(5+length));
          this.#pending.fill(0);this.#pending=rest;
          try {await accept(kind,bytes);} finally {bytes.fill(0);}
        }
      }
      check(this.#pending.length===0);
    } finally {this.#pending.fill(0);this.#pending=Buffer.alloc(0);}
  }
  async send(kind,value) {
    check(!this.#closed&&Object.values(K).includes(kind));
    const bytes=Buffer.isBuffer(value)?value:Buffer.from(groupCanonical(value));
    check(bytes.length>0&&bytes.length<=MAX_FRAME&&this.#queued+bytes.length+5<=this.#limit);
    const frame=Buffer.alloc(5+bytes.length);frame[0]=kind;frame.writeUInt32BE(bytes.length,1);bytes.copy(frame,5);
    this.#queued+=frame.length;
    try {await new Promise((resolve,reject)=>{
      let settled=false;const done=error=>{if(settled)return;settled=true;this.#socket.off('close',closed);error?reject(fail()):resolve();};
      const closed=()=>done(fail());this.#socket.once('close',closed);this.#socket.write(frame,done);
    });check(!this.#closed);} finally {this.#queued-=frame.length;frame.fill(0);}
  }
  close(){this.#closed=true;this.#socket.destroy();}
}

export class RequesterGroupReadiness {
  #admission;#keys;#closed=false;
  constructor(guard,admission,keys){check(guard===construction);this.#admission=admission;this.#keys=keys;}
  static async create(admission,key) {
    const d=inspectGroupAdmission(admission);privateKey(key);const keys=[];
    try {for(const p of d.peers)keys.push(await secret(key,p.channelJwk,d.payload.value.groupDigest,'requester-ready/'+p.rank));
      inspectGroupAdmission(admission);return new RequesterGroupReadiness(construction,admission,keys);
    } catch(error){for(const key of keys)key.fill(0);throw error;}
  }
  review(readiness) {
    check(!this.#closed);const d=inspectGroupAdmission(this.#admission);
    const payload=groupStartPayload(this.#admission,readiness,d.observedAt);
    for(const [rank,r] of readiness.entries()) {
      const expected=Buffer.from(authenticator(this.#keys[rank],readyContent(r)),'base64url'),actual=Buffer.from(r.authenticator,'base64url');
      check(actual.length===32&&timingSafeEqual(expected,actual));
    }
    return payload;
  }
  close(){this.#closed=true;for(const key of this.#keys)key.fill(0);this.#keys=[];}
}

export class GuestGroupMesh {
  #admission;#d;#rank;#keys;#requesterKey;#server;#connections=new Map();#incoming=new WeakMap();#sockets=new Set();
  #state='created';#connectStarted=false;#abort=new AbortController();#timer;#end;#ready=deferred();#started=deferred();#finished=deferred();
  #readiness;#localMeshDigest;#startDigest;#onPacket;#localDone=false;#closePromise;#externalSignal;#externalAbort;#traffic=0;
  constructor(guard,admission,rank,keys,requesterKey,onPacket,signal) {
    check(guard===construction);this.#admission=admission;this.#d=inspectGroupAdmission(admission);this.#rank=rank;
    this.#keys=keys;this.#requesterKey=requesterKey;this.#onPacket=onPacket;
    this.#end=performance.now()+(this.#d.group.expiresAt-this.#d.observedAt)*1000;
    this.#timer=setTimeout(()=>this.close(fail()),Math.max(1,this.#end-performance.now()));
    this.#externalSignal=signal;this.#externalAbort=()=>this.close(fail());signal?.addEventListener('abort',this.#externalAbort,{once:true});
    if(signal?.aborted)this.close(fail());
  }
  static async create(admission,rank,key,{onPacket,signal}={}) {
    const d=inspectGroupAdmission(admission);privateKey(key);
    check(Number.isInteger(rank)&&rank>=0&&rank<d.peers.length&&typeof onPacket==='function'&&
      (signal===undefined||signal instanceof AbortSignal)&&!signal?.aborted);
    const keys=new Map();let requestKey;
    try {
      for(const p of d.peers)if(p.rank!==rank)keys.set(p.rank,await secret(key,p.channelJwk,d.payload.value.groupDigest,
        'peer/'+Math.min(rank,p.rank)+'/'+Math.max(rank,p.rank)));
      requestKey=await secret(key,d.group.requesterChannelJwk,d.payload.value.groupDigest,'requester-ready/'+rank);
      inspectGroupAdmission(admission);
      return new GuestGroupMesh(construction,admission,rank,keys,requestKey,onPacket,signal);
    }catch(error){for(const key of keys.values())key.fill(0);requestKey?.fill(0);throw error;}
  }
  get signal(){return this.#abort.signal;}
  get status(){return {state:this.#state,rank:this.#rank,worldSize:this.#d.peers.length,
    groupDigest:this.#d.payload.value.groupDigest,executionAuthorized:false};}
  #fresh(started=false) {
    check(!['closed','failed','complete'].includes(this.#state)&&performance.now()<this.#end&&!this.#abort.signal.aborted);
    return inspectGroupAdmission(this.#admission,{allowStarted:started});
  }
  async listen() {
    this.#fresh();check(this.#state==='created');this.#state='listening';
    const profile=this.#d.group.peers[this.#rank].signed.configuration.execution.profile.group;
    check(profile&&['0.0.0.0','127.0.0.1','::','::1'].includes(profile.bindHost)&&
      Number.isInteger(profile.port)&&profile.port>=1024&&profile.port<=65535&&
      Number.isInteger(profile.maxBufferedBytes)&&profile.maxBufferedBytes>=2*HIGH_WATER&&profile.maxBufferedBytes<=8*1024*1024);
    this.#server=tls.createServer({...tlsOptions,handshakeTimeout:Math.min(10000,Math.max(1,this.#end-performance.now())),
      pskCallback:(socket,id)=>{
        try {
          this.#fresh();
          const p=this.#d.peers.find(p=>p.rank<this.#rank&&identity(this.#d.payload.value.groupDigest,p.rank,this.#rank)===id);
          if(!p||this.#connections.has(p.rank))return null;
          this.#incoming.set(socket,p.rank);return this.#keys.get(p.rank);
        }catch{return null;}
      }},socket=>{
        try {const rank=this.#incoming.get(socket);check(Number.isInteger(rank));this.#attach(rank,socket,profile.maxBufferedBytes);}
        catch {socket.destroy();this.close(fail());}
      });
    this.#server.maxConnections=Math.max(1,this.#d.peers.length-1);
    this.#server.on('connection',socket=>{this.#sockets.add(socket);socket.once('close',()=>this.#sockets.delete(socket));});
    this.#server.on('tlsClientError',(_error,socket)=>socket.destroy());
    this.#server.on('error',()=>this.close(fail()));
    await new Promise((resolve,reject)=>{this.#server.once('error',reject);this.#server.listen(profile.port,profile.bindHost,()=>{
      this.#server.off('error',reject);resolve();});});
    this.#fresh();return this.status;
  }
  async connect() {
    this.#fresh();check(!this.#connectStarted&&['listening','ready'].includes(this.#state));this.#connectStarted=true;
    if(this.#state==='ready')return this.#ready.promise;this.#state='joining';
    const profile=this.#d.group.peers[this.#rank].signed.configuration.execution.profile.group;
    try {
      await Promise.all(this.#d.peers.filter(p=>p.rank>this.#rank).map(p=>new Promise((resolve,reject)=>{
        let pskUsed=false;const endpoint=groupEndpoint(p.endpoint),socket=tls.connect({...tlsOptions,...endpoint,
          checkServerIdentity:()=>undefined,pskCallback:()=>{this.#fresh();pskUsed=true;
            return {psk:this.#keys.get(p.rank),identity:identity(this.#d.payload.value.groupDigest,this.#rank,p.rank)};}});
        this.#sockets.add(socket);socket.once('close',()=>this.#sockets.delete(socket));
        const failed=()=>{reject(fail());this.close(fail());};socket.once('error',failed);socket.once('close',failed);
        socket.once('secureConnect',()=>{
          try {check(pskUsed);this.#attach(p.rank,socket,profile.maxBufferedBytes);socket.off('error',failed);socket.off('close',failed);resolve();}
          catch {failed();}
        });
      })));
      return await this.#ready.promise;
    }catch(error){await this.close(error);throw fail();}
  }
  #attach(rank,socket,limit) {
    this.#fresh();check(!this.#connections.has(rank)&&socket.getProtocol()==='TLSv1.3'&&
      socket.getCipher()?.standardName===cipher&&socket.alpnProtocol===groupALPN&&!socket.getPeerCertificate()?.raw);
    socket.disableRenegotiation();socket.setNoDelay(true);
    const channelBinding='0x'+socket.exportKeyingMaterial(32,'EXPORTER-Cannabis-Protected-Group-v1',
      Buffer.from(this.#d.payload.value.groupDigest.slice(2),'hex')).toString('hex');
    const entry={rank,wire:new Frames(socket,limit),channelBinding,hello:false,ready:null,start:null,done:false};
    this.#connections.set(rank,entry);
    const failed=()=>{if(!['complete','closed','failed'].includes(this.#state)&&!(entry.done&&this.#localDone))this.close(fail());};
    socket.on('error',failed);
    entry.wire.read((kind,bytes)=>this.#receive(entry,kind,bytes)).then(failed,failed);
    entry.wire.send(K.HELLO,{groupDigest:this.#d.payload.value.groupDigest,from:this.#rank,to:rank,channelBinding}).catch(failed);
  }
  async #receive(peer,kind,bytes) {
    this.#fresh(['active','finishing'].includes(this.#state));
    if(kind===K.PACKET) {
      check(peer.hello&&['active','finishing'].includes(this.#state));
      this.#account(bytes.length);
      validateGroupPacket(bytes,peer.rank,this.#rank,this.#d.peers.length);await this.#onPacket(peer.rank,bytes);return;
    }
    const v=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    if(kind===K.HELLO) {
      exact(v,['groupDigest','from','to','channelBinding']);check(!peer.hello&&v.groupDigest===this.#d.payload.value.groupDigest&&
        v.from===peer.rank&&v.to===this.#rank&&v.channelBinding===peer.channelBinding);peer.hello=true;
      await this.#announceReady();return;
    }
    check(peer.hello);
    if(kind===K.READY) {
      exact(v,['meshDigest']);check(!peer.ready&&/^0x[0-9a-f]{64}$/.test(v.meshDigest));peer.ready=v.meshDigest;this.#resolveReady();
    }else if(kind===K.START) {
      exact(v,['digest']);check(this.#localMeshDigest&&peer.ready&&!peer.start&&/^0x[0-9a-f]{64}$/.test(v.digest));
      peer.start=v.digest;if(this.#startDigest)check(v.digest===this.#startDigest);this.#resolveStart();
    }else if(kind===K.DONE) {
      exact(v,['digest']);check(['active','finishing'].includes(this.#state)&&!peer.done&&v.digest===this.#startDigest);
      peer.done=true;this.#resolveFinish();
    }else if(kind===K.ABORT){throw fail();}else throw fail();
  }
  async #announceReady() {
    if(this.#localMeshDigest||this.#connections.size!==this.#d.peers.length-1||
      ![...this.#connections.values()].every(p=>p.hello))return;
    this.#localMeshDigest=groupHash([...this.#connections.values()].sort((a,b)=>a.rank-b.rank)
      .map(p=>({rank:p.rank,channelBinding:p.channelBinding})));
    await Promise.all([...this.#connections.values()].map(p=>p.wire.send(K.READY,{meshDigest:this.#localMeshDigest})));
    this.#resolveReady();
  }
  #resolveReady() {
    if(this.#readiness||!this.#localMeshDigest||this.#connections.size!==this.#d.peers.length-1||
      ![...this.#connections.values()].every(p=>p.ready))return;
    const d=this.#fresh();const message={schema:'cannabis.protected-group-ready.v1',groupDigest:d.payload.value.groupDigest,
      rank:this.#rank,meshDigest:this.#localMeshDigest,readyAt:d.observedAt};
    this.#readiness={...message,authenticator:authenticator(this.#requesterKey,message)};
    this.#state='ready';this.#ready.resolve(structuredClone(this.#readiness));
  }
  async start(start) {
    this.#fresh();check(this.#state==='ready'&&!this.#startDigest);
    this.#startDigest=verifyGroupStart(this.#admission,start,this.#readiness,this.#fresh().observedAt);
    try {
      for(const p of this.#connections.values())if(p.start)check(p.start===this.#startDigest);
      await Promise.all([...this.#connections.values()].map(p=>p.wire.send(K.START,{digest:this.#startDigest})));
      this.#resolveStart();await this.#started.promise;return this.status;
    }catch(error){await this.close(error);throw fail();}
  }
  #resolveStart() {
    if(!this.#startDigest||this.#state==='active'||![...this.#connections.values()].every(p=>p.start===this.#startDigest))return;
    const d=this.#fresh();this.#state='active';clearTimeout(this.#timer);
    this.#end=performance.now()+(d.serviceEnd-d.observedAt)*1000;
    this.#timer=setTimeout(()=>this.close(fail()),Math.max(1,this.#end-performance.now()));this.#started.resolve();
  }
  assertActive(){this.#fresh(true);check(['active','finishing'].includes(this.#state));}
  #account(bytes) {
    this.#traffic+=bytes;
    const limit=this.#d.group.peers[this.#rank].signed.configuration.execution.profile.group.maxTrafficBytes;
    check(Number.isSafeInteger(limit)&&limit>0&&limit<=1024**4&&this.#traffic<=limit);
  }
  async sendPacket(rank,packet) {
    try {this.assertActive();validateGroupPacket(packet,this.#rank,rank,this.#d.peers.length);this.#account(packet.length);
      await this.#connections.get(rank).wire.send(K.PACKET,packet);this.assertActive();}
    catch(error){await this.close(error);throw fail();}
  }
  async finish() {
    this.assertActive();check(!this.#localDone);this.#localDone=true;this.#state='finishing';
    try {await Promise.all([...this.#connections.values()].map(p=>p.wire.send(K.DONE,{digest:this.#startDigest})));
      this.#resolveFinish();await this.#finished.promise;return {groupCompleted:true};
    }catch(error){await this.close(error);throw fail();}
  }
  #resolveFinish(){if(this.#localDone&&[...this.#connections.values()].every(p=>p.done))this.#finished.resolve();}
  close(error) {
    if(this.#closePromise)return this.#closePromise;
    const complete=!error&&this.#localDone&&[...this.#connections.values()].every(p=>p.done);
    this.#state=complete?'complete':'failed';clearTimeout(this.#timer);
    this.#externalSignal?.removeEventListener('abort',this.#externalAbort);
    if(!complete){this.#abort.abort();for(const d of [this.#ready,this.#started,this.#finished])d.reject(fail());}
    for(const p of this.#connections.values())p.wire.close();for(const socket of this.#sockets)socket.destroy();
    for(const key of this.#keys.values())key.fill(0);this.#keys.clear();this.#requesterKey.fill(0);
    this.#closePromise=this.#server?new Promise(resolve=>this.#server.close(()=>resolve())):Promise.resolve();
    return this.#closePromise;
  }
}
