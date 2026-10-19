// Booked-party authentication over one direct TLS 1.3 connection. This is an
// ordinary-host transport, never protected execution or permission to release keys.
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TLSSocket, checkServerIdentity } from 'node:tls';
import { TypedDataEncoder, verifyTypedData } from 'ethers';
import { inspectLaunchConsent } from './guest_consent.mjs';
import { readMarketLeaseState } from './market_lease.mjs';
import { validateWalletApprovals } from './wallet_signatures.mjs';
import { GuestWire } from './result_transport.mjs';

export const peerALPN='cannabis-peer/1';
const protocol='cannabis.peer-channel.v1',usedSockets=new WeakSet(),authenticated=new WeakMap();
const failure=()=>Error('Booked peer channel authentication failed');
const check=ok=>{if(!ok)throw failure();};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const hash=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const roles=['requester','provider'];
const seconds=()=>Math.floor(Date.now()/1000);
function endpoint(value) {
  check(typeof value==='string'&&value.length<=512);const url=new URL(value);
  check(url.protocol==='https:'&&url.origin===value&&!url.username&&!url.password);
  return url;
}
export const peerChannelTypes=Object.freeze({BookedPeerChannel:Object.freeze([
  ['role','uint8'],['genesisHash','bytes32'],['configurationSHA256','bytes32'],['assignmentSHA256','bytes32'],
  ['leaseDigest','bytes32'],['bookingId','bytes32'],['requester','address'],['provider','address'],
  ['origin','string'],['channelBinding','bytes32'],['requesterNonce','bytes32'],['providerNonce','bytes32'],
  ['validFrom','uint64'],['validUntil','uint64']
].map(([name,type])=>Object.freeze({name,type})))});

function payload(checked,binding,role,now) {
  exact(binding,['origin','channelBinding','requesterNonce','providerNonce','validFrom','validUntil']);
  endpoint(binding.origin);const d=checked,r=d.reservation,c=d.configuration;
  check(roles.includes(role)&&['channelBinding','requesterNonce','providerNonce'].every(k=>hash(binding[k]))&&
    binding.requesterNonce!==binding.providerNonce&&integer(binding.validFrom,r.start,now)&&
    integer(binding.validUntil,now+1,Math.min(r.end,binding.validFrom+Math.ceil(c.transport.timeoutMs/1000))));
  const domain={name:'Cannabis booked peer channel',version:'1',chainId:c.context.chainId,verifyingContract:c.context.market};
  const value={role:roles.indexOf(role),genesisHash:c.network.genesisHash,
    configurationSHA256:d.configurationSHA256,assignmentSHA256:d.assignmentSHA256,
    leaseDigest:d.lease.digest,bookingId:r.reservationId,requester:d.lease.requester,provider:r.provider,...binding};
  return {domain,types:peerChannelTypes,value,digest:TypedDataEncoder.hash(domain,peerChannelTypes,value),
    signer:role==='requester'?d.lease.requester:r.provider};
}
// Offline signing description only. Caller-supplied exporter bytes are not a live
// connection; authenticatePeerChannel derives them from the retained TLS socket.
export function peerChannelPayload(signed,initialization,proof,binding,role,now=seconds()) {
  const d=inspectLaunchConsent(signed,initialization,proof,now);
  return {...payload(d,structuredClone(binding),role,now),channelAuthenticated:false,chainVerified:false,
    executionAuthorized:false,keyReleaseAuthorized:false};
}

// Consume the live local capability once for the retained launch. A copied report
// or caller-set boolean cannot substitute for the actual authenticated channel.
export function inspectPeerChannel(channel,localRole,signed,initialization,proof) {
  const entry=authenticated.get(channel);check(entry&&!entry.claimed&&entry.role===localRole);
  channel.assertActive();const d=inspectLaunchConsent(signed,initialization,proof,entry.clock()),s=entry.state;
  check(d.configurationSHA256===s.configurationSHA256&&d.assignmentSHA256===s.assignmentSHA256&&
    d.lease.digest===s.leaseDigest&&d.reservation.reservationId===s.bookingId&&d.lease.requester===s.requester&&d.reservation.provider===s.provider);
  return structuredClone(s.binding);
}
export function claimPeerChannel(channel,localRole,signed,initialization,proof) {
  const binding=inspectPeerChannel(channel,localRole,signed,initialization,proof);
  authenticated.get(channel).claimed=true;return binding;
}

function approvals(checked,binding,signatures,now) {
  check(Array.isArray(signatures)&&signatures.length===2);
  const list=roles.map((role,i)=>{
    const s=signatures[i],p=payload(checked,binding,role,now);exact(s,['role','signature']);check(s.role===role);
    return {role,signer:p.signer,digest:p.digest,signature:s.signature};
  });
  validateWalletApprovals(list);
  const p=payload(checked,binding,'requester',now);
  check(verifyTypedData(p.domain,p.types,p.value,list[0].signature)===p.signer);
  return list;
}

// Both consent sets are evaluated at the very same hash-bound finalized/current
// funding observations. The provider can be an EOA or an ERC-1271 contract wallet.
// A state report by itself cannot authenticate a socket or authorize execution.
export async function readPeerChannelState(signed,initialization,proof,binding,signatures,
  {clock=seconds,timeoutMs=60000,signal}={}) {
  const began=performance.now(),start=clock(),d=inspectLaunchConsent(signed,initialization,proof,start);
  binding=structuredClone(binding);signatures=structuredClone(signatures);
  const channelApprovals=approvals(d,binding,signatures,start);
  check(integer(timeoutMs,1,60000)&&(!signal||signal instanceof AbortSignal));
  const controller=new AbortController(),abort=()=>controller.abort();let last=start;
  const timer=setTimeout(abort,Math.max(1,timeoutMs-(performance.now()-began)));signal?.addEventListener('abort',abort,{once:true});
  const active=()=>{
    const now=clock();check(!signal?.aborted&&!controller.signal.aborted&&performance.now()-began<timeoutMs&&
      integer(now,last,binding.validUntil-1));last=now;return now;
  };
  try {
    active();const funding=await readMarketLeaseState(d.lease.proof,d.configuration.network,active,
      {launchApprovals:d.approvals,channelApprovals},{timeoutMs,signal:controller.signal});active();
    check(funding.headBlock.timestamp>=d.reservation.start&&funding.headBlock.timestamp<d.reservation.end);
    return {schema:'cannabis.peer-channel-state.v1',binding,configurationSHA256:d.configurationSHA256,
      assignmentSHA256:d.assignmentSHA256,leaseDigest:d.lease.digest,bookingId:d.reservation.reservationId,
      requester:d.lease.requester,provider:d.reservation.provider,approvals:channelApprovals,funding,
      chainVerified:true,chainVerification:'rpc-finalized',channelAuthenticated:false,
      hardwareVerified:false,executionAuthorized:false,keyReleaseAuthorized:false};
  } finally {abort();clearTimeout(timer);signal?.removeEventListener('abort',abort);}
}

function cancellable(action,signal) {
  return new Promise((resolve,reject)=>{
    const abort=()=>reject(failure());if(signal.aborted)return abort();signal.addEventListener('abort',abort,{once:true});
    Promise.resolve().then(()=>{check(!signal.aborted);return action();}).then(resolve,reject)
      .finally(()=>signal.removeEventListener('abort',abort));
  });
}

// Call only after TLS has completed, with the independently selected origin and
// locally retained booking/configuration. signApproval is user-controlled and
// receives a public typed payload, never wallet secrets or customer content.
// One authentication instance per TLS connection; close disposes that connection.
// Browser APIs do not expose this exporter: this adapter is explicitly Node-only.
export async function authenticatePeerChannel(socket,{role,origin,signed,initialization,proof,signApproval,
  timeoutMs=60000,sessionTimeoutMs,signal,clock=seconds}={}) {
  const began=performance.now();let wire,timer,controller,stop;let complete=false;
  try {
    check(socket instanceof TLSSocket&&!socket.destroyed&&!usedSockets.has(socket));usedSockets.add(socket);
    const url=endpoint(origin);check(roles.includes(role)&&typeof signApproval==='function'&&integer(timeoutMs,1,60000)&&
      (!signal||signal instanceof AbortSignal)&&socket.encrypted&&socket.getProtocol()==='TLSv1.3'&&socket.alpnProtocol===peerALPN);
    // The requester checks both the configured TLS trust store and hostname.
    // Provider authentication of the requester comes from its booked signature.
    if(role==='requester')check(socket.authorized&&checkServerIdentity(url.hostname,socket.getPeerCertificate())===undefined);
    socket.disableRenegotiation();
    // RFC 9266: 32 bytes, this label, and an explicitly empty context. It is a
    // public connection binding, never a content key or bearer credential.
    const channelBinding='0x'+socket.exportKeyingMaterial(32,'EXPORTER-Channel-Binding',Buffer.alloc(0)).toString('hex');
    signed=structuredClone(signed);initialization=structuredClone(initialization);proof=structuredClone(proof);
    const start=clock(),d=inspectLaunchConsent(signed,initialization,proof,start);let last=start,expiresAt=d.reservation.end;
    check(sessionTimeoutMs===undefined||integer(sessionTimeoutMs,1,d.configuration.transport.timeoutMs));
    const totalMs=Math.min(sessionTimeoutMs??d.configuration.transport.timeoutMs,(d.reservation.end-start)*1000);
    const wireBudget=Math.floor(totalMs-(performance.now()-began));check(integer(wireBudget,1,3600000));controller=new AbortController();
    wire=new GuestWire(socket,socket,{timeoutMs:wireBudget,signal:controller.signal});
    stop=()=>{clearTimeout(timer);signal?.removeEventListener('abort',stop);socket.off('close',stop);controller.abort();wire.fail();wire.close();};
    signal?.addEventListener('abort',stop,{once:true});socket.once('close',stop);
    const active=()=>{
      try {
        const now=clock();check(!signal?.aborted&&!socket.destroyed&&integer(now,last,expiresAt-1)&&performance.now()-began<totalMs);
        wire.assertActive();last=now;return now;
      } catch {stop();throw failure();}
    };
    active();timer=setTimeout(stop,Math.max(1,Math.min(timeoutMs,totalMs)-(performance.now()-began)));
    const own={protocol,operation:'hello',role,nonce:'0x'+randomBytes(32).toString('hex'),
      issuedAt:start,expiresAt:Math.min(d.reservation.end,start+Math.ceil(totalMs/1000))};
    await wire.writeJSON(own);const other=await wire.readJSON(2048);active();
    exact(other,Object.keys(own));check(other.protocol===protocol&&other.operation==='hello'&&other.role===roles[1-roles.indexOf(role)]&&
      hash(other.nonce)&&other.nonce!==own.nonce&&integer(other.issuedAt,d.reservation.start,active())&&
      integer(other.expiresAt,active()+1,Math.min(d.reservation.end,other.issuedAt+Math.ceil(d.configuration.transport.timeoutMs/1000))));
    const hello=role==='requester'?[own,other]:[other,own];
    const binding={origin,channelBinding,requesterNonce:hello[0].nonce,providerNonce:hello[1].nonce,
      validFrom:Math.max(own.issuedAt,other.issuedAt),validUntil:Math.min(own.expiresAt,other.expiresAt)};
    expiresAt=binding.validUntil;
    const receive=async()=>{
      const received=await wire.readJSON(18000);active();exact(received,['protocol','operation','role','signature']);
      check(received.protocol===protocol&&received.operation==='approval'&&received.role===other.role);
      return received;
    };
    // A network client cannot prompt the provider signer until it proves the
    // booked requester EOA on this exact connection. Provider contract approval
    // still needs the later canonical chain observations on both sides.
    let received;
    if(role==='provider') {
      received=await receive();const requester=payload(d,binding,'requester',active());
      check(verifyTypedData(requester.domain,requester.types,requester.value,received.signature)===requester.signer);
    }
    const p=payload(d,binding,role,active());
    const signature=await cancellable(()=>signApproval(structuredClone(p),{signal:wire.signal,
      timeoutMs:Math.max(1,Math.floor(Math.min(timeoutMs,totalMs)-(performance.now()-began)))}),wire.signal);active();
    check(typeof signature==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(signature));
    await wire.writeJSON({protocol,operation:'approval',role,signature});
    if(role==='requester')received=await receive();
    const ownSignature={role,signature},peerSignature={role:other.role,signature:received.signature};
    const signatures=role==='requester'?[ownSignature,peerSignature]:[peerSignature,ownSignature];
    const remaining=()=>Math.floor(Math.min(timeoutMs,totalMs)-(performance.now()-began));
    const state=await readPeerChannelState(signed,initialization,proof,binding,signatures,
      {clock:active,timeoutMs:Math.max(1,remaining()),signal:wire.signal});active();check(remaining()>0);
    const ready={protocol,operation:'authenticated',requesterDigest:state.approvals[0].digest,providerDigest:state.approvals[1].digest};
    await wire.writeJSON(ready);const ack=await wire.readJSON(1024);active();exact(ack,Object.keys(ready));
    check(Object.entries(ready).every(([k,v])=>ack[k]===v)&&remaining()>0);
    // Authentication expiry also caps later application traffic. No implicit
    // renewal, socket reuse, plaintext fallback or execution authority is given.
    clearTimeout(timer);timer=setTimeout(stop,Math.min(totalMs-(performance.now()-began),(binding.validUntil-active())*1000));
    const close=stop;
    const call=method=>async(...args)=>{try{active();const v=await wire[method](...args);active();return v;}catch{close();throw failure();}};
    complete=true;
    const channel=Object.freeze({readJSON:call('readJSON'),writeJSON:call('writeJSON'),readChunk:call('readChunk'),writeChunk:call('writeChunk'),
      assertActive:active,signal:wire.signal,fail:close,close,
      report:Object.freeze({...structuredClone(state),channelAuthenticated:true,localRole:role,protocol,tls:'TLSv1.3'})});
    authenticated.set(channel,{role,state,clock:active,claimed:false});return channel;
  } catch {throw failure();}
  finally {
    if(!complete){clearTimeout(timer);if(stop){signal?.removeEventListener('abort',stop);socket?.off?.('close',stop);}controller?.abort();wire?.fail();wire?.close();socket?.destroy?.();}
  }
}
