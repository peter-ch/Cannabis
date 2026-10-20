// A requester sends a public attestation challenge and, when required, a signed
// dependency commitment on its already booked TLS channel. Configuration,
// initialization and proof stay provider-retained.
// This capability binds boot intake; it is never confidential-hardware admission.
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { inspectPeerChannel } from './peer_channel.mjs';
import { inspectLaunchConsent } from './guest_consent.mjs';
import { guestInitialization } from './guest_initialization.mjs';
import { validateAttestationPolicy } from './attestation.mjs';
import { prepareGuestLaunch,encodeLaunchJSON } from './guest_launch.mjs';
import { inspectGuestDependency } from './guest_dependency.mjs';

const protocol='cannabis.launch-handoff.v1',used=new WeakSet(),tickets=new WeakMap();
const fail=()=>Error('Booked launch handoff failed; retain the assignment and reconcile its consumed dispatch');
const check=v=>{if(!v)throw fail();};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const integer=(n,min,max)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const seconds=()=>Math.floor(Date.now()/1000);
const sha=v=>'0x'+createHash('sha256').update(encodeLaunchJSON(v)).digest('hex');

function retained(channel,role,input,clock) {
  exact(input,['signed','initialization','proof']);const local=structuredClone(input);
  const binding=inspectPeerChannel(channel,role,local.signed,local.initialization,local.proof);
  const checked=inspectLaunchConsent(local.signed,local.initialization,local.proof,clock());
  check(!used.has(channel));used.add(channel);
  return {...local,binding,checked};
}
function challengeChecked(local,value,now) {
  exact(value,['schema','nonce','issuedAt','expiresAt','attestationPolicySHA256','binding']);
  const c=local.checked.configuration,init=guestInitialization(local.initialization);
  const policy=structuredClone(c.attestationPolicyTemplate);policy.measurements.initData=init.digest;
  check(value.schema==='cannabis.attestation.challenge.v1'&&typeof value.nonce==='string'&&/^[0-9a-f]{64}$/.test(value.nonce)&&
    !/^0+$/.test(value.nonce)&&value.attestationPolicySHA256===validateAttestationPolicy(policy)&&
    encodeLaunchJSON(value.binding)===encodeLaunchJSON(init.assignment.binding)&&
    integer(value.issuedAt,c.validFrom,now)&&integer(value.expiresAt,now+1,Math.min(c.validUntil,value.issuedAt+policy.challengeTTLSeconds)));
  return structuredClone(value);
}
function lifetime(channel,local,clock) {
  const began=performance.now(),start=clock();let last=start;
  const end=Math.min(local.checked.reservation.end,local.binding.validUntil);
  const totalMs=Math.min(local.checked.configuration.transport.timeoutMs,(end-start)*1000);
  const remaining=()=>Math.floor(Math.min(totalMs-(performance.now()-began),(end-clock())*1000));
  const active=()=>{const now=clock();channel.assertActive();check(integer(now,last,end-1)&&remaining()>0);last=now;return now;};
  return {active,remaining};
}
async function bounded(channel,limit,signal,action) {
  check(integer(limit,1,60000)&&(!signal||signal instanceof AbortSignal));
  let timer,abort;
  const stopped=new Promise((_,reject)=>{
    abort=()=>{channel.fail();reject(fail());};
    timer=setTimeout(abort,limit);signal?.addEventListener('abort',abort,{once:true});
    if(signal?.aborted)abort();
  });
  try {return await Promise.race([Promise.resolve().then(()=>{check(!signal?.aborted);return action();}),stopped]);}
  finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);}
}
function dependencyChecked(local,dependency,now) {
  return inspectGuestDependency({proof:local.proof,network:local.checked.configuration.network,
    binding:local.initialization.binding,execution:local.checked.configuration.execution,dependency,now});
}
function description(local,challenge,dependency) {
  return {protocol,assignmentSHA256:local.checked.assignmentSHA256,
    channelBinding:local.binding.channelBinding,challengeSHA256:sha(challenge),
    ...(dependency?{dependencyApprovalDigest:dependency.approvalDigest}:{})};
}

// Call before sendEncryptedInput. The requester retains the same challenge in
// its attestation ledger and later appraises evidence before wrapping any key.
export async function sendLaunchHandoff(channel,input,challenge,{timeoutMs=30000,signal,clock=seconds,dependency}={}) {
  try {
    check(integer(timeoutMs,1,60000)&&typeof clock==='function');
    const local=retained(channel,'requester',input,clock),life=lifetime(channel,local,clock);
    challenge=challengeChecked(local,challenge,life.active());
    const selected=dependencyChecked(local,dependency,clock()),d=description(local,challenge,selected);
    const request=selected?{dependency:{descriptor:selected.descriptor,signed:selected.signed}}:{};
    check(Buffer.byteLength(JSON.stringify({...d,challenge,...request}))<=128*1024-128);
    return await bounded(channel,Math.min(timeoutMs,life.remaining()),signal,async()=>{
      life.active();await channel.writeJSON({...d,operation:'challenge',challenge,...request});
      const ack=await channel.readJSON(2048);life.active();challengeChecked(local,challenge,clock());
      exact(ack,[...Object.keys(d),'operation','hardwareValidated','executionAuthorized','keyReleaseAuthorized']);
      check(Object.entries(d).every(([key,value])=>ack[key]===value)&&ack.operation==='challenge-accepted'&&
        ack.hardwareValidated===false&&ack.executionAuthorized===false&&ack.keyReleaseAuthorized===false);
      return Object.freeze({...ack});
    });
  }catch{channel?.fail?.();throw fail();}
}

// listenBookedPeers consumes its durable route BEFORE invoking this function.
// No proof, network endpoint, execution command or filesystem path comes from
// the peer frame. Late RPC completion cannot revive an expired/cancelled ticket.
export async function receiveLaunchHandoff(channel,input,{timeoutMs=30000,signal,clock=seconds}={}) {
  try {
    check(integer(timeoutMs,1,60000)&&typeof clock==='function');
    const local=retained(channel,'provider',input,clock),life=lifetime(channel,local,clock);
    return await bounded(channel,Math.min(timeoutMs,life.remaining()),signal,async()=>{
      life.active();const message=await channel.readJSON(128*1024);life.active();
      const hasDependency=Object.hasOwn(message??{},'dependency');
      exact(message,['protocol','operation','assignmentSHA256','channelBinding','challengeSHA256','challenge',
        ...(hasDependency?['dependency','dependencyApprovalDigest']:[])]);
      const challenge=challengeChecked(local,message.challenge,clock());
      const dependency=dependencyChecked(local,message.dependency,clock()),d=description(local,challenge,dependency);
      check(Object.entries(d).every(([key,value])=>message[key]===value)&&message.operation==='challenge');
      const request={proof:local.proof,challenge,...(dependency?{dependency:{descriptor:dependency.descriptor,signed:dependency.signed}}:{})};
      const launch=await prepareGuestLaunch(local.signed,local.initialization,request,{clock:life.active});
      life.active();challengeChecked(local,challenge,clock());
      await channel.writeJSON({...d,operation:'challenge-accepted',hardwareValidated:false,executionAuthorized:false,keyReleaseAuthorized:false});
      life.active();
      const ticket=Object.freeze({schema:'cannabis.launch-handoff-ticket.v1',...d,
        hardwareValidated:false,executionAuthorized:false,keyReleaseAuthorized:false});
      tickets.set(ticket,{local,launch,request,channel,life,clock,signal,consumed:false});return ticket;
    });
  }catch{channel?.fail?.();throw fail();}
}

// Process-local capability only: copied JSON/status reports cannot stage a VM.
// A failed or uncertain staging attempt consumes it permanently.
export function consumeLaunchHandoff(ticket) {
  const t=tickets.get(ticket);check(t&&!t.consumed);t.consumed=true;
  const active=()=>{check(!t.signal?.aborted);const now=t.life.active();challengeChecked(t.local,t.request.challenge,now);
    inspectPeerChannel(t.channel,'provider',t.local.signed,t.local.initialization,t.local.proof);return now;};
  active();
  return {launch:structuredClone(t.launch),requester:t.channel,signal:t.signal,active,remaining:t.life.remaining,
    bootRemaining:()=>Math.min(t.life.remaining(),Math.floor((t.request.challenge.expiresAt-t.clock())*1000)),
    publicFiles:[t.local.signed,t.local.initialization,t.request].map(v=>Buffer.from(encodeLaunchJSON(v)))};
}

// Read only the retained VM selection before starting its owned process. This
// does not consume boot intake or grant hardware/key-release authority.
export function inspectLaunchHandoff(ticket) {
  const t=tickets.get(ticket);check(t&&!t.consumed&&!t.signal?.aborted);
  challengeChecked(t.local,t.request.challenge,t.life.active());
  inspectPeerChannel(t.channel,'provider',t.local.signed,t.local.initialization,t.local.proof);
  const init=guestInitialization(t.local.initialization);check(init.assignment.tee==='snp');
  return {request:{schema:'cannabis.host-vm-request.v1',initialization:init.canonical,initData:init.digest,
    expectedLaunchDigest:t.launch.policy.measurements.launch,serviceStart:t.launch.interval.start,
    serviceEnd:t.launch.interval.end,timeoutMs:t.life.remaining()},signal:t.channel.signal};
}
