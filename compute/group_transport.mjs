// Public group control messages pass through the existing authenticated booked
// session. Content keys and application packets never enter this transport.
import {GROUP_MAX_BYTES,groupCanonical,verifyGroupAdmission,inspectGroupAdmission,verifyGroupStart} from './group_admission.mjs';
const protocol='cannabis.guest-wire.v1';
const check=v=>{if(!v)throw Error('Protected group control handoff failed');};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const same=(a,b)=>groupCanonical(a)===groupCanonical(b);
function command(value,operation,keys=[]) {
  exact(value,['protocol','operation',...keys]);check(value.protocol===protocol&&value.operation===operation);return value;
}
function listening(value,binding) {
  exact(value,['schema','groupDigest','rank','worldSize']);
  check(value.schema==='cannabis.protected-group-listening.v1');
  for(const k of ['groupDigest','rank','worldSize'])check(value[k]===binding[k]);return value;
}
function readiness(value,binding) {
  exact(value,['schema','groupDigest','rank','meshDigest','readyAt','authenticator']);
  check(value.schema==='cannabis.protected-group-ready.v1'&&value.groupDigest===binding.groupDigest&&value.rank===binding.rank&&
    /^0x[0-9a-f]{64}$/.test(value.meshDigest)&&/^[A-Za-z0-9_-]{43}$/.test(value.authenticator)&&Number.isSafeInteger(value.readyAt));
  return value; // The requester MUST authenticate this with its retained ECDH key.
}
function active(value,binding) {
  exact(value,['schema','groupDigest','groupStartDigest','rank','worldSize']);check(value.schema==='cannabis.protected-group-active.v1');
  for(const k of ['groupDigest','groupStartDigest','rank','worldSize'])check(value[k]===binding[k]);return value;
}

export async function serveGuestGroup(session,wire) {
  check(session.groupRequired);
  const prepare=command(await wire.readJSON(GROUP_MAX_BYTES+65536),'group-prepare',['approval']);
  const ready=await session.prepareGroup(prepare.approval);
  await wire.writeJSON({protocol,operation:'group-listening',listening:ready});
  command(await wire.readJSON(1024),'group-connect');
  const joined=await session.connectGroup();
  await wire.writeJSON({protocol,operation:'group-ready',readiness:joined});
  const start=command(await wire.readJSON(131072),'group-start',['start']);
  const started=await session.startGroup(start.start);
  await wire.writeJSON({protocol,operation:'group-active',active:started});
}

export async function prepareGuestGroup(wire,approval,binding) {
  await wire.writeJSON({protocol,operation:'group-prepare',approval});
  return listening(command(await wire.readJSON(1024),'group-listening',['listening']).listening,binding);
}
export async function connectGuestGroup(wire,binding) {
  await wire.writeJSON({protocol,operation:'group-connect'});
  return readiness(command(await wire.readJSON(2048),'group-ready',['readiness']).readiness,binding);
}
export async function startGuestGroup(wire,start,binding) {
  await wire.writeJSON({protocol,operation:'group-start',start});
  return active(command(await wire.readJSON(2048),'group-active',['active']).active,{...binding,groupStartDigest:start.payload.digest});
}

// The operator only relays public authorization and opaque transport. Its
// validation neither supplies a hardware appraisal nor authorizes guest keys.
export async function relayGuestGroup(launch,evidence,requester,guest) {
  const prepare=command(await requester.readJSON(GROUP_MAX_BYTES+65536),'group-prepare',['approval']);
  const admission=await verifyGroupAdmission(launch.funding.proof,launch.funding.network,prepare.approval);
  const d=inspectGroupAdmission(admission),rank=launch.initialization.binding.rank,own=d.group.peers[rank];
  check(own&&same(own.initialization,launch.initialization)&&same(own.challenge,launch.challenge)&&
    same(own.signed,launch.funding.consent)&&same(own.channelJwk,evidence.channelJwk));
  const binding={groupDigest:admission.groupDigest,rank,worldSize:admission.worldSize};
  await guest.writeJSON(prepare);
  const prepared=command(await guest.readJSON(1024),'group-listening',['listening']);listening(prepared.listening,binding);
  await requester.writeJSON(prepared);
  const connect=command(await requester.readJSON(1024),'group-connect');await guest.writeJSON(connect);
  const ready=command(await guest.readJSON(2048),'group-ready',['readiness']);readiness(ready.readiness,binding);
  await requester.writeJSON(ready);
  const start=command(await requester.readJSON(131072),'group-start',['start']);
  const groupStartDigest=verifyGroupStart(admission,start.start,ready.readiness);
  await guest.writeJSON(start);
  const started=command(await guest.readJSON(2048),'group-active',['active']);active(started.active,{...binding,groupStartDigest});
  await requester.writeJSON(started);return {groupDigest:admission.groupDigest,groupStartDigest};
}
