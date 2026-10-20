// Ordinary-host transport for the fixed operating PID-1 protocol. The selected
// VM launcher must own the socket and process lifetime. READY/STAGED only say
// public intake progressed; they never authenticate protected execution.
import { Socket } from 'node:net';
import { performance } from 'node:perf_hooks';
import { consumeLaunchHandoff } from '../compute/launch_handoff.mjs';
import { GuestWire } from '../compute/result_transport.mjs';
import { relayAuthenticatedSession } from './session-relay.mjs';

const magic=Buffer.from('CANNABIS-BOOT\x01'),ready=Buffer.from('CANNABIS-READY\x01'),staged=Buffer.from('CANNABIS-STAGED\x01');
const sockets=new WeakSet(),sessions=new WeakMap(),limits=[256*1024,65536,16*1024*1024];
const fail=()=>Error('Operating guest boot transport failed; preserve consumed dispatch and uncertain results');
const check=v=>{if(!v)throw fail();};

function readStatus(socket,expected,signal) {
  return new Promise((resolve,reject)=>{
    let done=false;
    const finish=ok=>{if(done)return;done=true;socket.off('readable',read);socket.off('error',stop);socket.off('end',stop);socket.off('close',stop);
      signal.removeEventListener('abort',stop);ok?resolve():reject(fail());};
    const stop=()=>finish(false);
    const read=()=>{if(signal.aborted||socket.destroyed||socket.readableLength>65536)return stop();
      const bytes=socket.read(expected.length);if(bytes)finish(bytes.equals(expected));};
    socket.on('readable',read);socket.once('error',stop);socket.once('end',stop);socket.once('close',stop);
    signal.addEventListener('abort',stop,{once:true});read();
  });
}
function write(socket,bytes,signal) {
  return new Promise((resolve,reject)=>{
    let done=false;
    const finish=ok=>{if(done)return;done=true;socket.off('error',stop);socket.off('close',stop);signal.removeEventListener('abort',stop);ok?resolve():reject(fail());};
    const stop=()=>finish(false);socket.once('error',stop);socket.once('close',stop);signal.addEventListener('abort',stop,{once:true});
    if(signal.aborted||socket.destroyed)return stop();socket.write(bytes,e=>finish(!e));
  });
}

export async function stageOperatingGuest(socket,ticket,{timeoutMs=30000,signal}={}) {
  const controller=new AbortController(),began=performance.now();let timer,held,wire,handedOff=false;
  const stop=()=>{controller.abort();socket?.destroy();};
  try {
    check(socket instanceof Socket&&!socket.destroyed&&!socket.connecting&&socket.readable&&socket.writable&&!sockets.has(socket)&&
      Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=60000&&(!signal||signal instanceof AbortSignal)&&!signal?.aborted);
    sockets.add(socket);held=consumeLaunchHandoff(ticket);
    const external=[signal,held.signal,held.requester.signal].filter(Boolean);
    for(const s of external){check(!s.aborted);s.addEventListener('abort',stop,{once:true});}
    const budget=Math.min(timeoutMs,held.bootRemaining());check(budget>0);timer=setTimeout(stop,budget);
    const active=()=>{held.active();check(!controller.signal.aborted&&performance.now()-began<budget&&held.bootRemaining()>0);};
    active();await readStatus(socket,ready,controller.signal);active();
    const sizes=Buffer.alloc(12);held.publicFiles.forEach((bytes,i)=>{check(bytes.length>=2&&bytes.length<=limits[i]);sizes.writeUInt32BE(bytes.length,i*4);});
    await write(socket,Buffer.concat([magic,sizes]),controller.signal);
    for(const file of held.publicFiles)for(let offset=0;offset<file.length;offset+=65536){active();await write(socket,file.subarray(offset,offset+65536),controller.signal);}
    active();await readStatus(socket,staged,controller.signal);active();
    // Only now install the single framed parser. readStatus consumed precisely
    // the fixed acknowledgement; pipelined GuestWire bytes remain in the socket.
    wire=new GuestWire(socket,socket,{timeoutMs:held.remaining(),signal:controller.signal});
    const dispose=()=>{for(const s of external)s.removeEventListener('abort',stop);};socket.once('close',dispose);
    clearTimeout(timer);timer=undefined;
    const state={wire,held,used:false,phase:'staged'};
    const session=Object.freeze({schema:'cannabis.operating-guest-channel.v1',assignmentSHA256:ticket.assignmentSHA256,
      challengeSHA256:ticket.challengeSHA256,publicPrefixStaged:true,hardwareValidated:false,executionAuthorized:false,
      snapshot:()=>({phase:state.phase,guestRetirementVerified:false,hardwareValidated:false}),
      close:()=>{state.phase='transport-closed';stop();wire.fail();wire.close();dispose();}});
    sessions.set(session,state);handedOff=true;return session;
  }catch{stop();held?.requester.fail();throw fail();}
  finally {clearTimeout(timer);if(!handedOff){signal?.removeEventListener('abort',stop);held?.signal?.removeEventListener('abort',stop);
    held?.requester.signal.removeEventListener('abort',stop);wire?.fail();wire?.close();}}
}

// Exact held launch and channel, never caller-selected launch metadata. Physical
// storage and remote read-grant admission remain mandatory in the existing relay.
export async function relayOperatingGuest(session,options={}) {
  const state=sessions.get(session);check(state&&!state.used);state.used=true;
  try {
    check(Object.keys(options).every(k=>['origin','spool','reserveResult','signal','fetchImpl','wait'].includes(k)));
    state.held.active();state.phase='relaying';
    const report=await relayAuthenticatedSession(state.wire,state.held.requester,{...options,launch:state.held.launch});
    state.phase='awaiting-guest-exit';return report;
  }catch(error){session.close();state.phase='failed';throw error;}
  // Successful result transport is not completed guest cleanup. The owning VM
  // adapter must observe its process/tree termination before closing/reclaiming.
}
