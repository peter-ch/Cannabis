// Actual fixed host adapter. No arbitrary executable, argv, VM type or fallback
// can be supplied by a requester. Status reports never admit confidential keys.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { inspectLaunchHandoff,receiveLaunchHandoff } from '../compute/launch_handoff.mjs';
import { stageOperatingGuest,relayOperatingGuest } from './guest-boot-channel.mjs';

const script=fileURLToPath(new URL('../scripts/compute-host-vm.py',import.meta.url)),started=new WeakSet();
const failure=()=>Error('Selected SNP VM is unavailable or its lifecycle did not complete; retain dispatch and result recovery state');
const check=v=>{if(!v)throw failure();};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());

export async function launchSnpVm(ticket,{profileFile,signal}={}) {
  check(process.platform==='linux'&&process.geteuid()===0&&typeof profileFile==='string'&&path.isAbsolute(profileFile)&&
    !profileFile.includes('\0')&&(!signal||signal instanceof AbortSignal)&&!signal?.aborted&&!started.has(ticket));
  const retained=inspectLaunchHandoff(ticket);started.add(ticket);
  const child=spawn('/usr/bin/python3',['-I','-B',script,profileFile,String(process.pid)],{
    stdio:['pipe','pipe','ignore','ignore','pipe'],shell:false,windowsHide:true,
    env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',PYTHONDONTWRITEBYTECODE:'1'}});
  const socket=child.stdio[4];let buffer='',bytes=0,readyValue,terminal,exited=false,closed=false,cancelled=false,killTimer;
  let readyResolve,readyReject,resolve,reject;
  const ready=new Promise((yes,no)=>{readyResolve=yes;readyReject=no;});
  const completion=new Promise((yes,no)=>{resolve=yes;reject=no;});completion.catch(()=>{});ready.catch(()=>{});
  const stop=()=>{
    if(cancelled||exited)return;cancelled=true;clearInterval(heartbeat);
    socket.destroy();if(child.stdin.writable)child.stdin.end('C');
    // If the host supervisor itself hangs, terminate that owned process. Its
    // independent guardian observes pidfd death; absent a report, cleanup stays
    // unverified to the caller and no uncertain storage is reclaimed.
    killTimer=setTimeout(()=>child.kill('SIGKILL'),10000);
  };
  const heartbeat=setInterval(()=>{if(!exited&&!cancelled&&child.stdin.writable&&child.stdin.writableLength<16)child.stdin.write('H');else if(!exited)stop();},1000);
  const setupTimer=setTimeout(stop,Math.min(30000,retained.request.timeoutMs));
  for(const s of [signal,retained.signal].filter(Boolean))s.addEventListener('abort',stop,{once:true});
  const cleanup=()=>{clearInterval(heartbeat);clearTimeout(setupTimer);clearTimeout(killTimer);
    for(const s of [signal,retained.signal].filter(Boolean))s.removeEventListener('abort',stop);};
  child.stdin.on('error',stop);socket.on('error',stop);child.stdout.on('error',stop);child.on('error',stop);
  child.stdout.on('data',part=>{
    try {
      bytes+=part.length;check(bytes<=8192);buffer+=part.toString('utf8');check(buffer.length<=8192);
      while(buffer.includes('\n')) {
        const pos=buffer.indexOf('\n'),line=buffer.slice(0,pos);buffer=buffer.slice(pos+1);const row=JSON.parse(line);
        check(!terminal);
        if(row.schema==='cannabis.host-vm-ready.v1') {
          exact(row,['schema','initData','expectedLaunchDigest','hardwareValidated']);
          check(!readyValue&&!cancelled&&row.initData===retained.request.initData&&
            row.expectedLaunchDigest===retained.request.expectedLaunchDigest&&row.hardwareValidated===false);
          readyValue=row;clearTimeout(setupTimer);readyResolve();
        }else if(row.schema==='cannabis.host-vm-retirement.v1') {
          exact(row,['schema','localTreeStopped','guestShutdownObserved','protectedKeyRetirementVerified','hardwareValidated']);
          check(readyValue&&row.localTreeStopped===true&&row.guestShutdownObserved===true&&
            row.protectedKeyRetirementVerified===false&&row.hardwareValidated===false);terminal=row;
        }else {
          exact(row,['schema','readyEmitted','localTreeStopped','protectedKeyRetirementVerified','hardwareValidated']);
          check(row.schema==='cannabis.host-vm-failure.v1'&&typeof row.readyEmitted==='boolean'&&typeof row.localTreeStopped==='boolean'&&
            row.protectedKeyRetirementVerified===false&&row.hardwareValidated===false);terminal=row;readyReject(failure());
        }
      }
    }catch{stop();}
  });
  child.on('close',code=>{
    exited=closed=true;cleanup();socket.destroy();
    if(code===0&&terminal?.schema==='cannabis.host-vm-retirement.v1'&&!buffer&&!cancelled)resolve(Object.freeze(terminal));
    else {
      const error=failure();Object.defineProperty(error,'localCleanupReport',{value:terminal??null,enumerable:false});
      readyReject(error);reject(error);
    }
  });
  const request=Buffer.from(JSON.stringify(retained.request)),header=Buffer.alloc(4);header.writeUInt32BE(request.length);
  child.stdin.write(Buffer.concat([header,request]));
  if(signal?.aborted||retained.signal.aborted)stop();
  try{await ready;check(!cancelled&&!closed);}
  catch(error){stop();await completion.catch(()=>{});throw error;}
  return Object.freeze({socket,completion,cancel:stop,
    snapshot:()=>({schema:'cannabis.host-vm-state.v1',phase:closed?'stopped':cancelled?'stopping':'running',
      localTreeStopped:terminal?.localTreeStopped===true,hardwareValidated:false,protectedKeyRetirementVerified:false})});
}

// Use as the provider's retained route handler. Independent providers can own
// this adapter; no founder service or universal launch signer is consulted.
export async function runSnpBookedSession(requester,local,{profileFile,origin,spool,reserveResult,signal,fetchImpl,wait}={}) {
  let vm,guest;
  try {
    const ticket=await receiveLaunchHandoff(requester,{signed:local.signed,initialization:local.initialization,proof:local.proof},{signal});
    vm=await launchSnpVm(ticket,{profileFile,signal});
    guest=await stageOperatingGuest(vm.socket,ticket,{signal});
    const result=await relayOperatingGuest(guest,{origin,spool,reserveResult,signal,fetchImpl,wait});
    const cleanup=await vm.completion;
    return {...result,hostVm:cleanup};
  }catch(error){vm?.cancel();if(vm)await vm.completion.catch(()=>{});requester.fail();throw error;}
  finally{guest?.close();}
}
