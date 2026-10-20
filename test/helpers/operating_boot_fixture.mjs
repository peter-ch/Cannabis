// Isolated transport fixture, NOT a VM launcher or hardware admission adapter.
// Emulates only PID-1's public prefix intake before forwarding the already-owned
// guarded guest's opaque pipes. Used to exercise the real host relay end to end.
import net from 'node:net';
import { encodeLaunchJSON } from '../../compute/guest_launch.mjs';
const ready=Buffer.from('CANNABIS-READY\x01'),staged=Buffer.from('CANNABIS-STAGED\x01'),magic=Buffer.from('CANNABIS-BOOT\x01');
function read(socket,count) {
  return new Promise((resolve,reject)=>{
    const clean=()=>{socket.off('readable',take);socket.off('error',fail);socket.off('close',fail);socket.off('end',fail);};
    const fail=()=>{clean();reject(Error('Owned boot fixture intake failed'));};
    const take=()=>{const value=socket.read(count);if(value){clean();resolve(value);}else if(socket.destroyed)fail();};
    socket.on('readable',take);socket.once('error',fail);socket.once('close',fail);socket.once('end',fail);take();
  });
}
export async function operatingBootFixture(local,{input,output,mode='normal'}={}) {
  const expected=[local.signed,local.initialization,local.request].map(v=>Buffer.from(encodeLaunchJSON(v)));
  const sockets=new Set();let timer,task,stagedPrefix=false;
  const guestEnded=input?new Promise((resolve,reject)=>{input.once('end',resolve);input.once('error',reject);}):Promise.resolve();
  guestEnded.catch(()=>{});
  const server=net.createServer(socket=>{
    sockets.add(socket);socket.on('error',()=>{});
    task=(async()=>{
      if(mode==='silent')return;
      if(mode==='wrong-ready'){socket.write(Buffer.alloc(ready.length,88));return;}
      socket.write(ready.subarray(0,4));socket.write(ready.subarray(4));
      const prefix=await read(socket,magic.length+12);
      if(!prefix.subarray(0,magic.length).equals(magic))throw Error('Owned fixture magic mismatch');
      for(let i=0;i<3;i++) {
        if(prefix.readUInt32BE(magic.length+i*4)!==expected[i].length)throw Error('Owned fixture length mismatch');
        if(!(await read(socket,expected[i].length)).equals(expected[i]))throw Error('Owned fixture retained bytes mismatch');
      }
      if(mode==='missing-staged')return;
      if(mode==='wrong-staged'){socket.write(Buffer.alloc(staged.length,88));return;}
      stagedPrefix=true;clearTimeout(timer);socket.write(staged);
      if(input&&output){input.on('error',()=>socket.destroy());output.on('error',()=>socket.destroy());input.pipe(socket);socket.pipe(output);}
    })().catch(()=>socket.destroy());
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const socket=net.connect(server.address().port,'127.0.0.1');socket.on('error',()=>{});
  await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});sockets.add(socket);
  timer=setTimeout(()=>{for(const s of sockets)s.destroy();},30000);
  return {socket,guestEnded,staged:()=>stagedPrefix,close:async()=>{
    clearTimeout(timer);for(const s of sockets)s.destroy();input?.destroy();output?.destroy();
    await task;await new Promise(resolve=>server.close(resolve));
  }};
}
