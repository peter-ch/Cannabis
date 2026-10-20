// One owned fixture rank per separately guarded job tree. Its private ECDH key
// never leaves this process. Fixture input keys are disposable, not customer keys.
import fs from 'node:fs';
import {webcrypto} from 'node:crypto';
import {createInterface} from 'node:readline';
import {verifyGroupAdmission,groupCanonical} from '../../compute/group_admission.mjs';
import {GuestGroupMesh} from '../../compute/group_mesh.mjs';
import {GroupPacketPipe} from '../../compute/group_packet_pipe.mjs';
import {executeNativeGuest} from '../../compute/guest_execution.mjs';
const lines=createInterface({input:process.stdin,crlfDelay:Infinity})[Symbol.asyncIterator]();
const read=async()=>{const next=await lines.next();if(next.done)throw Error('Owned coordinator ended');return JSON.parse(next.value);};
const send=value=>process.stdout.write(JSON.stringify(value)+'\n');
const input=await read();let mesh,pipe;
try {
  const pair=await webcrypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']),j=await webcrypto.subtle.exportKey('jwk',pair.publicKey),
    channelJwk=Object.fromEntries(['kty','crv','x','y'].map(k=>[k,j[k]]));
  send({channelJwk});
  const {proof,network,approval}=await read(),admission=await verifyGroupAdmission(proof,network,approval),entry=approval.group.peers[input.rank];
  if(groupCanonical(entry.channelJwk)!==groupCanonical(channelJwk))throw Error('Owned rank key substituted');
  pipe=new GroupPacketPipe(131072);mesh=await GuestGroupMesh.create(admission,input.rank,pair.privateKey,{onPacket:(peer,p)=>pipe.receive(peer,p)});pipe.bind(mesh);
  await mesh.listen();send({listening:true});
  if((await read()).operation!=='connect')throw Error('Owned phase changed');send({readiness:await mesh.connect()});
  await mesh.start(await read());send({active:true});
  if((await read()).operation!=='execute')throw Error('Owned phase changed');
  const result=await executeNativeGuest(entry.signed.configuration.execution,{...input.binding,rank:input.rank,worldSize:2},input.interval,async()=>{
    mesh.assertActive();fs.writeFileSync(input.marker,'owned key released');return input.job;
  },{timeoutMs:input.timeoutMs,groupPipe:pipe,signal:mesh.signal});
  send({report:result,receipt:result.receipt,ciphertext:result.ciphertext,groupCompleted:mesh.status.state==='complete'});
}catch(error){fs.writeFileSync(input.diagnostic,String(error.stack)+'\n');process.exitCode=2;}
finally{await pipe?.close();await mesh?.close();process.stdin.destroy();}
