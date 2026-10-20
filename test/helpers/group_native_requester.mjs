// Owned synthetic roster/approval fixture; no hardware or funding authority.
import {createInterface} from 'node:readline';
import {groupFixture} from './group_fixture.mjs';
import {RequesterGroupReadiness} from '../../compute/group_mesh.mjs';
const lines=createInterface({input:process.stdin,crlfDelay:Infinity})[Symbol.asyncIterator]();
const read=async()=>{const n=await lines.next();if(n.done)throw Error('Owned group intake ended');return JSON.parse(n.value);};
const input=await read();let f,reviewer;
try {
  f=await groupFixture({...input,realTime:true});process.stdout.write(JSON.stringify({proof:f.proof,network:f.network,approval:f.approval})+'\n');
  reviewer=await RequesterGroupReadiness.create(f.admission,f.requesterKey);
  const readiness=await read(),payload=reviewer.review(readiness),start={schema:'cannabis.protected-group-start.v1',readiness,payload,
    requesterSignature:await f.requester.signTypedData(payload.domain,payload.types,payload.value)};
  process.stdout.write(JSON.stringify(start)+'\n');
}finally{reviewer?.close();f?.close();process.stdin.destroy();}
