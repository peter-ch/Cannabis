// Called after the requester has independently appraised evidence, selected its
// signed approval locally and sent the sealed execution record. No key or wallet.
import { validateRelayAccess } from '../web/work-relay.js';
const fields=(v,n)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===n.sort().join();
export async function receiveSessionResultAccess(wire,{approvalDigest,origin}) {
  try {
    wire.assertActive();const message=await wire.readJSON(4096);wire.assertActive();
    if(!fields(message,['protocol','operation','approvalDigest','access'])||message.protocol!=='cannabis.hosted-session.v1'||
      message.operation!=='result-access'||message.approvalDigest!==approvalDigest)throw Error();
    const [access]=validateRelayAccess([message.access],origin,[{approvalDigest}]);
    if(Date.now()>=access.expiresAt)throw Error();
    await wire.writeJSON({protocol:'cannabis.hosted-session.v1',operation:'result-access-ready',approvalDigest,relayId:access.id});
    wire.assertActive();return access;
  }catch{wire.fail();throw Error('Session result access differs from the selected requester approval or configured origin');}
}
