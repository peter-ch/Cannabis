// Owned signatures only: no hardware, chain funding, customer keys or payment.
import {Wallet,TypedDataEncoder} from 'ethers';
import {peerChannelTypes} from '../../compute/peer_channel.mjs';
import {dependencyHandoffTypes} from '../../compute/dependency_handoff.mjs';
import {deliveryApprovalTypes} from '../../compute/key_delivery.mjs';
import {resultStoredTypes} from '../../compute/result_transport.mjs';
export async function workflowApprovals() {
  const owner=Wallet.createRandom(),contract=Wallet.createRandom().address,h=n=>'0x'+n.toString(16).padStart(64,'0'),now=Math.floor(Date.now()/1000),items=[];
  for(const [kind,name,version,types] of [['peer','Cannabis booked peer channel','1',peerChannelTypes],
    ['dependency','Cannabis dependency handoff','1',dependencyHandoffTypes],
    ['key-release','Cannabis confidential key delivery','4',deliveryApprovalTypes('4')],
    ['stored','Cannabis encrypted result stored','1',resultStoredTypes]]) {
    const value={};let i=1;
    for(const field of Object.values(types)[0])value[field.name]=field.type==='bytes32'?h(i++):field.type==='address'?owner.address:
      field.type==='string'?(field.name==='origin'?'https://owned.invalid':'age1'+'a'.repeat(58)):1;
    if(kind==='peer')Object.assign(value,{role:0,genesisHash:h(100),bookingId:h(101),validFrom:now-1,validUntil:now+50});
    if(['dependency','key-release'].includes(kind))Object.assign(value,{reservationId:h(101),notBefore:now-1,expiresAt:now+50,rank:0});
    if(kind==='dependency')value.genesisHash=h(100);
    const domain={name,version,chainId:31337,verifyingContract:contract},digest=TypedDataEncoder.hash(domain,types,value),payload={domain,types,value,digest};
    items.push({input:{kind,reservationId:h(101),requester:owner.address,genesisHash:h(100),expiresAt:now+50,payload},
      signature:await owner.signTypedData(domain,types,value)});
  }
  return {owner,items};
}
