// Atomic promotion of signed capacity holds after finalized, fully accepted escrow funding.
import { AbiCoder, TypedDataEncoder, getAddress, keccak256, verifyTypedData } from 'ethers';
import { domain, reservationPayload, verifyOffer } from './capacity.mjs';
import { readFinalizedEscrow } from './finality.mjs';
import { settlementTerms, termsDigest } from '../scripts/compute-escrow.mjs';
import { policy } from '../scripts/compute-plan.mjs';

const hash=v=>typeof v==='string' && /^0x[0-9a-f]{64}$/.test(v) && !/^0x0+$/.test(v);
const coder=AbiCoder.defaultAbiCoder();
function exact(v,keys){if(!v || typeof v!=='object' || Array.isArray(v) || Object.keys(v).sort().join()!==[...keys].sort().join())throw Error('Unexpected or missing lease fields');}
export const leaseTypes={CapacityLeaseBundle:[
  ['leaseId','bytes32'],['reservationDigests','bytes32[]'],['escrow','address'],['orderId','bytes32'],['termsDigest','bytes32'],['expiresAt','uint64']
].map(([name,type])=>({name,type}))};

function build(ledger,request,now) {
  exact(request,['leaseId','reservationIds','job','settlement','escrow','expiresAt']);
  if(!hash(request.leaseId) || !Array.isArray(request.reservationIds) || !request.reservationIds.length || request.reservationIds.length>4096 || request.reservationIds.some(id=>!hash(id)) || new Set(request.reservationIds).size!==request.reservationIds.length)throw Error('Require unique bounded reservation IDs');
  if(!Number.isSafeInteger(now) || !Number.isSafeInteger(request.expiresAt) || request.expiresAt<=now)throw Error('Lease signing window expired');
  if(request.job?.schema!=='cannabis.compute.order.v2')throw Error('A universal v2 workload order is required');
  exact(request.settlement,['workers','deliveryManager','adjudicator','acceptBy','deliverBy','reviewSeconds','disputeSeconds']);
  if(Array.isArray(request.settlement.workers))for(const worker of request.settlement.workers)exact(worker,['account','shareBps']);
  const escrow=getAddress(request.escrow),terms=settlementTerms(request.job,request.settlement);
  if(escrow==='0x0000000000000000000000000000000000000000')throw Error('Invalid escrow address');
  const reservations=[],digests=[],prices=new Map();let total=0n;
  for(const id of [...request.reservationIds].sort()) {
    const row=ledger.db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
    if(!row)throw Error('Unknown reservation');
    if(row.holdUntil<=now || row.start<now || request.expiresAt>row.holdUntil)throw Error('Reservation hold expired or does not cover signing window');
    if(ledger.db.prepare('SELECT 1 FROM leased_reservations WHERE reservationId=?').get(id))throw Error('Reservation already belongs to a funded lease');
    const signed=JSON.parse(row.body),r=signed.reservation;
    const offerRow=ledger.db.prepare('SELECT body FROM offers WHERE digest=?').get(r.offerDigest);
    const signedOffer=JSON.parse(offerRow.body),offer=signedOffer.offer;
    verifyOffer(ledger.context,signedOffer,now);
    const rp=reservationPayload(ledger.context,r),provider=getAddress(offer.provider);
    if(verifyTypedData(rp.domain,rp.types,rp.value,signed.requesterSignature)!==terms.requester || verifyTypedData(rp.domain,rp.types,rp.value,signed.providerSignature)!==provider)throw Error('Stored reservation signatures differ');
    if(getAddress(r.requester)!==terms.requester || r.jobSHA256!=='0x'+request.job.packageSHA256 || offer.policySHA256!=='0x'+request.job.policySHA256)throw Error('Reservation workload, policy or requester mismatch');
    if(terms.terms.acceptBy>r.start || terms.terms.deliverBy<r.end)throw Error('Escrow deadlines do not cover the reserved service interval');
    const gross=BigInt(r.grossBaseUnits);total+=gross;prices.set(provider,(prices.get(provider)??0n)+gross);
    reservations.push({id,start:r.start,end:r.end,provider,grossBaseUnits:r.grossBaseUnits});digests.push(rp.digest);
  }
  if(total!==BigInt(terms.terms.budget) || prices.size!==terms.accounts.length || terms.accounts.some(a=>!prices.has(a)))throw Error('Escrow budget or providers differ from capacity quotes');
  for(let i=0;i<terms.accounts.length;i++) {
    if(total*BigInt(terms.shares[i])!==prices.get(terms.accounts[i])*10000n)throw Error('Quoted gross allocations cannot be represented by the agreed escrow basis points; re-quote or use separate orders');
  }
  const binding={chainId:ledger.context.chainId,escrow,token:getAddress(ledger.context.token),founderRecipient:getAddress(policy.founderRecipient),...terms};
  const orderId=keccak256(coder.encode(['string','uint256','address','address','bytes32'],['Cannabis compute order v1',ledger.context.chainId,escrow,terms.requester,terms.terms.jobHash]));
  const value={leaseId:request.leaseId,reservationDigests:digests,escrow,orderId,termsDigest:termsDigest(binding),expiresAt:request.expiresAt};
  const d=domain(ledger.context);
  return {domain:d,types:leaseTypes,value,digest:TypedDataEncoder.hash(d,leaseTypes,value),requester:terms.requester,providers:terms.accounts,reservations};
}

export function leasePayload(ledger,request,now=Math.floor(Date.now()/1000)) {
  return ledger.transaction(()=>build(ledger,request,now));
}

function signatures(payload,signed) {
  if(verifyTypedData(payload.domain,payload.types,payload.value,signed.requesterSignature)!==payload.requester)throw Error('Requester lease signature mismatch');
  if(!Array.isArray(signed.providerSignatures) || signed.providerSignatures.length!==payload.providers.length)throw Error('Every provider must sign the same lease bundle');
  const seen=new Set();
  for(const item of signed.providerSignatures) {
    exact(item,['provider','signature']);const provider=getAddress(item.provider);
    if(seen.has(provider) || !payload.providers.includes(provider) || verifyTypedData(payload.domain,payload.types,payload.value,item.signature)!==provider)throw Error('Provider lease signature mismatch');
    seen.add(provider);
  }
}

export async function promoteLease(ledger,signed,network,clock=()=>Math.floor(Date.now()/1000)) {
  signed=structuredClone(signed);network=structuredClone(network);
  exact(signed,['request','requesterSignature','providerSignatures']);
  const payload=leasePayload(ledger,signed.request,clock());signatures(payload,signed);
  if(BigInt(network.chainId)!==BigInt(ledger.context.chainId) || getAddress(network.token)!==getAddress(ledger.context.token) || getAddress(network.escrow)!==payload.value.escrow)throw Error('Lease and network domains differ');
  const snapshot=await readFinalizedEscrow({...network,orderId:payload.value.orderId},clock);
  if(snapshot.termsDigest.toLowerCase()!==payload.value.termsDigest.toLowerCase() || snapshot.requester!==payload.requester)throw Error('Finalized escrow differs from the signed lease terms');
  if(snapshot.state!==2 || snapshot.acceptedCount!==payload.providers.length || BigInt(snapshot.acceptedBitmap)!==(1n<<BigInt(payload.providers.length))-1n)throw Error('Every provider must have accepted the funded order in finalized state');
  return ledger.transaction(()=>{
    // Recheck expiry and ownership after the asynchronous chain reads while holding the write lock.
    const current=build(ledger,signed.request,clock());
    if(current.digest!==payload.digest)throw Error('Reservation bundle changed during finality inspection');
    const record={schema:'cannabis.compute.funded-lease.v1',leaseId:payload.value.leaseId,digest:payload.digest,agreement:signed,
      escrow:snapshot.escrow,orderId:snapshot.orderId,reservations:payload.reservations,finalityEvidence:snapshot,
      executionAuthorized:false,keyReleaseAuthorized:false,paymentSent:false,
      note:'Capacity is reserved through each signed service interval. Fresh attestation and protected runtime authorization remain separate requirements.'};
    ledger.db.prepare('INSERT INTO lease_bundles VALUES (?,?,?,?,?)').run(record.leaseId,record.digest,record.escrow,record.orderId,JSON.stringify(record));
    for(const r of payload.reservations)ledger.db.prepare('INSERT INTO leased_reservations VALUES (?,?)').run(r.id,record.leaseId);
    return record;
  });
}

export function inspectLease(ledger,leaseId) {
  if(!hash(leaseId))throw Error('Invalid lease ID');
  const row=ledger.db.prepare('SELECT body FROM lease_bundles WHERE id=?').get(leaseId);
  if(!row)throw Error('Unknown funded lease');
  return JSON.parse(row.body);
}
