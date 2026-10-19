// Public, typed market plans. Never accept an RPC destination, private key,
// arbitrary ABI call or plaintext customer workload from a browser action.
import {createHash} from 'node:crypto';
import {AbiCoder,Interface,TypedDataEncoder,getAddress,keccak256,ZeroAddress} from 'ethers';
import {bookingPayload,prepareMarketTransaction} from '../compute/market.mjs';
import {encodeProviderManifest} from '../compute/provider_manifest.mjs';
import {settlementTerms,termsDigest} from '../scripts/compute-escrow.mjs';
import escrowABI from '../compute/escrow-abi.json' with {type:'json'};

export const check=v=>{if(!v)throw Error('Market plan or retained selection is invalid');};
export const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
export const uint=(v,bits=256,zero=false)=>{check(typeof v==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(v));const n=BigInt(v);check((zero||n>0n)&&n<2n**BigInt(bits));return n;};
export const hash=v=>{check(typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v));return v;};
export const address=(v,zero=false)=>{check(typeof v==='string'&&getAddress(v)===v&&(zero||v!==ZeroAddress));return v;};
export const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?
  '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
export const sha=v=>createHash('sha256').update(typeof v==='string'?v:canonical(v)).digest('hex');
export const json=v=>JSON.parse(JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x));
const coder=AbiCoder.defaultAbiCoder(),escrow=new Interface(escrowABI),token=new Interface(['function approve(address spender,uint256 value) returns(bool)']);
const founder='0xe02Ad92413aD0a3Aac8263eE3C2Bd9410955F89b';
const deploymentKeys=['chainId','genesisHash','market','marketCodeHash','nativeEscrow','nativeEscrowCodeHash','cannabisEscrow','cannabisEscrowCodeHash','token','tokenCodeHash','founderRecipient'];

export function marketConfiguration(input) {
  const c=structuredClone(input);exact(c,['schema','rpc',...deploymentKeys,'maxFinalizedAgeSeconds','maxHeadAgeSeconds','feeLimits']);
  check(c.schema==='cannabis.market-console.v1'&&typeof c.rpc==='string'&&c.rpc.length<=2048);
  const u=new URL(c.rpc);check(!u.username&&!u.password&&!u.hash&&(u.protocol==='https:'||u.protocol==='http:'&&u.hostname==='127.0.0.1'));
  uint(c.chainId);for(const k of ['genesisHash','marketCodeHash','nativeEscrowCodeHash','cannabisEscrowCodeHash','tokenCodeHash'])hash(c[k]);
  for(const k of ['market','nativeEscrow','cannabisEscrow','token','founderRecipient'])address(c[k]);
  check(new Set(['market','nativeEscrow','cannabisEscrow','token'].map(k=>c[k])).size===4&&c.founderRecipient===founder);
  check(Number.isSafeInteger(c.maxFinalizedAgeSeconds)&&c.maxFinalizedAgeSeconds>=1&&c.maxFinalizedAgeSeconds<=7200&&
    Number.isSafeInteger(c.maxHeadAgeSeconds)&&c.maxHeadAgeSeconds>=1&&c.maxHeadAgeSeconds<=120);
  exact(c.feeLimits,['gas','maxFeePerGas','maxPriorityFeePerGas','maxTotalWei']);
  for(const v of Object.values(c.feeLimits))uint(v);
  check(uint(c.feeLimits.gas)<=100000000n&&uint(c.feeLimits.maxPriorityFeePerGas)<=uint(c.feeLimits.maxFeePerGas));
  return c;
}
export const deployment=c=>Object.fromEntries(deploymentKeys.map(k=>[k,c[k]]));
export const readerOptions=c=>({rpc:c.rpc,chainId:c.chainId,genesisHash:c.genesisHash,market:c.market,marketCodeHash:c.marketCodeHash,
  finality:'rpc-finalized',maxFinalizedAgeSeconds:c.maxFinalizedAgeSeconds,maxHeadAgeSeconds:c.maxHeadAgeSeconds});
export function assetFor(c,name) {
  check(['ETH','Cannabis'].includes(name));return name==='ETH'?{name,escrow:c.nativeEscrow,codeHash:c.nativeEscrowCodeHash,token:ZeroAddress}:
    {name,escrow:c.cannabisEscrow,codeHash:c.cannabisEscrowCodeHash,token:c.token};
}

export function prepareMarketPlan(configuration,input) {
  const c=marketConfiguration(configuration),p=structuredClone(input);
  check(Buffer.byteLength(canonical(p))<=131072&&p.schema==='cannabis.market-plan.v1');
  let detail;
  if(p.kind==='resource') {
    exact(p,['schema','kind','provider','resourceId','serviceHash','units']);address(p.provider);hash(p.resourceId);hash(p.serviceHash);uint(p.units,32);
    detail={resource:keccak256(coder.encode(['address','bytes32'],[p.provider,p.resourceId]))};
  } else if(p.kind==='offer') {
    exact(p,['schema','kind','provider','nonce','manifest']);address(p.provider);hash(p.nonce);
    const encoded=encodeProviderManifest(p.manifest),m=encoded.manifest;
    check(m.chainId===c.chainId&&m.genesisHash===c.genesisHash&&m.market===c.market&&m.resource.provider===p.provider&&
      [c.nativeEscrow,c.cannabisEscrow].includes(m.offer.escrow)&&m.offerId===keccak256(coder.encode(['address','bytes32'],[p.provider,p.nonce])));
    detail={offerId:m.offerId,manifestHash:encoded.manifestHash,manifestBytes:encoded.bytes.toString('utf8'),offer:{...m.offer,manifestHash:encoded.manifestHash}};
  } else if(p.kind==='order') {
    exact(p,['schema','kind','asset','job','settlement','bookings']);const asset=assetFor(c,p.asset);
    // Universal public commitments only; legacy workload plans contain code/args.
    check(p.job?.schema==='cannabis.compute.order.v2');
    exact(p.settlement,['workers','deliveryManager','adjudicator','acceptBy','deliverBy','reviewSeconds','disputeSeconds']);
    check(Array.isArray(p.settlement.workers)&&p.settlement.workers.length<=64);
    for(const w of p.settlement.workers)exact(w,['account','shareBps']);
    const s=settlementTerms(p.job,p.settlement);address(s.requester);
    const digest=termsDigest({chainId:c.chainId,escrow:asset.escrow,token:asset.token,founderRecipient:c.founderRecipient,...s});
    const orderId=keccak256(coder.encode(['string','uint256','address','address','bytes32'],['Cannabis compute order v1',c.chainId,asset.escrow,s.requester,s.terms.jobHash]));
    check(Array.isArray(p.bookings)&&p.bookings.length>0&&p.bookings.length<=64);
    const nonces=new Set();let gross=0n;
    const bookings=p.bookings.map(b=>{
      exact(b,['reservationId','offerId','start','end','units','gross','holdUntil']);hash(b.reservationId);hash(b.offerId);
      check(!nonces.has(b.reservationId));nonces.add(b.reservationId);
      for(const k of ['start','end','holdUntil'])uint(b[k],64);uint(b.units,32);uint(b.gross);
      const value={...b,requester:s.requester,orderId,termsDigest:digest},payload=bookingPayload(c,value);
      check(BigInt(b.start)>=BigInt(s.terms.acceptBy)&&BigInt(b.end)<=BigInt(s.terms.deliverBy));gross+=BigInt(b.gross);
      return {...payload,bookingId:payload.digest};
    });
    check(gross===BigInt(s.terms.budget));detail={...s,asset,orderId,termsDigest:digest,bookings};
  } else check(false);
  return json({schema:'cannabis.market-retained-plan.v1',id:sha({deployment:deployment(c),plan:p}),deployment:deployment(c),plan:p,detail});
}

export function marketAction(configuration,retained,input,signatures={}) {
  const c=marketConfiguration(configuration),r=prepareMarketPlan(c,retained.plan);check(r.id===retained.id);
  exact(input,['method','actor','bookingId']);address(input.actor);check(input.bookingId===null||hash(input.bookingId));
  const {method,actor,bookingId}=input,p=r.plan,d=r.detail;let transaction,summary;
  const market=(name,args)=>prepareMarketTransaction(c,{from:actor,method:name,args}).transaction;
  const contract=(to,name,args,value='0')=>({chainId:c.chainId,from:actor,to,value,data:escrow.encodeFunctionData(name,args)});
  if(p.kind==='resource') {
    check(method==='publishResource'&&actor===p.provider&&bookingId===null);
    transaction=market(method,[p.resourceId,p.serviceHash,p.units]);summary={resource:d.resource,resourceId:p.resourceId,serviceHash:p.serviceHash,declaredUnits:p.units};
  } else if(p.kind==='offer') {
    check(['publishOffer','withdrawOffer'].includes(method)&&actor===p.provider&&bookingId===null);
    transaction=market(method,method==='publishOffer'?[p.nonce,d.offer]:[d.offerId]);summary={offerId:d.offerId,nonce:p.nonce,...d.offer};
  } else {
    summary={orderId:d.orderId,asset:p.asset,requester:d.requester,escrow:d.asset.escrow,termsDigest:d.termsDigest,
      grossBaseUnits:d.terms.budget,serviceFeeBaseUnits:(BigInt(d.terms.budget)/100n).toString(),workerBaseUnits:(BigInt(d.terms.budget)*99n/100n).toString(),
      terms:d.terms,accounts:d.accounts,shares:d.shares,bookings:d.bookings.map(b=>b.value)};
    if(method==='signBooking') {
      const b=d.bookings.find(x=>x.bookingId===bookingId);check(b);
      return {kind:'signature',planId:r.id,method,actor,bookingId,summary,
        typedData:json(TypedDataEncoder.getPayload(b.domain,b.types,b.value)),digest:b.digest};
    }
    check(bookingId===null);
    if(method==='reserveBatch') {
      check(actor===d.requester);const signed=d.bookings.map(b=>signatures[b.bookingId]);
      check(signed.every(v=>typeof v==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(v)));
      transaction=market(method,[d.bookings.map(b=>b.value),signed]);
    } else if(method==='approveToken') {
      check(p.asset==='Cannabis'&&actor===d.requester);transaction={chainId:c.chainId,from:actor,to:c.token,value:'0',data:token.encodeFunctionData('approve',[d.asset.escrow,d.terms.budget])};
    } else if(method==='fund') {
      check(actor===d.requester);transaction=contract(d.asset.escrow,'fund',[d.terms,d.accounts,d.shares],p.asset==='ETH'?d.terms.budget:'0');
    } else if(method==='accept') {
      check(d.accounts.includes(actor));transaction=contract(d.asset.escrow,'accept',[d.orderId]);
    } else if(method==='activate') {
      check(actor===d.requester||d.accounts.includes(actor));transaction=market(method,[d.bookings.map(b=>b.bookingId).sort()]);
    } else if(method==='cancel') {
      check(actor===d.requester);transaction=contract(d.asset.escrow,'cancel',[d.orderId]);
    } else if(method==='withdrawWorker') {
      check(d.accounts.includes(actor));transaction=contract(d.asset.escrow,'withdrawWorker',[d.orderId,actor]);
    } else if(method==='withdrawCredit') {
      check(actor===d.requester||d.accounts.includes(actor));transaction=contract(d.asset.escrow,'withdrawCredit',[actor]);
    } else check(false);
  }
  return json({kind:'transaction',planId:r.id,method,actor,bookingId,transaction,summary});
}
