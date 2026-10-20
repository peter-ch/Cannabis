// Bounded direct chain observation and simulation. RPC-reported finality is
// explicit trust in the selected RPC; it is not a local consensus proof.
import {Interface,getAddress,keccak256,recoverAddress,ZeroAddress} from 'ethers';
import marketABI from '../compute/market-abi.json' with {type:'json'};
import escrowABI from '../compute/escrow-abi.json' with {type:'json'};
import {boundedDiscoveryRPC} from '../compute/discovery_rpc.mjs';
import {termsDigest} from '../compute/settlement.mjs';
import {marketConfiguration,marketAction,prepareMarketPlan,check,hash,uint,canonical,json} from './market-plan.mjs';

const market=new Interface(marketABI),escrow=new Interface(escrowABI);
const token=new Interface(['function decimals() view returns(uint8)','function balanceOf(address) view returns(uint256)',
  'function allowance(address,address) view returns(uint256)']);
const signatureWallet=new Interface(['function isValidSignature(bytes32,bytes) view returns(bytes4)']);
const quantity=v=>{check(typeof v==='string'&&/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/.test(v));return BigInt(v);};
const hex=v=>'0x'+BigInt(v).toString(16),tag=b=>({blockHash:b.hash,requireCanonical:true});
const bytes=v=>{check(typeof v==='string'&&/^0x(?:[0-9a-fA-F]{2})*$/.test(v)&&v.length<=262146);return v;};
const same=(a,b)=>canonical(json(a))===canonical(json(b));
const stateNames=['not-funded','funded','active','delivered','disputed','settled'];
async function boundedMap(items,action) {
  const result=[];for(let i=0;i<items.length;i+=4)result.push(...await Promise.all(items.slice(i,i+4).map(action)));return result;
}

class ChainView {
  constructor(c,runtime) {this.c=marketConfiguration(c);this.transport=boundedDiscoveryRPC(runtime);this.sequence=0;this.lastClock=Date.now();}
  now() {const value=Date.now();check(value>=this.lastClock);this.lastClock=value;return Math.floor(value/1000);}
  async send(method,params) {
    const id=++this.sequence,response=await this.transport.getUrl({url:new URL(this.c.rpc).href,method:'POST',
      body:new TextEncoder().encode(JSON.stringify({jsonrpc:'2.0',id,method,params}))});
    const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(response.body));
    check(value?.jsonrpc==='2.0'&&value.id===id&&!value.error&&Object.hasOwn(value,'result'));return value.result;
  }
  async block(selector) {
    const b=await this.send('eth_getBlockByNumber',[selector,false]);hash(b?.hash);
    const number=quantity(b.number),timestamp=quantity(b.timestamp);check(number<=BigInt(Number.MAX_SAFE_INTEGER)&&timestamp<=BigInt(Number.MAX_SAFE_INTEGER));
    return {...b,number:Number(number),timestamp:Number(timestamp)};
  }
  age(b,limit) {const age=this.now()-b.timestamp;check(age>=-30&&age<=limit);}
  async call(abi,to,method,args,b) {return abi.decodeFunctionResult(method,bytes(await this.send('eth_call',[
    {to,data:abi.encodeFunctionData(method,args)},tag(b)])));}
  async verifyDeployment(b) {
    const c=this.c;
    for(const [target,expected] of [[c.market,c.marketCodeHash],[c.nativeEscrow,c.nativeEscrowCodeHash],
      [c.cannabisEscrow,c.cannabisEscrowCodeHash],[c.token,c.tokenCodeHash]]) {
      const code=bytes(await this.send('eth_getCode',[target,tag(b)]));check(code!=='0x'&&keccak256(code)===expected);
    }
    check((await this.call(market,c.market,'nativeEscrow',[],b))[0]===c.nativeEscrow&&
      (await this.call(market,c.market,'cannabisEscrow',[],b))[0]===c.cannabisEscrow);
    for(const [target,asset] of [[c.nativeEscrow,ZeroAddress],[c.cannabisEscrow,c.token]]) {
      check((await this.call(escrow,target,'token',[],b))[0]===asset&&
        (await this.call(escrow,target,'founderRecipient',[],b))[0]===c.founderRecipient&&
        (await this.call(escrow,target,'FEE_BPS',[],b))[0]===100n&&
        (await this.call(escrow,target,'PAYMENT_QUANTUM',[],b))[0]===100n);
    }
    check((await this.call(token,c.token,'decimals',[],b))[0]===18n);
  }
  async open() {
    check(quantity(await this.send('eth_chainId',[]))===BigInt(this.c.chainId));
    const genesis=await this.block('0x0');check(genesis.hash===this.c.genesisHash);
    this.finalized=await this.block('finalized');this.head=await this.block('latest');
    check(this.head.number>=this.finalized.number);this.age(this.finalized,this.c.maxFinalizedAgeSeconds);this.age(this.head,this.c.maxHeadAgeSeconds);
    await this.verifyDeployment(this.finalized);if(this.head.hash!==this.finalized.hash)await this.verifyDeployment(this.head);
  }
  async finish() {
    for(const b of [this.finalized,this.head])check((await this.block(hex(b.number))).hash===b.hash);
    check((await this.block('finalized')).number>=this.finalized.number&&(await this.block('latest')).number>=this.head.number);
    this.age(this.finalized,this.c.maxFinalizedAgeSeconds);this.age(this.head,this.c.maxHeadAgeSeconds);
  }
  publicBlocks() {const pick=b=>({number:b.number,hash:b.hash,timestamp:b.timestamp});return {finalizedBlock:pick(this.finalized),headBlock:pick(this.head)};}
  async offer(id,b) {
    const offer=json((await this.call(market,this.c.market,'offers',[id],b)).toObject(true));hash(offer.resource);
    const resource=json((await this.call(market,this.c.market,'resources',[offer.resource],b)).toObject(true));check(resource.provider!==ZeroAddress);
    return {offerId:id,offer,resource,withdrawn:(await this.call(market,this.c.market,'withdrawnOffers',[id],b))[0]};
  }
  async order(plan,b) {
    const d=plan.detail,raw=await this.call(escrow,d.asset.escrow,'orders',[d.orderId],b),order=json(raw.toObject(true));
    const state=Number(order.state);check(stateNames[state]);
    if(state===0)return {state:'not-funded',stateNumber:0,order,workers:[]};
    check(order.requester===d.requester&&Number(order.workerCount)===d.accounts.length);
    const observed=await boundedMap(Array.from({length:Number(order.workerCount)},(_,i)=>i),async index=>{
      const w=await this.call(escrow,d.asset.escrow,'workerAt',[d.orderId,index],b);
      return {worker:w[0],due:(await this.call(escrow,d.asset.escrow,'workerDue',[d.orderId,w[0].account],b))[0]};
    });
    let previous=0n;const accounts=[],shares=[],workers=[];
    for(let index=0;index<observed.length;index++) {
      const {worker:w,due}=observed[index],account=w.account,cumulative=w.cumulativeBps;
      check(cumulative>previous&&cumulative<=10000n);accounts.push(account);shares.push(Number(cumulative-previous));previous=cumulative;
      workers.push({account,shareBps:shares[index],accepted:(BigInt(order.acceptedBitmap)&(1n<<BigInt(index)))!==0n,
        withdrawn:(BigInt(order.withdrawnBitmap)&(1n<<BigInt(index)))!==0n,
        dueBaseUnits:due.toString()});
    }
    check(previous===10000n&&termsDigest({chainId:this.c.chainId,escrow:d.asset.escrow,token:d.asset.token,
      founderRecipient:this.c.founderRecipient,requester:d.requester,terms:order.terms,accounts,shares})===d.termsDigest);
    return {state:stateNames[state],stateNumber:state,order,workers};
  }
  async bookingGroup(plan,b) {
    const d=plan.detail,groups=new Map();
    const bookings=await boundedMap(d.bookings,async expected=>{
      const selected=await this.offer(expected.value.offerId,b),o=selected.offer,v=expected.value;
      check(o.escrow===d.asset.escrow&&o.policyHash==='0x'+plan.plan.job.policySHA256&&
        BigInt(v.start)>=BigInt(o.start)&&BigInt(v.end)<=BigInt(o.end)&&BigInt(v.units)<=BigInt(o.units)&&
        BigInt(v.gross)===BigInt(o.grossPerUnitSecond)*(BigInt(v.end)-BigInt(v.start))*BigInt(v.units));
      const provider=selected.resource.provider;groups.set(provider,(groups.get(provider)??0n)+BigInt(v.gross));
      if(plan.plan.executionPlan) {
        const a=plan.plan.executionPlan.assignments.find(a=>a.booking.reservationId===v.reservationId);
        check(a&&a.provider===provider&&a.serviceSHA256===selected.resource.serviceHash);
      }
      const record=await this.call(market,this.c.market,'bookings',[expected.bookingId],b);
      const recorded=record.booking.offerId!=='0x'+'0'.repeat(64);
      if(recorded)check(same(record.booking.toObject(true),v));
      return {...selected,bookingId:expected.bookingId,value:v,recorded,activated:record.activated,
        nonceUsed:(await this.call(market,this.c.market,'usedReservationIds',[d.requester,v.reservationId],b))[0]};
    });
    check(groups.size===d.accounts.length);
    for(let i=0;i<d.accounts.length;i++)check(groups.get(d.accounts[i])===BigInt(d.terms.budget)*BigInt(d.shares[i])/10000n&&
      BigInt(d.terms.budget)*BigInt(d.shares[i])%10000n===0n);
    return bookings;
  }
  async validateAction(plan,action) {
    const d=plan.detail,p=plan.plan,b=this.head,c=this.c;
    if(p.kind==='resource')return {};
    if(p.kind==='offer') {
      const resource=json((await this.call(market,c.market,'resources',[d.offer.resource],this.finalized)).toObject(true));
      check(same(resource,{provider:p.provider,serviceHash:p.manifest.resource.serviceHash,units:p.manifest.resource.units}));
      if(action.method==='withdrawOffer') {const observed=await this.offer(d.offerId,b);check(!observed.withdrawn&&same(observed.offer,d.offer));}
      return {};
    }
    const bookings=await this.bookingGroup(plan,b),order=await this.order(plan,b);
    const method=action.method;
    if(['signBooking','reserveBatch'].includes(method)) {
      for(const item of bookings)check(!item.recorded&&!item.nonceUsed&&!item.withdrawn&&BigInt(item.offer.expiresAt)>BigInt(b.timestamp)&&
        BigInt(item.value.start)>BigInt(b.timestamp)&&BigInt(item.value.holdUntil)>BigInt(b.timestamp)&&
        BigInt(item.value.holdUntil)<=BigInt(b.timestamp+1800)&&BigInt(item.value.holdUntil)<=BigInt(item.offer.expiresAt));
      // Require published offers to be finalized before another party signs.
      await boundedMap(bookings,async item=>{const finalized=await this.offer(item.offerId,this.finalized);check(!finalized.withdrawn&&same(finalized.offer,item.offer));});
      if(method==='signBooking')check(bookings.find(v=>v.bookingId===action.bookingId)?.resource.provider===action.actor);
      check(order.stateNumber===0);
    } else if(['approveToken','fund','accept','activate'].includes(method)) {
      // These sequential transactions must fit the 30-minute hold. Waiting for
      // every intermediate transaction to finalize can exhaust that hold.
      // Inspect the canonical head and disclose its reorg risk; guest admission
      // separately requires the finalized activation/funding proof.
      check(bookings.every(v=>v.recorded&&!v.activated&&BigInt(v.value.holdUntil)>BigInt(b.timestamp)&&BigInt(v.value.start)>BigInt(b.timestamp)));
      if(['approveToken','fund'].includes(method))check(order.stateNumber===0);
      if(method==='accept')check(order.stateNumber===1&&
        !order.workers.find(w=>w.account===action.actor)?.accepted);
      if(method==='activate')check(order.stateNumber===2);
      if(method==='approveToken') {
        const allowance=(await this.call(token,c.token,'allowance',[d.requester,d.asset.escrow],b))[0];
        // Never replace a different outstanding allowance without a separate,
        // explicitly reviewed allowance-reconciliation workflow.
        check(allowance===0n);
      }
    } else if(method==='cancel')check(order.stateNumber===1);
    else if(['deliver','approve','dispute','resolve','finalizeExpiredState'].includes(method)) {
      const selected=action.summary.decision,o=order.order;
      check(bookings.every(v=>v.recorded&&v.activated)||method==='finalizeExpiredState'&&selected.expectedState===1);
      if(method==='deliver')check(order.stateNumber===2&&b.timestamp<Number(o.terms.deliverBy));
      else if(method==='approve'||method==='dispute') {
        check(order.stateNumber===3&&o.outputDigest===selected.outputDigest);
        if(method==='dispute')check(b.timestamp<Number(o.reviewBy));
      } else if(method==='resolve')check(order.stateNumber===4&&o.outputDigest===selected.outputDigest&&
        o.disputeDigest===selected.reasonDigest&&b.timestamp<Number(o.resolveBy));
      else {
        check(order.stateNumber===selected.expectedState);
        const deadline={1:o.terms.acceptBy,2:o.terms.deliverBy,3:o.reviewBy,4:o.resolveBy}[order.stateNumber];
        check(BigInt(deadline)>0n&&BigInt(b.timestamp)>=BigInt(deadline));
      }
    }
    else if(method==='withdrawWorker')check(order.stateNumber===5&&(await this.order(plan,this.finalized)).stateNumber===5&&
      BigInt(order.workers.find(w=>w.account===action.actor)?.dueBaseUnits??'0')>0n);
    const credit=(await this.call(escrow,d.asset.escrow,'credits',[action.actor],b))[0];
    if(method==='withdrawCredit')check(credit>0n&&(await this.call(escrow,d.asset.escrow,'credits',[action.actor],this.finalized))[0]>0n);
    return {bookings,order,actorCreditBaseUnits:credit.toString()};
  }
  async signature(signer,digest,signature,b) {
    check(typeof signature==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(signature));
    const code=bytes(await this.send('eth_getCode',[signer,tag(b)]));
    if(code==='0x')check(recoverAddress(digest,signature)===signer);
    else check((await this.call(signatureWallet,signer,'isValidSignature',[digest,signature],b))[0]==='0x1626ba7e');
  }
  close(){this.transport.close();}
}

async function withView(c,runtime,action,basis='finalized') {
  const v=new ChainView(c,runtime);try{await v.open();const value=await action(v);await v.finish();return json({...value,...v.publicBlocks(),
    chainId:v.c.chainId,genesisHash:v.c.genesisHash,market:v.c.market,snapshotBasis:basis,
    finality:basis==='finalized'?'rpc-finalized':basis==='head'?'rpc-latest':'rpc-receipt',hardwareValidated:false,executionAuthorized:false,keyReleaseAuthorized:false});}
  finally{v.close();}
}
export async function inspectMarketPlan(c,input,runtime) {
  const r=prepareMarketPlan(c,input.plan);check(r.id===input.id);
  return withView(c,runtime,async v=>{
    if(r.plan.kind==='resource')return {resource:json((await v.call(market,v.c.market,'resources',[r.detail.resource],v.finalized)).toObject(true))};
    if(r.plan.kind==='offer') {
      // A not-yet-published offer is a legitimate state, not invented capacity.
      const raw=await v.call(market,v.c.market,'offers',[r.detail.offerId],v.finalized);
      return {offer:raw.resource==='0x'+'0'.repeat(64)?null:await v.offer(r.detail.offerId,v.finalized)};
    }
    const d=r.detail,credits={};for(const actor of [d.requester,...d.accounts])
      credits[actor]=(await v.call(escrow,d.asset.escrow,'credits',[actor],v.finalized))[0].toString();
    const bookings=await v.bookingGroup(r,v.finalized),order=await v.order(r,v.finalized);
    return {bookings,order,credits,headState:v.head.hash===v.finalized.hash?{bookings,order}:
      {bookings:await v.bookingGroup(r,v.head),order:await v.order(r,v.head)},
      tokenAllowanceBaseUnits:r.plan.asset==='Cannabis'?(await v.call(token,v.c.token,'allowance',[d.requester,d.asset.escrow],v.finalized))[0].toString():null};
  });
}
export const inspectMarketNetwork=(c,runtime)=>withView(c,runtime,async()=>({state:'observed'}));

export async function reviewMarketAction(c,input,selection,signatures,runtime,{retainedTransaction=null,minimumNonce=0n}={}) {
  const retained=prepareMarketPlan(c,input.plan);check(retained.id===input.id);
  const action=marketAction(c,retained,selection,signatures);
  retainedTransaction=retainedTransaction===null?null:structuredClone(retainedTransaction);
  return withView(c,runtime,async v=>{
    const state=await v.validateAction(retained,action);
    if(action.kind==='signature')return {action,state};
    // This adapter submits direct EOA transactions. Contract-wallet transaction
    // adapters need separate reviewed semantics; ERC-1271 booking signatures work.
    check(bytes(await v.send('eth_getCode',[action.actor,tag(v.head)]))==='0x');
    const tx={...action.transaction,chainId:hex(v.c.chainId),value:hex(action.transaction.value)};
    const nonce=quantity(await v.send('eth_getTransactionCount',[action.actor,tag(v.head)]));
    check(typeof minimumNonce==='bigint'&&minimumNonce>=0n&&nonce>=minimumNonce);
    check(quantity(await v.send('eth_getTransactionCount',[action.actor,'pending']))===nonce);
    const estimate=quantity(await v.send('eth_estimateGas',[tx,hex(v.head.number)])),gas=(estimate*120n+99n)/100n;
    const base=quantity(v.head.baseFeePerGas),priority=quantity(await v.send('eth_maxPriorityFeePerGas',[])),maxFee=base*2n+priority;
    check(gas>0n&&gas<=uint(v.c.feeLimits.gas)&&priority<=uint(v.c.feeLimits.maxPriorityFeePerGas)&&maxFee<=uint(v.c.feeLimits.maxFeePerGas));
    let transaction={...tx,type:'0x2',nonce:hex(nonce),gas:hex(gas),maxPriorityFeePerGas:hex(priority),maxFeePerGas:hex(maxFee)};
    if(retainedTransaction) {
      check(Object.keys(retainedTransaction).sort().join()===Object.keys(transaction).sort().join());
      for(const key of ['chainId','from','to','value','data','type','nonce'])check(retainedTransaction[key]===transaction[key]);
      for(const key of ['gas','maxPriorityFeePerGas','maxFeePerGas'])check(quantity(retainedTransaction[key])>=BigInt(transaction[key]));
      check(BigInt(retainedTransaction.gas)<=uint(v.c.feeLimits.gas)&&BigInt(retainedTransaction.maxFeePerGas)<=uint(v.c.feeLimits.maxFeePerGas)&&
        BigInt(retainedTransaction.maxPriorityFeePerGas)<=uint(v.c.feeLimits.maxPriorityFeePerGas));
      transaction=retainedTransaction;
    }
    const maximumGasCost=BigInt(transaction.gas)*BigInt(transaction.maxFeePerGas),maximumTotal=maximumGasCost+BigInt(tx.value);
    check(maximumTotal<=uint(v.c.feeLimits.maxTotalWei)&&quantity(await v.send('eth_getBalance',[action.actor,tag(v.head)]))>=maximumTotal);
    bytes(await v.send('eth_call',[transaction,tag(v.head)]));
    return {action:{...action,transaction},state,quote:{estimatedGas:estimate.toString(),gasLimit:BigInt(transaction.gas).toString(),
      maxFeePerGas:BigInt(transaction.maxFeePerGas).toString(),maxPriorityFeePerGas:BigInt(transaction.maxPriorityFeePerGas).toString(),maximumGasWei:maximumGasCost.toString(),
      nativeValueWei:BigInt(tx.value).toString(),maximumTotalWei:maximumTotal.toString(),
      scope:'This transaction only. Later funding, acceptance and activation need their own fresh reviews.'}};
  },'head');
}
export async function verifyBookingSignature(c,input,selection,signature,runtime) {
  const r=prepareMarketPlan(c,input.plan);check(r.id===input.id&&selection.method==='signBooking');
  const action=marketAction(c,r,selection);
  return withView(c,runtime,async v=>{await v.validateAction(r,action);await v.signature(action.actor,action.digest,signature,v.finalized);
    await v.signature(action.actor,action.digest,signature,v.head);return {bookingId:action.bookingId,signer:action.actor,signature,digest:action.digest};},'head');
}
export async function observeMarketTransaction(c,retainedReview,transactionHash,runtime) {
  hash(transactionHash);const expected=structuredClone(retainedReview.action.transaction);check(retainedReview.action.kind==='transaction');
  return withView(c,runtime,async v=>{
    const tx=await v.send('eth_getTransactionByHash',[transactionHash]);
    if(tx===null)return {transactionHash,state:'not-observed',mayHaveBeenSubmitted:true};
    check(tx.hash===transactionHash&&getAddress(tx.from)===expected.from&&getAddress(tx.to)===expected.to&&tx.input.toLowerCase()===expected.data.toLowerCase());
    for(const key of ['chainId','type','nonce','gas','value','maxFeePerGas','maxPriorityFeePerGas'])check(quantity(tx[key])===BigInt(expected[key]));
    const receipt=await v.send('eth_getTransactionReceipt',[transactionHash]);
    if(receipt===null)return {transactionHash,state:'pending',mayHaveBeenSubmitted:true};
    hash(receipt.blockHash);check(receipt.transactionHash===transactionHash&&getAddress(receipt.from)===expected.from&&getAddress(receipt.to)===expected.to);
    const height=quantity(receipt.blockNumber);check(height<=BigInt(Number.MAX_SAFE_INTEGER));
    const b=await v.block(hex(height));check(b.hash===receipt.blockHash&&tx.blockHash===receipt.blockHash&&quantity(tx.blockNumber)===height);
    const success=quantity(receipt.status);check(success===0n||success===1n);
    const gasUsed=quantity(receipt.gasUsed),price=quantity(receipt.effectiveGasPrice);
    check(gasUsed<=BigInt(expected.gas)&&price<=BigInt(expected.maxFeePerGas));
    return {transactionHash,state:height>BigInt(v.finalized.number)?'included-unfinalized':success?'confirmed':'reverted',
      success:success===1n,receiptBlock:{number:Number(height),hash:b.hash},gasPaidWei:(gasUsed*price).toString(),
      nativeValueWei:success===1n?BigInt(expected.value).toString():'0',mayHaveBeenSubmitted:true};
  },'receipt');
}
