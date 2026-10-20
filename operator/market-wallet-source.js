// Built into market-wallet.js for the local browser. Fixed contract operations,
// explicit selection and exact review; never personal_sign or a generic send UI.
import {Interface,TypedDataEncoder,sha256,toUtf8Bytes,getAddress,ZeroAddress} from 'ethers';
import marketABI from '../compute/market-abi.json';
import escrowABI from '../compute/escrow-abi.json';
import {postDeliveryMethods,settlementDecision} from '../compute/settlement_decision.mjs';
export {inspectResultCommitment} from '../compute/result_commitment.mjs';
const market=new Interface(marketABI),escrow=new Interface(escrowABI),token=new Interface(['function approve(address,uint256) returns(bool)']);
const check=v=>{if(!v)throw Error('Wallet review changed, expired or is unsupported. Review again.');};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const address=v=>typeof v==='string'&&getAddress(v)===v&&v!==ZeroAddress;
const digest=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const number=v=>typeof v==='string'&&/^(0|[1-9][0-9]{0,77}|0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63}))$/.test(v)&&BigInt(v)<2n**256n;
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?
  '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const same=(a,b)=>canonical(a)===canonical(b);
const bookingFields=[['reservationId','bytes32'],['offerId','bytes32'],['requester','address'],['orderId','bytes32'],['termsDigest','bytes32'],
  ['start','uint64'],['end','uint64'],['units','uint32'],['gross','uint256'],['holdUntil','uint64']].map(([name,type])=>({name,type}));

function checkReview(input,historical=false) {
  const r=structuredClone(input),a=r.action,d=r.deployment,s=a?.summary;
  check(r.schema==='cannabis.market-wallet-review.v1'&&/^[0-9a-f]{64}$/.test(r.id)&&r.planId===a?.planId&&
    Number.isSafeInteger(r.expiresAt)&&r.expiresAt>0&&(historical||r.expiresAt>Date.now()&&r.expiresAt<=Date.now()+31000)&&address(a?.actor)&&s&&
    r.executionAuthorized===false&&r.keyReleaseAuthorized===false&&r.hardwareValidated===false&&
    sha256(toUtf8Bytes(canonical(a))).slice(2)===r.actionDigest);
  check(number(d.chainId)&&BigInt(d.chainId)>0n&&digest(d.genesisHash)&&
    ['market','nativeEscrow','cannabisEscrow','token','founderRecipient'].every(k=>address(d[k]))&&
    ['marketCodeHash','nativeEscrowCodeHash','cannabisEscrowCodeHash','tokenCodeHash'].every(k=>digest(d[k]))&&
    r.chainId===d.chainId&&r.genesisHash===d.genesisHash&&r.market===d.market);
  if(a.kind==='signature') {
    check(a.method==='signBooking'&&digest(a.bookingId)&&digest(a.digest));const t=a.typedData;
    exact(t,['domain','types','primaryType','message']);check(t.primaryType==='Booking');
    exact(t.types,['EIP712Domain','Booking']);check(same(t.types.Booking,bookingFields));
    check(same(t.types.EIP712Domain,[['name','string'],['version','string'],['chainId','uint256'],['verifyingContract','address']].map(([name,type])=>({name,type}))));
    exact(t.domain,['name','version','chainId','verifyingContract']);check(t.domain.name==='Cannabis compute market'&&t.domain.version==='1'&&
      BigInt(t.domain.chainId)===BigInt(d.chainId)&&getAddress(t.domain.verifyingContract)===d.market);
    exact(t.message,bookingFields.map(f=>f.name));
    const types={Booking:bookingFields};check(TypedDataEncoder.hash(t.domain,types,t.message)===a.digest&&a.digest===a.bookingId&&
      getAddress(t.message.requester)===s.requester&&t.message.orderId===s.orderId&&t.message.termsDigest===s.termsDigest);
    check(r.state?.bookings?.find(b=>b.bookingId===a.bookingId)?.resource.provider===a.actor);
    return r;
  }
  check(a.kind==='transaction');const tx=a.transaction;
  exact(tx,['chainId','from','to','value','data','type','nonce','gas','maxPriorityFeePerGas','maxFeePerGas']);
  check(['chainId','value','type','nonce','gas','maxPriorityFeePerGas','maxFeePerGas'].every(k=>number(tx[k]))&&
    BigInt(tx.chainId)===BigInt(d.chainId)&&tx.from===a.actor&&address(tx.to)&&tx.type==='0x2'&&
    typeof tx.data==='string'&&/^0x(?:[0-9a-fA-F]{2})+$/.test(tx.data)&&tx.data.length<=262146);
  const nativeValue=BigInt(tx.value),fee=r.feePolicy,q=r.quote;
  exact(fee,['gas','maxFeePerGas','maxPriorityFeePerGas','maxTotalWei']);check(Object.values(fee).every(number)&&q);
  check(BigInt(tx.gas)>0n&&BigInt(tx.gas)<=BigInt(fee.gas)&&BigInt(tx.maxFeePerGas)<=BigInt(fee.maxFeePerGas)&&
    BigInt(tx.maxPriorityFeePerGas)<=BigInt(fee.maxPriorityFeePerGas)&&BigInt(tx.maxPriorityFeePerGas)<=BigInt(tx.maxFeePerGas));
  const maximum=BigInt(tx.gas)*BigInt(tx.maxFeePerGas)+nativeValue;
  check(maximum===BigInt(q.maximumTotalWei)&&maximum<=BigInt(fee.maxTotalWei)&&BigInt(q.nativeValueWei)===nativeValue&&
    BigInt(q.maximumGasWei)===maximum-nativeValue&&BigInt(q.gasLimit)===BigInt(tx.gas));
  let to=d.market,data,value=0n;
  if(a.method==='publishResource')data=market.encodeFunctionData(a.method,[s.resourceId,s.serviceHash,s.declaredUnits]);
  else if(a.method==='publishOffer')data=market.encodeFunctionData(a.method,[s.nonce,
    Object.fromEntries(['resource','escrow','policyHash','manifestHash','start','end','expiresAt','units','grossPerUnitSecond'].map(k=>[k,s[k]]))]);
  else if(a.method==='withdrawOffer')data=market.encodeFunctionData(a.method,[s.offerId]);
  else {
    check(['ETH','Cannabis'].includes(s.asset)&&s.escrow===(s.asset==='ETH'?d.nativeEscrow:d.cannabisEscrow)&&address(s.requester)&&
      digest(s.orderId)&&digest(s.termsDigest)&&BigInt(s.grossBaseUnits)%100n===0n&&BigInt(s.serviceFeeBaseUnits)===BigInt(s.grossBaseUnits)/100n&&
      BigInt(s.workerBaseUnits)+BigInt(s.serviceFeeBaseUnits)===BigInt(s.grossBaseUnits));
    if(['reserveBatch','approveToken','fund','cancel'].includes(a.method))check(a.actor===s.requester);
    else if(!postDeliveryMethods.includes(a.method))check(a.actor===s.requester||s.accounts.includes(a.actor));
    if(a.method==='reserveBatch') {
      const decoded=market.decodeFunctionData(a.method,tx.data);data=market.encodeFunctionData(a.method,[s.bookings,decoded[1]]);
    } else if(a.method==='activate') {
      const ids=s.bookings.map(b=>TypedDataEncoder.hash({name:'Cannabis compute market',version:'1',chainId:d.chainId,verifyingContract:d.market},
        {Booking:bookingFields},b)).sort();data=market.encodeFunctionData(a.method,[ids]);
    } else if(a.method==='approveToken') {
      check(s.asset==='Cannabis');to=d.token;data=token.encodeFunctionData('approve',[s.escrow,s.grossBaseUnits]);
    } else {
      to=s.escrow;
      if(a.method==='fund'){data=escrow.encodeFunctionData('fund',[s.terms,s.accounts,s.shares]);value=s.asset==='ETH'?BigInt(s.grossBaseUnits):0n;}
      else if(['accept','cancel'].includes(a.method))data=escrow.encodeFunctionData(a.method,[s.orderId]);
      else if(postDeliveryMethods.includes(a.method)) {
        const selected=settlementDecision(a.method,s.decision,{requester:s.requester,...s.terms,termsDigest:s.termsDigest,acceptanceSHA256:s.acceptanceSHA256},a.actor);
        check(same(selected.outcome,s.outcome));data=escrow.encodeFunctionData(selected.contractMethod,[s.orderId,...selected.args]);
      }
      else if(a.method==='withdrawWorker'){check(s.accounts.includes(a.actor));data=escrow.encodeFunctionData(a.method,[s.orderId,a.actor]);}
      else if(a.method==='withdrawCredit')data=escrow.encodeFunctionData(a.method,[a.actor]);
      else check(false);
    }
  }
  check(tx.to===to&&nativeValue===value&&tx.data.toLowerCase()===data.toLowerCase());return r;
}
export const validateMarketReview=input=>checkReview(input);
// Recovery may inspect old immutable wallet payloads, but cannot send them.
// sign()/send() always use the fresh-review entry point above.
export const validateRetainedMarketReview=input=>checkReview(input,true);

export class MarketWallet {
  #provider;#epoch=0;#selection=0;#changed;#onChange;#accounts=[];
  constructor(onChange=()=>{}) {this.#changed=onChange;this.#onChange=()=>{++this.#epoch;this.#accounts=[];this.#changed();};}
  select(provider) {
    check(provider&&typeof provider.request==='function'&&typeof provider.on==='function'&&typeof provider.removeListener==='function');
    this.clear();this.#provider=provider;
    for(const event of ['accountsChanged','chainChanged','disconnect'])provider.on(event,this.#onChange);
  }
  clear() {if(this.#provider)for(const e of ['accountsChanged','chainChanged','disconnect'])this.#provider.removeListener(e,this.#onChange);
    this.#provider=undefined;++this.#epoch;++this.#selection;this.#accounts=[];this.#changed();}
  get accounts(){return [...this.#accounts];}
  async #call(method,params,epoch,expiresAt,signal,connecting=false,dispatch=null) {
    const provider=this.#provider,selection=this.#selection;
    const active=()=>check(provider&&this.#provider===provider&&this.#selection===selection&&(connecting||this.#epoch===epoch)&&
      !signal?.aborted&&Date.now()<expiresAt);
    active();let timer,abort;
    const invoke=()=>{active();return provider.request({method,...(params?{params}:{})});};
    const pending=Promise.resolve().then(()=>dispatch?dispatch(invoke):invoke());
    const cancelled=new Promise((_,reject)=>{abort=()=>reject(Error('Wallet response is unavailable. Inspect wallet activity; submission may be uncertain.'));
      timer=setTimeout(abort,Math.max(1,expiresAt-Date.now()));signal?.addEventListener('abort',abort,{once:true});});
    try{const value=await Promise.race([pending,cancelled]);active();return value;}
    finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }
  async connect(signal) {
    const until=Date.now()+60000,result=await this.#call('eth_requestAccounts',undefined,this.#epoch,until,signal,true);
    check(Array.isArray(result)&&result.length>0&&result.length<=64&&result.every(v=>address(getAddress(v))));
    const current=await this.#call('eth_accounts',undefined,this.#epoch,until,signal);
    check(Array.isArray(current)&&current.length===result.length&&same(current.map(getAddress).sort(),result.map(getAddress).sort()));
    this.#accounts=current.map(getAddress);return this.accounts;
  }
  async #verify(review,epoch,signal) {
    const call=(m,p,dispatch=null)=>this.#call(m,p,epoch,review.expiresAt,signal,false,dispatch);
    const accounts=await call('eth_accounts');check(Array.isArray(accounts)&&accounts.length<=64&&accounts.map(getAddress).includes(review.action.actor));
    const chain=await call('eth_chainId');check(number(chain)&&BigInt(chain)===BigInt(review.deployment.chainId));
    const genesis=await call('eth_getBlockByNumber',['0x0',false]);check(genesis?.hash?.toLowerCase()===review.deployment.genesisHash);
    return call;
  }
  async sign(input,signal) {
    const review=validateMarketReview(input),epoch=this.#epoch;check(review.action.kind==='signature'&&this.#accounts.includes(review.action.actor));
    const call=await this.#verify(review,epoch,signal),signature=await call('eth_signTypedData_v4',[review.action.actor,JSON.stringify(review.action.typedData)]);
    check(typeof signature==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(signature));await this.#verify(review,epoch,signal);return signature;
  }
  async send(input,handoff,signal,dispatch=null) {
    let dispatched=false,review;const epoch=this.#epoch;
    // Once request() starts, expiry/cancellation cannot revoke a wallet prompt.
    // The backend has already retained submission-uncertain before this call.
    try {
      review=validateMarketReview(input);
      check((dispatch===null||typeof dispatch==='function')&&review.action.kind==='transaction'&&this.#accounts.includes(review.action.actor)&&handoff?.schema==='cannabis.market-wallet-handoff.v1'&&
        /^[0-9a-f]{64}$/.test(handoff.id)&&handoff.review.id===review.id&&handoff.review.actionDigest===review.actionDigest&&same(handoff.transaction,review.action.transaction));
      const call=await this.#verify(review,epoch,signal);
      const transactionHash=await call('eth_sendTransaction',[review.action.transaction],invoke=>{
        const submit=()=>{dispatched=true;return invoke();};return dispatch?dispatch(submit):submit();
      });check(digest(transactionHash?.toLowerCase()));
      return {transactionHash:transactionHash.toLowerCase(),walletReported:true};
    } catch(error) {
      if(!dispatched)return {walletNotRequested:true};
      if(error?.code===4001&&this.#epoch===epoch&&!signal?.aborted&&Date.now()<review.expiresAt)return {walletRefused:true};
      throw Error('Submission may be uncertain. Inspect wallet activity and recover using its transaction hash.');
    }
  }
}
