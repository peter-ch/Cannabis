// Read-only, hash-pinned finalized escrow inspection. No signing or transaction submission.
import { FetchRequest, Interface, JsonRpcProvider, getAddress, keccak256 } from 'ethers';
import escrowABI from './escrow-abi.json' with { type: 'json' };
import { termsDigest } from '../scripts/compute-escrow.mjs';
import { policy } from '../scripts/compute-plan.mjs';

const bytes32=value=>typeof value==='string' && /^0x[0-9a-fA-F]{64}$/.test(value) && !/^0x0+$/.test(value);
const plain=value=>JSON.parse(JSON.stringify(value,(_,v)=>typeof v==='bigint'?v.toString():v));
let escrowInterface;

export async function readFinalizedEscrow(options, clock=()=>Math.floor(Date.now()/1000)) {
  return readEscrowSnapshot(options,clock,'finalized');
}

// A canonical latest-state observation supplements finalized funding; it never
// substitutes for finality and can still be reorganized after this observation.
export async function readCurrentEscrow(options, clock=()=>Math.floor(Date.now()/1000)) {
  if(!Number.isSafeInteger(options.maxHeadAgeSeconds) || options.maxHeadAgeSeconds<1 || options.maxHeadAgeSeconds>120)throw Error('Require a latest-head age limit of 1 to 120 seconds');
  if(options.finalizedAnchor && (!Number.isSafeInteger(options.finalizedAnchor.number) || options.finalizedAnchor.number<0 || !bytes32(options.finalizedAnchor.hash)))throw Error('Invalid finalized anchor');
  return readEscrowSnapshot(options,clock,'latest');
}

async function readEscrowSnapshot(options,clock,blockSelector) {
  const url=new URL(options.rpc);
  if(url.username || url.password || !(url.protocol==='https:' || url.protocol==='http:' && url.hostname==='127.0.0.1'))throw Error('Use HTTPS RPC or loopback verification RPC');
  if(options.finality!=='rpc-finalized')throw Error('An explicit reviewed rpc-finalized policy is required');
  if(!Number.isSafeInteger(options.maxFinalizedAgeSeconds) || options.maxFinalizedAgeSeconds<1 || options.maxFinalizedAgeSeconds>7200)throw Error('Require a bounded finalized-block age, at most two hours');
  for(const field of ['genesisHash','escrowCodeHash','tokenCodeHash','orderId'])if(!bytes32(options[field]))throw Error('Pin genesis, runtime hashes and order ID');
  const chainId=BigInt(options.chainId),escrow=getAddress(options.escrow),token=getAddress(options.token);
  if(chainId<=0n)throw Error('Invalid chain ID');
  const request=new FetchRequest(options.rpc);request.timeout=15000;
  const provider=new JsonRpcProvider(request,undefined,{cacheTimeout:-1});
  const send=async(method,params)=>{
    try{return await provider.send(method,params);}catch{throw Error('RPC '+method+' failed; finalized block/hash support is required');}
  };
  try {
    const [network,genesis,block]=await Promise.all([
      send('eth_chainId',[]),send('eth_getBlockByNumber',['0x0',false]),send('eth_getBlockByNumber',[blockSelector,false])
    ]);
    if(BigInt(network)!==chainId || !genesis || genesis.hash?.toLowerCase()!==options.genesisHash.toLowerCase())throw Error('Chain or genesis mismatch');
    if(!block || !bytes32(block.hash) || !/^0x[0-9a-f]+$/i.test(block.number) || !/^0x[0-9a-f]+$/i.test(block.timestamp))throw Error('Finalized block unavailable');
    const blockNumber=Number(BigInt(block.number)),timestamp=Number(BigInt(block.timestamp));
    if(!Number.isSafeInteger(blockNumber) || !Number.isSafeInteger(timestamp))throw Error('Invalid finalized block');
    const fresh=()=>{
      const now=clock();
      const maximumAge=blockSelector==='finalized'?options.maxFinalizedAgeSeconds:options.maxHeadAgeSeconds;
      if(!Number.isSafeInteger(now) || timestamp>now+60 || now-timestamp>maximumAge)throw Error('Observed block is stale or too far in the future');
      return now;
    };
    fresh();
    const tag={blockHash:block.hash,requireCanonical:true};
    const codes=await Promise.all([send('eth_getCode',[escrow,tag]),send('eth_getCode',[token,tag])]);
    if(codes.some(c=>c==='0x') || keccak256(codes[0]).toLowerCase()!==options.escrowCodeHash.toLowerCase() || keccak256(codes[1]).toLowerCase()!==options.tokenCodeHash.toLowerCase())throw Error('Runtime code differs from the reviewed release');
    escrowInterface??=new Interface(escrowABI);
    const call=async(name,args=[])=>{
      const encoded=escrowInterface.encodeFunctionData(name,args);
      const data=await send('eth_call',[{to:escrow,data:encoded},tag]);
      try{return escrowInterface.decodeFunctionResult(name,data);}catch{throw Error('Invalid escrow response');}
    };
    const [boundToken,fee,founder,order]=await Promise.all([call('token'),call('FEE_BPS'),call('founderRecipient'),call('orders',[options.orderId])]);
    if(getAddress(boundToken[0])!==token || fee[0]!==100n || getAddress(founder[0])!==getAddress(policy.founderRecipient))throw Error('Escrow asset or founder fee policy differs');
    const workerCount=Number(order.workerCount);
    if(order.state===0n || workerCount<1 || workerCount>128)throw Error('Order does not exist or has invalid worker count');
    const workers=await Promise.all(Array.from({length:workerCount},(_,i)=>call('workerAt',[options.orderId,i]).then(r=>r[0])));
    const accounts=workers.map(w=>getAddress(w.account));
    const shares=workers.map((w,i)=>Number(w.cumulativeBps-(i?workers[i-1].cumulativeBps:0n)));
    if(new Set(accounts).size!==accounts.length || shares.some(s=>s<=0) || shares.reduce((a,b)=>a+b,0)!==10000)throw Error('Invalid stored worker allocation');
    const t=order.terms;
    const terms={jobHash:t.jobHash,budget:t.budget,deliveryManager:t.deliveryManager,adjudicator:t.adjudicator,acceptBy:t.acceptBy,deliverBy:t.deliverBy,reviewSeconds:t.reviewSeconds,disputeSeconds:t.disputeSeconds};
    const result={chainId,escrow,token,founderRecipient:founder[0],requester:order.requester,terms,accounts,shares};
    // Recheck canonicality and the finality watermark after every hash-bound state read.
    const [canonical,watermark]=await Promise.all([send('eth_getBlockByNumber',[block.number,false]),send('eth_getBlockByNumber',[blockSelector,false])]);
    if(canonical?.hash!==block.hash || !watermark || BigInt(watermark.number)<BigInt(block.number))throw Error('Finalized chain changed during inspection');
    if(blockSelector==='latest' && options.finalizedAnchor) {
      const anchor=options.finalizedAnchor;
      const [ancestor,finality]=await Promise.all([send('eth_getBlockByNumber',['0x'+anchor.number.toString(16),false]),send('eth_getBlockByNumber',['finalized',false])]);
      if(ancestor?.hash?.toLowerCase()!==anchor.hash.toLowerCase() || !finality || BigInt(finality.number)<BigInt(anchor.number) || blockNumber<anchor.number)throw Error('Finalized funding anchor changed during latest-state inspection');
    }
    const observedAt=fresh();
    return plain({...result,orderId:options.orderId,termsDigest:termsDigest(result),state:Number(order.state),acceptedCount:Number(order.acceptedCount),acceptedBitmap:order.acceptedBitmap,
      [blockSelector==='finalized'?'finalizedBlock':'headBlock']:{number:blockNumber,hash:block.hash,timestamp},observedAt,
      finality:blockSelector==='finalized'?'rpc-finalized':'unfinalized-head',genesisHash:genesis.hash,maxFinalizedAgeSeconds:options.maxFinalizedAgeSeconds,
      ...(blockSelector==='latest'?{maxHeadAgeSeconds:options.maxHeadAgeSeconds}:{}),
      runtimeCodeHashes:{escrow:options.escrowCodeHash,token:options.tokenCodeHash},
      executionAuthorized:false,keyReleaseAuthorized:false,sent:false});
  }finally{provider.destroy();}
}
