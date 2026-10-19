// Read-only network checks and unsigned wallet-review packages for compute escrow.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Contract, FetchRequest, JsonRpcProvider, getAddress, keccak256, toBeHex } from 'ethers';
import escrowABI from '../compute/escrow-abi.json' with { type: 'json' };
import {planJob} from './compute-plan.mjs';
import {policy,publicOrderPlan,settlementForPlan,termsDigest} from '../compute/settlement.mjs';
const erc20 = ['function balanceOf(address) view returns(uint256)', 'function allowance(address,address) view returns(uint256)', 'function approve(address,uint256) returns(bool)'];
const zero = '0x0000000000000000000000000000000000000000';
export function planSettlementJob(job) {
  return job?.schema==='cannabis.compute.order.v2'?publicOrderPlan(job):planJob(job);
}
export function settlementTerms(job,settlement) {return settlementForPlan(job,settlement,planSettlementJob(job));}
export {termsDigest};
async function connect(options) {
  const url=new URL(options.rpc);
  if(url.username||url.password || url.protocol!=='https:' && !(url.protocol==='http:'&&url.hostname==='127.0.0.1'))throw Error('Use HTTPS RPC or loopback verification RPC');
  const chainId=BigInt(options.chainId),escrow=getAddress(options.escrow),token=getAddress(options.token);
  const native = token === zero;
  if(native && options.tokenCodeHash !== null)throw Error('Native ETH uses a null token runtime hash');
  if(chainId<=0n || [options.escrowCodeHash,...(native?[]:[options.tokenCodeHash])].some(v=>typeof v!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(v)))throw Error('Pin chain and both runtime hashes');
  const request=new FetchRequest(options.rpc);request.timeout=15000;
  const provider=new JsonRpcProvider(request,undefined,{cacheTimeout:-1});
  try{
    if((await provider.getNetwork()).chainId!==chainId)throw Error('RPC chain does not match');
    const codes=await Promise.all([provider.getCode(escrow),...(native?[]:[provider.getCode(token)])]);
    if(codes.some(c=>c==='0x') || keccak256(codes[0]).toLowerCase()!==options.escrowCodeHash.toLowerCase() ||
       !native && keccak256(codes[1]).toLowerCase()!==options.tokenCodeHash.toLowerCase())throw Error('Runtime code does not match the reviewed release');
    const contract=new Contract(escrow,escrowABI,provider),asset=native?null:new Contract(token,erc20,provider);
    const [boundToken,fee,recipient,quantum]=await Promise.all([contract.token(),contract.FEE_BPS(),contract.founderRecipient(),contract.PAYMENT_QUANTUM()]);
    if(boundToken!==token || fee!==100n || quantum!==100n || recipient!==getAddress(policy.founderRecipient))throw Error('Escrow token or fee policy does not match');
    return {provider,contract,asset,chainId,escrow,token,native,founderRecipient:recipient};
  }catch(error){provider.destroy();throw error;}
}
function transaction(connection,from,to,data,value=0n){return {chainId:toBeHex(connection.chainId),from,to,data,value:toBeHex(value)};}
function serialize(value){return JSON.parse(JSON.stringify(value,(_,v)=>typeof v==='bigint'?v.toString():v));}
const review=[
  'Only accept a reviewed escrow deployment and a funded, attested confidential job',
  'All worker recipients must accept before work; delivery manager represents the group',
  'No dispute before the review deadline allows automatic full payment',
  'Disputed jobs trust the named adjudicator; inactivity at the dispute deadline refunds the requester',
  'Worker operators receive no private job code, data or keys through this package',
  'Re-check state and simulate each transaction immediately before wallet signing'
];
export async function prepareFunding(options){
  const terms=settlementTerms(options.job,options.settlement),c=await connect(options);
  try{
    const latest=await c.provider.getBlock('latest');
    if(terms.terms.acceptBy<=latest.timestamp || terms.terms.deliverBy>latest.timestamp+90*86400)throw Error('Deadlines are expired or exceed the contract horizon');
    if([...terms.accounts,terms.terms.adjudicator].includes(c.escrow))throw Error('Escrow cannot be a participant');
    const id=await c.contract.orderId(terms.requester,terms.terms.jobHash);
    if((await c.contract.orders(id)).state!==0n)throw Error('An order already exists for this job');
    const budget=BigInt(terms.terms.budget),allowance=c.native?budget:await c.asset.allowance(terms.requester,c.escrow);
    if((c.native?await c.provider.getBalance(terms.requester):await c.asset.balanceOf(terms.requester))<budget)throw Error('Requester balance is below the agreed budget');
    const transactions=[];
    // Exact approval; never propose an unlimited allowance.
    if(!c.native && allowance!==budget)transactions.push({purpose:'Set exact job-budget allowance',transaction:transaction(c,terms.requester,c.token,c.asset.interface.encodeFunctionData('approve',[c.escrow,budget]))});
    const data=c.contract.interface.encodeFunctionData('fund',[terms.terms,terms.accounts,terms.shares]);
    const value=c.native?budget:0n;
    if(allowance>=budget)await c.contract.fund.staticCall(terms.terms,terms.accounts,terms.shares,{from:terms.requester,value});
    transactions.push({purpose:'Fund the accepted job terms',transaction:transaction(c,terms.requester,c.escrow,data,value)});
    // The legacy planner labels amounts Cannabis. Native packages must never do so.
    if(c.native)for(const key of ['total','founderFee','workerPool']){
      terms.payment[key+'ETH']=terms.payment[key+'Cannabis'];delete terms.payment[key+'Cannabis'];
    }
    return serialize({name:'Cannabis',status:'UNSIGNED_COMPUTE_FUNDING',orderId:id,termsDigest:termsDigest({...c,...terms}),
      chainId:c.chainId,escrow:c.escrow,token:c.token,assetSymbol:c.native?'ETH':'Cannabis',...terms,transactions,
      fundingSimulated:allowance>=budget,sent:false,executionAuthorized:false,keyReleaseAuthorized:false,review});
  }finally{c.provider.destroy();}
}
export async function inspectOrder(options){
  const c=await connect(options);
  try{
    const order=await c.contract.orders(options.orderId);
    if(order.state===0n)throw Error('Order does not exist');
    const stored=await Promise.all(Array.from({length:Number(order.workerCount)},(_,i)=>c.contract.workerAt(options.orderId,i)));
    const accounts=stored.map(w=>w.account),shares=stored.map((w,i)=>Number(w.cumulativeBps-(i?stored[i-1].cumulativeBps:0n)));
    const t=order.terms,terms={jobHash:t.jobHash,budget:t.budget,deliveryManager:t.deliveryManager,adjudicator:t.adjudicator,
      acceptBy:t.acceptBy,deliverBy:t.deliverBy,reviewSeconds:t.reviewSeconds,disputeSeconds:t.disputeSeconds};
    const result={chainId:c.chainId,escrow:c.escrow,token:c.token,founderRecipient:c.founderRecipient,
      requester:order.requester,terms,accounts,shares};
    return serialize({...result,orderId:options.orderId,termsDigest:termsDigest(result),state:Number(order.state),
      acceptedCount:Number(order.acceptedCount),acceptedBitmap:order.acceptedBitmap,reviewBy:order.reviewBy,
      resolveBy:order.resolveBy,outputDigest:order.outputDigest,grossPaid:order.grossPaid,workerPool:order.workerPool});
  }finally{c.provider.destroy();}
}
export async function prepareAcceptance(options){
  const inspected=await inspectOrder(options),worker=getAddress(options.worker);
  if(typeof options.expectedTermsDigest!=='string'||inspected.termsDigest.toLowerCase()!==options.expectedTermsDigest.toLowerCase())throw Error('Settlement terms changed or differ from the reviewed agreement');
  if(!inspected.accounts.includes(worker))throw Error('Worker is not an agreed recipient');
  const c=await connect(options);
  try{
    await c.contract.accept.staticCall(options.orderId,{from:worker});
    return {...inspected,status:'UNSIGNED_COMPUTE_ACCEPTANCE',
      transaction:transaction(c,worker,c.escrow,c.contract.interface.encodeFunctionData('accept',[options.orderId])),
      sent:false,executionAuthorized:false,keyReleaseAuthorized:false,review};
  }finally{c.provider.destroy();}
}
function batchIds(ids) {
  if(!Array.isArray(ids)||ids.length<1||ids.length>128||ids.some(id=>typeof id!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(id))||new Set(ids.map(id=>id.toLowerCase())).size!==ids.length)
    throw Error('Require 1 to 128 distinct order IDs');
  return ids;
}
export async function prepareBatchApproval(options) {
  if(!Array.isArray(options.approvals))throw Error('Reviewed result approvals required');
  const ids=batchIds(options.approvals.map(a=>a.orderId)),requester=getAddress(options.requester);
  const reviewed=[];let gross=0n;
  for(const approval of options.approvals) {
    const order=await inspectOrder({...options,orderId:approval.orderId});
    if(order.requester!==requester||order.state!==3||order.termsDigest!==approval.expectedTermsDigest||order.outputDigest!==approval.expectedOutputDigest)
      throw Error('Requester, delivered state, terms or encrypted result differs from the reviewed approval');
    gross+=BigInt(order.terms.budget);reviewed.push(order);
  }
  const c=await connect(options);
  try {
    await c.contract.approveBatch.staticCall(ids,{from:requester});
    return {status:'UNSIGNED_COMPUTE_BATCH_APPROVAL',orders:reviewed,grossAtomic:gross.toString(),founderFeeAtomic:(gross/100n).toString(),
      transaction:transaction(c,requester,c.escrow,c.contract.interface.encodeFunctionData('approveBatch',[ids])),sent:false,
      review:[...review,'Verify and accept every private result before signing; this command cannot judge output quality']};
  }finally{c.provider.destroy();}
}
export async function prepareWorkerWithdrawal(options) {
  const ids=batchIds(options.orderIds),worker=getAddress(options.worker),recipient=getAddress(options.recipient),c=await connect(options);
  try {
    const amounts=await Promise.all(ids.map(id=>c.contract.workerDue(id,worker)));
    if(amounts.some(amount=>amount===0n))throw Error('Every selected order must have a positive unwithdrawn worker payment');
    await c.contract.withdrawWorkers.staticCall(ids,recipient,{from:worker});
    return {status:'UNSIGNED_COMPUTE_WORKER_WITHDRAWAL',orderIds:ids,worker,recipient,
      amountAtomic:amounts.reduce((a,b)=>a+b,0n).toString(),
      transaction:transaction(c,worker,c.escrow,c.contract.interface.encodeFunctionData('withdrawWorkers',[ids,recipient])),sent:false,review};
  }finally{c.provider.destroy();}
}
export async function prepareCreditWithdrawal(options) {
  const account=getAddress(options.account),recipient=getAddress(options.recipient),c=await connect(options);
  try {
    const amount=await c.contract.credits(account);
    await c.contract.withdrawCredit.staticCall(recipient,{from:account});
    return {status:'UNSIGNED_COMPUTE_CREDIT_WITHDRAWAL',account,recipient,amountAtomic:amount.toString(),
      transaction:transaction(c,account,c.escrow,c.contract.interface.encodeFunctionData('withdrawCredit',[recipient])),sent:false,review};
  }finally{c.provider.destroy();}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [action,file,out,...extra]=process.argv.slice(2);
  const actions={fund:prepareFunding,inspect:inspectOrder,accept:prepareAcceptance,'approve-batch':prepareBatchApproval,'withdraw-workers':prepareWorkerWithdrawal,'withdraw-credit':prepareCreditWithdrawal};
  if(!Object.hasOwn(actions,action)||!file||!out||extra.length)throw Error('Usage: compute-escrow.mjs fund|inspect|accept|approve-batch|withdraw-workers|withdraw-credit config.json output.json');
  if(fs.statSync(file).size>1048576)throw Error('Configuration exceeds 1 MiB');
  if(fs.existsSync(out))throw Error('Output exists; select a new file');
  const options=JSON.parse(fs.readFileSync(file,'utf8'));
  const result=await actions[action](options);
  fs.writeFileSync(out,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({output:path.resolve(out),status:result.status??'READ_ONLY_INSPECTION',sent:false}));
}
