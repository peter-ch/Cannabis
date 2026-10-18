// Read-only network checks and unsigned wallet-review packages for compute escrow.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AbiCoder, Contract, FetchRequest, JsonRpcProvider, getAddress, keccak256, toBeHex } from 'ethers';
import { compile } from './compile.mjs';
import { planJob, policy, quotePayment } from './compute-plan.mjs';
const erc20 = ['function balanceOf(address) view returns(uint256)', 'function allowance(address,address) view returns(uint256)', 'function approve(address,uint256) returns(bool)'];
const zero = '0x0000000000000000000000000000000000000000';
const coder = AbiCoder.defaultAbiCoder();
export function planSettlementJob(job) {
  if (job?.schema !== 'cannabis.compute.order.v2') return planJob(job);
  const keys=['schema','id','requester','packageSHA256','policySHA256','acceptanceSHA256','payment'];
  if(Object.keys(job).sort().join()!==keys.sort().join() || typeof job.id!=='string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(job.id))throw Error('Invalid universal compute order');
  const requester=getAddress(job.requester);
  if(requester===zero || ['packageSHA256','policySHA256','acceptanceSHA256'].some(k=>typeof job[k]!=='string'||!/^[0-9a-f]{64}$/.test(job[k])||/^0+$/.test(job[k])))throw Error('Requester and encrypted workload commitments required');
  const p=job.payment;
  if(!p || Object.keys(p).sort().join()!==['totalBudget','feeBasisPoints','founderRecipient'].sort().join() || p.feeBasisPoints!==100 || getAddress(p.founderRecipient)!==getAddress(policy.founderRecipient))throw Error('Universal order must use the published fee policy');
  const payment=quotePayment(p.totalBudget);
  const jobHash=keccak256(coder.encode(['string','string','address','bytes32','bytes32','bytes32','uint256','uint16','address'],
    ['Cannabis arbitrary workload order v2',job.id,requester,'0x'+job.packageSHA256,'0x'+job.policySHA256,'0x'+job.acceptanceSHA256,payment.totalAtomic,100,payment.founderRecipient]));
  return {schema:'cannabis.compute.order-plan.v2',jobHash,job:structuredClone(job),payment,executionAuthorized:false,keyReleaseAuthorized:false,fundsMoved:false};
}
function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) throw Error('Use explicit UTC deadlines');
  const ms=Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().replace('.000Z','Z')!==value) throw Error('Invalid UTC deadline');
  return ms/1000;
}
export function settlementTerms(job, settlement) {
  const plan=planSettlementJob(job);
  if (!settlement || !Array.isArray(settlement.workers) || settlement.workers.length<1 || settlement.workers.length>128) throw Error('Require 1 to 128 worker recipients');
  const accounts=settlement.workers.map(w=>getAddress(w.account)), shares=settlement.workers.map(w=>w.shareBps);
  const manager=getAddress(settlement.deliveryManager), adjudicator=getAddress(settlement.adjudicator), requester=getAddress(job.requester);
  if (new Set(accounts).size!==accounts.length || accounts.some(a=>a===zero || a===requester || a===adjudicator) ||
      !accounts.includes(manager) || [zero,requester,getAddress(policy.founderRecipient)].includes(adjudicator) ||
      shares.some(s=>!Number.isSafeInteger(s)||s<=0||s>10000) || shares.reduce((a,b)=>a+b,0)!==10000) throw Error('Invalid settlement roles or worker split');
  if (!Number.isSafeInteger(settlement.reviewSeconds)||settlement.reviewSeconds<86400||settlement.reviewSeconds>1209600 ||
      !Number.isSafeInteger(settlement.disputeSeconds)||settlement.disputeSeconds<86400||settlement.disputeSeconds>2592000) throw Error('Review/dispute duration outside contract limits');
  const terms={jobHash:plan.jobHash,budget:plan.payment.totalAtomic,deliveryManager:manager,adjudicator,
    acceptBy:timestamp(settlement.acceptBy),deliverBy:timestamp(settlement.deliverBy),
    reviewSeconds:settlement.reviewSeconds,disputeSeconds:settlement.disputeSeconds};
  if(terms.deliverBy<=terms.acceptBy)throw Error('Delivery must follow acceptance deadline');
  return {requester,terms,accounts,shares,payment:plan.payment};
}
export function termsDigest({chainId,escrow,token,founderRecipient,requester,terms,accounts,shares}) {
  return keccak256(coder.encode(
    ['string','uint256','address','address','address','uint16','address','tuple(bytes32 jobHash,uint256 budget,address deliveryManager,address adjudicator,uint64 acceptBy,uint64 deliverBy,uint32 reviewSeconds,uint32 disputeSeconds)','address[]','uint16[]'],
    ['Cannabis compute settlement v1',chainId,escrow,token,founderRecipient,100,requester,terms,accounts,shares]));
}
async function connect(options) {
  const url=new URL(options.rpc);
  if(url.username||url.password || url.protocol!=='https:' && !(url.protocol==='http:'&&url.hostname==='127.0.0.1'))throw Error('Use HTTPS RPC or loopback verification RPC');
  const chainId=BigInt(options.chainId),escrow=getAddress(options.escrow),token=getAddress(options.token);
  if(chainId<=0n || [options.escrowCodeHash,options.tokenCodeHash].some(v=>typeof v!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(v)))throw Error('Pin chain and both runtime hashes');
  const request=new FetchRequest(options.rpc);request.timeout=15000;
  const provider=new JsonRpcProvider(request,undefined,{cacheTimeout:-1});
  try{
    if((await provider.getNetwork()).chainId!==chainId)throw Error('RPC chain does not match');
    const codes=await Promise.all([provider.getCode(escrow),provider.getCode(token)]);
    if(codes.some(c=>c==='0x') || keccak256(codes[0]).toLowerCase()!==options.escrowCodeHash.toLowerCase() ||
       keccak256(codes[1]).toLowerCase()!==options.tokenCodeHash.toLowerCase())throw Error('Runtime code does not match the reviewed release');
    const contract=new Contract(escrow,compile().ComputeEscrow.abi,provider),asset=new Contract(token,erc20,provider);
    const [boundToken,fee,recipient]=await Promise.all([contract.token(),contract.FEE_BPS(),contract.founderRecipient()]);
    if(boundToken!==token || fee!==100n || recipient!==getAddress(policy.founderRecipient))throw Error('Escrow token or fee policy does not match');
    return {provider,contract,asset,chainId,escrow,token,founderRecipient:recipient};
  }catch(error){provider.destroy();throw error;}
}
function transaction(connection,from,to,data){return {chainId:toBeHex(connection.chainId),from,to,data,value:'0x0'};}
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
    const budget=BigInt(terms.terms.budget),allowance=await c.asset.allowance(terms.requester,c.escrow);
    if(await c.asset.balanceOf(terms.requester)<budget)throw Error('Requester balance is below the agreed budget');
    const transactions=[];
    // Exact approval; never propose an unlimited allowance.
    if(allowance!==budget)transactions.push({purpose:'Set exact job-budget allowance',transaction:transaction(c,terms.requester,c.token,c.asset.interface.encodeFunctionData('approve',[c.escrow,budget]))});
    const data=c.contract.interface.encodeFunctionData('fund',[terms.terms,terms.accounts,terms.shares]);
    if(allowance>=budget)await c.contract.fund.staticCall(terms.terms,terms.accounts,terms.shares,{from:terms.requester});
    transactions.push({purpose:'Fund the accepted job terms',transaction:transaction(c,terms.requester,c.escrow,data)});
    return serialize({name:'Cannabis',status:'UNSIGNED_COMPUTE_FUNDING',orderId:id,termsDigest:termsDigest({...c,...terms}),
      chainId:c.chainId,escrow:c.escrow,token:c.token,...terms,transactions,
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
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [action,file,out,...extra]=process.argv.slice(2);
  if(!['fund','inspect','accept'].includes(action)||!file||!out||extra.length)throw Error('Usage: compute-escrow.mjs fund|inspect|accept config.json output.json');
  if(fs.statSync(file).size>1048576)throw Error('Configuration exceeds 1 MiB');
  if(fs.existsSync(out))throw Error('Output exists; select a new file');
  const options=JSON.parse(fs.readFileSync(file,'utf8'));
  const result=await ({fund:prepareFunding,inspect:inspectOrder,accept:prepareAcceptance}[action])(options);
  fs.writeFileSync(out,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({output:path.resolve(out),status:result.status??'READ_ONLY_INSPECTION',sent:false}));
}
