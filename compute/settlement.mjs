// Shared deterministic payment and settlement model. No filesystem, RPC, wallet
// or execution. CLI and browser clients must derive identical commitments.
import {AbiCoder,getAddress,parseUnits,formatUnits,keccak256} from 'ethers';
import publishedPolicy from './policy.json' with {type:'json'};
export const policy=Object.freeze(structuredClone(publishedPolicy));
const zero='0x0000000000000000000000000000000000000000',coder=AbiCoder.defaultAbiCoder();
export function quotePayment(totalBudget) {
  if (typeof totalBudget !== 'string' || !/^(0|[1-9]\d*)(\.\d{1,18})?$/.test(totalBudget)) throw Error('Budget must be an exact decimal Cannabis amount');
  const total = parseUnits(totalBudget, 18);
  if (total <= 0n || total > (1n << 256n) - 1n) throw Error('Budget outside token amount range');
  if (total % 100n !== 0n) throw Error('Budget must use multiples of 0.0000000000000001 Cannabis for an exact 1% fee');
  const fee = total * BigInt(policy.feeBasisPoints) / 10000n;
  return { totalAtomic: total.toString(), founderFeeAtomic: fee.toString(), workerPoolAtomic: (total - fee).toString(),
    totalCannabis: formatUnits(total, 18), founderFeeCannabis: formatUnits(fee, 18), workerPoolCannabis: formatUnits(total - fee, 18),
    feeBasisPoints: policy.feeBasisPoints, founderRecipient: getAddress(policy.founderRecipient),
    feeAppliesTo: policy.feeAppliesTo, paymentQuantumAtomic: '100', networkFeesIncluded: false };
}
export function publicOrderPlan(job) {
  if (!['cannabis.compute.order.v2','cannabis.compute.order.v3'].includes(job?.schema)) throw Error('Require a public encrypted-commitment order');
  const planned=job.schema==='cannabis.compute.order.v3';
  const keys=['schema','id','requester','packageSHA256','policySHA256','acceptanceSHA256','payment',...(planned?['executionPlanSHA256']:[])];
  if(Object.keys(job).sort().join()!==keys.sort().join() || typeof job.id!=='string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(job.id))throw Error('Invalid universal compute order');
  const requester=getAddress(job.requester);
  if(requester===zero || ['packageSHA256','policySHA256','acceptanceSHA256',...(planned?['executionPlanSHA256']:[])].some(k=>typeof job[k]!=='string'||!/^[0-9a-f]{64}$/.test(job[k])||/^0+$/.test(job[k])))throw Error('Requester and encrypted workload commitments required');
  const p=job.payment;
  if(!p || Object.keys(p).sort().join()!==['totalBudget','feeBasisPoints','founderRecipient'].sort().join() || p.feeBasisPoints!==100 || getAddress(p.founderRecipient)!==getAddress(policy.founderRecipient))throw Error('Universal order must use the published fee policy');
  const payment=quotePayment(p.totalBudget);
  const jobHash=keccak256(coder.encode(['string','string','address','bytes32','bytes32','bytes32','uint256','uint16','address',...(planned?['bytes32']:[])],
    ['Cannabis arbitrary workload order '+(planned?'v3':'v2'),job.id,requester,'0x'+job.packageSHA256,'0x'+job.policySHA256,'0x'+job.acceptanceSHA256,payment.totalAtomic,100,payment.founderRecipient,...(planned?['0x'+job.executionPlanSHA256]:[])]));
  return {schema:'cannabis.compute.order-plan.'+(planned?'v3':'v2'),jobHash,job:structuredClone(job),payment,executionAuthorized:false,keyReleaseAuthorized:false,fundsMoved:false};
}
function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) throw Error('Use explicit UTC deadlines');
  const ms=Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().replace('.000Z','Z')!==value) throw Error('Invalid UTC deadline');
  return ms/1000;
}
export function settlementForPlan(job, settlement, plan) {
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
