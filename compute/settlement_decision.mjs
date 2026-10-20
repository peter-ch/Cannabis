// Fixed post-delivery decisions. Public commitments only, never private results,
// reasons, keys, arbitrary ABI calls or automatic output-quality approval.
import {getAddress,ZeroAddress} from 'ethers';
export const postDeliveryMethods=Object.freeze(['deliver','approve','dispute','resolve','finalizeExpiredState']);
const check=v=>{if(!v)throw Error('Settlement decision, role or exact amount is invalid');};
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const digest=v=>check(typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v));
const amount=v=>{check(typeof v==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(v));const n=BigInt(v);check(n<2n**256n&&n%100n===0n);return n;};
export function settlementDecision(method,input,terms,actor) {
  check(postDeliveryMethods.includes(method)&&getAddress(actor)===actor&&actor!==ZeroAddress);
  const decision=structuredClone(input),budget=amount(terms.budget);check(budget>0n);digest(terms.termsDigest);
  let args=[terms.termsDigest],gross=null,phase,contractMethod;
  if(method==='deliver') {
    exact(decision,['outputDigest']);digest(decision.outputDigest);check(actor===terms.deliveryManager);
    args.push(decision.outputDigest);phase='active';contractMethod='deliverResult';
  } else if(method==='approve') {
    exact(decision,['outputDigest','acceptanceSHA256']);digest(decision.outputDigest);
    check(typeof decision.acceptanceSHA256==='string'&&/^[0-9a-f]{64}$/.test(decision.acceptanceSHA256)&&
      decision.acceptanceSHA256===terms.acceptanceSHA256&&actor===terms.requester);
    args.push(decision.outputDigest);gross=budget;phase='delivered';contractMethod='approveResult';
  } else if(method==='dispute') {
    exact(decision,['outputDigest','reasonDigest']);digest(decision.outputDigest);digest(decision.reasonDigest);check(actor===terms.requester);
    args.push(decision.outputDigest,decision.reasonDigest);phase='delivered';contractMethod='disputeResult';
  } else if(method==='resolve') {
    exact(decision,['outputDigest','reasonDigest','grossPaidBaseUnits']);digest(decision.outputDigest);digest(decision.reasonDigest);
    gross=amount(decision.grossPaidBaseUnits);check(actor===terms.adjudicator&&gross<=budget);
    args.push(decision.outputDigest,decision.reasonDigest,gross.toString());phase='disputed';contractMethod='resolveDispute';
  } else {
    exact(decision,['expectedState']);check(Number.isSafeInteger(decision.expectedState)&&[1,2,3,4].includes(decision.expectedState));
    args.push(decision.expectedState);phase=['none','funded','active','delivered','disputed'][decision.expectedState];gross=decision.expectedState===3?budget:0n;contractMethod='finalizeExpiredState';
  }
  return {decision,contractMethod,args,outcome:{phase,grossPaidBaseUnits:gross===null?null:gross.toString(),
    serviceFeeBaseUnits:gross===null?null:(gross/100n).toString(),workerBaseUnits:gross===null?null:(gross-gross/100n).toString(),
    requesterRefundBaseUnits:gross===null?null:(budget-gross).toString()}};
}
