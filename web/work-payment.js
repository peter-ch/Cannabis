// Ephemeral, requester-local result review. No private workload, output or key
// enters a market plan or journal. A pending wallet prompt cannot be revoked.
import {resultCommitment} from '../compute/result_commitment.mjs';
import {marketConfiguration,check} from '../operator/market-plan.mjs';
let selected=null,epoch=0,changed=()=>{};
export function onPaymentResultsChanged(listener){check(typeof listener==='function');changed=listener;}
export function clearPaymentResults(){++epoch;selected=null;changed();}
export function retainPaymentResults(snapshot,archives,{assertCurrent,useCurrent}) {
  check(typeof assertCurrent==='function'&&typeof useCurrent==='function');
  selected={snapshot:structuredClone(snapshot),archives:structuredClone(archives),assertCurrent,useCurrent,epoch:++epoch};changed();
}
export async function reviewedResultCommitment(configuration,plan) {
  const c=marketConfiguration(configuration),current=selected;check(current&&plan?.plan.kind==='order');
  await current.assertCurrent();check(current===selected&&current.epoch===epoch);
  const p=plan.plan,d=plan.detail,s=current.snapshot,b=s.bundle;
  check(BigInt(b.context.chainId)===BigInt(c.chainId)&&b.context.escrow===d.asset.escrow&&b.context.requester===d.requester&&s.jobId===p.job.id&&
    s.bundle.entries.length===current.archives.length&&b.entries.every(e=>['3','4'].includes(e.approval.domain.version)&&e.approval.value.orderId===d.orderId&&
      e.approval.value.packageSHA256==='0x'+p.job.packageSHA256&&e.approval.value.policySHA256==='0x'+p.job.policySHA256));
  const commitment=resultCommitment({chainId:c.chainId,genesisHash:c.genesisHash,escrow:d.asset.escrow,requester:d.requester,
    orderId:d.orderId,termsDigest:d.termsDigest,packageSHA256:p.job.packageSHA256,policySHA256:p.job.policySHA256},current.archives);
  return {commitment,assertCurrent:async()=>{check(current===selected&&current.epoch===epoch);await current.assertCurrent();check(current===selected&&current.epoch===epoch);},
    dispatch:async submit=>{
      const pending=await current.useCurrent(()=>{
        check(current===selected&&current.epoch===epoch);
        // Invoke the wallet while the local attempt transaction excludes a
        // competing retirement. Immediately handle its asynchronous rejection.
        return {result:Promise.resolve(submit()).then(value=>({ok:true,value}),error=>({ok:false,error}))};
      });
      const result=await pending.result;if(!result.ok)throw result.error;return result.value;
    }};
}
