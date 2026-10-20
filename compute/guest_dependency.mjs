// Verify the separately signed dependency input against the retained booking.
// Funding, attestation and protected storage remain independent admission gates.
import { verifyMarketLeaseProof } from './market_lease.mjs';
import { verifyDependencyHandoff } from './dependency_handoff.mjs';

export function inspectGuestDependency({proof,network,binding,execution,dependency,now}) {
  const fail=()=>{throw Error('Dependency input differs from the approved guest assignment');};
  let required=false;
  if(proof?.schema==='cannabis.market-lease.v2') {
    const lease=verifyMarketLeaseProof(proof,network);
    const assignment=lease.assignments.find(a=>a.reservationId===binding.reservationId);
    if(!assignment)fail();
    required=lease.executionPlan.plan.requirements[assignment.task].dependsOn.length>0;
    for(const k of ['runtimeSHA256','taskSHA256','attempt','rank','worldSize','acceleratorClass'])
      if(assignment.run[k]!==binding[k])fail();
  }
  if(!required) {if(dependency!==undefined&&dependency!==null)fail();return null;}
  if(!dependency||Object.keys(dependency).sort().join()!=='descriptor,signed'||
      !['cannabis.guest-native-service.v3','cannabis.guest-native-service.v4'].includes(execution?.profile?.schema))fail();
  const retained=structuredClone(dependency);
  const checked=verifyDependencyHandoff(proof,network,binding.reservationId,retained.descriptor,retained.signed,now);
  const h=retained.signed.handoff,c=h.context,p=execution.profile;
  if(!Number.isSafeInteger(p.ciphertext.dependencyBytes)||p.ciphertext.dependencyBytes<1||
      h.ciphertextBytes>p.ciphertext.dependencyBytes||!Number.isSafeInteger(p.maxDependencyBytes)||
      p.maxDependencyBytes<0||p.maxDependencyBytes+p.maxInputBytes>p.staging.bytes)fail();
  for(const k of ['leaseDigest','orderId','reservationId','packageSHA256','policySHA256',
      'runtimeSHA256','taskSHA256','attempt','rank','worldSize','acceleratorClass'])if(c[k]!==binding[k])fail();
  return {...retained,approvalDigest:checked.approvalDigest};
}
