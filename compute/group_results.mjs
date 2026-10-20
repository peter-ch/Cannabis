// Shared by requester and browser reconstruction. A partial recovery selection
// is allowed, but ranks of a task cannot come from different group starts.
export function assertCompatibleGroupResults(approvals) {
  const groups=new Map();
  for(const a of approvals) {
    // Typed-data signatures permit equivalent chain-ID encodings and address
    // casing. Those must not split one task into separate consistency groups.
    const v=a.value,key=JSON.stringify([BigInt(a.domain.chainId).toString(),a.domain.verifyingContract.toLowerCase(),
      ...[v.orderId,v.packageSHA256,v.taskSHA256].map(value=>value.toLowerCase())]);
    const grouped=['5','6'].includes(a.domain.version),value=JSON.stringify([grouped,v.attempt,v.worldSize,
      grouped?v.groupDigest.toLowerCase():null,grouped?v.groupStartDigest.toLowerCase():null]);
    const prior=groups.get(key);
    if(prior&&(grouped||prior.grouped)&&prior.value!==value)throw Error('Selected ranks do not share one approved group attempt and start');
    groups.set(key,{grouped,value});
  }
}
