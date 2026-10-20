// Shared strict signing vocabulary. There are no transaction, permit or generic
// message-signing requests in this workflow wallet interface.
const fields=list=>list.map(([name,type])=>({name,type}));
const peer=fields([['role','uint8'],['genesisHash','bytes32'],['configurationSHA256','bytes32'],['assignmentSHA256','bytes32'],
  ['leaseDigest','bytes32'],['bookingId','bytes32'],['requester','address'],['provider','address'],['origin','string'],
  ['channelBinding','bytes32'],['requesterNonce','bytes32'],['providerNonce','bytes32'],['validFrom','uint64'],['validUntil','uint64']]);
const dependency=fields([['leaseDigest','bytes32'],['orderId','bytes32'],['executionPlanSHA256','bytes32'],['genesisHash','bytes32'],
  ['reservationId','bytes32'],['taskSHA256','bytes32'],['attempt','uint32'],['rank','uint32'],['worldSize','uint32'],['inputRecipient','string'],
  ['ciphertextSHA256','bytes32'],['ciphertextBytes','uint64'],['contextSHA256','bytes32'],['notBefore','uint64'],['expiresAt','uint64']]);
const key=fields([['releaseId','bytes32'],['leaseDigest','bytes32'],['orderId','bytes32'],['reservationId','bytes32'],
  ['packageSHA256','bytes32'],['policySHA256','bytes32'],['attestationPolicySHA256','bytes32'],['runtimeSHA256','bytes32'],
  ['taskSHA256','bytes32'],['capsuleSHA256','bytes32'],['inputRecipient','string'],['channelKeySHA256','bytes32'],['nonce','bytes32'],
  ['attempt','uint32'],['rank','uint32'],['worldSize','uint32'],['notBefore','uint64'],['expiresAt','uint64'],['resultKeySHA256','bytes32'],
  ['configurationSHA256','bytes32']]);
const stored=fields([['approvalDigest','bytes32'],['envelopeSHA256','bytes32'],['ciphertextSHA256','bytes32'],['ciphertextBytes','uint64']]);
const group=fields([['genesisHash','bytes32'],['leaseDigest','bytes32'],['executionPlanSHA256','bytes32'],
  ['taskSHA256','bytes32'],['attempt','uint32'],['worldSize','uint32'],['groupDigest','bytes32'],
  ['requester','address'],['validFrom','uint64'],['validUntil','uint64']]);
const start=fields([['groupDigest','bytes32'],['readinessDigest','bytes32'],['requester','address'],['validFrom','uint64'],['validUntil','uint64']]);
const check=v=>{if(!v)throw Error('Unsupported, expired or changed workflow approval');};
const exact=(v,n)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...n].sort().join());
export function workflowSigningSchema(kind,version) {
  const data={peer:['Cannabis booked peer channel','BookedPeerChannel',peer],dependency:['Cannabis dependency handoff','DependencyHandoff',dependency],
    'key-release':['Cannabis confidential key delivery','JobKeyDelivery',[...key,
      ...(['5','6'].includes(version)?fields([['groupDigest','bytes32'],['groupStartDigest','bytes32']]):[]),
      ...(['4','6'].includes(version)?fields([['dependencyApprovalDigest','bytes32']]):[])]],
    group:['Cannabis protected group','ProtectedGroup',group],
    'group-start':['Cannabis protected group start','ProtectedGroupStart',start],
    stored:['Cannabis encrypted result stored','ResultStored',stored]}[kind];
  check(data&&(kind==='key-release'?['3','4','5','6'].includes(version):version==='1'));
  return {name:data[0],primaryType:data[1],types:{[data[1]]:data[2]}};
}
export function validateWorkflowReview(review,now=Date.now()) {
  exact(review,['id','kind','reservationId','requester','genesisHash','expiresAt','digest','typedData']);
  check(/^[0-9a-f]{64}$/.test(review.id)&&/^0x[0-9a-f]{64}$/.test(review.reservationId)&&/^0x[0-9a-f]{64}$/.test(review.genesisHash)&&
    /^0x[0-9a-fA-F]{40}$/.test(review.requester)&&/^0x[0-9a-f]{64}$/.test(review.digest)&&
    Number.isSafeInteger(review.expiresAt)&&review.expiresAt>now&&review.expiresAt<=now+61000);
  const d=review.typedData;exact(d,['domain','types','message','primaryType']);
  const s=workflowSigningSchema(review.kind,d.domain?.version),domain=fields([['name','string'],['version','string'],['chainId','uint256'],['verifyingContract','address']]);
  exact(d.domain,domain.map(x=>x.name));exact(d.types,['EIP712Domain',s.primaryType]);
  check(d.domain.name===s.name&&d.primaryType===s.primaryType&&/^0x[0-9a-fA-F]{40}$/.test(d.domain.verifyingContract)&&BigInt(d.domain.chainId)>0n);
  for(const [name,list] of [['EIP712Domain',domain],[s.primaryType,s.types[s.primaryType]]])
    check(JSON.stringify(d.types[name])===JSON.stringify(list));
  exact(d.message,s.types[s.primaryType].map(x=>x.name));
  for(const {name,type} of s.types[s.primaryType]) {
    const value=d.message[name];
    if(type==='bytes32')check(/^0x[0-9a-fA-F]{64}$/.test(value));
    else if(type==='address')check(/^0x[0-9a-fA-F]{40}$/.test(value));
    else if(type.startsWith('uint'))check(/^[0-9]+$/.test(String(value))&&BigInt(value)<2n**BigInt(type.slice(4)));
    else check(typeof value==='string'&&value.length<=512);
  }
  if(review.kind==='peer')check(BigInt(d.message.role)===0n&&d.message.requester.toLowerCase()===review.requester.toLowerCase()&&
    d.message.bookingId===review.reservationId&&d.message.genesisHash===review.genesisHash&&new URL(d.message.origin).origin===d.message.origin&&
    d.message.origin.startsWith('https://'));
  if(['dependency','key-release'].includes(review.kind))check(d.message.reservationId===review.reservationId&&BigInt(d.message.expiresAt)>BigInt(d.message.notBefore));
  if(review.kind==='dependency')check(d.message.genesisHash===review.genesisHash);
  if(['group','group-start'].includes(review.kind))check(d.message.requester.toLowerCase()===review.requester.toLowerCase()&&
    BigInt(d.message.validUntil)>BigInt(d.message.validFrom));
  if(review.kind==='group')check(d.message.genesisHash===review.genesisHash&&BigInt(d.message.worldSize)>=2n&&BigInt(d.message.worldSize)<=64n);
  return structuredClone(review);
}
