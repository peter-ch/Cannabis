// Offline Cannabis ceremony approvals. Neither signatures nor opaque registry
// tags prove human uniqueness; both human review roles remain explicit trust.
import {AbiCoder,concat,getAddress,id,Interface,keccak256,TypedDataEncoder,verifyTypedData} from 'ethers';

const abi=AbiCoder.defaultAbiCoder();
const FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const exact=(v,keys)=>{if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)))throw Error('Unexpected ceremony fields');};
const word=v=>{if(typeof v!=='string'||!/^0x[0-9a-f]{64}$/.test(v)||/^0x0+$/.test(v))throw Error('Require a nonzero canonical bytes32 identifier');return v;};
const integer=(v,min,max)=>{if(!Number.isSafeInteger(v)||v<min||v>max)throw Error('Invalid ceremony integer');return v;};
const address=v=>{const a=getAddress(v);if(BigInt(a)===0n)throw Error('Zero ceremony address');return a;};
const order=(a,b)=>BigInt(a)<BigInt(b)?-1:BigInt(a)>BigInt(b)?1:0;
const decimal=v=>{if(typeof v!=='string'||!(/^[1-9][0-9]{0,77}$/).test(v)||BigInt(v)>=FIELD)throw Error('Invalid identity commitment');return v;};
const keys=(list,quorum)=>{
  if(!Array.isArray(list)||list.length<3||list.length>9)throw Error('Require three to nine independently controlled keys');
  integer(quorum,Math.ceil(2*list.length/3),list.length);
  const normalized=list.map(address).sort(order);
  if(new Set(normalized).size!==normalized.length)throw Error('Repeated approval key');
  return normalized;
};
export const roundTypes=Object.freeze({RoundPolicy:[
  {name:'number',type:'uint64'},{name:'policyRoot',type:'bytes32'},
  {name:'startsAt',type:'uint64'},{name:'endsAt',type:'uint64'},{name:'submissionsCloseAt',type:'uint64'}
]});
export const rosterTypes=Object.freeze({VenueRoster:[
  {name:'round',type:'uint64'},{name:'policyRoot',type:'bytes32'},{name:'enrollment',type:'address'},
  {name:'startsAt',type:'uint64'},{name:'endsAt',type:'uint64'},{name:'submissionsCloseAt',type:'uint64'},
  {name:'venueId',type:'bytes32'},{name:'commitmentsHash',type:'bytes32'},{name:'personTagsHash',type:'bytes32'}
]});
export const personTypes=Object.freeze({PersonApproval:[{name:'rosterDigest',type:'bytes32'}]});
export const reviewerChangeTypes=Object.freeze({ReviewerChange:[
  {name:'epoch',type:'uint64'},{name:'reviewersHash',type:'bytes32'},{name:'quorum',type:'uint8'},{name:'deadline',type:'uint64'}
]});
export const registrarInterface=new Interface([
  'function authorizeRound((uint64 number,bytes32 policyRoot,uint64 startsAt,uint64 endsAt,uint64 submissionsCloseAt) round,bytes[] approvals)',
  'function registerVenue((uint64 round,(bytes32 id,uint16 capacity,uint8 quorum,address[] witnesses) venue,bytes32[] proof,uint256[] commitments,bytes32[] personTags,bytes[] witnessApprovals,bytes[] registryApprovals) submission)',
  'function changeReviewers(address[] reviewers,uint8 quorum,uint64 deadline,bytes[] approvals)'
]);
export function venueLeaf(v){return keccak256(keccak256(abi.encode(['bytes32','bytes32','uint16','uint8','bytes32'],
  [id('Cannabis venue policy v1'),v.id,v.capacity,v.quorum,keccak256(abi.encode(['address[]'],[v.witnesses]))])));}
function tree(leaves){
  const levels=[leaves];
  while(levels.at(-1).length>1){const current=levels.at(-1),next=[];
    for(let i=0;i<current.length;i+=2)next.push(i+1===current.length?current[i]:keccak256(concat([current[i],current[i+1]].sort())));
    levels.push(next);
  }return levels;
}
export function normalizeCeremonyPolicy(input){
  exact(input,['schema','chainId','registrar','enrollment','registryReviewers','registryQuorum','round','startsAt','endsAt','submissionsCloseAt','venues']);
  if(input.schema!=='cannabis.ceremony-policy.v2'||typeof input.chainId!=='string'||!(/^[1-9][0-9]{0,77}$/).test(input.chainId)||BigInt(input.chainId)>=(1n<<256n))throw Error('Invalid ceremony policy');
  integer(input.round,1,Number.MAX_SAFE_INTEGER);
  const startsAt=integer(input.startsAt,1,Number.MAX_SAFE_INTEGER-40*86400);
  const endsAt=integer(input.endsAt,startsAt+3600,startsAt+14400);
  const submissionsCloseAt=integer(input.submissionsCloseAt,endsAt+86400,endsAt+30*86400);
  const registryReviewers=keys(input.registryReviewers,input.registryQuorum);
  if(!Array.isArray(input.venues)||input.venues.length<1||input.venues.length>10000)throw Error('Invalid venue count');
  const used=new Set(registryReviewers),ids=new Set();let capacity=0;
  const venues=input.venues.map(v=>{
    exact(v,['id','capacity','quorum','witnesses']);word(v.id);
    if(ids.has(v.id))throw Error('Duplicate venue');ids.add(v.id);
    integer(v.capacity,1,256);capacity+=v.capacity;
    const witnesses=keys(v.witnesses,v.quorum);
    for(const key of witnesses){if(used.has(key))throw Error('Venue and registry roles must be separate; venue keys cannot repeat across simultaneous venues');used.add(key);}
    return {id:v.id,capacity:v.capacity,quorum:v.quorum,witnesses};
  }).sort((a,b)=>order(a.id,b.id));
  if(capacity>990000||capacity<1)throw Error('Invalid total ceremony capacity');
  const policy={schema:input.schema,chainId:input.chainId,registrar:address(input.registrar),enrollment:address(input.enrollment),
    registryReviewers,registryQuorum:input.registryQuorum,round:input.round,startsAt,endsAt,submissionsCloseAt,venues};
  if(policy.registrar===policy.enrollment)throw Error('Registrar and enrollment must differ');return policy;
}
export function ceremonyConfiguration(input){
  const policy=normalizeCeremonyPolicy(input),levels=tree(policy.venues.map(venueLeaf)),policyRoot=levels.at(-1)[0];
  const round={number:policy.round,policyRoot,startsAt:policy.startsAt,endsAt:policy.endsAt,submissionsCloseAt:policy.submissionsCloseAt};
  const domain={name:'Cannabis community registrar',version:'1',chainId:policy.chainId,verifyingContract:policy.registrar};
  return {policy,policyRoot,round,domain,constructorArguments:[policy.enrollment,policy.registryReviewers,policy.registryQuorum]};
}
function typed(domain,types,message){return {domain,types,message,digest:TypedDataEncoder.hash(domain,types,message)};}
function approvals(request,signatures,approved,quorum){
  if(!Array.isArray(signatures)||signatures.length<quorum||signatures.length>approved.length)throw Error('Approval quorum is missing');
  const recovered=signatures.map(signature=>{
    if(typeof signature!=='string'||!/^0x[0-9a-fA-F]{130}$/.test(signature))throw Error('Invalid approval signature');
    const signer=verifyTypedData(request.domain,request.types,request.message,signature);
    if(!approved.includes(signer))throw Error('Unknown or mismatched approval');return {signer,signature};
  }).sort((a,b)=>order(a.signer,b.signer));
  if(new Set(recovered.map(x=>x.signer)).size!==recovered.length)throw Error('Repeated approval signature');return recovered;
}
const transaction=(p,name,args)=>({chainId:'0x'+BigInt(p.chainId).toString(16),to:p.registrar,value:'0x0',data:registrarInterface.encodeFunctionData(name,args)});
export function prepareRoundPolicy(input){const c=ceremonyConfiguration(input);return {schema:'cannabis.round-approval-request.v1',...typed(c.domain,roundTypes,c.round)};}
export function verifyRoundApprovals(input,signatures,now=Math.floor(Date.now()/1000)){
  const c=ceremonyConfiguration(input),request=prepareRoundPolicy(c.policy);integer(now,1,Number.MAX_SAFE_INTEGER-7*86400);
  if(c.policy.startsAt<now+7*86400)throw Error('Round needs seven days of on-chain notice');
  const signed=approvals(request,signatures,c.policy.registryReviewers,c.policy.registryQuorum);
  return {schema:'cannabis.round-approval.v1',digest:request.digest,signatureQuorumVerified:true,sent:false,
    transaction:transaction(c.policy,'authorizeRound',[c.round,signed.map(x=>x.signature)])};
}
export function prepareVenueRoster(input,venueId,members){
  const {policy,policyRoot,domain}=ceremonyConfiguration(input),index=policy.venues.findIndex(v=>v.id===venueId);
  if(index<0)throw Error('Venue is not approved');const venue=policy.venues[index];
  if(!Array.isArray(members)||!members.length||members.length>venue.capacity)throw Error('Invalid roster count');
  const rows=members.map(row=>{exact(row,['personTag','commitment']);return {personTag:word(row.personTag),commitment:decimal(row.commitment)};}).sort((a,b)=>order(a.commitment,b.commitment));
  const commitments=rows.map(x=>x.commitment),personTags=rows.map(x=>x.personTag);
  if(new Set(commitments).size!==commitments.length||new Set(personTags).size!==personTags.length)throw Error('Duplicate permanent record or commitment');
  const levels=tree(policy.venues.map(venueLeaf)),proof=[];let cursor=index;
  for(const level of levels.slice(0,-1)){const sibling=cursor^1;if(sibling<level.length)proof.push(level[sibling]);cursor=Math.floor(cursor/2);}
  const message={round:policy.round,policyRoot,enrollment:policy.enrollment,startsAt:policy.startsAt,endsAt:policy.endsAt,
    submissionsCloseAt:policy.submissionsCloseAt,venueId,commitmentsHash:keccak256(abi.encode(['uint256[]'],[commitments])),personTagsHash:keccak256(abi.encode(['bytes32[]'],[personTags]))};
  const witnessRequest=typed(domain,rosterTypes,message);
  return {schema:'cannabis.ceremony-roster.v2',round:policy.round,venue,proof,commitments,personTags,witnessRequest,
    registryRequest:typed(domain,personTypes,{rosterDigest:witnessRequest.digest})};
}
export function verifyVenueApprovals(input,venueId,members,witnessSignatures,registrySignatures,now=Math.floor(Date.now()/1000)){
  const policy=normalizeCeremonyPolicy(input),request=prepareVenueRoster(policy,venueId,members);integer(now,1,Number.MAX_SAFE_INTEGER);
  if(now<=policy.endsAt||now>policy.submissionsCloseAt)throw Error('Outside ceremony submission window');
  const witness=approvals(request.witnessRequest,witnessSignatures,request.venue.witnesses,request.venue.quorum);
  const registry=approvals(request.registryRequest,registrySignatures,policy.registryReviewers,policy.registryQuorum);
  const submission={round:request.round,venue:request.venue,proof:request.proof,commitments:request.commitments,personTags:request.personTags,
    witnessApprovals:witness.map(x=>x.signature),registryApprovals:registry.map(x=>x.signature)};
  return {schema:'cannabis.ceremony-approval.v2',digest:request.witnessRequest.digest,witnesses:witness.map(x=>x.signer),reviewers:registry.map(x=>x.signer),
    witnessQuorumVerified:true,registryQuorumVerified:true,humanUniquenessEstablished:false,enrolled:false,sent:false,
    transaction:transaction(policy,'registerVenue',[submission])};
}

// Reviewer additions/removals: the current quorum approves the complete next set for one epoch.
function reviewerChange(input){
  exact(input,['chainId','registrar','epoch','currentReviewers','currentQuorum','reviewers','quorum','deadline']);
  if(typeof input.chainId!=='string'||!(/^[1-9][0-9]{0,77}$/).test(input.chainId))throw Error('Invalid reviewer change');
  const current=keys(input.currentReviewers,input.currentQuorum),reviewers=keys(input.reviewers,input.quorum);
  integer(input.epoch,0,Number.MAX_SAFE_INTEGER);integer(input.deadline,1,Number.MAX_SAFE_INTEGER);
  if(current.join()===reviewers.join()&&input.currentQuorum===input.quorum)throw Error('Reviewer change does not change anything');
  const p={chainId:input.chainId,registrar:address(input.registrar)};
  const domain={name:'Cannabis community registrar',version:'1',chainId:p.chainId,verifyingContract:p.registrar};
  const message={epoch:input.epoch,reviewersHash:keccak256(abi.encode(['address[]'],[reviewers])),quorum:input.quorum,deadline:input.deadline};
  return {p,current,reviewers,quorum:input.quorum,deadline:input.deadline,request:typed(domain,reviewerChangeTypes,message)};
}
export function prepareReviewerChange(input){
  const c=reviewerChange(input);
  return {schema:'cannabis.reviewer-change-request.v1',reviewers:c.reviewers,quorum:c.quorum,
    added:c.reviewers.filter(a=>!c.current.includes(a)),removed:c.current.filter(a=>!c.reviewers.includes(a)),...c.request};
}
export function verifyReviewerChange(input,signatures,now=Math.floor(Date.now()/1000)){
  const c=reviewerChange(input);integer(now,1,Number.MAX_SAFE_INTEGER);
  if(c.deadline<now||c.deadline>now+30*86400)throw Error('Reviewer change deadline must be within thirty days');
  const signed=approvals(c.request,signatures,c.current,input.currentQuorum);
  return {schema:'cannabis.reviewer-change.v1',digest:c.request.digest,signatureQuorumVerified:true,sent:false,
    transaction:transaction(c.p,'changeReviewers',[c.reviewers,c.quorum,c.deadline,signed.map(x=>x.signature)])};
}
