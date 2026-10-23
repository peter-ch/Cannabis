import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {Contract,ContractFactory,getCreateAddress,id,Wallet} from 'ethers';
import {Group} from '@semaphore-protocol/group';
import {generateProof} from '@semaphore-protocol/proof';
import {compile} from '../scripts/compile.mjs';
import {startNode,deployLocal,localSources,localIdentity,end24Months,closeProver} from '../scripts/lib.mjs';
import {normalizeCeremonyPolicy,ceremonyConfiguration,prepareRoundPolicy,verifyRoundApprovals,prepareVenueRoster,verifyVenueApprovals,venueLeaf,prepareReviewerChange,verifyReviewerChange} from '../claims/community-enrollment.mjs';

let node,provider,artifacts,policy,registrar,token,enrollment,owner,snapshot;
const witnesses=Array.from({length:9},()=>Wallet.createRandom());
const reviewers=Array.from({length:3},()=>Wallet.createRandom()); // Disposable fixture keys only.
const member=i=>({personTag:id('OWNED LOCAL PERSON '+i),commitment:localIdentity(i+10000).commitment.toString()});
const roster=Array.from({length:128},(_,i)=>member(i));
const port=()=>new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
const signatures=(request,keys)=>Promise.all(keys.map(k=>k.signTypedData(request.domain,request.types,request.message)));
const time=async t=>{await provider.send('evm_setNextBlockTimestamp',[t]);await provider.send('evm_mine',[]);};
const reset=async()=>{await provider.send('evm_revert',[snapshot]);snapshot=await provider.send('evm_snapshot',[]);};
const reverts=promise=>assert.rejects(promise,error=>error.code==='CALL_EXCEPTION');
async function authorize(p){const request=prepareRoundPolicy(p),signed=await signatures(request,reviewers.slice(0,2));
  const checked=verifyRoundApprovals(p,signed,(await provider.getBlock('latest')).timestamp);
  await (await owner.sendTransaction(checked.transaction)).wait();}
async function checkedRoster(p=policy,venueId=p.venues[0].id,members=roster,keys=witnesses.slice(0,2)){
  const r=prepareVenueRoster(p,venueId,members);
  return verifyVenueApprovals(p,venueId,members,await signatures(r.witnessRequest,keys),await signatures(r.registryRequest,reviewers.slice(0,2)),p.endsAt+1);
}
const submit=async(...args)=>owner.sendTransaction((await checkedRoster(...args)).transaction);
before(async()=>{
  artifacts=compile(localSources);node=await startNode(await port(),'community-enrollment-node.log');provider=node.provider;
  const dependency=await deployLocal(provider,artifacts,{memberCount:0});owner=await provider.getSigner(0);
  const from=await owner.getAddress(),nonce=await provider.getTransactionCount(from);
  const registrarAddress=getCreateAddress({from,nonce}),tokenAddress=getCreateAddress({from,nonce:nonce+1});
  const enrollmentAddress=getCreateAddress({from:tokenAddress,nonce:1}),now=(await provider.getBlock('latest')).timestamp;
  policy={schema:'cannabis.ceremony-policy.v2',chainId:'31337',registrar:registrarAddress,enrollment:enrollmentAddress,
    registryReviewers:reviewers.map(x=>x.address),registryQuorum:2,round:1,startsAt:now+8*86400,endsAt:now+8*86400+3600,submissionsCloseAt:now+9*86400+3600,
    venues:Array.from({length:3},(_,i)=>({id:id('OWNED LOCAL VENUE '+i),capacity:128,quorum:2,witnesses:witnesses.slice(i*3,i*3+3).map(w=>w.address)}))};
  registrar=await new ContractFactory(artifacts.CommunityRegistrar.abi,artifacts.CommunityRegistrar.bytecode,owner).deploy(...ceremonyConfiguration(policy).constructorArguments);
  await registrar.waitForDeployment();assert.equal(await registrar.getAddress(),registrarAddress);
  const opening=policy.submissionsCloseAt+86400;
  token=await new ContractFactory(artifacts.Cannabis.abi,artifacts.Cannabis.bytecode,owner).deploy(from,opening,end24Months(opening),await dependency.semaphore.getAddress(),registrarAddress,1);
  await token.waitForDeployment();assert.equal(await token.enrollment(),enrollmentAddress);
  enrollment=new Contract(enrollmentAddress,artifacts.CannabisEnrollment.abi,owner);
  await authorize(policy);snapshot=await provider.send('evm_snapshot',[]);
});
after(async()=>{provider?.destroy();node?.child.kill();await closeProver();});

test('independent presence and registry quorums bind a real enrollment; no founder-only path',async()=>{
  await reset();const r=prepareVenueRoster(policy,policy.venues[0].id,roster);
  assert.equal(await registrar.venueLeaf(r.venue),venueLeaf(r.venue));
  assert.equal(await registrar.roundDigest(ceremonyConfiguration(policy).round),prepareRoundPolicy(policy).digest);
  assert.equal(await registrar.rosterDigest(r.round,r.venue.id,r.commitments,r.personTags),r.witnessRequest.digest);
  assert.equal(await registrar.personApprovalDigest(r.witnessRequest.digest),r.registryRequest.digest);
  await time(policy.endsAt+1);const checked=await checkedRoster();
  assert.equal(checked.humanUniquenessEstablished,false);assert.equal(checked.sent,false);
  await (await (await provider.getSigner(10)).sendTransaction(checked.transaction)).wait();
  assert.equal(await enrollment.enrolledCount(),128n);assert.equal(await token.communityIssued(),0n);
  assert.equal(await registrar.personCommitment(roster[0].personTag),BigInt(roster[0].commitment));
  assert.equal(registrar.interface.getFunction('owner'),null);assert.equal(registrar.interface.getFunction('reset'),null);
  await reverts(enrollment.addVerifiedMembers(['123']));
});
test('later newcomers enroll while old person records and commitments stay consumed across rounds',async()=>{
  await reset();await time(policy.endsAt+1);await (await submit()).wait();
  const next={...policy,round:2,startsAt:policy.submissionsCloseAt+10*86400,endsAt:policy.submissionsCloseAt+10*86400+3600,submissionsCloseAt:policy.submissionsCloseAt+11*86400+3600};
  await authorize(next);await time(next.endsAt+1);
  await reverts(submit(next,next.venues[0].id,[{personTag:roster[0].personTag,commitment:member(200).commitment}]));
  await reverts(submit(next,next.venues[0].id,[{personTag:member(200).personTag,commitment:roster[0].commitment}]));
  assert.equal(await enrollment.enrolledCount(),128n);
  await (await submit(next,next.venues[0].id,[member(200)])).wait();
  assert.equal(await enrollment.enrolledCount(),129n);
  assert.equal(await registrar.personCommitment(roster[0].personTag),BigInt(roster[0].commitment));
  assert.equal(await registrar.roundCount(),2n);
});
test('unknown rounds, early/late rosters and replayed venue submissions fail',async()=>{
  await reset();await reverts(submit());await time(policy.endsAt+1);await (await submit()).wait();await reverts(submit());
  const r=prepareVenueRoster(policy,policy.venues[1].id,[member(200)]);
  await reverts(registrar.registerVenue({round:99,venue:r.venue,proof:r.proof,commitments:r.commitments,personTags:r.personTags,witnessApprovals:[],registryApprovals:[]}));
  await time(policy.submissionsCloseAt+1);await reverts(submit(policy,policy.venues[1].id,[member(200)],witnesses.slice(3,5)));
});
test('round approval requires current reviewers, seven days notice and ordered nonoverlapping rounds',async()=>{
  await reset();const c=ceremonyConfiguration(policy),request=prepareRoundPolicy(policy);
  await reverts(registrar.authorizeRound(c.round,await signatures(request,reviewers.slice(0,2))));
  const future={...policy,round:2,startsAt:policy.submissionsCloseAt+10*86400,endsAt:policy.submissionsCloseAt+10*86400+3600,submissionsCloseAt:policy.submissionsCloseAt+11*86400+3600};
  const f=ceremonyConfiguration(future),rq=prepareRoundPolicy(future);
  await reverts(registrar.authorizeRound(f.round,await signatures(rq,witnesses.slice(0,2))));
  await reverts(registrar.authorizeRound(f.round,await signatures(rq,reviewers.slice(0,1))));
  await reverts(registrar.authorizeRound({...f.round,startsAt:policy.startsAt},await signatures(rq,reviewers.slice(0,2))));
  await authorize(future);assert.equal(await registrar.roundCount(),2n);
});
test('missing or mismatched role approvals, wrong schedule, venue, chain and person bindings revert atomically',async()=>{
  await reset();await time(policy.endsAt+1);const r=prepareVenueRoster(policy,policy.venues[0].id,roster);
  const ws=await signatures(r.witnessRequest,witnesses.slice(0,2)),rs=await signatures(r.registryRequest,reviewers.slice(0,2));
  for(const change of [{domain:{...r.witnessRequest.domain,chainId:'1'}},{domain:{...r.witnessRequest.domain,verifyingContract:policy.enrollment}},
    {message:{...r.witnessRequest.message,startsAt:policy.startsAt+1}},{message:{...r.witnessRequest.message,venueId:policy.venues[1].id}},
    {message:{...r.witnessRequest.message,personTagsHash:id('wrong')}}]){
    const wrong=await signatures({...r.witnessRequest,...change},witnesses.slice(0,2));
    assert.throws(()=>verifyVenueApprovals(policy,r.venue.id,roster,wrong,rs,policy.endsAt+1));
  }
  const prepared=await checkedRoster(),parsed=registrar.interface.decodeFunctionData('registerVenue',prepared.transaction.data)[0];
  const s={round:r.round,venue:r.venue,proof:r.proof,commitments:r.commitments,personTags:r.personTags,witnessApprovals:Array.from(parsed.witnessApprovals),registryApprovals:Array.from(parsed.registryApprovals)};
  for(const changes of [{registryApprovals:[]},{witnessApprovals:[]},{witnessApprovals:[s.witnessApprovals[0],s.witnessApprovals[0]]},
    {registryApprovals:[s.registryApprovals[0],s.registryApprovals[0]]},{personTags:r.personTags.map(()=>r.personTags[0])},
    {personTags:[...r.personTags.slice(1),id('changed')]},{venue:{...r.venue,capacity:256}}]) await reverts(registrar.registerVenue({...s,...changes}));
  assert.equal(await enrollment.enrolledCount(),0n);assert.equal(await registrar.personCommitment(r.personTags[0]),0n);
  await (await submit()).wait();
  // Both non-power-of-two Merkle siblings are actually accepted with their own witness teams.
  for(let i=1;i<3;i++)await (await submit(policy,policy.venues[i].id,[member(200+i)],witnesses.slice(i*3,i*3+2))).wait();
  assert.equal(await enrollment.enrolledCount(),130n);
  assert.throws(()=>verifyVenueApprovals(policy,r.venue.id,roster,ws,ws,policy.endsAt+1));
});
test('enrolled fixture identities produce a real Semaphore claim, with one allocation and a common opening',async()=>{
  await reset();await time(policy.endsAt+1);await (await submit()).wait();const r=prepareVenueRoster(policy,policy.venues[0].id,roster);
  const recipient=await (await provider.getSigner(11)).getAddress();
  const proof=await generateProof(localIdentity(10000),new Group(r.commitments.map(BigInt)),BigInt(recipient),await token.claimScope());
  await reverts(token.claim(recipient,proof));await time(Number(await token.claimsStartAt()));await (await token.claim(recipient,proof)).wait();
  assert.equal(await token.balanceOf(recipient),420n*10n**18n);await reverts(token.claim(recipient,proof));
});
test('first-round capacity may be one and a witnessed singleton claims without a recruitment threshold',async()=>{
  const small={...policy,venues:[{...policy.venues[0],capacity:1}]};
  assert.equal(normalizeCeremonyPolicy(small).venues[0].capacity,1);
  assert.equal(prepareVenueRoster(small,small.venues[0].id,[member(10000)]).commitments.length,1);
  assert.throws(()=>normalizeCeremonyPolicy({...small,venues:[{...small.venues[0],capacity:0}]}));
  await reset();await time(policy.endsAt+1);await (await submit(policy,policy.venues[0].id,[roster[0]])).wait();
  assert.equal(await enrollment.enrolledCount(),1n);
  const recipient=await (await provider.getSigner(11)).getAddress(),group=new Group([BigInt(roster[0].commitment)]);
  const proof=await generateProof(localIdentity(10000),group,BigInt(recipient),await token.claimScope());
  await time(Number(await token.claimsStartAt()));await (await token.claim(recipient,proof)).wait();
  assert.equal(await token.balanceOf(recipient),420n*10n**18n);await reverts(token.claim(recipient,proof));
});
test('current reviewer quorum adds and removes reviewers once per epoch; removed keys lose authority',async()=>{
  await reset();const now=(await provider.getBlock('latest')).timestamp,added=Wallet.createRandom(),deadline=now+86400;
  const sorted=keys=>[...keys].sort((a,b)=>BigInt(a.address)<BigInt(b.address)?-1:1);
  const base={chainId:'31337',registrar:policy.registrar,epoch:0,currentReviewers:reviewers.map(x=>x.address),currentQuorum:2};
  // Add one reviewer (4 keys, quorum 3), then remove the original first reviewer (3 keys, quorum 2).
  const grown=sorted([...reviewers,added]),change={...base,reviewers:grown.map(x=>x.address),quorum:3,deadline};
  const request=prepareReviewerChange(change);
  assert.deepEqual(request.added,[added.address]);assert.deepEqual(request.removed,[]);
  assert.equal(await registrar.reviewerChangeDigest(request.reviewers,3,deadline),request.digest);
  const one=await signatures(request,reviewers.slice(0,1)),outsiders=await signatures(request,witnesses.slice(0,2));
  assert.throws(()=>verifyReviewerChange(change,one,now));
  assert.throws(()=>verifyReviewerChange(change,outsiders,now));
  const checked=verifyReviewerChange(change,await signatures(request,reviewers.slice(0,2)),now);
  const parsed=registrar.interface.decodeFunctionData('changeReviewers',checked.transaction.data);
  for(const [r,q,d,a] of [[request.reviewers,3,deadline,[parsed[3][0]]],[request.reviewers,2,deadline,Array.from(parsed[3])],
    [request.reviewers,3,deadline+1,Array.from(parsed[3])]])await reverts(registrar.changeReviewers(r,q,d,a));
  await (await (await provider.getSigner(10)).sendTransaction(checked.transaction)).wait();
  assert.equal(await registrar.reviewerEpoch(),1n);assert.equal(await registrar.registryQuorum(),3n);
  assert.equal(await registrar.registryReviewerCount(),4n);assert.equal(await registrar.isRegistryReviewer(added.address),true);
  await reverts(owner.sendTransaction(checked.transaction)); // Epoch-bound approvals cannot be replayed.
  const removedKey=reviewers[0],next=grown.filter(x=>x!==removedKey);
  const shrink={...base,epoch:1,currentReviewers:grown.map(x=>x.address),currentQuorum:3,reviewers:next.map(x=>x.address),quorum:2,deadline};
  const shrinkRequest=prepareReviewerChange(shrink);assert.deepEqual(shrinkRequest.removed,[removedKey.address]);
  const short=await signatures(shrinkRequest,grown.slice(0,2));assert.throws(()=>verifyReviewerChange(shrink,short,now));
  await (await owner.sendTransaction(verifyReviewerChange(shrink,await signatures(shrinkRequest,grown.slice(0,3)),now).transaction)).wait();
  assert.equal(await registrar.reviewerEpoch(),2n);assert.equal(await registrar.registryReviewerCount(),3n);
  assert.equal(await registrar.isRegistryReviewer(removedKey.address),false);
  // Enrollment now needs the current set: the removed reviewer's approval is refused.
  await time(policy.endsAt+1);const r=prepareVenueRoster(policy,policy.venues[0].id,[member(300)]);
  const ws=await signatures(r.witnessRequest,sorted(witnesses.slice(0,2)));
  const s={round:r.round,venue:r.venue,proof:r.proof,commitments:r.commitments,personTags:r.personTags,witnessApprovals:ws};
  const withKeys=async list=>Array.from(await signatures(r.registryRequest,sorted(list)));
  await reverts(registrar.registerVenue({...s,registryApprovals:await withKeys([removedKey,next[0]])}));
  await (await registrar.registerVenue({...s,registryApprovals:await withKeys(next.slice(0,2))})).wait();
  assert.equal(await enrollment.enrolledCount(),1n);
});
test('reviewer changes refuse invalid sets, stale or distant deadlines and witness-unchanged no-ops',async()=>{
  await reset();const now=(await provider.getBlock('latest')).timestamp,base={chainId:'31337',registrar:policy.registrar,epoch:0,
    currentReviewers:reviewers.map(x=>x.address),currentQuorum:2,reviewers:reviewers.map(x=>x.address),quorum:2,deadline:now+3600};
  assert.throws(()=>prepareReviewerChange(base));
  assert.throws(()=>prepareReviewerChange({...base,reviewers:reviewers.slice(0,2).map(x=>x.address)}));
  assert.throws(()=>prepareReviewerChange({...base,quorum:1}));
  const sign=async(list,quorum,deadline)=>{
    const digest=await registrar.reviewerChangeDigest(list,quorum,deadline);
    return Promise.all(reviewers.map(k=>k.signingKey.sign(digest).serialized)).then(a=>a.map((sig,i)=>({sig,a:reviewers[i].address}))
      .sort((x,y)=>BigInt(x.a)<BigInt(y.a)?-1:1).slice(0,2).map(x=>x.sig));
  };
  const extra=Array.from({length:3},()=>Wallet.createRandom().address).sort((a,b)=>BigInt(a)<BigInt(b)?-1:1);
  for(const [list,quorum,deadline] of [[extra.slice(0,2),2,now+3600],[[...extra].reverse(),2,now+3600],[extra,1,now+3600],
    [[extra[0],extra[0],extra[1]],2,now+3600],[extra,2,now-1],[extra,2,now+31*86400],[[policy.enrollment,...extra].sort((a,b)=>BigInt(a)<BigInt(b)?-1:1),3,now+3600]])
    await reverts(registrar.changeReviewers(list,quorum,deadline,await sign(list,quorum,deadline)));
  await (await registrar.changeReviewers(extra,2,now+3600,await sign(extra,2,now+3600))).wait();
  assert.equal(await registrar.registryReviewers(0),extra[0]);assert.equal(await registrar.isRegistryReviewer(reviewers[0].address),false);
});
test('policy rejects role/key reuse, inadequate quorums, malformed schedules and repeated records',()=>{
  for(const change of [{chainId:'01'},{round:0},{endsAt:policy.startsAt+10},{extra:true}])assert.throws(()=>normalizeCeremonyPolicy({...policy,...change}));
  const p=structuredClone(policy);p.venues[0].witnesses[0]=reviewers[0].address;assert.throws(()=>normalizeCeremonyPolicy(p));
  p.venues[0].witnesses[0]=policy.venues[1].witnesses[0];assert.throws(()=>normalizeCeremonyPolicy(p));
  assert.throws(()=>normalizeCeremonyPolicy({...policy,registryQuorum:1}));
  for(const members of [[],[member(1),member(1)],[{...member(1),commitment:'01'}],[{...member(1),personTag:'0x'+'00'.repeat(32)}]])assert.throws(()=>prepareVenueRoster(policy,policy.venues[0].id,members));
  assert.deepEqual(ceremonyConfiguration({...policy,venues:[...policy.venues].reverse()}),ceremonyConfiguration(policy));
});
test('offline CLI creates review messages and unsigned calls, refuses overwrites and emits no private roster',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-ceremony-cli-'));
  try{
    const now=Math.floor(Date.now()/1000),p={...policy,startsAt:now-7200,endsAt:now-3600,submissionsCloseAt:now+86400};
    const config=path.join(dir,'config.json'),out=path.join(dir,'request.json'),venueId=p.venues[0].id,members=[member(300)];
    const run=()=>spawnSync(process.execPath,['scripts/check-person-verification.mjs','--config',config,'--out',out],{encoding:'utf8',windowsHide:true});
    fs.writeFileSync(config,JSON.stringify({kind:'roster',policy:p,venueId,members}));let result=run();assert.equal(result.status,0,result.stderr);
    const request=JSON.parse(fs.readFileSync(out));assert.equal(request.humanUniquenessEstablished,false);assert.equal(result.stdout.includes(members[0].commitment),false);
    const original=fs.readFileSync(out);assert.equal(run().status,1);assert.deepEqual(fs.readFileSync(out),original);fs.unlinkSync(out);
    fs.writeFileSync(config,JSON.stringify({kind:'roster',policy:p,venueId,members,witnessSignatures:await signatures(request.witnessRequest,witnesses.slice(0,2)),registrySignatures:await signatures(request.registryRequest,reviewers.slice(0,2))}));
    result=run();assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(fs.readFileSync(out)).transaction.to,p.registrar);
  }finally{
    const target=fs.realpathSync(dir);if(path.dirname(target)!==fs.realpathSync(os.tmpdir())||!path.basename(target).startsWith('cannabis-ceremony-cli-'))throw Error('Unexpected cleanup target');
    fs.rmSync(target,{recursive:true});
  }
});
