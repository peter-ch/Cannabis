import {test,beforeEach,afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {marketConsoleFixture,waitRequest,nonce,founder} from './helpers/market_console_fixture.mjs';
import {MarketWallet} from '../operator/market-wallet.js';
import {approvedBrowserFixture} from './fixtures/approved-browser.mjs';
import {openVerifiedResultSet} from '../web/work-approvals.js';
import {prepareResultCommitment} from '../scripts/compute-result-commitment.mjs';
import {resultCommitment,inspectResultCommitment} from '../compute/result_commitment.mjs';
let f;
// Each scenario owns its chain. Sharing a rapidly mined chain across cases can
// advance its timestamp beyond the client's legitimate future-clock tolerance.
beforeEach(async()=>{f=await marketConsoleFixture();});
afterEach(async()=>{await f?.close();});
const selection=(method,actor,decision)=>({method,actor,bookingId:null,...(decision?{decision}:{})});
async function walletFor(signer){const provider=new EventEmitter(),calls=[];provider.request=async({method,params})=>{
  calls.push(method);if(['eth_accounts','eth_requestAccounts'].includes(method))return [signer.address];
  return f.provider.send(method,params??[]);
};const wallet=new MarketWallet();wallet.select(provider);await wallet.connect();return {wallet,calls};}
async function send(client,plan,method,signer,decision,dispatch=null){
  const review=(await waitRequest(client,client.begin(plan.id,selection(method,signer.address,decision)),'awaiting-wallet')).result;
  const handoff=(await waitRequest(client,client.handoff(review.id),'handed-off')).result,{wallet,calls}=await walletFor(signer);
  try{const result=await wallet.send(review,handoff,undefined,dispatch);
    if(result.walletNotRequested){await client.walletNotRequested(handoff.id);return {review,handoff,result,calls};}
    assert.ok(result.transactionHash);await client.reportHash(handoff.id,result.transactionHash);
    const observed=(await waitRequest(client,client.observe(handoff.id),'completed')).result;assert.equal(observed.state,'confirmed');
    return {review,handoff,result,observed,calls};
  }finally{wallet.clear();}
}
async function booked(asset,{accept=true,activate=true}={}){
  const resource=f.seller.importPlan(f.resource());await send(f.seller,resource,'publishResource',f.worker);
  const offer=f.seller.importPlan(f.offer(resource.plan,asset));await send(f.seller,offer,'publishOffer',f.worker);
  const raw=f.order(offer.plan,asset),buyer=f.buyer.importPlan(raw),seller=f.seller.importPlan(raw);
  for(const b of buyer.detail.bookings){const signature=await f.worker.signTypedData(b.domain,b.types,b.value);
    await waitRequest(f.buyer,f.buyer.importSignature(buyer.id,b.bookingId,f.worker.address,signature),'signature-retained');}
  await send(f.buyer,buyer,'reserveBatch',f.requester);
  if(asset==='Cannabis')await send(f.buyer,buyer,'approveToken',f.requester);
  await send(f.buyer,buyer,'fund',f.requester);
  if(accept)await send(f.seller,seller,'accept',f.worker);
  if(activate)await send(f.buyer,buyer,'activate',f.requester);
  const escrow=asset==='ETH'?f.native:f.cannabis;
  assert.equal(await escrow.termsCommitments(buyer.detail.orderId),buyer.detail.termsDigest);
  return {buyer,seller,escrow};
}
async function authenticated(plan){const p=plan.plan,d=plan.detail;
  const fixture=await approvedBrowserFixture({version:'3',owner:f.requester,escrow:d.asset.escrow,orderId:d.orderId,jobId:p.job.id,
    packageSHA256:p.job.packageSHA256,policySHA256:p.job.policySHA256});
  const verified=await openVerifiedResultSet(fixture);assert.equal(new TextDecoder().decode(verified.files.get('finished/answer.txt')),'owned verification result\n');
  for(const bytes of verified.files.values())bytes.fill(0);
  return {fixture,commitment:prepareResultCommitment({configuration:f.configuration,plan:p,archives:verified.archives})};
}
for(const asset of ['ETH','Cannabis'])test(`${asset}: authenticated encrypted result, guarded delivery, approval and exact credits`,async()=>{
  const {buyer,seller,escrow}=await booked(asset),{commitment}=await authenticated(buyer),id=buyer.detail.orderId;
  assert.deepEqual(inspectResultCommitment(commitment),commitment);
  const beforeFee=await escrow.credits(founder);
  const delivered=await send(f.seller,seller,'deliver',f.worker,{outputDigest:commitment.outputDigest});
  assert.equal(delivered.review.action.summary.outcome.grossPaidBaseUnits,null);
  await assert.rejects(escrow.connect(f.requester).approveResult.staticCall(id,nonce(),commitment.outputDigest));
  await assert.rejects(escrow.connect(f.requester).approveResult.staticCall(id,buyer.detail.termsDigest,nonce()));
  const approved=await send(f.buyer,buyer,'approve',f.requester,{outputDigest:commitment.outputDigest,acceptanceSHA256:buyer.plan.job.acceptanceSHA256});
  assert.deepEqual(approved.review.action.summary.outcome,{phase:'delivered',grossPaidBaseUnits:'10000',serviceFeeBaseUnits:'100',workerBaseUnits:'9900',requesterRefundBaseUnits:'0'});
  assert.equal((await escrow.orders(id)).state,5n);assert.equal(await escrow.credits(founder)-beforeFee,100n);
  assert.equal(await escrow.workerDue(id,f.worker.address),9900n);await send(f.seller,seller,'withdrawWorker',f.worker);
  assert.equal(await escrow.workerDue(id,f.worker.address),0n);
  const malformed=structuredClone(commitment);malformed.context.orderId=nonce();assert.throws(()=>inspectResultCommitment(malformed));
  assert.throws(()=>resultCommitment(commitment.context,[...commitment.entries,...commitment.entries]));
});
test('explicit dispute and partial adjudication bind roles, original commitments and exact fee quantum',async()=>{
  const {buyer,seller,escrow}=await booked('ETH'),id=buyer.detail.orderId,output=nonce(),reason=nonce();
  await send(f.seller,seller,'deliver',f.worker,{outputDigest:output});
  assert.throws(()=>f.seller.begin(seller.id,selection('approve',f.worker.address,{outputDigest:output,acceptanceSHA256:buyer.plan.job.acceptanceSHA256})));
  await send(f.buyer,buyer,'dispute',f.requester,{outputDigest:output,reasonDigest:reason});
  const judge=f.makeConsole('post-delivery-judge'),plan=judge.importPlan(buyer.plan);
  assert.throws(()=>judge.begin(plan.id,selection('resolve',f.judge.address,{outputDigest:output,reasonDigest:reason,grossPaidBaseUnits:'5501'})));
  await assert.rejects(escrow.connect(f.judge).resolveDispute.staticCall(id,buyer.detail.termsDigest,output,nonce(),5500));
  const fee=await escrow.credits(founder),refund=await escrow.credits(f.requester.address);
  const resolved=await send(judge,plan,'resolve',f.judge,{outputDigest:output,reasonDigest:reason,grossPaidBaseUnits:'5500'});
  assert.equal(resolved.review.action.summary.outcome.serviceFeeBaseUnits,'55');assert.equal(resolved.review.action.summary.outcome.requesterRefundBaseUnits,'4500');
  assert.equal(await escrow.credits(founder)-fee,55n);assert.equal(await escrow.credits(f.requester.address)-refund,4500n);
  assert.equal(await escrow.workerDue(id,f.worker.address),5445n);await send(f.buyer,buyer,'withdrawCredit',f.requester);
});
test('changed result selection before wallet dispatch is recorded without pretending a submission or blocking all future review',async()=>{
  const {buyer,seller,escrow}=await booked('ETH'),output=nonce();await send(f.seller,seller,'deliver',f.worker,{outputDigest:output});
  const decision={outputDigest:output,acceptanceSHA256:buyer.plan.job.acceptanceSHA256};
  const halted=await send(f.buyer,buyer,'approve',f.requester,decision,()=>{throw Error('Selected attempt retired before request');});
  assert.deepEqual(halted.result,{walletNotRequested:true});assert.ok(!halted.calls.includes('eth_sendTransaction'));
  assert.equal(f.buyer.action(halted.handoff.id).state,'wallet-not-requested');assert.equal((await escrow.orders(buyer.detail.orderId)).state,3n);
  await f.buyer.close();f.buyer=f.makeConsole('requester',f.configuration,false);
  assert.equal(f.buyer.action(halted.handoff.id).state,'wallet-not-requested');
  await send(f.buyer,buyer,'approve',f.requester,decision);
});
test('phase and term binding prevents a delayed refund action from paying delivered work; all four expiry outcomes stay exact',async()=>{
  const scenarios=[];
  for(const expectedState of [1,2,3,4]){
    const order=await booked('ETH',{accept:expectedState!==1,activate:expectedState!==1}),output=nonce(),reason=nonce();
    if(expectedState>=3)await send(f.seller,order.seller,'deliver',f.worker,{outputDigest:output});
    if(expectedState===4)await send(f.buyer,order.buyer,'dispute',f.requester,{outputDigest:output,reasonDigest:reason});
    scenarios.push({...order,expectedState});
  }
  const deadlines=[];for(const s of scenarios){const o=await s.escrow.orders(s.buyer.detail.orderId);deadlines.push(Number([0,o.terms.acceptBy,o.terms.deliverBy,o.reviewBy,o.resolveBy][s.expectedState]));}
  await f.provider.send('evm_setNextBlockTimestamp',[Math.max(...deadlines)+1]);await f.provider.send('evm_mine',[]);
  const delivered=scenarios.find(s=>s.expectedState===3),id=delivered.buyer.detail.orderId;
  await assert.rejects(delivered.escrow.finalizeExpiredState.staticCall(id,delivered.buyer.detail.termsDigest,1));
  for(const s of scenarios){const d=s.buyer.detail,fee=await s.escrow.credits(founder),refund=await s.escrow.credits(f.requester.address);
    await assert.rejects(s.escrow.finalizeExpiredState.staticCall(d.orderId,nonce(),s.expectedState));
    await(await s.escrow.finalizeExpiredState(d.orderId,d.termsDigest,s.expectedState)).wait();
    const paid=s.expectedState===3?10000n:0n;assert.equal((await s.escrow.orders(d.orderId)).grossPaid,paid);
    assert.equal(await s.escrow.credits(founder)-fee,paid/100n);assert.equal(await s.escrow.credits(f.requester.address)-refund,10000n-paid);
  }
});
