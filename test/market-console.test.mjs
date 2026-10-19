import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {marketConsoleFixture,waitRequest,nonce,founder} from './helpers/market_console_fixture.mjs';
import {MarketWallet,validateMarketReview} from '../operator/market-wallet.js';
import {reviewMarketAction} from '../operator/market-chain.mjs';
import {sha} from '../operator/market-plan.mjs';
let f;
before(async()=>{f=await marketConsoleFixture();});
after(async()=>{await f?.close();});
const select=(method,actor,bookingId=null)=>({method,actor,bookingId});
async function walletFor(signer) {
  const injected=new EventEmitter(),calls=[];injected.request=async({method,params})=>{
    calls.push(method);if(['eth_accounts','eth_requestAccounts'].includes(method))return [signer.address];
    if(method==='eth_signTypedData_v4'){const typed=JSON.parse(params[1]);return signer.signTypedData(typed.domain,{Booking:typed.types.Booking},typed.message);}
    return f.provider.send(method,params??[]);
  };
  const wallet=new MarketWallet();wallet.select(injected);await wallet.connect();return {wallet,injected,calls};
}
async function send(console,plan,method,signer,{observe=true}={}) {
  const review=(await waitRequest(console,console.begin(plan.id,select(method,signer.address)),'awaiting-wallet')).result;
  validateMarketReview(review);
  const handoff=(await waitRequest(console,console.handoff(review.id),'handed-off')).result;
  const {wallet}=await walletFor(signer);let outcome;
  try{outcome=await wallet.send(review,handoff);}finally{wallet.clear();}
  console.reportHash(handoff.id,outcome.transactionHash);
  const observation=observe?(await waitRequest(console,console.observe(handoff.id),'completed')).result:null;
  return {review,handoff,transactionHash:outcome.transactionHash,observation};
}
async function prepare(asset) {
  f.options.finalized=null;
  const resource=f.resource(),r=f.seller.importPlan(resource);await send(f.seller,r,'publishResource',f.worker);
  const offer=f.offer(resource,asset),o=f.seller.importPlan(offer);await send(f.seller,o,'publishOffer',f.worker);
  const order=f.order(offer,asset),buyer=f.buyer.importPlan(order),seller=f.seller.importPlan(order);
  const bookingId=buyer.detail.bookings[0].bookingId;
  const review=(await waitRequest(f.seller,f.seller.begin(seller.id,select('signBooking',f.worker.address,bookingId)),'awaiting-wallet')).result;
  const {wallet}=await walletFor(f.worker);const signature=await wallet.sign(review);wallet.clear();
  await waitRequest(f.seller,f.seller.submitSignature(review.id,signature),'signature-retained');
  const shared=f.seller.exportPlan(seller.id);assert.equal(shared.signatures.length,1);
  await waitRequest(f.buyer,f.buyer.importSignature(buyer.id,bookingId,f.worker.address,signature),'signature-retained');
  return {buyer,seller,offer};
}
for(const asset of ['ETH','Cannabis'])test(`${asset}: independent consoles publish, sign, reserve, fund, accept, activate and recover actual settlement`,async()=>{
  const {buyer,seller}=await prepare(asset);
  f.options.finalized=(await f.provider.getBlock('latest')).number;
  const reserved=await send(f.buyer,buyer,'reserveBatch',f.requester);assert.equal(reserved.observation.state,'included-unfinalized');
  if(asset==='Cannabis') {
    await send(f.buyer,buyer,'approveToken',f.requester);
    assert.equal(await f.token.allowance(f.requester.address,f.configuration.cannabisEscrow),10000n);
  }
  // No per-step finality wait: each prior exact included receipt is rechecked.
  await send(f.buyer,buyer,'fund',f.requester);await send(f.seller,seller,'accept',f.worker);
  await send(f.buyer,buyer,'activate',f.requester);
  const observed=(await waitRequest(f.buyer,f.buyer.inspect(buyer.id),'completed')).result;
  assert.equal(observed.order.state,'not-funded');assert.equal(observed.headState.order.state,'active');
  assert.equal(observed.headState.bookings[0].activated,true);assert.equal(observed.executionAuthorized,false);
  const escrow=asset==='ETH'?f.native:f.cannabis;
  await (await escrow.connect(f.worker).deliver(buyer.detail.orderId,nonce())).wait();
  await (await escrow.connect(f.requester).approve(buyer.detail.orderId)).wait();
  assert.equal(await escrow.credits(founder),100n);assert.equal(await escrow.workerDue(buyer.detail.orderId,f.worker.address),9900n);
  // Withdrawal needs final settlement, independently of fast funding steps.
  assert.equal((await waitRequest(f.seller,f.seller.begin(seller.id,select('withdrawWorker',f.worker.address)))).state,'failed');
  f.options.finalized=null;
  const withdrawal=await send(f.seller,seller,'withdrawWorker',f.worker);assert.equal(withdrawal.observation.state,'confirmed');
  assert.equal(await escrow.workerDue(buyer.detail.orderId,f.worker.address),0n);
  await f.seller.close();f.seller=f.makeConsole('provider',f.configuration,false);
  assert.equal(f.seller.plan(seller.id).id,seller.id);assert.ok(f.seller.snapshot().actions.some(a=>a.id===withdrawal.handoff.id&&a.state==='confirmed'));
});

test('cancelled funding becomes a finalized withdrawable credit and offers can be withdrawn',async()=>{
  const {buyer,seller,offer}=await prepare('ETH');
  await send(f.buyer,buyer,'reserveBatch',f.requester);await send(f.buyer,buyer,'fund',f.requester);
  await send(f.buyer,buyer,'cancel',f.requester);assert.equal(await f.native.credits(f.requester.address),10000n);
  await send(f.buyer,buyer,'withdrawCredit',f.requester);assert.equal(await f.native.credits(f.requester.address),0n);
  const o=f.seller.importPlan(offer);await send(f.seller,o,'withdrawOffer',f.worker);
  assert.equal((await waitRequest(f.seller,f.seller.inspect(o.id),'completed')).result.offer.withdrawn,true);
});

test('unknown handoff survives reopen, blocks duplicate submission and rejects foreign receipts',async()=>{
  f.options.finalized=null;const resource=f.resource(),plan=f.seller.importPlan(resource);
  const review=(await waitRequest(f.seller,f.seller.begin(plan.id,select('publishResource',f.worker.address)),'awaiting-wallet')).result;
  const handoff=(await waitRequest(f.seller,f.seller.handoff(review.id),'handed-off')).result;
  await f.seller.close();f.seller=f.makeConsole('provider',f.configuration,false);
  assert.throws(()=>f.seller.begin(plan.id,select('publishResource',f.worker.address)));
  assert.equal(f.seller.snapshot().actions.find(a=>a.id===handoff.id).state,'submission-uncertain');
  const {wallet}=await walletFor(f.worker),sent=await wallet.send(review,handoff);wallet.clear();
  f.seller.reportHash(handoff.id,sent.transactionHash);
  f.options.transform=(m,r)=>m.method==='eth_getTransactionByHash'?{...r,result:{...r.result,to:f.configuration.token}}:r;
  assert.equal((await waitRequest(f.seller,f.seller.observe(handoff.id))).state,'failed');f.options.transform=null;
  assert.throws(()=>f.seller.begin(plan.id,select('publishResource',f.worker.address)));
  await waitRequest(f.seller,f.seller.observe(handoff.id),'completed');
  const next=f.seller.importPlan(f.resource());const request=await waitRequest(f.seller,f.seller.begin(next.id,select('publishResource',f.worker.address)),'awaiting-wallet');
  f.seller.cancel(request.id);assert.throws(()=>f.seller.handoff(request.id));
});

test('reorganization and nonce floors stop unsafe continuation of an unfinalized handoff',async()=>{
  f.options.finalized=null;const snap=await f.provider.send('evm_snapshot',[]);
  f.options.finalized=(await f.provider.getBlock('latest')).number;
  const p=f.seller.importPlan(f.resource()),sent=await send(f.seller,p,'publishResource',f.worker);
  assert.equal(sent.observation.state,'included-unfinalized');
  await f.provider.send('evm_revert',[snap]);
  const next=f.seller.importPlan(f.resource());
  assert.equal((await waitRequest(f.seller,f.seller.begin(next.id,select('publishResource',f.worker.address)))).state,'failed');
  assert.equal(f.seller.snapshot().actions.find(a=>a.id===sent.handoff.id).state,'not-observed');
  await assert.rejects(reviewMarketAction(f.configuration,next,select('publishResource',f.worker.address),{},undefined,
    {minimumNonce:BigInt(sent.review.action.transaction.nonce)+1n}));
  // Recovery sends exactly the previously handed transaction in this fixture;
  // the product never automatically retries or signs it.
  const txHash=await f.provider.send('eth_sendTransaction',[sent.review.action.transaction]);
  assert.equal(txHash,sent.transactionHash);f.options.finalized=null;
  await waitRequest(f.seller,f.seller.observe(sent.handoff.id),'completed');
});

test('runtime, fee, nonce and wallet binding failures never become another transaction',async()=>{
  const p=f.seller.importPlan(f.resource()),chosen=select('publishResource',f.worker.address);
  const review=(await waitRequest(f.seller,f.seller.begin(p.id,chosen),'awaiting-wallet')).result;
  const {wallet,injected,calls}=await walletFor(f.worker);
  for(const change of [r=>r.action.transaction.to=f.configuration.token,r=>r.action.transaction.value='0x1',r=>r.action.transaction.data='0xdeadbeef',
    r=>r.action.transaction.gas='0xfffffff',r=>r.expiresAt=Date.now()-1]) {
    const altered=structuredClone(review);change(altered);altered.actionDigest=sha(altered.action);assert.throws(()=>validateMarketReview(altered));
  }
  const handoff=(await waitRequest(f.seller,f.seller.handoff(review.id),'handed-off')).result;
  const original=injected.request;
  injected.request=async input=>input.method==='eth_chainId'?'0x1':original(input);
  await assert.rejects(wallet.send(review,handoff));assert.ok(!calls.includes('eth_sendTransaction'));
  injected.request=async input=>{if(input.method==='eth_sendTransaction')throw Object.assign(Error('Rejected'),{code:4001});return original(input);};
  assert.deepEqual(await wallet.send(review,handoff),{walletRefused:true});f.seller.walletRefused(handoff.id);wallet.clear();
  for(const change of [c=>c.marketCodeHash=nonce(),c=>c.feeLimits.maxTotalWei='1']) {
    const changed=structuredClone(f.configuration);change(changed);
    await assert.rejects(reviewMarketAction(changed,p,chosen,{},undefined));
  }
  f.options.transform=(m,r)=>m.method==='eth_getTransactionCount'&&m.params[1]==='pending'?{...r,result:'0xffff'}:r;
  await assert.rejects(reviewMarketAction(f.configuration,p,chosen,{},undefined));f.options.transform=null;
});

test('lost wallet response after actual submission stays uncertain and remains recoverable',async()=>{
  const p=f.seller.importPlan(f.resource()),review=(await waitRequest(f.seller,f.seller.begin(p.id,select('publishResource',f.worker.address)),'awaiting-wallet')).result;
  const handoff=(await waitRequest(f.seller,f.seller.handoff(review.id),'handed-off')).result;
  const {wallet,injected}=await walletFor(f.worker),original=injected.request,controller=new AbortController();let actualHash;
  injected.request=async input=>{
    if(input.method!=='eth_sendTransaction')return original(input);
    actualHash=await original(input);controller.abort();return new Promise(()=>{});
  };
  await assert.rejects(wallet.send(review,handoff,controller.signal),/uncertain/);wallet.clear();
  assert.equal(f.seller.snapshot().actions.find(a=>a.id===handoff.id).state,'submission-uncertain');
  assert.throws(()=>f.seller.begin(p.id,select('publishResource',f.worker.address)));
  f.seller.reportHash(handoff.id,nonce());await waitRequest(f.seller,f.seller.observe(handoff.id),'completed');
  assert.equal(f.seller.action(handoff.id).state,'not-observed');
  f.seller.reportHash(handoff.id,actualHash);assert.equal(f.seller.action(handoff.id).previousReportedHashes.length,1);
  assert.equal((await waitRequest(f.seller,f.seller.observe(handoff.id),'completed')).result.state,'confirmed');
});

test('HTTP market controls retain exact plans, forbid cross-origin/arbitrary calls and expose honest status',async()=>{
  const origin=await f.httpConsole(f.buyer),control=await(await fetch(origin+'/api/control')).json();assert.equal(control.market,true);
  const post=(route,body,headers={})=>fetch(origin+'/api/market/'+route,{method:'POST',headers:{origin,'content-type':'application/json',
    'x-cannabis-console':control.actionToken,...headers},body:JSON.stringify(body)});
  assert.equal((await post('network',{}, {origin:'https://foreign.invalid'})).status,403);
  assert.equal((await post('network',{rpc:f.node.rpc})).status,400);
  assert.equal((await post('import',{plan:{...f.resource(),command:'send'}})).status,409);
  const p=await(await post('import',{plan:f.resource()})).json();assert.equal(p.plan.kind,'resource');
  const status=await(await fetch(origin+'/api/status')).json();assert.equal(status.worker.admitted,false);
  assert.equal(status.worker.earningsThisSession,'0');assert.equal(status.market.keyReleaseAuthorized,false);
  assert.ok(!JSON.stringify(status).includes(f.directory));
});
