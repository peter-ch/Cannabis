import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { ContractFactory, parseEther, ZeroAddress, ZeroHash, keccak256, toUtf8Bytes } from 'ethers';
import { compile } from '../scripts/compile.mjs';
import { startNode } from '../scripts/lib.mjs';
import { prepareFunding, inspectOrder, prepareAcceptance } from '../scripts/compute-escrow.mjs';
import { policy } from '../scripts/compute-plan.mjs';

let node, provider, artifacts, asset, escrow, owner, founder, first, second, adjudicator, outsider, initial;
const hash = value => keccak256(toUtf8Bytes(value));
const amount = parseEther('100');
async function freePort() { return new Promise(resolve => { const s=net.createServer(); s.listen(0,'127.0.0.1',()=>{ const port=s.address().port; s.close(()=>resolve(port)); }); }); }
async function at(time) { await provider.send('evm_setNextBlockTimestamp',[Number(time)]); await provider.send('evm_mine',[]); }
before(async () => {
  artifacts=compile({ 'EscrowFixtures.sol': { content: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract EscrowAsset is ERC20 {
 constructor() ERC20("Escrow verification fixture","FIX") { _mint(msg.sender, 1000000 ether); }
}
contract InexactAsset is ERC20 {
 constructor() ERC20("Inexact verification fixture","BAD") { _mint(msg.sender, 1000000 ether); }
 function _update(address from, address to, uint256 value) internal override {
  if (from != address(0) && to != address(0)) { super._update(from, address(0), 1); value -= 1; }
  super._update(from, to, value);
 }
}` } });
  node=await startNode(await freePort(),'escrow-test-node.log'); provider=node.provider;
  [owner,founder,first,second,adjudicator,outsider]=await Promise.all(Array.from({length:6},(_,i)=>provider.getSigner(i)));
  asset=await new ContractFactory(artifacts.EscrowAsset.abi,artifacts.EscrowAsset.bytecode,owner).deploy(); await asset.waitForDeployment();
  escrow=await new ContractFactory(artifacts.ComputeEscrow.abi,artifacts.ComputeEscrow.bytecode,owner).deploy(await asset.getAddress(),await founder.getAddress()); await escrow.waitForDeployment();
  await (await asset.approve(await escrow.getAddress(),parseEther('1000000'))).wait();
  initial=await provider.send('evm_snapshot',[]);
});
after(async()=>{provider?.destroy();node?.child.kill();});
async function reset(){ await provider.send('evm_revert',[initial]);initial=await provider.send('evm_snapshot',[]);}
async function create({budget=amount, shares=[6000,4000], name='job', extra={}}={}) {
  const now=(await provider.getBlock('latest')).timestamp;
  const terms={jobHash:hash(name),budget,deliveryManager:await first.getAddress(),adjudicator:await adjudicator.getAddress(),
    acceptBy:now+300,deliverBy:now+900,reviewSeconds:86400,disputeSeconds:86400,...extra};
  const accounts=[await first.getAddress(),await second.getAddress()];
  const receipt=await (await escrow.fund(terms,accounts,shares)).wait();
  return {id:await escrow.orderId(await owner.getAddress(),terms.jobHash),terms,receipt};
}
async function activate(id){await (await escrow.connect(first).accept(id)).wait();await (await escrow.connect(second).accept(id)).wait();}
async function deliver(id){await (await escrow.connect(first).deliver(id,hash('encrypted-output'))).wait();}
async function withdrawAll(id) {
  for(const signer of [first,second])if(await escrow.workerDue(id,await signer.getAddress())>0n)
    await (await escrow.connect(signer).withdrawWorker(id,await signer.getAddress())).wait();
  for(const signer of [owner,founder])if(await escrow.credits(await signer.getAddress())>0n)
    await (await escrow.connect(signer).withdrawCredit(await signer.getAddress())).wait();
}
test('funded multi-worker job pays exactly 1% and preserves all token units',async t=>{
  await reset();const {id,receipt}=await create();
  assert.equal(await escrow.totalLiability(),amount);
  await assert.rejects(escrow.connect(first).deliver.staticCall(id,hash('output')),/InvalidState/);
  await (await escrow.connect(first).accept(id)).wait();
  assert.equal((await escrow.orders(id)).state,1n);
  await assert.rejects(escrow.connect(first).accept.staticCall(id),/AlreadyAccepted/);
  await (await escrow.connect(second).accept(id)).wait();
  assert.equal((await escrow.orders(id)).state,2n);
  await deliver(id);await (await escrow.approve(id)).wait();
  assert.equal(await escrow.credits(await founder.getAddress()),parseEther('1'));
  assert.equal(await escrow.workerDue(id,await first.getAddress()),parseEther('59.4'));
  assert.equal(await escrow.workerDue(id,await second.getAddress()),parseEther('39.6'));
  await withdrawAll(id);
  assert.equal(await escrow.totalLiability(),0n);assert.equal(await asset.balanceOf(await escrow.getAddress()),0n);
  assert.equal(await asset.balanceOf(await founder.getAddress()),parseEther('1'));
  await assert.rejects(escrow.connect(first).withdrawWorker.staticCall(id,await outsider.getAddress()),/NothingToWithdraw/);
  await assert.rejects(escrow.approve.staticCall(id),/InvalidState/);
  t.diagnostic('Funding two-worker order used '+receipt.gasUsed+' local EVM gas; not a network fee quote.');
});
test('unapproved actors cannot accept, deliver, approve, dispute, resolve or collect funds',async()=>{
  await reset();const {id}=await create();
  await assert.rejects(escrow.connect(outsider).accept.staticCall(id),/Unauthorized/);
  await assert.rejects(escrow.connect(first).cancel.staticCall(id),/Unauthorized/);
  await activate(id);
  await assert.rejects(escrow.cancel.staticCall(id),/InvalidState/);
  await assert.rejects(escrow.connect(second).deliver.staticCall(id,hash('output')),/Unauthorized/);
  await deliver(id);
  await assert.rejects(escrow.connect(first).approve.staticCall(id),/Unauthorized/);
  await assert.rejects(escrow.connect(outsider).dispute.staticCall(id,hash('reason')),/Unauthorized/);
  await (await escrow.dispute(id,hash('encrypted-reason'))).wait();
  await assert.rejects(escrow.resolve.staticCall(id,amount),/Unauthorized/);
  await assert.rejects(escrow.connect(adjudicator).resolve.staticCall(id,amount+1n),/InvalidTerms/);
  await assert.rejects(escrow.connect(outsider).withdrawCredit.staticCall(await outsider.getAddress()),/NothingToWithdraw/);
});
test('partial dispute award charges fee only on the paid portion and refunds the rest',async()=>{
  await reset();const {id}=await create();await activate(id);await deliver(id);
  await (await escrow.dispute(id,hash('encrypted-dispute'))).wait();
  await (await escrow.connect(adjudicator).resolve(id,parseEther('40'))).wait();
  assert.equal(await escrow.credits(await owner.getAddress()),parseEther('60'));
  assert.equal(await escrow.credits(await founder.getAddress()),parseEther('0.4'));
  assert.equal(await escrow.workerDue(id,await first.getAddress())+await escrow.workerDue(id,await second.getAddress()),parseEther('39.6'));
  await withdrawAll(id);assert.equal(await escrow.totalLiability(),0n);
});
test('requester cancellation before activation returns the whole budget with no fee',async()=>{
  await reset();const {id}=await create();await (await escrow.connect(first).accept(id)).wait();
  await (await escrow.cancel(id)).wait();
  assert.equal(await escrow.credits(await owner.getAddress()),amount);assert.equal(await escrow.credits(await founder.getAddress()),0n);
  await withdrawAll(id);assert.equal(await asset.balanceOf(await escrow.getAddress()),0n);
  await assert.rejects(escrow.connect(second).accept.staticCall(id),/InvalidState/);
});
test('acceptance and delivery expiry refund without fees, with exact boundary enforcement',async()=>{
  await reset();const firstJob=await create({name:'unaccepted'});
  await assert.rejects(escrow.finalizeExpired.staticCall(firstJob.id),/Deadline/);
  await at(firstJob.terms.acceptBy);
  await assert.rejects(escrow.connect(first).accept.staticCall(firstJob.id),/Deadline/);
  await (await escrow.connect(outsider).finalizeExpired(firstJob.id)).wait();
  const secondJob=await create({name:'undelivered'});await activate(secondJob.id);await at(secondJob.terms.deliverBy);
  await assert.rejects(escrow.connect(first).deliver.staticCall(secondJob.id,hash('late')),/Deadline/);
  await (await escrow.finalizeExpired(secondJob.id)).wait();
  assert.equal(await escrow.credits(await owner.getAddress()),2n*amount);assert.equal(await escrow.credits(await founder.getAddress()),0n);
});
test('no dispute by the agreed review deadline releases the delivered job payment',async()=>{
  await reset();const {id}=await create();await activate(id);await deliver(id);
  const {reviewBy}=await escrow.orders(id);
  await at(reviewBy-1n);await assert.rejects(escrow.finalizeExpired.staticCall(id),/Deadline/);
  await at(reviewBy);await assert.rejects(escrow.dispute.staticCall(id,hash('late')),/Deadline/);
  await (await escrow.connect(outsider).finalizeExpired(id)).wait();
  assert.equal((await escrow.orders(id)).grossPaid,amount);await withdrawAll(id);assert.equal(await escrow.totalLiability(),0n);
});
test('adjudicator inactivity cannot lock funds permanently or collect a founder fee',async()=>{
  await reset();const {id}=await create();await activate(id);await deliver(id);
  await (await escrow.dispute(id,hash('reason'))).wait();await at((await escrow.orders(id)).resolveBy);
  await assert.rejects(escrow.connect(adjudicator).resolve.staticCall(id,amount),/Deadline/);
  await (await escrow.finalizeExpired(id)).wait();
  assert.equal(await escrow.credits(await owner.getAddress()),amount);assert.equal(await escrow.credits(await founder.getAddress()),0n);
});
test('worker-share rounding conserves indivisible units and zero rewards cannot be collected',async()=>{
  await reset();const {id}=await create({budget:101n,shares:[3333,6667]});await activate(id);await deliver(id);await (await escrow.approve(id)).wait();
  assert.equal(await escrow.credits(await founder.getAddress()),1n);
  assert.equal(await escrow.workerDue(id,await first.getAddress()),33n);assert.equal(await escrow.workerDue(id,await second.getAddress()),67n);
  await withdrawAll(id);assert.equal(await escrow.totalLiability(),0n);
  const tiny=await create({budget:1n,name:'tiny',shares:[1,9999]});await activate(tiny.id);await deliver(tiny.id);await (await escrow.approve(tiny.id)).wait();
  assert.equal(await escrow.workerDue(tiny.id,await first.getAddress()),0n);await withdrawAll(tiny.id);assert.equal(await escrow.totalLiability(),0n);
});
test('duplicate jobs and malformed roles, schedules and worker shares are rejected',async()=>{
  await reset();const {terms,id}=await create();
  const accounts=[await first.getAddress(),await second.getAddress()];
  await assert.rejects(escrow.fund.staticCall(terms,accounts,[6000,4000]),/InvalidState/);
  await assert.rejects(escrow.connect(first).withdrawWorker.staticCall(id,ZeroAddress),/NothingToWithdraw/);
  for(const change of [{jobHash:ZeroHash},{budget:0n},{adjudicator:await owner.getAddress()},{adjudicator:await founder.getAddress()},
    {deliveryManager:await outsider.getAddress()},{acceptBy:0},{reviewSeconds:86399},{disputeSeconds:0}]){
    await assert.rejects(escrow.fund.staticCall({...terms,jobHash:hash('other'),...change},accounts,[6000,4000]),/InvalidTerms/);
  }
  for(const [addresses,shares]of [[accounts,[5000,4000]],[[accounts[0],accounts[0]],[5000,5000]],[accounts,[10000,0]],[[],[]]])
    await assert.rejects(escrow.fund.staticCall({...terms,jobHash:hash('other')},addresses,shares),/InvalidTerms/);
  await activate(id);await deliver(id);await (await escrow.approve(id)).wait();
  await assert.rejects(escrow.connect(first).withdrawWorker.staticCall(id,await escrow.getAddress()),/InvalidTerms/);
  assert.equal(await escrow.workerDue(id,await first.getAddress()),parseEther('59.4'));
});
test('inexact token deposits revert all funding state and liabilities',async()=>{
  await reset();
  const bad=await new ContractFactory(artifacts.InexactAsset.abi,artifacts.InexactAsset.bytecode,owner).deploy();await bad.waitForDeployment();
  const target=await new ContractFactory(artifacts.ComputeEscrow.abi,artifacts.ComputeEscrow.bytecode,owner).deploy(await bad.getAddress(),await founder.getAddress());await target.waitForDeployment();
  await (await bad.approve(await target.getAddress(),amount)).wait();
  const {terms}=await create();
  await assert.rejects(target.fund.staticCall(terms,[await first.getAddress(),await second.getAddress()],[6000,4000]),/InexactTokenTransfer/);
  await assert.rejects(async () => { await (await target.fund(terms,[await first.getAddress(),await second.getAddress()],[6000,4000],{gasLimit:1000000})).wait(); });
  assert.equal(await target.totalLiability(),0n);assert.equal(await bad.balanceOf(await target.getAddress()),0n);
  assert.equal((await target.orders(await target.orderId(await owner.getAddress(),terms.jobHash))).state,0n);
});

test('unsigned funding and worker acceptance verify code, fee, chain and complete settlement terms',async()=>{
  await reset();
  const target=await new ContractFactory(artifacts.ComputeEscrow.abi,artifacts.ComputeEscrow.bytecode,owner)
    .deploy(await asset.getAddress(),policy.founderRecipient);await target.waitForDeployment();
  const now=(await provider.getBlock('latest')).timestamp;
  const utc=seconds=>new Date(seconds*1000).toISOString().replace('.000Z','Z');
  const job={schema:'cannabis.compute.job.v1',id:'encrypted-order',requester:await owner.getAddress(),kind:'torch-distributed',
    runtime:'cpu',collectiveBackend:'gloo',execution:{image:'registry.example/protected@sha256:'+'a'.repeat(64)},
    confidentiality:{required:true,policySHA256:'b'.repeat(64),encryptedBundleSHA256:'c'.repeat(64),cipher:'AES-256-GCM',keyRelease:'attested-only'},
    resources:{nodes:2,processesPerNode:1,cpusPerNode:2,memoryMiBPerNode:1024,scratchMiBPerNode:512,acceleratorsPerNode:0,acceleratorMemoryMiB:0,wallSeconds:600},
    payment:{totalBudget:'100',feeBasisPoints:100,founderRecipient:policy.founderRecipient},acceptance:{encryptedTermsSHA256:'d'.repeat(64)}};
  const options={rpc:node.rpc,chainId:31337,escrow:await target.getAddress(),token:await asset.getAddress(),
    escrowCodeHash:keccak256(await provider.getCode(await target.getAddress())),tokenCodeHash:keccak256(await provider.getCode(await asset.getAddress())),
    job:{schema:'cannabis.compute.order.v2',id:job.id,requester:job.requester,packageSHA256:'c'.repeat(64),policySHA256:'b'.repeat(64),acceptanceSHA256:'d'.repeat(64),payment:job.payment},settlement:{workers:[{account:await first.getAddress(),shareBps:6000},{account:await second.getAddress(),shareBps:4000}],
      deliveryManager:await first.getAddress(),adjudicator:await adjudicator.getAddress(),acceptBy:utc(now+300),deliverBy:utc(now+900),reviewSeconds:86400,disputeSeconds:86400}};
  const package_=await prepareFunding(options);
  assert.equal(package_.sent,false);assert.equal(package_.fundingSimulated,false);
  assert.equal(package_.transactions.length,2);assert.equal(await asset.balanceOf(await target.getAddress()),0n);
  assert.equal(await asset.allowance(await owner.getAddress(),await target.getAddress()),0n);
  for(const step of package_.transactions)await(await owner.sendTransaction(step.transaction)).wait();
  const inspected=await inspectOrder({...options,orderId:package_.orderId});
  assert.equal(inspected.termsDigest,package_.termsDigest);assert.equal(inspected.state,1);
  const acceptOptions={...options,orderId:package_.orderId,worker:await first.getAddress(),expectedTermsDigest:package_.termsDigest};
  const prepared=await prepareAcceptance(acceptOptions);
  assert.equal(prepared.sent,false);assert.equal((await target.orders(package_.orderId)).acceptedCount,0n);
  await(await first.sendTransaction(prepared.transaction)).wait();
  assert.equal((await target.orders(package_.orderId)).acceptedCount,1n);
  await assert.rejects(prepareAcceptance({...acceptOptions,expectedTermsDigest:hash('tampered-terms')}),/terms changed/);
  await assert.rejects(inspectOrder({...options,orderId:package_.orderId,chainId:8453}),/chain does not match/);
  await assert.rejects(inspectOrder({...options,orderId:package_.orderId,tokenCodeHash:ZeroHash}),/Runtime code/);
  await assert.rejects(prepareFunding({...options,escrow:await escrow.getAddress(),escrowCodeHash:keccak256(await provider.getCode(await escrow.getAddress()))}),/fee policy/);
  await assert.rejects(prepareFunding({...options,job:{...job,id:'new-job',payment:{...job.payment,totalBudget:'1000000000000'}}}),/balance is below/);
});
