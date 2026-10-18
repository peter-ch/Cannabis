// Fixed local integration checks. Never accepts a public endpoint, wallet or arbitrary workload.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { ContractFactory, keccak256, toUtf8Bytes } from 'ethers';
import { compile, root } from './compile.mjs';
import { startNode, runtime } from './lib.mjs';

export async function exerciseMicrojobs() {
  const port=await new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
  const runId=new Date().toISOString().replace(/[:.]/g,'-');
  let node;
  try {
    const artifacts=compile({'MicrojobFixture.sol':{content:`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract MicrojobFixture is ERC20 {
 constructor() ERC20("Local payment verification fixture", "FIX") { _mint(msg.sender, 1000000); }
 function decimals() public pure override returns(uint8) { return 6; }
}`}});
    node=await startNode(port,'microjobs-'+runId+'.log');const provider=node.provider;
    assert.equal((await provider.getNetwork()).chainId,31337n);
    const [requester,founder,first,second,resolver]=await Promise.all([0,1,2,3,4].map(i=>provider.getSigner(i)));
    const addresses=await Promise.all([requester,founder,first,second,resolver].map(s=>s.getAddress()));
    const asset=await new ContractFactory(artifacts.MicrojobFixture.abi,artifacts.MicrojobFixture.bytecode,requester).deploy();await asset.waitForDeployment();
    const escrow=await new ContractFactory(artifacts.ComputeEscrow.abi,artifacts.ComputeEscrow.bytecode,requester).deploy(await asset.getAddress(),addresses[1]);await escrow.waitForDeployment();
    const budget=11300n;const gas=[];
    async function sent(label,transaction){const receipt=await (await transaction).wait();gas.push({label,gasUsed:receipt.gasUsed.toString()});return receipt;}
    await sent('exact-allowance',asset.approve(await escrow.getAddress(),budget));
    const orders=[];
    async function fund(name,amount,workers=[addresses[2]],shares=[10000]) {
      const now=(await provider.getBlock('latest')).timestamp;
      const terms={jobHash:keccak256(toUtf8Bytes('owned-local-'+runId+'-'+name)),budget:amount,deliveryManager:addresses[2],adjudicator:addresses[4],
        acceptBy:now+300,deliverBy:now+900,reviewSeconds:86400,disputeSeconds:86400};
      await sent(name+'-fund',escrow.fund(terms,workers,shares));
      return await escrow.orderId(addresses[0],terms.jobHash);
    }
    for (const [kind,amount] of [['matrix',100n],['dag',1000n],['regression',10000n]]) {
      const group=kind==='dag';
      const id=await fund(kind,amount,group?[addresses[2],addresses[3]]:[addresses[2]],group?[5000,5000]:[10000]);
      await sent(kind+'-accept-first',escrow.connect(first).accept(id));
      if(group)await sent(kind+'-accept-second',escrow.connect(second).accept(id));
      const {stdout}=await promisify(execFile)(process.env.PYTHON??'python',[path.join(root,'scripts/exercise-microjob-workload.py'),kind],
        {cwd:root,windowsHide:true,timeout:120000,maxBuffer:1048576});
      const workload=JSON.parse(stdout);
      assert.equal(workload.requesterAcceptancePassed,true);assert.equal(workload.integrityVerified,true);
      assert.equal(workload.confidentialExecutionEstablished,false);
      await sent(kind+'-deliver',escrow.connect(first).deliver(id,workload.outputDigest));
      orders.push({id,grossBaseUnits:amount.toString(),founderFeeBaseUnits:(amount/100n).toString(),workload});
    }
    const ids=orders.map(x=>x.id);
    // Compare identical states and operations on this temporary chain only.
    let snapshot=await provider.send('evm_snapshot',[]);let individualApprovalGas=0n;
    for(const id of ids)individualApprovalGas+=(await (await escrow.approve(id)).wait()).gasUsed;
    await provider.send('evm_revert',[snapshot]);
    const approval=await sent('approve-three-results',escrow.approveBatch(ids));
    for (const order of orders) {
      const stored=await escrow.orders(order.id);
      assert.equal(stored.grossPaid,BigInt(order.grossBaseUnits));
      assert.equal(stored.workerPool,BigInt(order.grossBaseUnits)*99n/100n);
      assert.equal(stored.outputDigest,order.workload.outputDigest);
    }
    assert.equal(await escrow.credits(addresses[1]),111n);
    // Cancellation and a rejected delivery must not create founder income.
    const cancelled=await fund('cancelled',100n);await sent('cancel-before-start',escrow.cancel(cancelled));
    const rejected=await fund('rejected-result',100n);await sent('rejected-accept',escrow.connect(first).accept(rejected));
    await sent('rejected-deliver',escrow.connect(first).deliver(rejected,keccak256(toUtf8Bytes('owned deliberately incorrect result'))));
    await sent('dispute-rejected-result',escrow.dispute(rejected,keccak256(toUtf8Bytes('owned rejection evidence'))));
    await sent('refund-rejected-result',escrow.connect(resolver).resolve(rejected,0));
    assert.equal(await escrow.credits(addresses[0]),200n);assert.equal(await escrow.credits(addresses[1]),111n);
    snapshot=await provider.send('evm_snapshot',[]);let individualWithdrawalGas=0n;
    for(const id of ids)individualWithdrawalGas+=(await (await escrow.connect(first).withdrawWorker(id,addresses[2])).wait()).gasUsed;
    await provider.send('evm_revert',[snapshot]);
    const withdrawal=await sent('first-worker-three-orders',escrow.connect(first).withdrawWorkers(ids,addresses[2]));
    await sent('second-worker-order',escrow.connect(second).withdrawWorker(orders[1].id,addresses[3]));
    await sent('founder-accumulated-fees',escrow.connect(founder).withdrawCredit(addresses[1]));
    await sent('requester-refunds',escrow.withdrawCredit(addresses[0]));
    assert.equal(await asset.balanceOf(addresses[1]),111n);
    assert.equal(await asset.balanceOf(addresses[2]),10494n);assert.equal(await asset.balanceOf(addresses[3]),495n);
    assert.equal(await asset.balanceOf(addresses[0]),1000000n-11100n);
    assert.equal(await escrow.totalLiability(),0n);assert.equal(await asset.balanceOf(await escrow.getAddress()),0n);
    assert.equal(await asset.allowance(addresses[0],await escrow.getAddress()),0n);
    const report={schema:'cannabis.local-microjobs.v1',checkedAt:new Date().toISOString(),classification:'ISOLATED_SOFTWARE_VERIFICATION',
      chainId:31337,orders,cancellationRefundPassed:true,rejectedDeliveryRefundPassed:true,exactFeesPassed:true,
      founderTotalBaseUnits:'111',workerTotalBaseUnits:'10989',requesterRefundBaseUnits:'200',remainingLiabilityBaseUnits:'0',
      allowanceExhausted:true,fixtureAssetDecimals:6,fixtureAssetIsUSDC:false,publicOrders:0,realPaidJobs:0,realSpendEUR:'0',
      confidentialExecutionEstablished:false,gas,gasTotal:gas.reduce((sum,x)=>sum+BigInt(x.gasUsed),0n).toString(),
      batching:{individualApprovalGas:individualApprovalGas.toString(),batchApprovalGas:approval.gasUsed.toString(),
        individualWorkerWithdrawalGas:individualWithdrawalGas.toString(),batchWorkerWithdrawalGas:withdrawal.gasUsed.toString()},
      limitations:['Local computations use owned nonsensitive fixture inputs and ephemeral encryption keys.',
        'No hardware confidentiality, live provider admission, real payment, customer demand or market price is established.',
        'Gas measurements exclude deployment and are not live transaction fee quotes.']};
    const file=path.join(runtime,'microjobs-'+runId+'.json');
    fs.writeFileSync(file,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
    return {report,file};
  }finally{node?.provider.destroy();node?.child.kill();}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if(process.argv.length!==2)throw Error('This exercise accepts no endpoints, wallets or workload arguments');
  const {report,file}=await exerciseMicrojobs();
  console.log(JSON.stringify({report:file,verifiedWorkloads:report.orders.length,realPaidJobs:0,realSpendEUR:'0',exactFeesPassed:report.exactFeesPassed,batching:report.batching}));
}
