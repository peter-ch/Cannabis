import test from 'node:test';
import assert from 'node:assert/strict';
import { planSettlementJob } from '../scripts/compute-escrow.mjs';
import { policy } from '../scripts/compute-plan.mjs';
import { compile } from '../scripts/compile.mjs';
import escrowABI from '../compute/escrow-abi.json' with { type: 'json' };
const job=()=>({schema:'cannabis.compute.order.v2',id:'arbitrary-opaque-job',requester:'0x1000000000000000000000000000000000000001',
  packageSHA256:'a'.repeat(64),policySHA256:'b'.repeat(64),acceptanceSHA256:'c'.repeat(64),
  payment:{totalBudget:'100',feeBasisPoints:100,founderRecipient:policy.founderRecipient}});
test('runtime escrow ABI matches the current compiled contract',()=>{
  assert.deepEqual(escrowABI,compile().ComputeEscrow.abi);
});
test('arbitrary workload settlement binds private package, policy, terms, requester and budget',()=>{
  const input=job(),planned=planSettlementJob(input);assert.equal(planned.payment.founderFeeCannabis,'1.0');assert.equal(planned.fundsMoved,false);
  for(const change of [{packageSHA256:'d'.repeat(64)},{policySHA256:'d'.repeat(64)},{acceptanceSHA256:'d'.repeat(64)},{id:'new-order'},{requester:'0x2000000000000000000000000000000000000002'},{payment:{...input.payment,totalBudget:'101'}}])assert.notEqual(planSettlementJob({...input,...change}).jobHash,planned.jobHash);
});
test('universal settlement rejects plaintext additions, absent commitments and fee substitution',()=>{
  const input=job();
  for(const change of [{launch:{command:'private'}},{packageSHA256:'0'.repeat(64)},{policySHA256:''},{payment:{...input.payment,feeBasisPoints:0}}])assert.throws(()=>planSettlementJob({...input,...change}));
});
