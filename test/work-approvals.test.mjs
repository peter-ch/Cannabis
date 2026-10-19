import test from 'node:test';
import assert from 'node:assert/strict';
import { TypedDataEncoder } from 'ethers';
import { generateIdentity } from 'age-encryption';
import { approvalTypes, validateRecoveryBundle, openApprovedResults } from '../web/work-approvals.js';
import { deliveryTypesV2 } from '../compute/key_delivery.mjs';
import { approvedBrowserFixture } from './fixtures/approved-browser.mjs';

test('browser schema matches the guest; desktop encrypted custody and receipts reconstruct the Python archive',async()=>{
  assert.deepEqual(approvalTypes,deliveryTypesV2);
  const f=await approvedBrowserFixture(),checked=await validateRecoveryBundle(f.bundle);
  assert.equal(checked.jobId,f.spec.id);
  const files=await openApprovedResults(f);
  assert.equal(new TextDecoder().decode(files.get('finished/answer.txt')),'owned verification result\n');
  assert.deepEqual([...files.keys()],['finished/answer.txt']);
  await assert.rejects(openApprovedResults({...f,identity:await generateIdentity()}));
});
test('browser refuses substituted signer, chain, escrow, approval, custody and duplicate attempts',async()=>{
  const f=await approvedBrowserFixture();
  for(const change of [b=>b.context.chainId=1,b=>b.context.requester='0x'+'44'.repeat(20),b=>b.context.escrow='0x'+'55'.repeat(20),
    b=>b.entries[0].approval.value.attempt++,b=>b.entries[0].approval.requesterSignature='0x'+'11'.repeat(65),
    b=>b.entries[0].custody.resultKeySHA256='0x'+'22'.repeat(32),b=>b.entries.push(b.entries[0])]) {
    const bundle=structuredClone(f.bundle);change(bundle);await assert.rejects(validateRecoveryBundle(bundle));
  }
});
test('an authentic signed approval still requires the exact encrypted receipt and original task/runtime/policy',async()=>{
  const f=await approvedBrowserFixture();
  const replaced=structuredClone(f.bundle),p=replaced.entries[0].approval;p.value.nonce='0x'+'99'.repeat(32);
  p.digest=TypedDataEncoder.hash(p.domain,approvalTypes,p.value);p.requesterSignature=await f.owner.signTypedData(p.domain,approvalTypes,p.value);
  await validateRecoveryBundle(replaced);await assert.rejects(openApprovedResults({...f,bundle:replaced}),/receipt/);
  for(const change of [s=>s.policySHA256='e'.repeat(64),s=>s.tasks[0].runtime.digestSHA256='f'.repeat(64),
    s=>s.tasks.unshift({...s.tasks[0],id:'different'})]) {
    const spec=structuredClone(f.spec);change(spec);await assert.rejects(openApprovedResults({...f,spec}));
  }
  const tampered=structuredClone(f.bundle),parts=tampered.entries[0].envelope.split('.');parts[3]=(parts[3][0]==='A'?'B':'A')+parts[3].slice(1);
  tampered.entries[0].envelope=parts.join('.');await assert.rejects(openApprovedResults({...f,bundle:tampered}),/receipt/);
  const damaged=f.encrypted[0].slice();damaged[damaged.length-1]^=1;await assert.rejects(openApprovedResults({...f,encrypted:[damaged]}));
});
test('superseding approval, receipt and archive all need the same attempt; plaintext receipts are not a recovery export',async()=>{
  const first=await approvedBrowserFixture(),next=await approvedBrowserFixture({attempt:2,owner:first.owner,identity:first.identity});
  const output=await openApprovedResults(next);assert.equal(output.size,1);
  await assert.rejects(openApprovedResults({...next,encrypted:first.encrypted}));
  const stale=structuredClone(next.bundle);stale.entries[0].envelope=first.bundle.entries[0].envelope;
  await assert.rejects(openApprovedResults({...next,bundle:stale}));
  await assert.rejects(validateRecoveryBundle(first.receipt));
});
