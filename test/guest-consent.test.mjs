// Offline owned consent checks only. No chain, customer keys or authorization.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Wallet, AbiCoder, formatUnits, keccak256, ZeroAddress } from 'ethers';
import { launchFixture } from './helpers/launch_fixture.mjs';
import { nativeServiceCommitment } from '../compute/guest_execution.mjs';
import { validateGuestConfiguration } from '../compute/guest_configuration.mjs';
import { guestInitialization } from '../compute/guest_initialization.mjs';
import { configuredMarketAttestationBinding } from '../compute/attestation.mjs';
import { verifyMarketLeaseProof } from '../compute/market_lease.mjs';
import { bookingPayload } from '../compute/market.mjs';
import { settlementTerms,termsDigest } from '../scripts/compute-escrow.mjs';
import { policy } from '../scripts/compute-plan.mjs';
import { launchConsentPayload,inspectLaunchConsent } from '../compute/guest_consent.mjs';
const h=n=>'0x'+n.toString(16).padStart(64,'0'),coder=AbiCoder.defaultAbiCoder();
const utc=n=>new Date(n*1000).toISOString().replace('.000Z','Z');
async function fixture({sameParty=false}={}) {
  const requester=Wallet.createRandom(),provider=sameParty?requester:Wallet.createRandom(),c=launchFixture().configuration;
  c.schema='cannabis.guest-launch-configuration.v3';c.context={chainId:31337,market:Wallet.createRandom().address,token:ZeroAddress};
  c.network.market=c.context.market;c.network.marketCodeHash=h(99);c.provider=provider.address;
  const resourceId=keccak256(coder.encode(['address','bytes32'],[provider.address,h(10)]));c.resourceId=resourceId;
  const start=1000,end=2000,gross=100000n,service=nativeServiceCommitment(c.execution);
  const job={schema:'cannabis.compute.order.v2',id:'owned-consent-only',requester:requester.address,
    packageSHA256:h(2).slice(2),policySHA256:h(3).slice(2),acceptanceSHA256:h(4).slice(2),
    payment:{totalBudget:formatUnits(gross,18),feeBasisPoints:100,founderRecipient:policy.founderRecipient}};
  const settlement={workers:[{account:provider.address,shareBps:10000}],deliveryManager:provider.address,
    adjudicator:Wallet.createRandom().address,acceptBy:utc(999),deliverBy:utc(2100),reviewSeconds:86400,disputeSeconds:86400};
  const terms=settlementTerms(job,settlement);
  const orderId=keccak256(coder.encode(['string','uint256','address','address','bytes32'],
    ['Cannabis compute order v1',31337,c.network.escrow,requester.address,terms.terms.jobHash]));
  const digest=termsDigest({chainId:31337,escrow:c.network.escrow,token:ZeroAddress,founderRecipient:policy.founderRecipient,...terms});
  const booking={reservationId:h(5),offerId:h(6),requester:requester.address,orderId,termsDigest:digest,
    start:'1000',end:'2000',units:'1',gross:gross.toString(),holdUntil:'999'};
  const bookingId=bookingPayload(c.context,booking).digest;
  const proof={schema:'cannabis.market-lease.v1',chainId:31337,market:c.context.market,token:ZeroAddress,escrow:c.network.escrow,job,settlement,
    bookings:[{bookingId,booking,offer:{resource:resourceId,escrow:c.network.escrow,policyHash:'0x'+job.policySHA256,manifestHash:h(7),
      start:'1000',end:'2000',expiresAt:'999',units:'1',grossPerUnitSecond:'100'},resource:{provider:provider.address,serviceHash:service.serviceSHA256,units:'1'}}],
    fundedAnchor:{number:12,hash:h(8),timestamp:999}};
  verifyMarketLeaseProof(proof,c.context); // Consistent invented records are NOT chain evidence.
  const configHash=validateGuestConfiguration(c).configurationSHA256;
  const run={runtimeSHA256:c.execution.profile.runtime.digestSHA256,taskSHA256:h(9).slice(2),attempt:1,rank:0,worldSize:1,acceleratorClass:'cpu'};
  const binding=configuredMarketAttestationBinding(proof,c.context,bookingId,run,configHash,1000);
  const initialization={schema:'cannabis.guest-initialization.v2',tee:'snp',requester:requester.address,jobId:job.id,binding};
  const consents=[];
  for(const [role,wallet] of [['requester',requester],['provider',provider]]) {
    const p=launchConsentPayload(c,initialization,proof,role);
    consents.push({role,signer:wallet.address,signature:await wallet.signTypedData(p.domain,p.types,p.value)});
  }
  const signed={schema:'cannabis.guest-launch-consent.v1',configuration:c,consents};
  return {requester,provider,configuration:c,initialization,proof,signed};
}
test('role-specific consent commits the canonical assignment without a global signer',async()=>{
  for(const sameParty of [false]) {
    const f=await fixture({sameParty}),checked=inspectLaunchConsent(f.signed,f.initialization,f.proof,1500);
    assert.equal(checked.chainVerified,false);assert.equal(checked.executionAuthorized,false);assert.equal(checked.keyReleaseAuthorized,false);
    assert.notEqual(checked.approvals[0].digest,checked.approvals[1].digest);
    assert.equal(checked.assignmentSHA256,'0x'+createHash('sha256').update(guestInitialization(f.initialization).canonical).digest('hex'));
    assert.equal(checked.approvals[0].signer,f.requester.address);assert.equal(checked.approvals[1].signer,f.provider.address);
    assert.equal(checked.configurationSHA256,f.initialization.binding.configurationSHA256);
    const reversed=Object.fromEntries(Object.entries(f.initialization).reverse());
    assert.equal(launchConsentPayload(f.configuration,reversed,f.proof,'requester').digest,checked.approvals[0].digest);
  }
  await assert.rejects(fixture({sameParty:true}),/Invalid settlement roles/);
});
test('missing role, duplicate role, foreign requester, malformed signatures and extra fields are refused',async()=>{
  const f=await fixture();
  for(const alter of [s=>s.consents.pop(),s=>s.consents.reverse(),s=>s.consents[1]=s.consents[0],s=>s.authorities=[],
    s=>s.consents[0].signer=f.provider.address,s=>s.consents[0].signature=s.consents[1].signature,
    s=>s.consents[1].signature='0x1',s=>s.consents[1].signature='0x'+'aa'.repeat(8193),s=>s.consents[1].secret='forbidden']) {
    const signed=structuredClone(f.signed);alter(signed);assert.throws(()=>inspectLaunchConsent(signed,f.initialization,f.proof,1500));
  }
  for(const now of [999,2000,NaN])assert.throws(()=>inspectLaunchConsent(f.signed,f.initialization,f.proof,now));
});
test('changed configuration or assignment cannot reuse a consent signature',async()=>{
  const f=await fixture();
  for(const alter of [c=>c.network.rpc='https://changed.invalid/',c=>c.network.marketCodeHash=h(91),c=>c.transport.timeoutMs--,
    c=>c.resourceId=h(91),c=>c.provider=f.requester.address,c=>c.execution.profile.tools.pythonSHA256=h(91).slice(2)]) {
    const signed=structuredClone(f.signed);alter(signed.configuration);
    assert.throws(()=>inspectLaunchConsent(signed,f.initialization,f.proof,1500));
  }
  const signed=structuredClone(f.signed);signed.configuration.transport.timeoutMs--;
  const init=structuredClone(f.initialization);init.binding.configurationSHA256=validateGuestConfiguration(signed.configuration).configurationSHA256;
  assert.throws(()=>inspectLaunchConsent(signed,init,f.proof,1500)); // Even internally consistent replacement needs new signatures.
  const changed=structuredClone(f.initialization);changed.binding.attempt++;
  assert.throws(()=>inspectLaunchConsent(f.signed,changed,f.proof,1500));
});
test('offline provider bytes are never interpreted as contract-wallet or chain authorization',async()=>{
  const f=await fixture();f.signed.consents[1].signature='0x1234';
  const inspected=inspectLaunchConsent(f.signed,f.initialization,f.proof,1500);
  assert.equal(inspected.approvals[1].signature,'0x1234');assert.equal(inspected.chainVerified,false);assert.equal(inspected.executionAuthorized,false);
});
