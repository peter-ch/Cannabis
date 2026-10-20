// Offline owned consent checks only. No chain, customer keys or authorization.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { guestInitialization } from '../compute/guest_initialization.mjs';
import { validateGuestConfiguration } from '../compute/guest_configuration.mjs';
import { launchConsentPayload,inspectLaunchConsent } from '../compute/guest_consent.mjs';
import { consentFixture as fixture } from './helpers/consent_fixture.mjs';
const h=n=>'0x'+n.toString(16).padStart(64,'0');
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
