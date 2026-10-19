import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { consentFixture } from './helpers/consent_fixture.mjs';
import { guestInitialization } from '../compute/guest_initialization.mjs';
import { AttestationLedger } from '../compute/attestation.mjs';
import { keyDeliveryPayload } from '../compute/key_delivery.mjs';
import { verifyMarketLeaseProof } from '../compute/market_lease.mjs';

test('requester CLI prepares consent-bound approval and refuses configuration-only or local-ledger downgrade',async t=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-requester-consent-'));
  t.after(()=>{assert.equal(path.dirname(fs.realpathSync(directory)),fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('cannabis-requester-consent-'));fs.rmSync(directory,{recursive:true});});
  const write=(name,value)=>{const p=path.join(directory,name+'.json');fs.writeFileSync(p,JSON.stringify(value));return p;};
  const now=Math.floor(Date.now()/1000),f=await consentFixture({start:now-10});
  const policy=structuredClone(f.configuration.attestationPolicyTemplate);policy.measurements.initData=guestInitialization(f.initialization).digest;
  const config={context:f.configuration.context,marketProofFile:write('proof',f.proof),
    launchConfigurationFile:write('configuration',f.configuration),launchConsentFile:write('consent',f.signed),
    attestationPolicyFile:write('policy',policy),attestationLedger:path.join(directory,'attestations.sqlite')};
  const journal=new AttestationLedger(config.attestationLedger,policy);
  const challenge=journal.challenge(f.initialization.binding);
  const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),lease=verifyMarketLeaseProof(f.proof,config.context),h=n=>'0x'+n.toString(16).padStart(64,'0');
  const request={releaseId:h(97),leaseId:lease.digest,nonce:challenge.nonce,channelJwk:key.publicKey.export({format:'jwk'}),
    descriptor:{schema:'cannabis.package.v2',id:lease.job.id,ciphertextSHA256:lease.job.packageSHA256,policySHA256:lease.job.policySHA256,
      recipient:'age1'+'a'.repeat(58),keyCustody:{schema:'cannabis.job-key.custody.v1',format:'age-v1+json',ciphertextSHA256:h(96).slice(2),ciphertextBytes:100}},
    notBefore:challenge.issuedAt,expiresAt:challenge.issuedAt+60,resultKeySHA256:h(98)};
  const expected=keyDeliveryPayload({schema:'cannabis.market-requester.v3',context:config.context,proof:f.proof,
    configuration:f.configuration,consent:f.signed},journal,request,now);
  journal.close();
  const input=write('input',request),configFile=write('config',config);
  const run=(action='prepare')=>spawnSync(process.execPath,['scripts/compute-key-delivery.mjs',action,configFile,input],
    {encoding:'utf8',windowsHide:true,timeout:30000});
  const prepared=run();assert.equal(prepared.status,0,prepared.stderr);
  assert.deepEqual(JSON.parse(prepared.stdout),expected);assert.equal(expected.domain.version,'3');
  for(const remove of ['launchConsentFile','launchConfigurationFile','marketProofFile']) {
    const missing={...config};delete missing[remove];write('config',missing);
    for(const action of ['challenge','appraise','prepare','seal']) {
      const result=run(action);assert.equal(result.status,1);assert.match(result.stderr,/requires marketProofFile/);
    }
  }
  write('config',{...config,capacityLedger:path.join(directory,'obsolete.sqlite')});
  assert.match(run().stderr,/without a legacy capacity database/);
  assert.equal(fs.existsSync(path.join(directory,'obsolete.sqlite')),false);
  // Read-only retrieval is independent of removed launch/proof files. There is
  // no issued record in this fixture, so the journal supplies its own refusal.
  write('config',{attestationLedger:config.attestationLedger,attestationPolicyFile:config.attestationPolicyFile});
  fs.unlinkSync(config.launchConsentFile);fs.unlinkSync(config.marketProofFile);
  const inspected=run('inspect');assert.equal(inspected.status,1);assert.match(inspected.stderr,/Unknown encrypted key delivery/);
});
