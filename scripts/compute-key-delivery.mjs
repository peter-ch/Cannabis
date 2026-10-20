// Local requester workflow. Outputs wallet-review data or encrypted envelopes only.
import fs from 'node:fs';
import path from 'node:path';
import { AttestationLedger, configuredMarketAttestationBinding, requestTrusteeResult } from '../compute/attestation.mjs';
import { keyDeliveryPayload, sealJobKeyDelivery, inspectKeyDelivery, recoverRequesterJobKey } from '../compute/key_delivery.mjs';
import { validateGuestConfiguration } from '../compute/guest_configuration.mjs';
import { createResultKeyCustody, recoverRequesterResultKey } from '../compute/result_keys.mjs';
import { verifyGroupAdmission } from '../compute/group_admission.mjs';

function read(file) {
  if (fs.statSync(file).size > 5 * 1024 * 1024) throw Error('Local key-delivery input exceeds bound');
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { throw Error('Invalid local JSON input'); }
}
const [action, configFile, inputFile] = process.argv.slice(2);
let capacity, attestations;
try {
  if (!['challenge', 'appraise', 'prepare', 'seal', 'inspect', 'create-result-key'].includes(action) || !configFile || !inputFile) throw Error('Usage: node scripts/compute-key-delivery.mjs ACTION private-config.json private-input.json');
  const config = read(configFile), input = read(inputFile);
  // Journal inspection and result-key creation do not depend on a provider's
  // current consent, a still-active order or historic source files remaining available.
  if (!['inspect','create-result-key'].includes(action)) {
    if (config.capacityLedger || !config.marketProofFile || !config.launchConfigurationFile || !config.launchConsentFile)
      throw Error('New key delivery requires marketProofFile, launchConfigurationFile and launchConsentFile without a legacy capacity database');
    capacity = { schema: 'cannabis.market-requester.v3', context: config.context,
      proof: read(config.marketProofFile), configuration: read(config.launchConfigurationFile), consent: read(config.launchConsentFile) };
  }
  if (action !== 'create-result-key') attestations = new AttestationLedger(config.attestationLedger, read(config.attestationPolicyFile));
  let result;
  if (action === 'create-result-key') result = await createResultKeyCustody(input);
  else if (action === 'challenge') result = attestations.challenge(configuredMarketAttestationBinding(
    capacity.proof,config.context,input.reservationId,input.run,validateGuestConfiguration(capacity.configuration).configurationSHA256));
  else if (action === 'appraise') result = await requestTrusteeResult(attestations, config.trusteeEndpoint, input.nonce, input.channelJwk, input.evidence);
  else if (action === 'prepare') {
    const groupAdmission=input.group?await verifyGroupAdmission(capacity.proof,config.network,input.group.approval):undefined;
    result=keyDeliveryPayload(capacity,attestations,input,undefined,{groupAdmission});
  }
  else if (action === 'inspect') result = inspectKeyDelivery(attestations, input.releaseId);
  else {
    const source = config.keySource;
    if (!source || !path.isAbsolute(source.age) || !path.isAbsolute(source.python)) throw Error('Pin absolute local age and Python executable paths');
    const ageKeygen = path.join(path.dirname(source.age), process.platform === 'win32' ? 'age-keygen.exe' : 'age-keygen');
    result = await sealJobKeyDelivery(capacity, attestations, input.approval, input.token, config.network,
      expected => recoverRequesterJobKey(source, expected), { ageKeygen,
        loadResultKey:expected=>recoverRequesterResultKey(config.resultKeySource,expected) });
  }
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(JSON.stringify({ error: error.message })); process.exitCode = 1;
} finally { attestations?.close(); capacity?.close?.(); }
