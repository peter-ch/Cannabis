// Local requester workflow. Outputs wallet-review data or encrypted envelopes only.
import fs from 'node:fs';
import path from 'node:path';
import { CapacityLedger } from '../compute/capacity.mjs';
import { AttestationLedger, leaseAttestationBinding, requestTrusteeResult } from '../compute/attestation.mjs';
import { keyDeliveryPayload, sealJobKeyDelivery, inspectKeyDelivery, recoverRequesterJobKey } from '../compute/key_delivery.mjs';

function read(file) {
  if (fs.statSync(file).size > 5 * 1024 * 1024) throw Error('Local key-delivery input exceeds bound');
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { throw Error('Invalid local JSON input'); }
}
const [action, configFile, inputFile] = process.argv.slice(2);
let capacity, attestations;
try {
  if (!['challenge', 'appraise', 'prepare', 'seal', 'inspect'].includes(action) || !configFile || !inputFile) throw Error('Usage: node scripts/compute-key-delivery.mjs ACTION private-config.json private-input.json');
  const config = read(configFile), input = read(inputFile);
  if (!fs.existsSync(config.capacityLedger)) throw Error('Existing funded capacity ledger required');
  capacity = new CapacityLedger(config.capacityLedger, config.context);
  attestations = new AttestationLedger(config.attestationLedger, read(config.attestationPolicyFile));
  let result;
  if (action === 'challenge') result = attestations.challenge(leaseAttestationBinding(capacity, input.leaseId, input.reservationId, input.run));
  else if (action === 'appraise') result = await requestTrusteeResult(attestations, config.trusteeEndpoint, input.nonce, input.channelJwk, input.evidence);
  else if (action === 'prepare') result = keyDeliveryPayload(capacity, attestations, input);
  else if (action === 'inspect') result = inspectKeyDelivery(attestations, input.releaseId);
  else {
    const source = config.keySource;
    if (!source || !path.isAbsolute(source.age) || !path.isAbsolute(source.python)) throw Error('Pin absolute local age and Python executable paths');
    const ageKeygen = path.join(path.dirname(source.age), process.platform === 'win32' ? 'age-keygen.exe' : 'age-keygen');
    result = await sealJobKeyDelivery(capacity, attestations, input.approval, input.token, config.network,
      expected => recoverRequesterJobKey(source, expected), { ageKeygen });
  }
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(JSON.stringify({ error: error.message })); process.exitCode = 1;
} finally { attestations?.close(); capacity?.close(); }
