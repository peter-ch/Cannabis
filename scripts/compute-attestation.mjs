import fs from 'node:fs';
import { AttestationLedger, attestWithTrustee, trusteeEvidenceRequest, validateAttestationPolicy } from '../compute/attestation.mjs';

function read(file) {
  if (fs.statSync(file).size > 5 * 1024 * 1024) throw Error('Attestation input too large');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
const [action, policyFile, inputFile, dbFile] = process.argv.slice(2);
try {
  if (!['policy-digest', 'challenge', 'request', 'verify', 'attest', 'cancel'].includes(action) || !policyFile) throw Error('Usage: node scripts/compute-attestation.mjs ACTION private-policy.json [input.json] [private-challenges.sqlite]');
  const policy = read(policyFile); let result;
  if (action === 'policy-digest') result = { attestationPolicySHA256: validateAttestationPolicy(policy) };
  else {
    if (!inputFile || !dbFile) throw Error('Require input and a private durable challenge ledger');
    const input = read(inputFile), ledger = new AttestationLedger(dbFile, policy);
    try {
      if (action === 'challenge') result = ledger.challenge(input);
      else if (action === 'cancel') result = ledger.cancel(input.nonce);
      else if (action === 'request') result = trusteeEvidenceRequest(policy, ledger.pending(input.nonce), input.channelJwk, input.evidence);
      else if (action === 'attest') result = await attestWithTrustee(ledger, input.endpoint, input.nonce, input.channelJwk, input.evidence);
      else result = await ledger.verify(input.nonce, input.token, input.channelJwk);
    } finally { ledger.close(); }
  }
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(JSON.stringify({ error: error.message })); process.exitCode = 1;
}
