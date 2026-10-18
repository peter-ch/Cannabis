import fs from 'node:fs';
import path from 'node:path';
import { readBounded } from '../claims/identity.mjs';
import { prepareVenueRoster, verifyVenueApprovals, prepareRoundPolicy, verifyRoundApprovals } from '../claims/community-enrollment.mjs';

// Offline Cannabis ceremony tooling: no provider, signing or RPC.
try {
  const [flag, configPath, outFlag, outPath, ...extra] = process.argv.slice(2);
  if (flag !== '--config' || outFlag !== '--out' || !configPath || !outPath || extra.length || fs.existsSync(outPath)) throw Error('Invalid arguments');
  const config = JSON.parse(readBounded(path.resolve(configPath), 8*1024*1024).toString('utf8'));
  const keys=Object.keys(config).sort().join(',');
  let result;
  if(config.kind==='round' && ['kind,policy','kind,policy,registrySignatures'].includes(keys)) {
    result=Object.hasOwn(config,'registrySignatures') ? verifyRoundApprovals(config.policy,config.registrySignatures) : prepareRoundPolicy(config.policy);
  } else if(config.kind==='roster' && ['kind,members,policy,venueId','kind,members,policy,registrySignatures,venueId,witnessSignatures'].includes(keys)) {
    result=Object.hasOwn(config,'witnessSignatures')
      ? verifyVenueApprovals(config.policy,config.venueId,config.members,config.witnessSignatures,config.registrySignatures)
      : prepareVenueRoster(config.policy,config.venueId,config.members);
  } else throw Error('Invalid configuration');
  result={...result,humanUniquenessEstablished:false,enrolled:false,sent:false};
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({prepared:true,witnessQuorumVerified:result.witnessQuorumVerified??false,registryQuorumVerified:result.registryQuorumVerified??result.signatureQuorumVerified??false,humanUniquenessEstablished:false,enrolled:false,sent:false}));
} catch {
  console.error('Ceremony preparation failed. Check the reviewed venue policy, roster, witness approvals, submission window and unused private output path. Nothing was signed or sent.');
  process.exitCode = 1;
}
