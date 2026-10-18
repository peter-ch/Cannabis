import fs from 'node:fs';
import path from 'node:path';
import { readBounded } from '../claims/identity.mjs';
import { checkBrightIDProvider, BrightIDIntakeLedger } from '../claims/brightid.mjs';

let ledger;
try {
  const [flag, configPath, outFlag, outPath, ...extra] = process.argv.slice(2);
  if (flag !== '--config' || outFlag !== '--out' || !configPath || !outPath || extra.length || fs.existsSync(outPath)) throw Error('Invalid arguments');
  const config = JSON.parse(readBounded(path.resolve(configPath), 16384).toString('utf8'));
  if (!config || Object.keys(config).sort().join(',') !== 'commitment,ledger,policy' || typeof config.ledger !== 'string' || !path.isAbsolute(config.ledger)) throw Error('Invalid configuration');
  // The immutable database policy is checked before sending a request to any provider.
  ledger = new BrightIDIntakeLedger(config.ledger, config.policy);
  const checked = await checkBrightIDProvider(config);
  const result = ledger.record(checked.record, config.commitment);
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ eligibilitySignatureVerified: true, alreadyRecorded: result.alreadyRecorded, enrollmentAuthorized: false, sent: false }));
} catch {
  console.error('Person-verification check failed. Check the pinned provider policy, deployment binding, freshness and protected intake database. No enrollment was authorized.');
  process.exitCode = 1;
} finally { ledger?.close(); }
