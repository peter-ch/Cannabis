import fs from 'node:fs';
import path from 'node:path';
import { readBounded } from '../claims/identity.mjs';
import { downloadMembershipSnapshot } from '../claims/snapshot.mjs';

try {
  const [configFlag, configPath, outFlag, outPath, ...extra] = process.argv.slice(2);
  if (configFlag !== '--config' || outFlag !== '--out' || !configPath || !outPath || extra.length || fs.existsSync(outPath)) throw Error('Invalid arguments or existing output');
  const config = JSON.parse(readBounded(path.resolve(configPath), 16384).toString('utf8'));
  const result = await downloadMembershipSnapshot(config);
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ output: path.resolve(outPath), members: result.context.memberCount, anchor: result.evidence.anchor.hash, sent: false }));
} catch {
  console.error('Membership download failed. Check the reviewed deployment, RPC capabilities, enrollment finality and documented bounds. No snapshot was approved.');
  process.exitCode = 1;
}
