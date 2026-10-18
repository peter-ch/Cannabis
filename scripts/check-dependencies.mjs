import fs from 'node:fs';
import path from 'node:path';
import { readBounded } from '../claims/identity.mjs';
import { verifyLaunchDependencies } from '../launch/dependencies.mjs';

try {
  const [flag, configPath, outFlag, outPath, ...extra] = process.argv.slice(2);
  if (flag !== '--config' || outFlag !== '--out' || !configPath || !outPath || extra.length || fs.existsSync(outPath)) throw Error('Invalid arguments or existing output');
  const config = JSON.parse(readBounded(path.resolve(configPath), 16384).toString('utf8'));
  const result = await verifyLaunchDependencies(config);
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ output: path.resolve(outPath), chainId: result.dependencies.chainId, anchor: result.anchor.hash, sent: false }));
} catch {
  console.error('Dependency check failed. Check reviewed addresses, source-derived code hashes and links, chain, RPC finality support and freshness. No release was approved.');
  process.exitCode = 1;
}
