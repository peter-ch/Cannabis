import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readBounded } from '../claims/identity.mjs';
import { quoteNetworkRelease } from '../launch/release-fees.mjs';

try {
  const [flag, configPath, outFlag, outPath, ...extra] = process.argv.slice(2);
  if (flag !== '--config' || outFlag !== '--out' || !configPath || !outPath || extra.length) throw Error('Invalid quote arguments');
  const requested = path.resolve(outPath), destination = path.join(fs.realpathSync(path.dirname(requested)), path.basename(requested));
  const source = fs.realpathSync(fileURLToPath(new URL('..', import.meta.url))), relative = path.relative(source, destination);
  if (fs.existsSync(destination) || relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative)))
    throw Error('Use an unused private quote file');
  const config = JSON.parse(readBounded(path.resolve(configPath), 16384));
  if (!config || Object.keys(config).sort().join(',') !== 'expectedPackageSHA256,manifestFile,rpc') throw Error('Invalid quote configuration');
  const result = await quoteNetworkRelease(config);
  fs.writeFileSync(destination, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ transactions: result.transactions.length, estimatedNetworkFeeETH: result.estimatedNetworkFeeETH,
    planningBudgetETH: result.planningBudgetETH, spendAuthorized: false, sent: false }));
} catch {
  console.error('Complete release quote failed. Check the independently reviewed package, canonical sender state, funded balance and sequential simulation support. No transaction was sent.');
  process.exitCode = 1;
}
