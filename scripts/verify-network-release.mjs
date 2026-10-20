import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readBounded } from '../claims/identity.mjs';
import { verifyDeployedRelease } from '../launch/deployed-release.mjs';

try {
  const [flag, configPath, outFlag, outPath, ...extra] = process.argv.slice(2);
  if (flag !== '--config' || outFlag !== '--out' || !configPath || !outPath || extra.length) throw Error('Invalid verification arguments');
  const requested = path.resolve(outPath), destination = path.join(fs.realpathSync(path.dirname(requested)), path.basename(requested));
  const source = fs.realpathSync(fileURLToPath(new URL('..', import.meta.url))), relative = path.relative(source, destination);
  if (fs.existsSync(destination) || relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative)))
    throw Error('Use an unused private verification file');
  const config = JSON.parse(readBounded(path.resolve(configPath), 16384));
  const result = await verifyDeployedRelease(config);
  fs.writeFileSync(destination, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ status: result.status, creations: result.receipts.length, contracts: Object.keys(result.code).length,
    finalizedAnchor: result.finalizedAnchor, liveStatusAuthorized: false, sent: false }));
} catch {
  console.error('Complete deployment verification failed. Check the independently reviewed package, compiler, ordered finalized receipts and canonical contract state. No transaction was sent.');
  process.exitCode = 1;
}
