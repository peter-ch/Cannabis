// Consume only the complete package selected by an independently retained digest.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { readBounded } from '../claims/identity.mjs';
import { buildRelease, releaseArtifacts } from './release.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export async function readReleasePackage(manifestFile, expectedPackageSHA256) {
  if (typeof manifestFile !== 'string' || !path.isAbsolute(manifestFile) ||
      !/^[0-9a-f]{64}$/.test(expectedPackageSHA256)) throw Error('Require an absolute package and independently reviewed SHA256');
  const manifest = JSON.parse(readBounded(manifestFile, 2 * 1024 * 1024));
  const { preparedAt, files, packageSHA256, dependencyObservation, stateObservation, ...plan } = manifest;
  if (packageSHA256 !== expectedPackageSHA256 || sha(JSON.stringify({ plan, files })) !== expectedPackageSHA256)
    throw Error('Complete release commitment mismatch');
  const names = ['compiler-input.json', ...releaseArtifacts.map(name => `artifacts/${name}.json`)];
  if (!files || Object.keys(files).sort().join(',') !== names.toSorted().join(',')) throw Error('Incomplete release files');
  const directory = fs.realpathSync(path.dirname(manifestFile)), artifacts = {};
  for (const name of names) {
    const file = path.join(directory, name), resolved = fs.realpathSync(file);
    if (resolved !== file) throw Error('Release package links are not accepted');
    const bytes = readBounded(file, 4 * 1024 * 1024);
    if (sha(bytes) !== files[name]) throw Error('Release artifact commitment mismatch');
    const value = JSON.parse(bytes);
    if (name.startsWith('artifacts/')) artifacts[path.basename(name, '.json')] = value;
  }
  // This rebuild checks fields, predictions, constructor arguments and every byte
  // of creation data. Old RPC observations are never accepted as fresh state.
  const rebuilt = await buildRelease(plan.configuration, plan.dependencies, artifacts);
  if (!isDeepStrictEqual(rebuilt, plan)) throw Error('Release plan does not reproduce');
  return { plan: rebuilt, artifacts, packageSHA256 };
}
