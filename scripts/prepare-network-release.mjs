// Export a complete review package without accessing custody or sending transactions.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { compile, root } from './compile.mjs';
import { readBounded } from '../claims/identity.mjs';
import { verifyLaunchDependencies } from '../launch/dependencies.mjs';
import { buildRelease, releaseArtifacts, validateRelease } from '../launch/release.mjs';
import { observeReleaseState } from '../launch/release-state.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export async function prepareNetworkRelease({ configuration, dependencyConfig, out }) {
  // Retain one configuration across asynchronous observations and serialization.
  // A caller changing its objects must not cause a different sender to be checked.
  const dependencies = structuredClone(dependencyConfig);
  const retained = validateRelease(configuration, dependencies?.dependencies).configuration;
  if (typeof out !== 'string' || !out.length) throw Error('Require an unused private output directory');
  const requested = path.resolve(out);
  const destination = path.join(fs.realpathSync(path.dirname(requested)), path.basename(requested));
  const sourceRoot = fs.realpathSync(root);
  const relative = path.relative(sourceRoot, destination);
  if (relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative)) || fs.existsSync(destination))
    throw Error('Choose an unused review directory outside the public source');
  const artifacts = compile();
  const compilerInput = fs.readFileSync(path.join(root, 'artifacts/compiler-input.json'));
  const plan = await buildRelease(retained, dependencies.dependencies, artifacts);
  // Network observations follow compilation so that preparation does not age them during compilation.
  const dependencyObservation = await verifyLaunchDependencies(dependencies);
  const stateObservation = await observeReleaseState(retained, dependencies, dependencyObservation);
  const files = { 'compiler-input.json': compilerInput };
  for (const name of releaseArtifacts) files[`artifacts/${name}.json`] = Buffer.from(JSON.stringify(artifacts[name], null, 2) + '\n');
  const fileHashes = Object.fromEntries(Object.entries(files).map(([name, bytes]) => [name, sha(bytes)]));
  const packageCommitment = { plan, files: fileHashes };
  const manifest = { ...plan, preparedAt: new Date().toISOString(), files: fileHashes,
    packageSHA256: sha(JSON.stringify(packageCommitment)), dependencyObservation, stateObservation };
  // Do not write any package files on invalid configuration or failed state verification.
  // The manifest is written last. Partial filesystem failures never produce a complete manifest.
  fs.mkdirSync(destination);
  fs.mkdirSync(path.join(destination, 'artifacts'));
  for (const [name, bytes] of Object.entries(files)) fs.writeFileSync(path.join(destination, name), bytes, { flag: 'wx' });
  fs.writeFileSync(path.join(destination, 'network-release.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  return { manifestPath: path.join(destination, 'network-release.json'), packageSHA256: manifest.packageSHA256,
    transactions: plan.transactions.length, status: plan.status, sent: false };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2), values = {};
    if (args.length !== 6) throw Error('Require config, dependency-config and out');
    for (let i = 0; i < args.length; i += 2) {
      const name = args[i];
      if (!['--config', '--dependency-config', '--out'].includes(name) || Object.hasOwn(values, name) || !args[i + 1])
        throw Error('Invalid release arguments');
      values[name] = args[i + 1];
    }
    const json = name => JSON.parse(readBounded(path.resolve(values[name]), 16384).toString('utf8'));
    console.log(JSON.stringify(await prepareNetworkRelease({ configuration: json('--config'),
      dependencyConfig: json('--dependency-config'), out: values['--out'] }), null, 2));
  } catch {
    console.error('Network release preparation failed. Check the private configuration, reviewed dependencies, canonical sender state and unused output directory. No transaction was sent.');
    process.exitCode = 1;
  }
}
