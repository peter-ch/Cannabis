import fs from 'node:fs';
import path from 'node:path';

// Include full license texts for every dependency actually included by esbuild.
export function bundleNotices(metafile, root, output) {
  const packages = new Map();
  for (const input of Object.keys(metafile.inputs)) {
    if (!input.replaceAll('\\', '/').includes('node_modules/')) continue;
    let directory = path.dirname(path.resolve(root, input));
    while (!fs.existsSync(path.join(directory, 'package.json')) || !JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8')).name) {
      const parent = path.dirname(directory); if (parent === directory) throw Error('Missing dependency metadata'); directory = parent;
    }
    if (packages.has(directory)) continue;
    const pkg = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
    const license = ['LICENSE', 'LICENSE.md', 'LICENSE.txt'].find(name => fs.existsSync(path.join(directory, name)));
    if (!license) throw Error('Missing bundled dependency license: ' + pkg.name);
    packages.set(directory, `${pkg.name} ${pkg.version}\n\n${fs.readFileSync(path.join(directory, license), 'utf8')}`);
  }
  const original = fs.existsSync(output) ? fs.readFileSync(output, 'utf8') : '';
  fs.writeFileSync(output, original + '\nFull dependency license texts\n\n' + [...packages.values()].join('\n\n--------------------\n\n'));
}
