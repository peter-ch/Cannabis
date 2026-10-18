import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { bundleNotices } from './bundle-notices.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'dist-work'); fs.mkdirSync(out, { recursive: true });
const bundled = await build({ absWorkingDir: root, entryPoints: [path.join(root, 'service/work-server.mjs')], outfile: path.join(out, 'server.mjs'), bundle: true,
  platform: 'node', target: 'node22', format: 'esm', minify: false, legalComments: 'linked', metafile: true });
bundleNotices(bundled.metafile, root, path.join(out, 'server.mjs.LEGAL.txt'));
const { createWorkServer } = await import(pathToFileURL(path.join(out, 'server.mjs')));
const { server } = createWorkServer({ file: ':memory:', origin: 'http://127.0.0.1:4210' });
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); await new Promise(resolve => server.close(resolve));
const names = ['server.mjs', 'server.mjs.LEGAL.txt'].filter(n => fs.existsSync(path.join(out, n)));
fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify({ schema: 'cannabis.work-service-build.v1',
  paymentsAvailable: false, files: names.map(name => ({ name, sha256: createHash('sha256').update(fs.readFileSync(path.join(out, name))).digest('hex') })) }, null, 2) + '\n');
console.log('Built and loaded standalone order service; payment admission remains closed.');
