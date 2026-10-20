import {build} from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {bundleNotices} from './bundle-notices.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),notices=path.join(root,'operator/market-wallet.js.LEGAL.txt');
fs.writeFileSync(notices,'');
const result=await build({absWorkingDir:root,entryPoints:['operator/market-wallet-source.js'],outfile:'operator/market-wallet.js',
  bundle:true,format:'esm',platform:'browser',target:['chrome100','firefox100','safari15.4'],minify:true,legalComments:'linked',metafile:true});
bundleNotices(result.metafile,root,notices);
