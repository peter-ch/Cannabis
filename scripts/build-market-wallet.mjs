import {build} from 'esbuild';
await build({entryPoints:['operator/market-wallet-source.js'],outfile:'operator/market-wallet.js',bundle:true,format:'esm',platform:'browser',
  target:['chrome100','firefox100','safari15.4'],minify:true,legalComments:'inline'});
