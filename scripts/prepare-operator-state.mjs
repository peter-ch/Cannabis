// Explicit first initialization on an already prepared physical metadata volume.
// Missing or partial existing databases are never erased or repaired here.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {PeerDispatchJournal} from '../compute/peer_dispatch.mjs';
import {WorkStore} from '../service/work-store.mjs';
import {ResultRelay} from '../service/result-relay.mjs';
const [home,origin,...extra]=process.argv.slice(2),u=new URL(origin);
if(extra.length||process.platform!=='linux'||process.geteuid()!==0||!path.isAbsolute(home)||
  u.origin!==origin||u.protocol!=='https:'||u.username||u.password)throw Error('Require an existing state volume and selected HTTPS relay origin');
process.umask(0o077);
const script=fileURLToPath(new URL('./operator-state-volume.py',import.meta.url));
const observed=JSON.parse(execFileSync('/usr/bin/python3',['-I','-B',script,'inspect',home],{encoding:'utf8',timeout:5000,maxBuffer:8192}));
if(observed.schema!=='cannabis.operator-state-observation.v1'||observed.availableBytes<8*1024**2)throw Error('Metadata volume unavailable');
const directory=path.join(home,'mount','state');
if(fs.readdirSync(directory).sort().join()!=='approvals,tmp'||fs.readdirSync(path.join(directory,'approvals')).length||
  fs.readdirSync(path.join(directory,'tmp')).length)throw Error('Only a fresh state directory can be initialized; retain existing files');
new PeerDispatchJournal(path.join(directory,'dispatch.sqlite'),{create:true}).close();
new WorkStore(path.join(directory,'orders.sqlite'),origin).close();
new ResultRelay(path.join(directory,'results.sqlite')).close();
const fd=fs.openSync(directory,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
console.log(JSON.stringify({initialized:true,serviceStarted:false,hardwareValidated:false}));
