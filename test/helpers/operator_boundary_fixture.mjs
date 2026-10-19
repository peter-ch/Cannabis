// Explicit owned kernel fixture, copied as the disposable unit's application.
// No provider, attestation, customer content or paid execution exists here.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {openOperatorBoundary} from './boundary.mjs';
const file=process.argv[process.argv.indexOf('--operator-config')+1],raw=fs.readFileSync(file),config=JSON.parse(raw);
const boundary=await openOperatorBoundary(config.resources,createHash('sha256').update(raw).digest('hex'));
const report=boundary.snapshot(),state=path.dirname(config.dispatch),checks={actualBoundary:report.state==='observed',
  noHardwareAuthority:report.hardwareValidated===false&&report.paymentAuthorized===false,rawStorageWritesDenied:report.rawStorageWritesDenied===true,
  actualRecoveryLease:report.recoveryLeaseHeld===true};
for(const [name,target] of [['outsideReadOnly',config.fixtureOutside],['sharedMemoryReadOnly','/dev/shm/cannabis-owned-boundary-check']]){
  try{fs.writeFileSync(target,'must fail',{flag:'wx'});throw Error('Unexpected writable path');}
  catch(error){if(!['EROFS','EACCES','EPERM'].includes(error.code))throw error;checks[name]=true;}
}
if(config.fixtureDescendant){
  const child=spawn('/usr/bin/python3',['-I','-B',path.join(path.dirname(new URL(import.meta.url).pathname),'fixture-descendant.py'),config.fixturePool,state],
    {stdio:'ignore',env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',PYTHONDONTWRITEBYTECODE:'1'}});
  child.on('error',()=>process.exit(1));
}
fs.writeFileSync(path.join(state,'tmp','ready.json'),JSON.stringify({pid:process.pid,checks,report}));
boundary.monitor();setInterval(()=>{},1000);
