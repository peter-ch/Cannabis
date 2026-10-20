// Separate-process storage/crash fixture. Receives public approvals/ciphertext,
// never requester secrets. Exit 86 intentionally omits normal database close.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { ResultSpool } from '../../operator/result-spool.mjs';
const c=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
let spool;
try {
  spool=new ResultSpool(c.directory);
  const handle=spool.reserve(c.request);
  if(c.stage!=='reserved')spool.dispatch(handle);
  if(['receiving','sealed','complete'].includes(c.stage)){
    const bytes=Buffer.from(c.ciphertext,'base64');spool.begin(handle,{resultEnvelope:c.envelope,ciphertextBytes:bytes.length});
    const length=c.stage==='receiving'?Math.floor(bytes.length/2):bytes.length;
    for(let i=0;i<length;i+=65536)spool.append(handle,bytes.subarray(i,Math.min(length,i+65536)));
    if(c.stage==='sealed'){
      const open=fs.openSync;fs.openSync=(file,...args)=>{
        if(typeof file==='string'&&file.endsWith('source.json.tmp'))throw Error('Owned interrupted receipt publication');return open(file,...args);
      };
      try{spool.seal(handle,createHash('sha256').update(bytes).digest('hex'));}catch{}finally{fs.openSync=open;}
      if(spool.status(handle.id).state!=='sealed')throw Error('Expected sealed persistence boundary');
    }else if(c.stage==='complete')spool.seal(handle,createHash('sha256').update(bytes).digest('hex'));
  }
  fs.writeSync(1,JSON.stringify({ok:true,id:handle.id})+'\n');
  if(c.crash)process.exit(86);
}catch{fs.writeSync(1,JSON.stringify({ok:false})+'\n');process.exitCode=1;}
finally{spool?.close();}
