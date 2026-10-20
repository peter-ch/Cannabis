// Read only encrypted artifacts and an upload capability. No wallet/key input.
import fs from 'node:fs';
import { uploadEncryptedResult } from '../operator/result-upload.mjs';
const [configFile,accessFile,sourceFile]=process.argv.slice(2);
const controller=new AbortController(),stop=()=>controller.abort();
function read(file,limit) {
  const selected=fs.lstatSync(file);if(!selected.isFile()||selected.isSymbolicLink())throw Error();
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{
    const s=fs.fstatSync(fd,{bigint:true});if(!s.isFile()||s.size<1n||s.size>BigInt(limit))throw Error();
    const bytes=Buffer.alloc(Number(s.size)+1);let length=0;
    while(length<bytes.length){const n=fs.readSync(fd,bytes,length,bytes.length-length,null);if(!n)break;length+=n;}
    const after=fs.fstatSync(fd,{bigint:true});
    if(length!==Number(s.size)||['size','mtimeNs','ctimeNs'].some(k=>s[k]!==after[k]))throw Error();
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,length)));
  }
  finally{fs.closeSync(fd);}
}
process.once('SIGINT',stop);process.once('SIGTERM',stop);
try {
  if(process.argv.length!==5||!configFile||!accessFile||!sourceFile)throw Error();
  const config=read(configFile,8192),access=read(accessFile,8192),source=read(sourceFile,6*1024*1024+8192);
  if(!config||Object.keys(config).sort().join()!=='origin,timeoutMs')throw Error();
  const result=await uploadEncryptedResult({source,access,origin:config.origin,timeoutMs:config.timeoutMs,signal:controller.signal});
  console.log(JSON.stringify(result,null,2));
}catch{
  // Never echo paths, bearer credentials, file contents or remote error bodies.
  console.error(JSON.stringify({error:'Encrypted result upload failed. Retain the original encrypted files and access file; verify the selected relay and retry within its expiry.'}));
  process.exitCode=1;
}finally{process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}
