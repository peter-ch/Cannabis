// Direct provider metadata preparation/inspection; no signing or job admission.
import fs from 'node:fs';
import { encodeProviderManifest, inspectProviderManifest, readProviderManifest } from '../compute/provider_manifest.mjs';

function bytes(file,limit=1024*1024) {
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NONBLOCK??0));
  try {
    const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size<1||stat.size>limit)throw Error('Require a bounded regular input file');
    const buffer=Buffer.alloc(limit+1);let length=0;
    while(length<buffer.length){const count=fs.readSync(fd,buffer,length,buffer.length-length,null);if(!count)break;length+=count;}
    if(length>limit)throw Error('Input exceeds the byte limit');return buffer.subarray(0,length);
  } finally {fs.closeSync(fd);}
}
const read=file=>JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes(file)));
const [action,...args]=process.argv.slice(2);
try {
  let result;
  if(action==='encode'&&args.length===2) {
    const prepared=encodeProviderManifest(read(args[0]));
    fs.writeFileSync(args[1],prepared.bytes,{flag:'wx',mode:0o600});
    result={schema:'cannabis.provider-manifest-file.v1',manifestHash:prepared.manifestHash,bytes:prepared.bytes.length,
      file:args[1],chainVerified:false,transactionSubmitted:false,executionAuthorized:false,keyReleaseAuthorized:false};
  } else if(action==='inspect'&&args.length===3) {
    result=inspectProviderManifest(bytes(args[0],65536),read(args[1]),args[2]);
  } else if(action==='fetch'&&args.length===3) {
    result=await readProviderManifest(read(args[0]),read(args[1]));
    fs.writeFileSync(args[2],encodeProviderManifest(result.manifest).bytes,{flag:'wx',mode:0o600});
    result={...result,file:args[2]};
  } else throw Error('Usage: node scripts/compute-provider-manifest.mjs encode manifest.json output.json | inspect manifest.json observation.json offerId | fetch network.json selection.json output.json');
  console.log(JSON.stringify(result,null,2));
} catch(error) {console.error(JSON.stringify({error:error.message}));process.exitCode=1;}
