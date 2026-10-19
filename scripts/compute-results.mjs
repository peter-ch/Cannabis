// Requester-local encrypted receipt inbox and streaming reconstruction. No signing
// or payment submission. Config, custody, manifests and output stay on this device.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { ResultInbox } from '../compute/result_inbox.mjs';
import { recoverRequesterResultKey } from '../compute/result_keys.mjs';
const [action,configFile,inputFile]=process.argv.slice(2);
function read(file,limit=8*1024*1024) {
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{const s=fs.fstatSync(fd);if(!s.isFile()||s.size>limit)throw Error('Input exceeds file bound');return JSON.parse(fs.readFileSync(fd,'utf8'));}
  finally{fs.closeSync(fd);}
}
let inbox;
try {
  if(!['activate','receive','recover','inspect','retire','assemble','export-browser'].includes(action)||!configFile||!inputFile)throw Error('Require ACTION config.json input.json');
  const config=read(configFile),input=read(inputFile);
  inbox=new ResultInbox(config.inbox,config.context,config.limits);
  const load=expected=>{
    const source=config.resultKeySources?.[expected.releaseId];
    if(!source||!path.isAbsolute(source.python)||!path.isAbsolute(source.age))throw Error('Require pinned requester recovery tools');
    return recoverRequesterResultKey(source,expected);
  };
  let result;
  if(action==='activate')result=inbox.activate(read(input.deliveryRecord),{resultRecipient:input.resultRecipient,previousApprovalDigest:input.previousApprovalDigest??null});
  else if(action==='receive') {
    const envelope=read(input.envelopeFile,6*1024*1024+4096);
    if(Object.keys(envelope).sort().join()!=='approvalDigest,resultEnvelope'||envelope.approvalDigest!==input.approvalDigest)throw Error('Encrypted receipt transport differs from selected approval');
    result=await inbox.receive(input.approvalDigest,envelope.resultEnvelope,load);
  } else if(action==='recover')result=await inbox.recover(input.approvalDigest,load);
  else if(action==='inspect')result=inbox.inspect(input.approvalDigest);
  else if(action==='retire')result=inbox.retire(input.approvalDigest);
  else if(action==='export-browser')result=inbox.exportBrowser(input.approvalDigests,expected=>{
    const source=config.resultKeySources?.[expected.releaseId];
    if(!source?.custody)throw Error('Missing requester result-key custody');
    return read(source.custody,32768);
  });
  else {
    if(!Array.isArray(input.results)||!input.results.length||input.results.length>4096||!config.reconstruction||
      !path.isAbsolute(config.reconstruction.python)||!path.isAbsolute(config.reconstruction.age))throw Error('Require local reconstruction configuration and results');
    const recovered=[];
    for(const item of input.results)recovered.push(await inbox.recover(item.approvalDigest,load));
    const selections=recovered.map(r=>({approvalDigest:r.approvalDigest,receiptSHA256:r.receiptSHA256}));
    result=inbox.useCurrent(selections,approvals=>{
      const request={source:{age:config.reconstruction.age,identity:config.reconstruction.identity,manifest:input.manifest,
        destination:input.destination},packageSHA256:input.packageSHA256,
        results:recovered.map((r,i)=>({receipt:r.receipt,file:input.results[i].file,approval:approvals[i]}))};
      const raw=JSON.stringify(request);if(Buffer.byteLength(raw)>16*1024*1024)throw Error('Reconstruction request exceeds bound');
      return JSON.parse(execFileSync(config.reconstruction.python,[fileURLToPath(new URL('./compute-result-reconstruct-pipe.py',import.meta.url))],
        {input:raw,encoding:'utf8',timeout:600000,maxBuffer:4*1024*1024,windowsHide:true,stdio:['pipe','pipe','ignore']}));
    });
  }
  // Receipt plaintext and identity/result secrets are deliberately non-enumerable
  // or kept in local helpers. Reconstruction reports only requester output paths.
  console.log(JSON.stringify(result,null,2));
}catch{
  // Do not echo subprocess arguments, manifests, cryptographic parser errors or
  // private result content from an untrusted archive into diagnostics.
  console.error(JSON.stringify({error:'Requester result operation failed; keep the recovery files and review the selected approval, custody and local paths.'}));
  process.exitCode=1;
}finally{inbox?.close();}
