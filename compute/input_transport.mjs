// Ciphertext intake precedes evidence/session key creation. Upload acknowledgements
// are not attestation, quality acceptance or payment authorization.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

const protocol='cannabis.guest-wire.v1',chunkSize=65536;
const failure=()=>Error('Encrypted input handoff failed; no execution authorized');
const fields=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.sort().join();
const valid=(digest,limit)=>typeof digest==='string'&&/^[0-9a-f]{64}$/.test(digest)&&Number.isSafeInteger(limit)&&limit>=1&&limit<=1024**4;
const size=(value,limit)=>Number.isSafeInteger(value)&&value>=1&&value<=limit;

export async function sendEncryptedInput(wire,{source,packageSHA256,maxCiphertextBytes}) {
  let fd;
  try {
    if(!valid(packageSHA256,maxCiphertextBytes)||typeof source!=='string'||!path.isAbsolute(source))throw failure();
    fd=fs.openSync(source,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    const info=fs.fstatSync(fd);
    if(!info.isFile()||!size(info.size,maxCiphertextBytes))throw failure();
    const ready=await wire.readJSON(1024);
    if(!fields(ready,['protocol','operation','packageSHA256','maxCiphertextBytes'])||ready.protocol!==protocol||
        ready.operation!=='input-ready'||ready.packageSHA256!==packageSHA256||ready.maxCiphertextBytes!==maxCiphertextBytes)throw failure();
    await wire.writeJSON({protocol,operation:'input',packageSHA256,ciphertextBytes:info.size});
    const state=createHash('sha256'),buffer=Buffer.alloc(chunkSize);let count=0;
    while(count<info.size) {
      wire.assertActive();
      const n=fs.readSync(fd,buffer,0,Math.min(chunkSize,info.size-count),null);if(!n)throw failure();
      const bytes=buffer.subarray(0,n);state.update(bytes);await wire.writeChunk(bytes);count+=n;
    }
    if(fs.readSync(fd,buffer,0,1,null)!==0||state.digest('hex')!==packageSHA256)throw failure();
    await wire.writeJSON({protocol,operation:'input-end',packageSHA256});
    const stored=await wire.readJSON(1024);
    if(!fields(stored,['protocol','operation','packageSHA256','ciphertextBytes'])||stored.protocol!==protocol||
        stored.operation!=='input-stored'||stored.packageSHA256!==packageSHA256||stored.ciphertextBytes!==count)throw failure();
    wire.assertActive();
    return {schema:'cannabis.encrypted-input-handoff.v1',packageSHA256,ciphertextBytes:count,
      peerReportedStorage:true,hardwareValidated:false,keyReleased:false,paymentAuthorized:false};
  }catch{wire.fail();throw failure();}
  finally{if(fd!==undefined)fs.closeSync(fd);}
}

export async function receiveEncryptedInput(wire,{destination,packageSHA256,maxCiphertextBytes}) {
  let fd,temp,published=false;
  try {
    if(!valid(packageSHA256,maxCiphertextBytes)||typeof destination!=='string'||!path.isAbsolute(destination))throw failure();
    // This caller-selected directory must be the dedicated, quota-bound volume
    // supplied by the outer launcher. Native admission independently verifies
    // its real kernel limits and the complete input before any key is created.
    const directory=path.dirname(destination);
    for(let current=directory;;current=path.dirname(current)) {
      const s=fs.lstatSync(current);if(!s.isDirectory()||s.isSymbolicLink())throw failure();
      if(current===path.dirname(current))break;
    }
    try{fs.lstatSync(destination);throw failure();}catch(error){if(error.code!=='ENOENT')throw error;}
    await wire.writeJSON({protocol,operation:'input-ready',packageSHA256,maxCiphertextBytes});
    const header=await wire.readJSON(1024);
    if(!fields(header,['protocol','operation','packageSHA256','ciphertextBytes'])||header.protocol!==protocol||
        header.operation!=='input'||header.packageSHA256!==packageSHA256||!size(header.ciphertextBytes,maxCiphertextBytes))throw failure();
    temp=path.join(directory,'.input-'+randomBytes(16).toString('hex'));
    fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);
    const state=createHash('sha256');let count=0;
    while(count<header.ciphertextBytes) {
      const bytes=await wire.readChunk();if(count+bytes.length>header.ciphertextBytes)throw failure();
      state.update(bytes);let offset=0;
      while(offset<bytes.length) {
        wire.assertActive();const n=fs.writeSync(fd,bytes,offset,bytes.length-offset);if(!n)throw failure();offset+=n;
      }
      count+=bytes.length;
    }
    const end=await wire.readJSON(1024);
    if(!fields(end,['protocol','operation','packageSHA256'])||end.protocol!==protocol||end.operation!=='input-end'||
        end.packageSHA256!==packageSHA256||state.digest('hex')!==packageSHA256)throw failure();
    fs.fchmodSync(fd,0o400);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    wire.assertActive();
    fs.linkSync(temp,destination);published=true;fs.unlinkSync(temp);temp=undefined;
    await wire.writeJSON({protocol,operation:'input-stored',packageSHA256,ciphertextBytes:count});
    wire.assertActive();
    return {schema:'cannabis.guest-input-received.v1',packageSHA256,ciphertextBytes:count,
      ciphertextVerified:true,hardwareValidated:false,keyReleased:false,paymentAuthorized:false};
  }catch{
    wire.fail();
    if(published)fs.unlinkSync(destination);
    throw failure();
  }finally{if(fd!==undefined)fs.closeSync(fd);if(temp)fs.unlinkSync(temp);}
}
