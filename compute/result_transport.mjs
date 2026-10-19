// Opaque transport between protected guest and requester. A relay may inspect
// framing, commitments, timing and ciphertext sizes, but receives no content key.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TypedDataEncoder, verifyTypedData } from 'ethers';

const protocol='cannabis.guest-wire.v1',maxControl=6*1024*1024+65536,chunkSize=65536;
const failure=()=>Error('Encrypted guest handoff failed; retain requester recovery material');
const hash=value=>createHash('sha256').update(value).digest('hex');
const fields=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.sort().join();
const digest=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const integer=(value,min,max)=>Number.isSafeInteger(value)&&value>=min&&value<=max;

export class GuestWire {
  #input;#output;#iterator;#pending=Buffer.alloc(0);#timer;#signal;#abort;#end;#failed=false;#closed=false;#cancel=new AbortController();
  constructor(input,output,{timeoutMs,signal}={}) {
    if(!input?.[Symbol.asyncIterator]||typeof output?.write!=='function'||!integer(timeoutMs,1,3600000)||
      signal!==undefined&&!(signal instanceof AbortSignal))throw failure();
    this.#input=input;this.#output=output;this.#iterator=input[Symbol.asyncIterator]();this.#signal=signal;
    this.#end=performance.now()+timeoutMs;this.#abort=()=>this.fail();this.#timer=setTimeout(this.#abort,timeoutMs);
    signal?.addEventListener('abort',this.#abort,{once:true});
    // Destroying either end on expiry/cancellation also unblocks pending reads or
    // backpressured writes. Do not leak transport/parser diagnostics to a host.
    input.on('error',this.#abort);output.on('error',this.#abort);
    if(signal?.aborted)this.fail();
  }
  #check(){if(this.#closed||this.#failed||this.#signal?.aborted||performance.now()>=this.#end){this.fail();throw failure();}}
  async #read(length) {
    this.#check();
    while(this.#pending.length<length) {
      const next=await this.#iterator.next();this.#check();
      if(next.done||!(next.value instanceof Uint8Array)||this.#pending.length+next.value.length>maxControl+chunkSize+10)throw failure();
      this.#pending=Buffer.concat([this.#pending,next.value]);
    }
    const value=this.#pending.subarray(0,length);this.#pending=this.#pending.subarray(length);return value;
  }
  async #frame(kind,limit) {
    const header=await this.#read(5),length=header.readUInt32BE(1);
    if(header[0]!==kind||!integer(length,1,limit))throw failure();
    return this.#read(length);
  }
  async readJSON(limit=maxControl) {
    if(!integer(limit,1,maxControl))throw failure();
    const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await this.#frame(0,limit)));
    this.#check();return value;
  }
  async readChunk(){return this.#frame(1,chunkSize);}
  async #write(kind,bytes,limit) {
    this.#check();if(!bytes.length||bytes.length>limit)throw failure();
    const header=Buffer.alloc(5);header[0]=kind;header.writeUInt32BE(bytes.length,1);
    const frame=Buffer.concat([header,bytes]);
    await new Promise((resolve,reject)=>{
      let finished=false;
      const done=error=>{if(finished)return;finished=true;this.#output.off('close',closed);error?reject(failure()):resolve();};
      const closed=()=>done(failure());this.#output.once('close',closed);
      this.#output.write(frame,done);
    });this.#check();
  }
  async writeJSON(value){return this.#write(0,Buffer.from(JSON.stringify(value)),maxControl);}
  async writeChunk(bytes){return this.#write(1,bytes,chunkSize);}
  get signal(){return this.#cancel.signal;}
  assertActive(){this.#check();}
  fail(){if(this.#failed||this.#closed)return;this.#failed=true;this.#cancel.abort();this.#input.destroy();this.#output.destroy();}
  close(){if(this.#closed)return;this.#closed=true;clearTimeout(this.#timer);this.#signal?.removeEventListener('abort',this.#abort);
    this.#input.off('error',this.#abort);this.#output.off('error',this.#abort);this.#pending=Buffer.alloc(0);}
}

export const resultStoredTypes={ResultStored:[
  {name:'approvalDigest',type:'bytes32'},{name:'envelopeSHA256',type:'bytes32'},
  {name:'ciphertextSHA256',type:'bytes32'},{name:'ciphertextBytes',type:'uint64'}
]};
export function resultStoredPayload(expected,{envelopeSHA256,ciphertextSHA256,ciphertextBytes}) {
  if(expected?.domain?.name!=='Cannabis confidential key delivery'||expected.domain.version!=='2'||
    typeof expected.digest!=='string'||!/^0x[0-9a-f]{64}$/.test(expected.digest)||
    !digest(envelopeSHA256)||!digest(ciphertextSHA256)||!integer(ciphertextBytes,1,1024**4))throw failure();
  const domain={name:'Cannabis encrypted result stored',version:'1',chainId:expected.domain.chainId,
    verifyingContract:expected.domain.verifyingContract};
  const value={approvalDigest:expected.digest,envelopeSHA256:'0x'+envelopeSHA256,
    ciphertextSHA256:'0x'+ciphertextSHA256,ciphertextBytes};
  return {domain,types:resultStoredTypes,value,digest:TypedDataEncoder.hash(domain,resultStoredTypes,value)};
}

export async function sendEncryptedResult(wire,result,expected,{maxCiphertextBytes}={}) {
  if(!integer(maxCiphertextBytes,1,1024**4)||typeof result?.resultEnvelope!=='string'||result.resultEnvelope.length>6*1024*1024||
    typeof result.ciphertext!=='string'||!path.isAbsolute(result.ciphertext))throw failure();
  let fd;
  try {
    fd=fs.openSync(result.ciphertext,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    const stat=fs.fstatSync(fd);if(!stat.isFile()||!integer(stat.size,1,maxCiphertextBytes))throw failure();
    await wire.writeJSON({protocol,operation:'result',approvalDigest:expected.digest,
      resultEnvelope:result.resultEnvelope,ciphertextBytes:stat.size});
    const state=createHash('sha256'),buffer=Buffer.alloc(chunkSize);let sent=0;
    while(sent<stat.size) {
      const count=fs.readSync(fd,buffer,0,Math.min(chunkSize,stat.size-sent),null);if(!count)throw failure();
      const chunk=buffer.subarray(0,count);state.update(chunk);await wire.writeChunk(chunk);sent+=count;
    }
    if(fs.readSync(fd,buffer,0,1,null)!==0)throw failure();
    const ciphertextSHA256=state.digest('hex'),envelopeSHA256=hash(result.resultEnvelope);
    await wire.writeJSON({protocol,operation:'end',ciphertextSHA256});
    const ack=await wire.readJSON(2048),payload=resultStoredPayload(expected,{envelopeSHA256,ciphertextSHA256,ciphertextBytes:sent});
    if(!fields(ack,['protocol','operation','signature'])||ack.protocol!==protocol||ack.operation!=='stored'||
      typeof ack.signature!=='string'||verifyTypedData(payload.domain,payload.types,payload.value,ack.signature)!==expected.requester)throw failure();
    wire.assertActive();
    return {schema:'cannabis.guest-result-handoff.v1',approvalDigest:expected.digest,
      requesterAcknowledgedStorage:true,qualityAccepted:false,paymentAuthorized:false};
  }catch{wire.fail();throw failure();}
  finally{if(fd!==undefined)fs.closeSync(fd);}
}

function syncDirectory(directory) {
  // Windows does not expose fsync for directory handles through this API. The
  // ciphertext itself is fsynced on both platforms; filesystem durability still
  // depends on the requester's storage and backup policy.
  if(process.platform==='win32')return;
  const fd=fs.openSync(directory,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);
  try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
export async function receiveEncryptedResult(wire,{inbox,approvalDigest,loadResultKey,destination,maxCiphertextBytes,signStored}) {
  let fd,temp;
  try {
    if(!integer(maxCiphertextBytes,1,1024**4)||typeof destination!=='string'||!path.isAbsolute(destination)||typeof signStored!=='function')throw failure();
    const header=await wire.readJSON();
    if(!fields(header,['protocol','operation','approvalDigest','resultEnvelope','ciphertextBytes'])||header.protocol!==protocol||
      header.operation!=='result'||header.approvalDigest!==approvalDigest||!integer(header.ciphertextBytes,1,maxCiphertextBytes))throw failure();
    const authenticated=await inbox.receive(approvalDigest,header.resultEnvelope,loadResultKey),receipt=authenticated.receipt;
    if(receipt.ciphertextBytes!==header.ciphertextBytes)throw failure();
    // Never overwrite an existing local artifact. Paths are chosen by the
    // requester, not transported in the guest's message.
    const directory=path.dirname(destination);if(!fs.statSync(directory).isDirectory()||fs.existsSync(destination))throw failure();
    temp=path.join(directory,'.cannabis-receive-'+randomBytes(16).toString('hex'));
    fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);
    const state=createHash('sha256');let received=0;
    while(received<header.ciphertextBytes) {
      const bytes=await wire.readChunk();if(received+bytes.length>header.ciphertextBytes)throw failure();
      state.update(bytes);let offset=0;
      while(offset<bytes.length){const n=fs.writeSync(fd,bytes,offset,bytes.length-offset);if(!n)throw failure();offset+=n;}
      received+=bytes.length;
    }
    const end=await wire.readJSON(1024),ciphertextSHA256=state.digest('hex');
    if(!fields(end,['protocol','operation','ciphertextSHA256'])||end.protocol!==protocol||end.operation!=='end'||
      end.ciphertextSHA256!==ciphertextSHA256||ciphertextSHA256!==receipt.ciphertextSHA256)throw failure();
    fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    wire.assertActive();
    const selection=[{approvalDigest,receiptSHA256:authenticated.receiptSHA256}];
    const expected=inbox.useCurrent(selection,([approval])=>{
      // link is exclusive even if another process creates destination now.
      fs.linkSync(temp,destination);fs.unlinkSync(temp);temp=undefined;syncDirectory(directory);return approval;
    });
    const payload=resultStoredPayload(expected,{envelopeSHA256:authenticated.receiptSHA256,ciphertextSHA256,ciphertextBytes:received});
    const signature=await signStored(payload);
    if(verifyTypedData(payload.domain,payload.types,payload.value,signature)!==expected.requester)throw failure();
    inbox.useCurrent(selection,()=>true); // Replacement while owner signs is not acknowledged.
    await wire.writeJSON({protocol,operation:'stored',signature});
    return Object.defineProperty({schema:'cannabis.requester-result-handoff.v1',approvalDigest,destination,ciphertextSHA256,ciphertextBytes:received,
      ciphertextStored:true,storageAcknowledged:true,outputVerified:false,qualityAccepted:false,paymentAuthorized:false},
      'resultEnvelope',{value:header.resultEnvelope,enumerable:false});
  }catch{wire.fail();throw failure();}
  finally{if(fd!==undefined)fs.closeSync(fd);if(temp)fs.unlinkSync(temp);
    // Once authenticated ciphertext has been published, keep it for recovery even
    // if acknowledgement fails. Never discard the user's only recovered result.
  }
}

export async function serveGuestSession(session,wire,{maxCiphertextBytes}={}) {
  const cancel=()=>session.close();wire.signal.addEventListener('abort',cancel,{once:true});
  try {
    if(wire.signal.aborted)throw failure();
    const evidence=await session.evidence();await wire.writeJSON({protocol,operation:'evidence',evidence});
    const command=await wire.readJSON(128*1024);
    if(!fields(command,['protocol','operation','envelope','expected'])||command.protocol!==protocol||command.operation!=='execute')throw failure();
    const result=await session.executeNative(command.envelope,command.expected);
    const handoff=await sendEncryptedResult(wire,result,command.expected,{maxCiphertextBytes});
    if(Date.now()>=session.serviceInterval.end*1000)throw failure();
    return handoff;
  }catch{wire.fail();throw failure();}
  finally{wire.signal.removeEventListener('abort',cancel);session.close();}
}
export async function receiveGuestEvidence(wire) {
  const response=await wire.readJSON(5*1024*1024);
  if(!fields(response,['protocol','operation','evidence'])||response.protocol!==protocol||response.operation!=='evidence')throw failure();
  // The requester must appraise this evidence and funding before sealing a key.
  return response.evidence;
}
export async function sendGuestExecution(wire,record) {
  if(record?.schema!=='cannabis.key-delivery.record.v2'||!record.expectedApproval||typeof record.envelope!=='string')throw failure();
  return wire.writeJSON({protocol,operation:'execute',envelope:record.envelope,expected:record.expectedApproval});
}
