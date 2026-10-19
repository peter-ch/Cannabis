// Fresh per-release result secrets. Only encrypted custody records are serializable.
import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const hash=data=>createHash('sha256').update(data).digest('hex');
const fail=()=>Error('Result-key custody does not match the approved release');
export function resultKeyCommitment(key) {
  if(!(key instanceof Uint8Array)||key.length!==32)throw fail();
  return '0x'+hash(key);
}
function expected(value) {
  if(!value||Object.keys(value).sort().join()!=='recipient,releaseId,resultKeySHA256' ||
    !/^0x[0-9a-f]{64}$/.test(value.releaseId)||/^0x0+$/.test(value.releaseId)||
    !/^0x[0-9a-f]{64}$/.test(value.resultKeySHA256)||/^0x0+$/.test(value.resultKeySHA256)||
    !/^age1[0-9a-z]{58}$/.test(value.recipient))throw fail();
}
export async function createResultKeyCustody({releaseId,recipient}) {
  const key=randomBytes(32),resultKeySHA256=resultKeyCommitment(key);
  const binding={releaseId,recipient,resultKeySHA256};expected(binding);
  const cleartext=Buffer.from(JSON.stringify({schema:'cannabis.result-key.v1',...binding,key:key.toString('base64url')}));
  try {
    const {Encrypter}=await import('age-encryption');
    const encrypter=new Encrypter();encrypter.addRecipient(recipient);
    const ciphertext=Buffer.from(await encrypter.encrypt(cleartext));
    return {schema:'cannabis.result-key.custody.v1',...binding,ciphertext: ciphertext.toString('base64url'),ciphertextSHA256:hash(ciphertext)};
  } finally {key.fill(0);cleartext.fill(0);}
}
export function inspectResultKeyCustody(custody,binding) {
  expected(binding);
  if(!custody||Object.keys(custody).sort().join()!=='ciphertext,ciphertextSHA256,recipient,releaseId,resultKeySHA256,schema'||
    custody.schema!=='cannabis.result-key.custody.v1'||Object.entries(binding).some(([k,v])=>custody[k]!==v)||
    typeof custody.ciphertext!=='string'||custody.ciphertext.length>16384||!custody.ciphertext.length||
    !/^[A-Za-z0-9_-]+$/.test(custody.ciphertext))throw fail();
  const bytes=Buffer.from(custody.ciphertext,'base64url');
  if(bytes.toString('base64url')!==custody.ciphertext||hash(bytes)!==custody.ciphertextSHA256)throw fail();
  return bytes;
}
// Use only in trusted requester memory. File/DPAPI recovery is the private child below.
export async function recoverResultKey(custody,identity,binding) {
  custody=structuredClone(custody);binding=structuredClone(binding);
  const bytes=inspectResultKeyCustody(custody,binding);
  const {Decrypter}=await import('age-encryption');
  const decrypter=new Decrypter();decrypter.addIdentity(identity);
  let cleartext;
  try {
    cleartext=await decrypter.decrypt(bytes);
    if(cleartext.length>4096)throw fail();
    const record=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(cleartext));
    if(Object.keys(record).sort().join()!=='key,recipient,releaseId,resultKeySHA256,schema'||record.schema!=='cannabis.result-key.v1'||
      Object.entries(binding).some(([k,v])=>record[k]!==v)||typeof record.key!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(record.key))throw fail();
    const key=Buffer.from(record.key,'base64url');
    if(key.toString('base64url')!==record.key||resultKeyCommitment(key)!==binding.resultKeySHA256){key.fill(0);throw fail();}
    return key;
  } catch {throw fail();}
  finally {cleartext?.fill(0);}
}
// The owner identity remains in this local helper. Only one result secret crosses
// an anonymous pipe; never expose it through a terminal or JSON command result.
export async function recoverRequesterResultKey(source,binding) {
  source=structuredClone(source);binding=structuredClone(binding);expected(binding);
  if(!source||Object.keys(source).sort().join()!=='age,custody,identity,python'||
    Object.values(source).some(v=>typeof v!=='string'||!v||v.includes('\0')))throw fail();
  const {python,...local}=source;
  return new Promise((resolve,reject)=>{
    const child=spawn(python,[fileURLToPath(new URL('../scripts/compute-result-key-pipe.py',import.meta.url))],
      {stdio:['pipe','pipe','ignore'],windowsHide:true,shell:false});
    let failed=false,size=0;const chunks=[];
    const stop=()=>{if(failed)return;failed=true;clearTimeout(timer);for(const b of chunks)b.fill(0);child.kill();reject(fail());};
    const timer=setTimeout(stop,30000);
    child.on('error',stop);child.stdin.on('error',stop);
    child.stdout.on('data',b=>{if(failed){b.fill(0);return;}size+=b.length;if(size>32){b.fill(0);stop();}else chunks.push(b);});
    child.on('close',code=>{
      clearTimeout(timer);if(failed)return;
      const key=Buffer.concat(chunks);for(const b of chunks)b.fill(0);
      try {if(code!==0||resultKeyCommitment(key)!==binding.resultKeySHA256)throw fail();resolve(key);}
      catch{key.fill(0);stop();}
    });
    child.stdin.end(JSON.stringify({protocol:'cannabis.local-result-key.v1',source:local,expected:binding}));
  });
}
