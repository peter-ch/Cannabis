// Disposable interoperability fixture. Never reads project custody or uses RPC.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { Wallet, TypedDataEncoder } from 'ethers';
import { Encrypter, generateIdentity, identityToRecipient } from 'age-encryption';
import { createResultKeyCustody, recoverResultKey } from '../../compute/result_keys.mjs';
import { sealResultDelivery } from '../../compute/result_delivery.mjs';
import { deliveryTypesV2 } from '../../compute/key_delivery.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex'),h=n=>'0x'+n.toString(16).padStart(64,'0');
export async function approvedBrowserFixture({attempt=1,owner,identity,repetitions=1,packageSHA256='a'.repeat(64)}={}) {
  owner??=Wallet.createRandom();identity??=await generateIdentity();
  const recipient=await identityToRecipient(identity),context={chainId:31337,escrow:'0x'+'11'.repeat(20),requester:owner.address};
  const custody=await createResultKeyCustody({releaseId:h(attempt+10),recipient});
  const key=await recoverResultKey(custody,identity,{releaseId:custody.releaseId,recipient,resultKeySHA256:custody.resultKeySHA256});
  const domain={name:'Cannabis confidential key delivery',version:'2',chainId:context.chainId,verifyingContract:context.escrow};
  const value=Object.fromEntries(deliveryTypesV2.JobKeyDelivery.map(({name,type})=>[name,type==='bytes32'?h(3):type==='string'?recipient:1]));
  const policySHA256='b'.repeat(64),runtime='c'.repeat(64);
  const taskSHA256=hash(Buffer.concat([Buffer.from('cannabis.task.v1\0'),Buffer.from(packageSHA256,'hex'),Buffer.alloc(4)]));
  Object.assign(value,{releaseId:custody.releaseId,resultKeySHA256:custody.resultKeySHA256,rank:0,attempt,worldSize:1,
    packageSHA256:'0x'+packageSHA256,policySHA256:'0x'+policySHA256,runtimeSHA256:'0x'+runtime,taskSHA256:'0x'+taskSHA256,notBefore:1000,expiresAt:1060});
  const approval={domain,value,digest:TypedDataEncoder.hash(domain,deliveryTypesV2,value),requester:owner.address,jobId:'owned-browser-fixture',
    requesterSignature:await owner.signTypedData(domain,deliveryTypesV2,value)};
  const archive=new Uint8Array(Buffer.from(execFileSync('python',['test/fixtures/browser-result.py',String(attempt),String(repetitions),packageSHA256],{encoding:'utf8',windowsHide:true}),'base64'));
  const encrypter=new Encrypter();encrypter.addRecipient(recipient);const bytes=await encrypter.encrypt(archive);
  const receipt={schema:'cannabis.result.v1',jobId:approval.jobId,taskId:'calculate',packageSHA256,attempt,rank:0,worldSize:1,
    recipient,ciphertextSHA256:hash(bytes),ciphertextBytes:bytes.length};
  let envelope;try{envelope=await sealResultDelivery(receipt,key,approval);}finally{key.fill(0);}
  const bundle={schema:'cannabis.browser-recovery.v1',context,entries:[{approval,recipient,custody,envelope}]};
  const spec={schema:'cannabis.workload.v1',id:approval.jobId,resultRecipient:recipient,policySHA256,
    tasks:[{id:'calculate',runtime:{digestSHA256:runtime},resources:{nodes:1},outputs:['answer.txt']}],
    assembly:[{task:'calculate',output:'answer.txt',destination:'finished/answer.txt'}]};
  return {bundle,spec,packageSHA256,identity,encrypted:[bytes],owner,receipt};
}
