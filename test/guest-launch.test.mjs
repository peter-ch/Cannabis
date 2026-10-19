import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { Wallet, ZeroAddress } from 'ethers';
import { encodeLaunchJSON, readLaunchJSON, parseLaunchSnapshot, validateLaunchAuthorities, launchConfigurationPayload, verifyLaunchConfiguration, prepareGuestLaunch, publicLaunchAdmission } from '../compute/guest_launch.mjs';

const h=n=>'0x'+n.toString(16).padStart(64,'0');
test('retained launch snapshots preserve canonical inputs and reject ambiguous or extra content',()=>{
  const original={configuration:encodeLaunchJSON({configuration:{name:'Cannabis'},signatures:[]}),
    initialization:encodeLaunchJSON({schema:'owned'}),request:encodeLaunchJSON({proof:{},challenge:{}})};
  const parse=value=>parseLaunchSnapshot(Buffer.from(JSON.stringify(value)));
  assert.deepEqual(parse(original),{signed:{configuration:{name:'Cannabis'},signatures:[]},initialization:{schema:'owned'},request:{proof:{},challenge:{}}});
  for(const value of [{...original,key:'forbidden'},{...original,configuration:'{"x":1,"x":2}\n'},
    {...original,initialization:'{}'},{...original,request:null},{...original,initialization:' '.repeat(65537)}])
    assert.throws(()=>parse(value));
  const bytes=JSON.stringify(original);
  assert.throws(()=>parseLaunchSnapshot(Buffer.from(bytes.slice(0,-1)+',"request":"{}\\n"}')));
  assert.throws(()=>parseLaunchSnapshot(Buffer.from([0xff])));
  assert.throws(()=>parseLaunchSnapshot(Buffer.alloc(17*1024**2+1)));
});
function fixture() {
  const keys=[Wallet.createRandom(),Wallet.createRandom()],pub=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'});
  const authorities={schema:'cannabis.guest-launch-authorities.v1',chainId:31337,signers:keys.map(k=>k.address),threshold:2,maxValiditySeconds:3600};
  const configuration={schema:'cannabis.guest-launch-configuration.v1',configurationId:h(1),validFrom:1000,validUntil:2000,
    context:{chainId:31337,registryId:h(2),token:ZeroAddress},
    network:{rpc:'http://127.0.0.1:8545',chainId:31337,token:ZeroAddress,escrow:keys[0].address,genesisHash:h(3),escrowCodeHash:h(4),
      tokenCodeHash:null,finality:'rpc-finalized',maxFinalizedAgeSeconds:1800,maxHeadAgeSeconds:120},
    provider:keys[1].address,resourceId:h(5),execution:{profile:{schema:'cannabis.guest-native-service.v2',units:1,
      runtime:{adapter:'native-linux-x86_64-v1',architecture:'x86_64',os:'linux',digestSHA256:'bb'.repeat(32)},
      resources:{cpus:1,memoryMiB:128,scratchMiB:8,wallSeconds:60,nodes:1},
      total:{cpu_millis:3000,memory_bytes:1024**3,processes:192,wall_seconds:120,children:3},
      control:{cpu_millis:1000,memory_bytes:512*1024**2,processes:64,wall_seconds:120},
      helper:{cpu_millis:1000,memory_bytes:256*1024**2,processes:64,wall_seconds:60},
      processLimit:32,scratchInodes:512,staging:{bytes:16*1024**2,inodes:1024},ciphertext:{bytes:8*1024**2,inodes:64,inputBytes:4*1024**2,outputBytes:4*1024**2},maxInputBytes:1024**2,
      tools:{pythonSHA256:'aa'.repeat(32),ageSHA256:'bb'.repeat(32),ageKeygenSHA256:'cc'.repeat(32)}},
      source:{python:'/usr/bin/python3',rootfs:'/opt/cannabis/runtime',age:'/usr/local/bin/age',ciphertext:'/run/job/workload.age',destination:'/run/job/result.age'}},
    attestationPolicyTemplate:{schema:'cannabis.attestation.trustee-policy.v1',issuer:'Owned configuration fixture',signingJwk:pub,
      verifierBuild:'Owned signature fixture only',appraisalPolicyId:'owned-fixture',maxTokenAgeSeconds:90,maxTokenLifetimeSeconds:120,challengeTTLSeconds:90,
      tee:'snp',measurements:{launch:'aa'.repeat(48),initData:null,minimumTCB:{bootloader:1,tee:1,snp:1,microcode:1}}},
    bootstrap:{agentBinary:'/usr/local/bin/ttrpc-aa',bridgeBinary:'/usr/local/bin/api-server-rest',runtimeDirectory:'/run',port:8006},
    transport:{timeoutMs:60000,maxCiphertextBytes:4*1024*1024}};
  async function sign(c=configuration,a=authorities) {
    const payload=launchConfigurationPayload(a,c);
    return {configuration:structuredClone(c),signatures:await Promise.all(keys.map(async k=>({signer:k.address,signature:await k.signTypedData(payload.domain,payload.types,payload.value)})))};
  }
  return {keys,authorities,configuration,sign};
}

test('launch configuration quorum authorizes exact image, runtime, RPC and resource settings',async()=>{
  const f=fixture(),signed=await f.sign(),verified=verifyLaunchConfiguration(f.authorities,signed,1500);
  assert.deepEqual(verified.configuration,f.configuration);assert.match(verified.configurationSHA256,/^0x[0-9a-f]{64}$/);
  assert.deepEqual(verifyLaunchConfiguration({...f.authorities,signers:[...f.authorities.signers].reverse()},signed,1500),verified);
  for(const mutate of [c=>c.network.rpc='https://attacker.invalid/',c=>c.execution.profile.runtime.digestSHA256='cc'.repeat(32),
    c=>c.bootstrap.agentBinary='/run/other-agent',c=>c.transport.maxCiphertextBytes++,c=>c.attestationPolicyTemplate.measurements.launch='cc'.repeat(48),
    c=>c.provider=f.keys[0].address,c=>c.validUntil++]) {
    const changed=structuredClone(signed);mutate(changed.configuration);assert.throws(()=>verifyLaunchConfiguration(f.authorities,changed,1500));
  }
});

test('missing, duplicated, foreign and wrong-root authorizations are refused',async()=>{
  const f=fixture(),signed=await f.sign();
  for(const signatures of [[],signed.signatures.slice(0,1),[signed.signatures[0],signed.signatures[0]],
    [{...signed.signatures[0],signer:Wallet.createRandom().address},signed.signatures[1]]])
    assert.throws(()=>verifyLaunchConfiguration(f.authorities,{...signed,signatures},1500));
  for(const change of [{threshold:1},{maxValiditySeconds:7200},{chainId:1},{signers:[f.keys[0].address,Wallet.createRandom().address]}])
    assert.throws(()=>verifyLaunchConfiguration({...f.authorities,...change},signed,1500));
  assert.throws(()=>validateLaunchAuthorities({...f.authorities,signers:[f.keys[0].address,f.keys[0].address]}));
});

test('market launch version binds the market deployment and rejects legacy production admission',async()=>{
  const f=fixture(),c=structuredClone(f.configuration);
  c.schema='cannabis.guest-launch-configuration.v2';c.context={chainId:31337,market:f.keys[0].address,token:ZeroAddress};
  c.network.market=f.keys[0].address;c.network.marketCodeHash=h(90);
  const signed=await f.sign(c),payload=launchConfigurationPayload(f.authorities,c);
  assert.equal(payload.domain.version,'2');assert.equal(verifyLaunchConfiguration(f.authorities,signed,1500).configuration.schema,c.schema);
  for(const mutate of [v=>v.context.market=f.keys[1].address,v=>v.network.marketCodeHash=h(91),
    v=>v.schema='cannabis.guest-launch-configuration.v1',v=>v.context.registryId=h(92)]) {
    const changed=structuredClone(signed);mutate(changed.configuration);assert.throws(()=>verifyLaunchConfiguration(f.authorities,changed,1500));
  }
  assert.throws(()=>publicLaunchAdmission({funding:{proof:{schema:'cannabis.lease-proof.v1'}}}));
});

test('configuration windows, secret-bearing extras and host-selected initialization policy are rejected',async()=>{
  const f=fixture(),signed=await f.sign();
  for(const now of [999,2000,3000,NaN])assert.throws(()=>verifyLaunchConfiguration(f.authorities,signed,now));
  for(const mutate of [c=>c.validUntil=5000,c=>c.privateKey='not-permitted',c=>c.network.rpc='https://user:password@example.invalid/',
    c=>c.network.tokenCodeHash=h(5),c=>c.context.chainId=1,c=>c.bootstrap.command='host command',c=>c.execution.profile.privateKey='forbidden',
    c=>c.attestationPolicyTemplate.measurements.initData='cc'.repeat(32),c=>c.execution.source.python='/run/../host/python',
    c=>c.attestationPolicyTemplate.tee='sample']) {
    const changed=structuredClone(f.configuration);mutate(changed);assert.throws(()=>launchConfigurationPayload(f.authorities,changed));
  }
  assert.throws(()=>prepareGuestLaunch(f.authorities,signed,{}, {proof:{},challenge:{},execution:f.configuration.execution},{now:1500}));
});

test('canonical launch files refuse duplicate keys, oversized data and alternate encodings',t=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-launch-')),file=path.join(directory,'authorities.json');
  t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('cannabis-launch-'));fs.rmSync(directory,{recursive:true,force:true});});
  const f=fixture();fs.writeFileSync(file,encodeLaunchJSON(f.authorities));assert.deepEqual(readLaunchJSON(file),f.authorities);
  assert.throws(()=>readLaunchJSON(file,{limit:10}));
  for(const content of ['{"x":1,"x":2}\n',JSON.stringify(f.authorities,null,2)+'\n','{}','[NaN]\n']) {
    fs.writeFileSync(file,content);assert.throws(()=>readLaunchJSON(file));
  }
  fs.writeFileSync(file,encodeLaunchJSON(f.authorities));
  if(process.platform==='win32')assert.throws(()=>readLaunchJSON(file,{trusted:true}));
  else{fs.chmodSync(file,0o666);assert.throws(()=>readLaunchJSON(file,{trusted:true}));}
});

test('review CLI emits canonical public authorities and unsigned wallet review data',async t=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-launch-cli-'));
  t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('cannabis-launch-cli-'));fs.rmSync(directory,{recursive:true,force:true});});
  const f=fixture(),now=Math.floor(Date.now()/1000),configuration={...f.configuration,validFrom:now-1,validUntil:now+60};
  const authorityFile=path.join(directory,'authorities.json'),configurationFile=path.join(directory,'configuration.json'),signedFile=path.join(directory,'signed.json');
  fs.writeFileSync(authorityFile,encodeLaunchJSON(f.authorities));fs.writeFileSync(configurationFile,encodeLaunchJSON(configuration));
  fs.writeFileSync(signedFile,encodeLaunchJSON(await f.sign(configuration)));
  const run=(action,file)=>execFileSync(process.execPath,['scripts/prepare-guest-launch.mjs',action,authorityFile,...(file?[file]:[])],{encoding:'utf8',stdio:['ignore','pipe','ignore']});
  assert.equal(run('authorities'),encodeLaunchJSON(validateLaunchAuthorities(f.authorities)));
  const prepared=JSON.parse(run('prepare',configurationFile)),verified=JSON.parse(run('verify',signedFile));
  assert.equal(prepared.digest,launchConfigurationPayload(f.authorities,configuration).digest);
  assert.equal(prepared.executionAuthorized,false);assert.equal(verified.hardwareValidated,false);
  assert.equal(verified.configurationSHA256,prepared.value.configurationSHA256);
  for(const key of f.keys)assert.equal(JSON.stringify([prepared,verified]).includes(key.privateKey),false);
});

test('embedded authority reads require actual root ownership and safe Linux paths',
  {skip:process.platform!=='linux'||process.getuid()!==0},t=>{
  const directory=fs.mkdtempSync('/run/cannabis-launch-authority-'),file=path.join(directory,'authorities.json');
  t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),'/run');
    assert.ok(path.basename(directory).startsWith('cannabis-launch-authority-'));fs.rmSync(directory,{recursive:true,force:true});});
  const authorities=validateLaunchAuthorities(fixture().authorities);
  fs.chmodSync(directory,0o700);fs.writeFileSync(file,encodeLaunchJSON(authorities),{mode:0o644});
  assert.deepEqual(readLaunchJSON(file,{trusted:true}),authorities);
  fs.chmodSync(file,0o664);assert.throws(()=>readLaunchJSON(file,{trusted:true}));fs.chmodSync(file,0o644);
  fs.chmodSync(directory,0o770);assert.throws(()=>readLaunchJSON(file,{trusted:true}));fs.chmodSync(directory,0o700);
  fs.chownSync(file,65534,65534);assert.throws(()=>readLaunchJSON(file,{trusted:true}));fs.chownSync(file,0,0);
  const link=path.join(directory,'linked.json');fs.symlinkSync(file,link);
  assert.throws(()=>readLaunchJSON(link,{trusted:true}));
  const parentLink=path.join(directory,'parent');fs.symlinkSync(directory,parentLink);
  assert.throws(()=>readLaunchJSON(path.join(parentLink,'authorities.json'),{trusted:true}));
  const fifo=path.join(directory,'fifo');execFileSync('/usr/bin/mkfifo',[fifo]);
  assert.throws(()=>readLaunchJSON(fifo,{trusted:true}));
  assert.throws(()=>readLaunchJSON(directory,{trusted:true}));
  assert.deepEqual(readLaunchJSON(file,{trusted:true}),authorities);
});
