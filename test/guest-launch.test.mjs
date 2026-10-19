import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { launchFixture as fixture } from './helpers/launch_fixture.mjs';
import { consentFixture } from './helpers/consent_fixture.mjs';
import { validateGuestConfiguration } from '../compute/guest_configuration.mjs';
import { launchConsentPayload } from '../compute/guest_consent.mjs';
import { encodeLaunchJSON, readLaunchJSON, parseLaunchSnapshot, prepareGuestLaunch, publicLaunchAdmission } from '../compute/guest_launch.mjs';

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

test('operating preparation refuses legacy authority envelopes and incomplete consent',async()=>{
  const f=await consentFixture(),request={proof:f.proof,challenge:{}};
  for(const signed of [{configuration:f.configuration,signatures:[]},
    {...f.signed,consents:f.signed.consents.slice(0,1)},{...f.signed,authorities:[]}])
    await assert.rejects(prepareGuestLaunch(signed,f.initialization,request,{clock:()=>1500}),/consent/);
  await assert.rejects(prepareGuestLaunch(f.signed,f.initialization,{...request,execution:f.configuration.execution},{clock:()=>1500}));
  assert.throws(()=>publicLaunchAdmission({funding:{proof:{schema:'cannabis.lease-proof.v1'}}}));
});

test('configuration refuses secret-bearing extras and host-selected initialization policy',()=>{
  const f=fixture();
  for(const mutate of [c=>c.validUntil=c.validFrom,c=>c.validUntil=c.validFrom+366*86400,
    c=>c.privateKey='not-permitted',c=>c.network.rpc='https://user:password@example.invalid/',
    c=>c.network.tokenCodeHash=h(5),c=>c.context.chainId=1,c=>c.bootstrap.command='host command',c=>c.execution.profile.privateKey='forbidden',
    c=>c.attestationPolicyTemplate.measurements.initData='cc'.repeat(32),c=>c.execution.source.python='/run/../host/python',
    c=>c.attestationPolicyTemplate.tee='sample']) {
    const changed=structuredClone(f.configuration);mutate(changed);assert.throws(()=>validateGuestConfiguration(changed));
  }
});

test('canonical launch files refuse duplicate keys, oversized data and alternate encodings',t=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-launch-')),file=path.join(directory,'configuration.json');
  t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('cannabis-launch-'));fs.rmSync(directory,{recursive:true,force:true});});
  const f=fixture();fs.writeFileSync(file,encodeLaunchJSON(f.configuration));assert.deepEqual(readLaunchJSON(file),f.configuration);
  assert.throws(()=>readLaunchJSON(file,{limit:10}));
  for(const content of ['{"x":1,"x":2}\n',JSON.stringify(f.configuration,null,2)+'\n','{}','[NaN]\n']) {
    fs.writeFileSync(file,content);assert.throws(()=>readLaunchJSON(file));
  }
  fs.writeFileSync(file,encodeLaunchJSON(f.configuration));
  if(process.platform==='win32')assert.throws(()=>readLaunchJSON(file,{trusted:true}));
  else{fs.chmodSync(file,0o666);assert.throws(()=>readLaunchJSON(file,{trusted:true}));}
});

test('review CLI prepares separate unsigned participant payloads and never authorizes offline inspection',async t=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-launch-cli-'));
  t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('cannabis-launch-cli-'));fs.rmSync(directory,{recursive:true,force:true});});
  const f=await consentFixture({start:Math.floor(Date.now()/1000)-60});
  const files={};
  for(const [name,value] of Object.entries({configuration:f.configuration,initialization:f.initialization,proof:f.proof,signed:f.signed})) {
    files[name]=path.join(directory,name+'.json');fs.writeFileSync(files[name],encodeLaunchJSON(value));
  }
  const run=(...args)=>JSON.parse(execFileSync(process.execPath,['scripts/prepare-guest-launch.mjs',...args],{encoding:'utf8',stdio:['ignore','pipe','ignore']}));
  const prepared=[];
  for(const role of ['requester','provider']) {
    const value=run('prepare',role,files.configuration,files.initialization,files.proof);prepared.push(value);
    assert.equal(value.digest,launchConsentPayload(f.configuration,f.initialization,f.proof,role).digest);
    assert.equal(value.executionAuthorized,false);assert.equal(value.keyReleaseAuthorized,false);
  }
  assert.notEqual(prepared[0].digest,prepared[1].digest);
  const inspected=run('inspect',files.signed,files.initialization,files.proof);
  assert.equal(inspected.chainVerified,false);assert.equal(inspected.hardwareValidated,false);
  assert.equal(inspected.configurationSHA256,prepared[0].value.configurationSHA256);
  for(const key of [f.requester,f.provider])assert.equal(JSON.stringify([prepared,inspected]).includes(key.privateKey),false);
  for(const args of [['authorities',files.configuration],['prepare','founder',files.configuration,files.initialization,files.proof]])
    assert.throws(()=>run(...args));
});

test('reviewed launch files require actual root ownership and safe Linux paths',
  {skip:process.platform!=='linux'||process.getuid()!==0},t=>{
  const directory=fs.mkdtempSync('/run/cannabis-launch-authority-'),file=path.join(directory,'configuration.json');
  t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),'/run');
    assert.ok(path.basename(directory).startsWith('cannabis-launch-authority-'));fs.rmSync(directory,{recursive:true,force:true});});
  const configuration=fixture().configuration;
  fs.chmodSync(directory,0o700);fs.writeFileSync(file,encodeLaunchJSON(configuration),{mode:0o644});
  assert.deepEqual(readLaunchJSON(file,{trusted:true}),configuration);
  fs.chmodSync(file,0o664);assert.throws(()=>readLaunchJSON(file,{trusted:true}));fs.chmodSync(file,0o644);
  fs.chmodSync(directory,0o770);assert.throws(()=>readLaunchJSON(file,{trusted:true}));fs.chmodSync(directory,0o700);
  fs.chownSync(file,65534,65534);assert.throws(()=>readLaunchJSON(file,{trusted:true}));fs.chownSync(file,0,0);
  const link=path.join(directory,'linked.json');fs.symlinkSync(file,link);
  assert.throws(()=>readLaunchJSON(link,{trusted:true}));
  const parentLink=path.join(directory,'parent');fs.symlinkSync(directory,parentLink);
  assert.throws(()=>readLaunchJSON(path.join(parentLink,'configuration.json'),{trusted:true}));
  const fifo=path.join(directory,'fifo');execFileSync('/usr/bin/mkfifo',[fifo]);
  assert.throws(()=>readLaunchJSON(fifo,{trusted:true}));
  assert.throws(()=>readLaunchJSON(directory,{trusted:true}));
  assert.deepEqual(readLaunchJSON(file,{trusted:true}),configuration);
});
