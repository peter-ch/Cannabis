import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runNativeGuestPipe } from '../compute/guest_execution.mjs';

const script = `import json,os,sys,time
def receive():
 n=int.from_bytes(sys.stdin.buffer.read(4),'big');return json.loads(sys.stdin.buffer.read(n))
def frame(v):
 b=json.dumps(v,separators=(',',':')).encode();return len(b).to_bytes(4,'big')+b
def send(v):sys.stdout.buffer.write(frame(v));sys.stdout.buffer.flush()
r=receive();mode=r['mode'];nonce='ab'*32
ready={'protocol':r['protocol'],'operation':'ready','nonce':nonce,'serviceSHA256':r['serviceSHA256']}
if mode=='early-result':send({'operation':'complete'});sys.exit()
if mode=='wrong-service':ready['serviceSHA256']='0x'+'ff'*32
if mode=='oversized':sys.stdout.buffer.write((7000000).to_bytes(4,'big'));sys.stdout.buffer.flush();time.sleep(5)
if mode=='partial':sys.stdout.buffer.write(b'\\x00\\x00');sys.stdout.buffer.flush();sys.exit()
if mode=='duplicate':sys.stdout.buffer.write(frame(ready)+frame(ready));sys.stdout.buffer.flush();time.sleep(5)
send(ready)
if mode=='pause':time.sleep(5)
request=receive();assert request['operation']=='execute' and request['nonce']==nonce
assert sys.stdin.buffer.read()==b''
report={'schema':'cannabis.guest-native-result.v1','executionCompleted':True,'resultEncrypted':True,'runtimeCleanupVerified':True,'hardwareAdmissionEstablished':False,'paymentAccepted':False}
done={'protocol':r['protocol'],'operation':'complete','nonce':nonce,'report':report,'receipt':{'ownedFixtureOnly':True}}
if mode=='wrong-nonce':done['nonce']='cd'*32
if mode=='private-report':report['unexpectedPrivateField']='OWNED-FIXTURE-PRIVATE-CONTENT'
send(done)
if mode=='trailing':send(done)
if mode=='nonzero':sys.exit(2)
if mode=='descendant':
 if os.fork()==0:time.sleep(5)
`;

test('native key release waits for one matching readiness and rejects malformed lifecycle messages', { skip: process.platform !== 'linux' }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owned-native-pipe-')), file = path.join(root, 'fixture.py');
  fs.writeFileSync(file, script);
  try {
    for (const mode of ['success','early-result','wrong-service','oversized','partial','duplicate','wrong-nonce','private-report','trailing','nonzero','descendant']) {
      let releases = 0;
      const pending = runNativeGuestPipe('/usr/bin/python3', file, { protocol:'cannabis.guest-native.pipe.v1', mode, serviceSHA256:'0x'+'12'.repeat(32) },
        async () => { releases++; return { identity:'OWNED-FIXTURE-SECRET' }; }, { timeoutMs:1000 });
      if (['success','descendant'].includes(mode)) {
        const result = await pending; assert.equal(result.report.executionCompleted,true); assert.equal(releases,1);
      } else {
        await assert.rejects(pending, e => e.message === 'Protected native execution failed; retire the job');
        assert.equal(releases, ['wrong-nonce','private-report','trailing','nonzero'].includes(mode) ? 1 : 0, mode);
      }
    }
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('cancellation during asynchronous key opening never transmits a later key', { skip: process.platform !== 'linux' }, async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'owned-native-cancel-')), file=path.join(root,'fixture.py');
  fs.writeFileSync(file,script);
  try {
    const abort=new AbortController();let release, begun;
    const started=new Promise(resolve=>{begun=resolve;});
    const pending=runNativeGuestPipe('/usr/bin/python3',file,{protocol:'cannabis.guest-native.pipe.v1',mode:'pause',serviceSHA256:'0x'+'12'.repeat(32)},
      ()=>{begun();return new Promise(resolve=>{release=resolve;});},{timeoutMs:1000,signal:abort.signal});
    const failed=assert.rejects(pending,/retire the job/);
    await started;abort.abort();await failed;
    release({identity:'OWNED-FIXTURE-SECRET'});
    await new Promise(resolve=>setTimeout(resolve,20));
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});
