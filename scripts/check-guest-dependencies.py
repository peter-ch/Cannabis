#!/usr/bin/env python3
"""Owned two-task native execution with an encrypted requester-mediated edge.

These kernel components receive retained fixture bindings, not real funding or
attestation. Signed v4/handoff authorization is verified separately by JS tests.
"""
import ctypes
from dataclasses import asdict
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.client import pack_workload,task_binding_sha256,assemble_results
from compute.dependency_bundle import prepare_dependency_bundle
from compute.guest_deadline import ExecutionDeadline
from compute.guest_native import NativeTaskPlan,NativeTaskResult,NATIVE_ADAPTER
from compute.guest_resources import ResourceLimits,ResourceTreeLimits
from compute.guest_job import GuestJobScope
from compute.guest_ciphertext import GuestCiphertextStorage,CiphertextLimits
from compute.guest_sandbox import ScratchLimits,tree_digest
from compute.job_keys import RecoveredJobKey,_new_identity

SCRIPT=str(Path(__file__).resolve());MIB=1024**2
AGE=os.environ.get('CANNABIS_AGE') or shutil.which('age') or '/usr/local/bin/age'
loader=importlib.util.spec_from_file_location('sandbox_fixture',Path(SCRIPT).with_name('check-guest-sandbox.py'))
fixture_module=importlib.util.module_from_spec(loader);loader.loader.exec_module(fixture_module)
MODES=('success','wrong-context','altered-ciphertext','missing-capsule','input-budget','combined-quota','cancel-after-input','deadline',
       'channel-success','channel-input-refusal')


def channel_run(parent,base,own,runtime,resources,key,binding,dependency,destination,mode):
    loader=importlib.util.spec_from_file_location('channel_fixture',Path(SCRIPT).with_name('check-guest-execution.py'))
    channel=importlib.util.module_from_spec(loader);loader.loader.exec_module(channel)
    controller=channel.make_controller(own)
    node=str(base/'tools/node')
    age=base/'tools/age';python=str(Path(sys.executable).resolve())
    pins={'pythonSHA256':channel.sha(python),'ageSHA256':channel.sha(age),'ageKeygenSHA256':channel.sha(age.with_name('age-keygen'))}
    profile={'schema':'cannabis.guest-native-service.v3','units':1,'runtime':runtime,'resources':resources,
        'total':asdict(ResourceTreeLimits(3000,1024*MIB,192,120,3)),
        'control':asdict(ResourceLimits(1000,512*MIB,64,120)),'helper':asdict(ResourceLimits(1000,256*MIB,64,60)),
        'processLimit':32,'scratchInodes':512,'staging':{'bytes':16*MIB,'inodes':1024},
        'ciphertext':{'bytes':12*MIB,'inodes':64,'inputBytes':4*MIB,'outputBytes':4*MIB,'dependencyBytes':4*MIB},
        'maxInputBytes':MIB,'maxDependencyBytes':MIB,'tools':pins}
    source={'python':python,'rootfs':str(base/'root'),'age':str(age),'ciphertext':str(own/'ciphertext/workload.age'),
            'destination':str(own/'ciphertext/result.age')}
    storage_source={k:source[k] for k in ['ciphertext','destination']}
    start,end=int(time.time())-1,int(time.time())+100
    with GuestCiphertextStorage(storage_source,CiphertextLimits(**profile['ciphertext'])):
        for name in ['workload.age','dependency.age']:
            p=own/'ciphertext'/name;shutil.copyfile(own/name,p);p.chmod(0o400)
        if mode=='channel-input-refusal':
            p=own/'ciphertext/dependency.age';p.write_bytes(b'changed before key readiness');p.chmod(0o400)
        with GuestJobScope(parent,ResourceTreeLimits(**profile['total']),ResourceLimits(**profile['control']),
                deadline=ExecutionDeadline.from_service_interval(start,end)) as scope:
            proc=scope.start(node,channel.sha(node),str(controller),channel.sha(controller))
            request={'execution':{'profile':profile,'source':source},'binding':binding,'interval':{'start':start,'end':end},
                'dependency':{'signed':{'handoff':dependency['handoff']}},'mode':mode,
                'readyMarker':str(own/'ready'),'keyMarker':str(own/'key'),'timeoutMs':100000,
                'job':{'identity':key.identity.decode('ascii'),'jobId':key.job_id,'packageSHA256':key.package_sha256,
                       'policySHA256':key.policy_sha256,'inputRecipient':key.input_recipient,'resultRecipient':key.result_recipient}}
            proc.stdin.write(json.dumps(request).encode());proc.stdin.close();code=proc.wait(timeout=110)
            raw=proc.stdout.read(1024*1024)
            if mode=='channel-input-refusal':
                assert code==2 and not (own/'ready').exists() and not (own/'key').exists() and not raw
                raise RuntimeError('Owned dependency was refused before key readiness')
            assert code==0 and (own/'ready').exists() and (own/'key').exists()
            result=json.loads(raw);assert scope.finish()['reason']=='finished'
            assert key.identity.strip() not in raw
            shutil.copyfile(result['ciphertext'],destination)
            return NativeTaskResult(result['report'],result['receipt'],destination)


def actor(parent,base,mode):
    parent,base=Path(parent),Path(base);own=base/mode;own.mkdir(mode=0o700)
    before_mounts=set(Path('/').glob('cannabis-staging-*'))|set(Path('/').glob('cannabis-sandbox-*'))
    inputs=own/'inputs';inputs.mkdir()
    (inputs/'source.py').write_text("open('/output/part','w').write('11')")
    if mode=='combined-quota':
        (inputs/'padding').write_bytes(b'p'*(512*1024))
        (inputs/'source.py').write_text("open('/output/part','w').write('1'*(512*1024))")
    join="from pathlib import Path\nassert not Path('/input/part').exists()\nPath('/output/answer').write_text(str(int(Path('/input/data/value').read_text())+31))\n"
    if mode=='combined-quota':join="from pathlib import Path\nassert len(Path('/input/data/value').read_bytes())==512*1024\nPath('/output/answer').write_text('42')\n"
    if mode=='deadline':join="import time; time.sleep(5)\n"+join
    (inputs/'join.py').write_text(join)
    runtime={'adapter':NATIVE_ADAPTER,'architecture':'x86_64','os':'linux','digestSHA256':tree_digest(base/'root')}
    resources={'cpus':1,'memoryMiB':128,'scratchMiB':8,'wallSeconds':60,'nodes':1}
    owner_secret,owner_public=_new_identity(AGE);input_secret,input_public=_new_identity(AGE)
    spec={'schema':'cannabis.workload.v1','id':'owned-encrypted-edge','policySHA256':'12'*32,'resultRecipient':owner_public,
          'files':sorted(p.name for p in inputs.iterdir()),'tasks':[
          {'id':'upstream','runtime':runtime,'resources':resources,'dependsOn':[],
           'launch':{'argv':['/usr/bin/python3','-I','-B','/input/source.py']},'outputs':['part'],'outputMaxBytes':MIB},
          {'id':'downstream','runtime':runtime,'resources':resources,'dependsOn':['upstream'],
           'dependencyInputs':[{'task':'upstream','rank':0,'output':'part','destination':'data/value'}],'dependencyInputMaxBytes':MIB,
           'launch':{'argv':['/usr/bin/python3','-I','-B','/input/join.py']},'outputs':['answer'],'outputMaxBytes':1024}],
          'assembly':[{'task':'downstream','output':'answer','destination':'answer'}]}
    descriptor=pack_workload(spec,inputs,input_public,own/'workload.age',age=AGE)
    common={'packageSHA256':descriptor['ciphertextSHA256'],'policySHA256':spec['policySHA256'],
            'runtimeSHA256':runtime['digestSHA256'],'attempt':1,'rank':0,'worldSize':1,'acceleratorClass':'cpu'}
    bindings=[{**common,'taskSHA256':task_binding_sha256(descriptor['ciphertextSHA256'],i)} for i in range(2)]
    key=RecoveredJobKey(input_secret,spec['id'],descriptor['ciphertextSHA256'],spec['policySHA256'],input_public,owner_public)
    budgets={'age':AGE,'helper_limits':ResourceLimits(1000,256*MIB,64,60),'staging_limits':ScratchLimits(16*MIB,1024),
             'max_input_bytes':MIB,'max_output_ciphertext_bytes':4*MIB}
    upstream=NativeTaskPlan(base/'root',runtime,resources,process_limit=32,scratch_inodes=512,deadline=ExecutionDeadline(time.monotonic()+120))
    result=upstream.run(parent,own/'workload.age',key,bindings[0],own/'upstream.age',**budgets)
    source={'reservationId':'0x'+'21'*32,'task':0,'taskSHA256':bindings[0]['taskSHA256'],'attempt':1,'rank':0,'worldSize':1,
            'approvalDigest':'0x'+'22'*32,'receiptSHA256':'23'*32,'ciphertextSHA256':result.receipt['ciphertextSHA256'],
            'ciphertextBytes':result.receipt['ciphertextBytes']}
    context={'schema':'cannabis.dependency-context.v1','jobId':spec['id'],**bindings[1],
             'task':1,'inputRecipient':input_public,'sources':[source]}
    approval={'digest':source['approvalDigest'],'jobId':spec['id'],'value':{'reservationId':source['reservationId'],
              **{k:'0x'+bindings[0][k] for k in ['packageSHA256','policySHA256','taskSHA256','runtimeSHA256']},
              'attempt':1,'rank':0,'worldSize':1}}
    handoff=prepare_dependency_bundle(spec,context,[{'receipt':result.receipt,'file':result.ciphertext,'approval':approval}],
        owner_secret,own/'dependency.age',age=AGE)
    dependency={'handoff':handoff,'ciphertext':str(own/'dependency.age')}
    if mode=='wrong-context':dependency['handoff']['context']['attempt']=2
    if mode=='altered-ciphertext':
        data=bytearray((own/'dependency.age').read_bytes());data[-1]^=1;(own/'dependency.age').write_bytes(data)
    if mode=='missing-capsule':dependency=None
    class Cancellation:
        observed=False
        def is_set(self):
            if mode!='cancel-after-input':return False
            self.observed|=any((p/'dependencies').is_dir() for p in set(Path('/').glob('cannabis-staging-*'))-before_mounts)
            return self.observed
    cancellation=Cancellation();destination=own/'downstream.age';refused=False;started=time.monotonic()
    if mode=='combined-quota':budgets['staging_limits']=ScratchLimits(2*MIB,1024)
    try:
        if mode.startswith('channel-'):
            returned=channel_run(parent,base,own,runtime,resources,key,bindings[1],dependency,destination,mode)
        else:
            downstream=NativeTaskPlan(base/'root',runtime,resources,process_limit=32,scratch_inodes=512,
                deadline=ExecutionDeadline(time.monotonic()+(2 if mode=='deadline' else 120)))
            returned=downstream.run(parent,own/'workload.age',key,bindings[1],destination,dependency=dependency,
                max_dependency_bytes=0 if mode=='input-budget' else MIB,cancelled=cancellation,**budgets)
    except (ValueError,RuntimeError,OSError):
        if mode in ['success','channel-success']:raise
        refused=True
    if mode in ['success','channel-success']:
        assembled=assemble_results(spec,descriptor['ciphertextSHA256'],[{'receipt':returned.receipt,'file':destination}],
            owner_secret,own/'assembled',age=AGE)
        assert assembled['integrityVerified'] and not assembled['paymentAuthorized']
        assert (own/'assembled/answer').read_text()=='42'
        assert not returned.report['hardwareAdmissionEstablished']
    else:assert refused and not destination.exists(),'Failure published a dependent result'
    if mode=='cancel-after-input':assert cancellation.observed
    if mode=='deadline':assert 1.5<=time.monotonic()-started<10
    assert not list(parent.glob('job-*'))
    assert before_mounts==set(Path('/').glob('cannabis-staging-*'))|set(Path('/').glob('cannabis-sandbox-*'))
    print(json.dumps({'mode':mode,'passed':True}),flush=True)


def main(modes):
    if sys.platform!='linux' or os.geteuid()!=0:raise RuntimeError('Use a disposable Linux root environment')
    if not modes or any(m not in MODES for m in modes):raise ValueError('Unknown dependency check')
    base=Path('/run')/('cannabis-edge-check-'+uuid.uuid4().hex);parent=Path('/sys/fs/cgroup')/base.name
    base.mkdir(mode=0o700);parent.mkdir(mode=0o700);libc=ctypes.CDLL(None,use_errno=True)
    assert libc.unshare(0x20000)==0
    assert libc.mount(None,b'/',None,0x4000|0x40000,None)==0
    assert libc.mount(b'tmpfs',os.fsencode(base),b'tmpfs',2|4,b'size=512m,nr_inodes=30000,mode=0700,noswap')==0
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids');fixture_module.fixture(base/'root')
        if any(m.startswith('channel-') for m in modes):
            (base/'tools').mkdir(mode=0o700)
            node=os.environ.get('CANNABIS_NODE') or shutil.which('node') or '/usr/local/bin/node'
            for name,source in [('node',node),('age',AGE),('age-keygen',str(Path(AGE).with_name('age-keygen')))]:
                target=base/'tools'/name;shutil.copyfile(source,target);target.chmod(0o755)
        for mode in modes:
            result=subprocess.run([sys.executable,'-I','-B',SCRIPT,'actor',str(parent),str(base),mode],capture_output=True,text=True,timeout=150)
            if result.returncode:
                sys.stderr.write(result.stderr);raise RuntimeError('Owned dependency check failed: '+mode)
            print(result.stdout.strip(),flush=True)
    finally:
        assert not list(parent.glob('job-*'))
        assert libc.umount2(os.fsencode(base),0)==0
        base.rmdir();parent.rmdir()
    print(json.dumps({'checks':len(modes),'cleanupVerified':True,'hardwareAdmissionEstablished':False,'realPaidJob':False}),flush=True)

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='actor':actor(*sys.argv[2:])
    else:main(tuple(sys.argv[1:]) or MODES)
