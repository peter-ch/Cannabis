#!/usr/bin/env python3
"""Owned encrypted two-rank TCP computation on the actual kernel; no hardware/funds."""
from dataclasses import asdict
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from compute.client import canonical,pack_workload,task_binding_sha256,assemble_results
from compute.guest_deadline import ExecutionDeadline
from compute.guest_job import GuestJobScope
from compute.guest_resources import ResourceLimits,ResourceTreeLimits
from compute.guest_sandbox import tree_digest
from compute.guest_ciphertext import GuestCiphertextStorage,CiphertextLimits
from compute.job_keys import _new_identity

MIB=1024**2
PYTHON=str(Path(sys.executable).resolve())
PROGRAM=r'''
import os,socket,time,struct,errno
rank=int(os.environ['RANK'])
assert os.environ['WORLD_SIZE']=='2'
assert not os.path.exists('/dev/net/tun')
for family,kind,protocol in [(socket.AF_INET6,socket.SOCK_STREAM,0),(socket.AF_INET,socket.SOCK_RAW,0),
                             (socket.AF_NETLINK,socket.SOCK_RAW,2),(socket.AF_NETLINK,socket.SOCK_RAW,16),
                             (socket.AF_PACKET,socket.SOCK_RAW,0),(socket.AF_VSOCK,socket.SOCK_STREAM,0)]:
    try: socket.socket(family,kind,protocol)
    except PermissionError: pass
    else: raise AssertionError('unapproved socket')
assert {name for _,name in socket.if_nameindex()}=={'lo','cannabis0'}
with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0) as query:
    query.settimeout(5)
    body=struct.pack('=BBHiII',socket.AF_UNSPEC,0,0,socket.if_nametoindex('cannabis0'),0,1)
    query.sendto(struct.pack('=IHHII',16+len(body),16,1|4,91,0)+body,(0,0))
    response=query.recv(4096)
    assert struct.unpack_from('=IHHII',response)[1:4:2]==(2,91)
    assert struct.unpack_from('=i',response,16)[0]==-errno.EPERM
if rank==0:
    server=socket.socket();server.bind((os.environ['MASTER_ADDR'],int(os.environ['MASTER_PORT'])));server.listen(1);server.settimeout(15)
    client,_=server.accept();client.settimeout(15)
    value=int(client.recv(16));answer=value+17;client.sendall(str(answer).encode());client.close();server.close()
else:
    deadline=time.monotonic()+15
    for _ in range(100):
        remaining=deadline-time.monotonic()
        if remaining<=0: raise AssertionError('peer absent')
        # A failed connect leaves the socket state unspecified. Each retry must
        # own a new socket; reusing one can abort even after the peer is ready.
        client=socket.socket();client.settimeout(min(1,remaining))
        try: client.connect((os.environ['MASTER_ADDR'],int(os.environ['MASTER_PORT'])));break
        except (ConnectionRefusedError,ConnectionAbortedError,TimeoutError):
            client.close();time.sleep(min(0.05,max(0,deadline-time.monotonic())))
    else: raise AssertionError('peer absent')
    client.settimeout(15);client.sendall(b'25');answer=int(client.recv(16));client.close()
assert answer==42
open('/output/result.txt','w').write(str(answer))
print('owned rank',rank,'completed')
'''

def sha(file):
    with Path(file).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def run(parent,base,tools,*,pytorch_runtime=None):
    module_spec=importlib.util.spec_from_file_location('owned_group_runtime',ROOT/'scripts/check-guest-sandbox.py')
    module=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(module)
    if pytorch_runtime is None:
        module.fixture(base/'root')
    else:
        shutil.copytree(pytorch_runtime,base/'root',symlinks=True)
    runtime={'adapter':'native-group-linux-x86_64-v1','architecture':'x86_64','os':'linux',
             'digestSHA256':tree_digest(base/'root'),'collectiveBackend':'attested-tls-ip-v1'}
    resources={'cpus':1,'memoryMiB':128,'scratchMiB':8,'wallSeconds':60,'nodes':2}
    owner,recipient=_new_identity(str(tools/'age'));job_key,job_recipient=_new_identity(str(tools/'age'))
    source=base/'input';source.mkdir();(source/'program.py').write_text(PROGRAM)
    spec={'schema':'cannabis.workload.v1','id':'owned-group-kernel','policySHA256':'12'*32,'resultRecipient':recipient,'files':['program.py'],
          'tasks':[{'id':'sum','runtime':runtime,'resources':resources,'outputScope':'per-rank',
                    'launch':{'argv':['/usr/bin/python3','-I','-B','/input/program.py'],'stdout':'stdout.txt'},
                    'outputs':['result.txt','stdout.txt'],'outputMaxBytes':4096}],
          'assembly':[{'task':'sum','rank':'all','output':name,'destination':'rank-{rank}/'+name} for name in ['result.txt','stdout.txt']]}
    if pytorch_runtime is not None:
        sys.path.insert(0,str(ROOT/'test/helpers'))
        import pytorch_fixture
        pytorch_fixture.prepare(source)
        resources.update(memoryMiB=512,scratchMiB=32,wallSeconds=120)
        spec['files']=['program.py','training.json']
        task=spec['tasks'][0]
        task['launch']['environment']=pytorch_fixture.ENVIRONMENT
        task['launch']['stderr']='stderr.txt'
        task['outputs']=pytorch_fixture.OUTPUTS
        task['outputMaxBytes']=65536
        spec['assembly']=[{'task':'sum','rank':'all','output':name,'destination':'rank-{rank}/'+name}
                          for name in pytorch_fixture.OUTPUTS]
    package=pack_workload(spec,source,job_recipient,base/'input.age',age=str(tools/'age'))
    binding={'packageSHA256':package['ciphertextSHA256'],'policySHA256':spec['policySHA256'],'runtimeSHA256':runtime['digestSHA256'],
             'taskSHA256':task_binding_sha256(package['ciphertextSHA256'],0),'attempt':1,'rank':0,'worldSize':2,'acceleratorClass':'cpu'}
    # Each rank owns a separate job tree/controller. Production additionally
    # requires a separately admitted protected VM; this kernel check supplies none.
    profile={'schema':'cannabis.guest-native-service.v4','units':1,'runtime':runtime,'resources':resources,
             'total':asdict(ResourceTreeLimits(3000,1024*MIB,192,120,3)),
             'control':asdict(ResourceLimits(1000,512*MIB,64,120)),
             'helper':asdict(ResourceLimits(1000,256*MIB,64,60)),'processLimit':32,'scratchInodes':512,
             'staging':{'bytes':16*MIB,'inodes':1024},
             'ciphertext':{'bytes':9*MIB,'inodes':64,'inputBytes':4*MIB,'outputBytes':4*MIB,'dependencyBytes':MIB},
             'maxInputBytes':MIB,'maxDependencyBytes':MIB,
             'tools':{'pythonSHA256':sha(PYTHON),'ageSHA256':sha(tools/'age'),'ageKeygenSHA256':sha(tools/'age-keygen')},
             'group':{'protocol':'cannabis.group-tls-ip.v1','bindHost':'127.0.0.1','port':29501,'maxBufferedBytes':131072,'maxTrafficBytes':1048576}}
    if pytorch_runtime is not None:
        profile['total'].update(memory_bytes=2048*MIB,processes=256,wall_seconds=240)
        profile['control']['wall_seconds']=240
        profile['processLimit']=64
        profile['group']['maxTrafficBytes']=16*MIB
    storages=[];scopes=[];processes=[];requester=None
    try:
        executions=[]
        for rank in range(2):
            files={'ciphertext':str(base/f'ciphertext-{rank}'/'workload.age'),'destination':str(base/f'ciphertext-{rank}'/'result.age')}
            storages.append(GuestCiphertextStorage(files,CiphertextLimits(**profile['ciphertext'])))
            shutil.copyfile(base/'input.age',files['ciphertext']);Path(files['ciphertext']).chmod(0o400)
            executions.append({'profile':profile,'source':{'python':PYTHON,'rootfs':str(base/'root'),'age':str(tools/'age'),**files}})
        lifetime=240 if pytorch_runtime is not None else 120
        start,end=int(time.time())-1,int(time.time())+lifetime
        # The checkout may belong to an unprivileged CI user. The trusted
        # control program must still have its own root-owned pinned file.
        original=ROOT/'test/helpers/group_native_controller.mjs'
        controller=base/'group-native-controller.mjs'
        controller.write_text(re.sub(r"from '([.][.]/[.][.]/[^']+)'",
            lambda m:"from '"+(original.parent/m.group(1)).resolve().as_uri()+"'",original.read_text()))
        controller.chmod(0o600)
        markers=[str(base/f'key-{rank}') for rank in range(2)]
        job={'identity':job_key.decode('ascii'),'jobId':spec['id'],'packageSHA256':binding['packageSHA256'],
             'policySHA256':spec['policySHA256'],'inputRecipient':job_recipient,'resultRecipient':recipient}
        buffers={};stop=time.monotonic()+lifetime-5
        def send(proc,value):
            raw=canonical(value)+b'\n';offset=0
            while offset<len(raw):
                count=proc.stdin.write(raw[offset:]);assert count and time.monotonic()<stop;offset+=count
        def receive(proc):
            fd=proc.stdout.fileno();pending=buffers.get(fd,b'')
            while b'\n' not in pending:
                left=stop-time.monotonic();assert left>0 and select.select([fd],[],[],left)[0],'Owned group phase expired'
                chunk=os.read(fd,65536);assert chunk,'Owned group process ended before its phase completed'
                pending+=chunk;assert len(pending)<=5*1024**2
            row,remaining=pending.split(b'\n',1);buffers[fd]=remaining;return json.loads(row)
        for rank in range(2):
            scope=GuestJobScope(parent,ResourceTreeLimits(**profile['total']),ResourceLimits(**profile['control']),
                               deadline=ExecutionDeadline.from_service_interval(start,end));scopes.append(scope)
            proc=scope.start(str(tools/'node'),sha(tools/'node'),str(controller),sha(controller));processes.append(proc)
            send(proc,{'rank':rank,'binding':binding,'interval':{'start':start,'end':end},'timeoutMs':(lifetime-10)*1000,
                       'job':job,'marker':markers[rank],'diagnostic':str(base/f'diagnostic-{rank}.txt')})
        channels=[receive(proc)['channelJwk'] for proc in processes]
        requester=subprocess.Popen([str(tools/'node'),str(ROOT/'test/helpers/group_native_requester.mjs')],
                                   stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        send(requester,{'executions':executions,'channelJwks':channels,
                       'workload':{'id':spec['id'],'ciphertextSHA256':binding['packageSHA256'],'policySHA256':spec['policySHA256']}})
        approval=receive(requester)
        for proc in processes:send(proc,approval)
        for proc in processes:assert receive(proc)=={'listening':True}
        for proc in processes:send(proc,{'operation':'connect'})
        readiness=[receive(proc)['readiness'] for proc in processes];send(requester,readiness);started=receive(requester)
        assert requester.wait(timeout=5)==0
        for proc in processes:send(proc,started)
        for proc in processes:assert receive(proc)=={'active':True}
        for proc in processes:send(proc,{'operation':'execute'})
        results=[receive(proc) for proc in processes]
        for proc in processes:assert proc.wait(timeout=5)==0
        for scope in scopes:assert scope.finish()['reason']=='finished'
        assert all(r['groupCompleted'] for r in results)
        assembled=assemble_results(spec,binding['packageSHA256'],[{'receipt':r['receipt'],'file':Path(r['ciphertext'])} for r in results],
                                   owner,base/'assembled',age=str(tools/'age'))
        assert assembled['integrityVerified'] and not assembled['paymentAuthorized']
        weights=[]
        for rank in range(2):
            assert Path(markers[rank]).exists()
            if pytorch_runtime is None:
                assert (base/f'assembled/rank-{rank}/result.txt').read_text()=='42'
            else:
                weights.append(pytorch_fixture.verify(base/f'assembled/rank-{rank}',rank,2))
        assert job_key.strip() not in canonical(results) and not list(parent.glob('job-*'))
        if pytorch_runtime is not None:
            assert weights[0]==weights[1]
            return {'twoRankGlooTraining':True,'synchronizedWeights':True,'numericCheckpointReconstruction':True,
                    'perRankCiphertextReconstruction':True,'unapprovedSocketRefusals':True,
                    'privateTunDeviceHidden':True,'privateInterfaceQueryAndMutationRefusal':True,'wholeTreeCleanup':True}
        return {'twoRankTcpComputation':True,'perRankCiphertextReconstruction':True,'unapprovedSocketRefusals':True,
                'privateTunDeviceHidden':True,'privateInterfaceQueryAndMutationRefusal':True,'wholeTreeCleanup':True}
    finally:
        for diagnostic in base.glob('diagnostic-*.txt'):print(diagnostic.read_text(),file=sys.stderr)
        if requester:
            if requester.poll() is None:requester.kill()
            requester.wait(timeout=5)
            if requester.returncode:print(requester.stderr.read(65536).decode(errors='replace'),file=sys.stderr)
        for scope in reversed(scopes):scope.close()
        for storage in reversed(storages):storage.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--tools',type=Path,required=True)
    parser.add_argument('--pytorch-runtime',type=Path);args=parser.parse_args()
    base=Path('/run')/('cannabis-group-check-'+uuid.uuid4().hex);parent=Path('/sys/fs/cgroup')/base.name
    base.mkdir(mode=0o700);parent.mkdir(mode=0o700);libc=ctypes.CDLL(None,use_errno=True)
    assert libc.unshare(0x20000)==0 and libc.mount(None,b'/',None,0x4000|0x40000,None)==0
    mount_options=b'size=2048m,nr_inodes=50000,mode=0700,noswap' if args.pytorch_runtime else b'size=512m,nr_inodes=30000,mode=0700,noswap'
    assert libc.mount(b'tmpfs',os.fsencode(base),b'tmpfs',2|4,mount_options)==0
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        tools=base/'tools';tools.mkdir()
        for name in ['node','age','age-keygen']:
            shutil.copyfile(args.tools/name,tools/name);(tools/name).chmod(0o755)
        checks=run(parent,base,tools,pytorch_runtime=args.pytorch_runtime)
        print(json.dumps({'schema':'cannabis.guest-group-check.v1','checks':checks,'hardwareValidated':False,'realPaidJob':False}))
    finally:
        if any(p.is_dir() for p in parent.iterdir()):
            (parent/'cgroup.kill').write_text('1');expiry=time.monotonic()+10
            while 'populated 1' in (parent/'cgroup.events').read_text():
                assert time.monotonic()<expiry;time.sleep(0.05)
            for p in sorted(parent.rglob('*'),key=lambda p:len(p.parts),reverse=True):
                if p.is_dir():p.rmdir()
        parent.rmdir();assert libc.umount2(os.fsencode(base),0)==0;base.rmdir()

if __name__=='__main__':main()
