#!/usr/bin/env python3
"""Owned two-phase execution checks; no customer keys, hardware or real payment."""
from dataclasses import asdict
import argparse
import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from compute.client import canonical, pack_workload, task_binding_sha256, assemble_results
from compute.guest_deadline import ExecutionDeadline
from compute.guest_job import GuestJobScope
from compute.guest_resources import ResourceLimits, ResourceTreeLimits
from compute.guest_sandbox import tree_digest
from compute.job_keys import _new_identity
from compute.guest_ciphertext import GuestCiphertextStorage, CiphertextLimits

MIB = 1024**2
PYTHON = str(Path(sys.executable).resolve())


def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def make_controller(base):
    script = base/'owned-controller.mjs'
    script.write_text('''import fs from 'node:fs';
import { executeNativeGuest } from MODULE;
let raw='';for await(const part of process.stdin)raw+=part;
const input=JSON.parse(raw);
try {
 const result=await executeNativeGuest(input.execution,input.binding,input.interval,async()=>{
  fs.writeFileSync(input.readyMarker,'ready');
  if(input.mode==='owner-death'||input.mode==='deadline')await new Promise(()=>{});
  fs.writeFileSync(input.keyMarker,'owned fixture key released');
  return input.job;
 },{timeoutMs:input.timeoutMs});
 if(JSON.stringify(result).includes('receipt')||JSON.stringify(result).includes('ciphertext'))throw Error('Private metadata enumerable');
 process.stdout.write(JSON.stringify({report:result,receipt:result.receipt,ciphertext:result.ciphertext}));
}catch{process.stderr.write('Owned execution fixture refused\\n');process.exitCode=2;}
'''.replace('MODULE', json.dumps((ROOT/'compute/guest_execution.mjs').as_uri())))
    script.chmod(0o600)
    return script


def fixture(base, tools, *, runtime_source=None):
    if runtime_source is None:
        specification = importlib.util.spec_from_file_location('native_runtime_fixture', ROOT/'scripts/check-guest-sandbox.py')
        module = importlib.util.module_from_spec(specification); specification.loader.exec_module(module)
        module.fixture(base/'root')
    else:
        shutil.copytree(runtime_source, base/'root', symlinks=True)
    source = base/'input'; source.mkdir(mode=0o700)
    (source/'data.txt').write_text('owned private channel input')
    (source/'program.py').write_text("print('owned private channel log'); open('/output/result.txt','w').write(open('/input/data.txt').read().upper())")
    runtime = {'adapter':'native-linux-x86_64-v1', 'architecture':'x86_64', 'os':'linux', 'digestSHA256':tree_digest(base/'root')}
    resources = {'cpus':1, 'memoryMiB':128, 'scratchMiB':8, 'wallSeconds':60, 'nodes':1}
    owner_secret, owner_public = _new_identity(str(tools/'age'))
    job_secret, job_public = _new_identity(str(tools/'age'))
    spec = {'schema':'cannabis.workload.v1', 'id':'owned-channel-job', 'policySHA256':'12'*32,
        'resultRecipient':owner_public, 'files':['data.txt','program.py'],
        'tasks':[{'id':'owned-task', 'runtime':runtime, 'resources':resources,
                  'launch':{'argv':['/usr/bin/python3','-I','-B','/input/program.py'], 'stdout':'stdout.txt'},
                  'outputs':['result.txt','stdout.txt'], 'outputMaxBytes':4096}],
        'assembly':[{'task':'owned-task','output':name,'destination':name} for name in ['result.txt','stdout.txt']]}
    package = pack_workload(spec, source, job_public, base/'input.age', age=str(tools/'age'))
    binding = {'packageSHA256':package['ciphertextSHA256'], 'policySHA256':spec['policySHA256'],
        'runtimeSHA256':runtime['digestSHA256'], 'taskSHA256':task_binding_sha256(package['ciphertextSHA256'],0),
        'attempt':1, 'rank':0, 'worldSize':1, 'acceleratorClass':'cpu'}
    profile = {'schema':'cannabis.guest-native-service.v2', 'units':1, 'runtime':runtime, 'resources':resources,
        'total':asdict(ResourceTreeLimits(3000,1024*MIB,192,120,3)),
        'control':asdict(ResourceLimits(1000,512*MIB,64,120)),
        'helper':asdict(ResourceLimits(1000,256*MIB,64,60)), 'processLimit':32, 'scratchInodes':512,
        'staging':{'bytes':16*MIB, 'inodes':1024}, 'ciphertext':{'bytes':8*MIB,'inodes':64,'inputBytes':4*MIB,'outputBytes':4*MIB}, 'maxInputBytes':MIB,
        'tools':{'pythonSHA256':sha(PYTHON), 'ageSHA256':sha(tools/'age'), 'ageKeygenSHA256':sha(tools/'age-keygen')}}
    job = {'identity':job_secret.decode('ascii'), 'jobId':spec['id'], 'packageSHA256':binding['packageSHA256'],
           'policySHA256':spec['policySHA256'], 'inputRecipient':job_public, 'resultRecipient':owner_public}
    return profile, binding, job, owner_secret, spec


def run(parent, base, tools):
    profile, binding, job, owner_secret, spec = fixture(base, tools)
    controller = make_controller(base)
    checks = {}
    for mode in ['success', 'resource-change', 'profile-underbudget', 'runtime-change', 'input-change', 'storage-change', 'owner-death', 'deadline']:
        print('Owned protected channel check: '+mode, file=sys.stderr, flush=True)
        selected = copy.deepcopy(profile)
        if mode == 'profile-underbudget': selected['staging']['bytes'] = 512*MIB
        marker, key_marker = base/(mode+'-ready'), base/(mode+'-key')
        if mode == 'runtime-change': (base/'root/changed').write_text('owned changed runtime')
        seconds = 45 if mode == 'deadline' else 120
        start, end = int(time.time())-1, int(time.time())+seconds
        deadline = ExecutionDeadline.from_service_interval(start,end)
        storage_source={'ciphertext':str(base/('ciphertext-'+mode)/'workload.age'),
                        'destination':str(base/('ciphertext-'+mode)/'result.age')}
        storage=GuestCiphertextStorage(storage_source,CiphertextLimits(**profile['ciphertext']))
        scope=None
        try:
            shutil.copyfile(base/'input.age',storage_source['ciphertext'])
            if mode=='input-change':Path(storage_source['ciphertext']).write_bytes(b'changed owned ciphertext')
            Path(storage_source['ciphertext']).chmod(0o400)
            if mode=='storage-change':
                assert ctypes.CDLL(None,use_errno=True).mount(None,os.fsencode(storage.path),None,32|2|4|8,b'size=4m,nr_inodes=64,noswap')==0
            scope = GuestJobScope(parent, ResourceTreeLimits(**profile['total']), ResourceLimits(**profile['control']), deadline=deadline)
            if mode == 'resource-change': (scope.path/'memory.max').write_text(str(1020*MIB))
            proc = scope.start(str(tools/'node'), sha(tools/'node'), str(controller), sha(controller))
            request = {'execution':{'profile':selected, 'source':{'python':PYTHON, 'rootfs':str(base/'root'),
                'age':str(tools/'age'), **storage_source}},
                'binding':binding, 'interval':{'start':start,'end':end}, 'job':job,
                'mode':mode, 'readyMarker':str(marker), 'keyMarker':str(key_marker), 'timeoutMs':seconds*1000}
            # The harness acts as the owner/requester for owned fixture keys. Real
            # outer scope owners must never receive customer content or job keys.
            proc.stdin.write(canonical(request)); proc.stdin.close()
            if mode in ['owner-death','deadline']:
                until = time.monotonic()+60
                while not marker.exists():
                    if proc.poll() is not None or time.monotonic() >= until:
                        raise AssertionError('Controller did not reach key-free readiness')
                    time.sleep(0.03)
                assert not key_marker.exists()
                if mode == 'owner-death':
                    os.kill(proc.pid,signal.SIGKILL)
                    proc.wait(timeout=5)
                    scope.close()
                else:
                    result = scope._guard.wait()
                    assert result['reason'] == 'deadline'
                    proc.wait(timeout=5)
                assert not scope.path.exists()
                assert not Path(storage_source['destination']).exists() and not key_marker.exists()
            else:
                code = proc.wait(timeout=100)
                assert code == (0 if mode == 'success' else 2), f'Owned controller exit code {code}'
                raw = proc.stdout.read(1024*1024)
                if mode == 'success':
                    assert marker.exists() and key_marker.exists()
                    result = json.loads(raw)
                    assert scope.finish()['reason'] == 'finished'
                    assembled = assemble_results(spec, binding['packageSHA256'],
                        [{'receipt':result['receipt'], 'file':Path(result['ciphertext'])}],
                        owner_secret, base/'assembled', age=str(tools/'age'))
                    assert assembled['integrityVerified'] and not assembled['paymentAuthorized']
                    assert (base/'assembled/result.txt').read_text() == 'OWNED PRIVATE CHANNEL INPUT'
                    assert (base/'assembled/stdout.txt').read_text() == 'owned private channel log\n'
                    assert job['identity'].encode().strip() not in raw
                else:
                    assert not marker.exists() and not key_marker.exists() and not raw
                    assert not Path(storage_source['destination']).exists()
            checks[mode] = True
        finally:
            if scope:scope.close()
            storage.close()
            if mode == 'runtime-change': (base/'root/changed').unlink()
        assert not list(parent.glob('job-*'))
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tools', type=Path, help='Optional shared directory of already verified fixture tools')
    args = parser.parse_args()
    base = Path('/run')/('cannabis-execution-check-'+uuid.uuid4().hex)
    parent = Path('/sys/fs/cgroup')/base.name
    base.mkdir(mode=0o700); parent.mkdir(mode=0o700)
    libc = ctypes.CDLL(None,use_errno=True)
    assert libc.unshare(0x20000)==0
    assert libc.mount(None,b'/',None,0x4000|0x40000,None)==0
    assert libc.mount(b'tmpfs',os.fsencode(base),b'tmpfs',2|4,b'size=512m,nr_inodes=30000,mode=0700,noswap')==0
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        tools = base/'tools'; tools.mkdir(mode=0o700)
        for name in ['node','age','age-keygen']:
            source = args.tools/name if args.tools else Path(shutil.which(name) or '/usr/local/bin/'+name)
            shutil.copyfile(source,tools/name); (tools/name).chmod(0o755)
        checks = run(parent,base,tools)
        print(json.dumps({'schema':'cannabis.guest-execution-check.v1', 'kernel':os.uname().release,
            'checks':checks, 'requesterReconstruction':True, 'customerCodeExecuted':False,
            'hardwareValidated':False, 'realPaidJob':False}))
    finally:
        if any(p.is_dir() for p in parent.iterdir()):
            (parent/'cgroup.kill').write_text('1')
            expiry=time.monotonic()+10
            while 'populated 1' in (parent/'cgroup.events').read_text():
                assert time.monotonic()<expiry; time.sleep(0.05)
            for p in sorted(parent.rglob('*'),key=lambda p:len(p.parts),reverse=True):
                if p.is_dir(): p.rmdir()
        parent.rmdir()
        assert libc.umount2(os.fsencode(base),0)==0
        base.rmdir()


if __name__=='__main__': main()
