#!/usr/bin/env python3
"""One owned funded execution; actual kernel, loopback ETH and synthetic appraisal.

Requester and guest run in separate processes with an opaque streaming handoff.
Fixture setup still creates disposable custody. This is not protected hardware,
a key-free production outer launcher or a real paid job.
"""
import argparse
import copy
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from compute.client import canonical, task_binding_sha256
from compute.job_keys import _new_identity, pack_job
from compute.guest_job import GuestJobScope
from compute.guest_launch_snapshot import LaunchSnapshot
from compute.guest_launcher import authorize_launch, relay_guest
from compute.guest_runtime import FrozenRuntime


def public_launch_frame(fd):
    until=time.monotonic()+60
    def read(size):
        raw=bytearray()
        while len(raw)<size:
            remaining=until-time.monotonic()
            if remaining<=0 or not select.select([fd],[],[],remaining)[0]: raise RuntimeError('Owned launch intake timeout')
            chunk=os.read(fd,size-len(raw))
            if not chunk: raise RuntimeError('Owned launch intake ended early')
            raw.extend(chunk)
        return raw
    header=read(5);size=int.from_bytes(header[1:],'big')
    assert header[0]==0 and 0<size<=256*1024
    value=json.loads(read(size))
    assert set(value)=={'authorities','signedConfiguration','initialization','request'}
    return value


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--tools',type=Path,help='Optional directory of already verified fixture tools')
    parser.add_argument('--node-path',type=Path,help='Optional directory of verified native Node dependencies')
    parser.add_argument('--runtime',type=Path,help='Optional built image runtime to copy into owned protected memory')
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('owned_execution_fixture',ROOT/'scripts/check-guest-execution.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    base=Path('/run')/('cannabis-funded-native-'+uuid.uuid4().hex)
    parent=Path('/sys/fs/cgroup')/base.name
    base.mkdir(mode=0o700);parent.mkdir(mode=0o700)
    libc=ctypes.CDLL(None,use_errno=True)
    assert libc.unshare(0x20000)==0
    assert libc.mount(None,b'/',None,0x4000|0x40000,None)==0
    assert libc.mount(b'tmpfs',os.fsencode(base),b'tmpfs',2|4,b'size=768m,nr_inodes=35000,mode=0700,noswap')==0
    chain=None;scope=None;chain_log=None;requester_proc=None;wire_fds=[]
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        tools=base/'tools';tools.mkdir(mode=0o700)
        for name in ['node','age','age-keygen']:
            source=args.tools/name if args.tools else Path(shutil.which(name) or '/usr/local/bin/'+name)
            shutil.copyfile(source,tools/name);(tools/name).chmod(0o755)
        profile,_,_,_,workload=fixture.fixture(base,tools,runtime_source=args.runtime)
        owner_secret,owner_public=_new_identity(str(tools/'age'))
        workload['resultRecipient']=owner_public
        identity=base/'owned-requester.key'
        with identity.open('xb') as out:os.chmod(identity,0o600);out.write(owner_secret)
        descriptor=pack_job(workload,base/'input',owner_public,base/'job',str(tools/'age'))
        controller=base/'owned-controller.mjs'
        source=ROOT/'test/helpers/funded_native_controller.mjs'
        text=source.read_text()
        # The retained controller imports the existing reviewed workspace modules.
        text=re.sub(r"from '([.][.]/[.][.]/[^']+|[.]/guest_agent_fixture.mjs)'",
            lambda m:"from '"+(source.parent/m.group(1)).resolve().as_uri()+"'",text)
        controller.write_text(text);controller.chmod(0o600)
        guest_controller=base/'owned-guest.mjs'
        guest_source=ROOT/'test/helpers/funded_native_guest.mjs'
        guest_text=re.sub(r"from '([.][.]/[.][.]/[^']+|[.]/guest_agent_fixture.mjs)'",
            lambda m:"from '"+(guest_source.parent/m.group(1)).resolve().as_uri()+"'",guest_source.read_text())
        guest_controller.write_text(guest_text);guest_controller.chmod(0o600)
        manifest=base/'owned-manifest.json';manifest.write_bytes(canonical(workload));manifest.chmod(0o600)
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        rpc=f'http://127.0.0.1:{port}'
        env={'PATH':str(tools)+':/usr/bin:/bin','LANG':'C.UTF-8'}
        if args.node_path:env['NODE_PATH']=str(args.node_path)
        chain_log=(base/'chain.log').open('wb')
        chain=subprocess.Popen([str(tools/'node'),str(ROOT/'node_modules/hardhat/dist/src/cli.js'),
            'node','--hostname','127.0.0.1','--port',str(port)],cwd=ROOT,env=env,
            stdin=subprocess.DEVNULL,stdout=chain_log,stderr=subprocess.STDOUT)
        until=time.monotonic()+30
        while True:
            assert chain.poll() is None, 'Owned chain startup failed'
            try:
                request=urllib.request.Request(rpc,data=canonical({'jsonrpc':'2.0','id':1,'method':'eth_chainId','params':[]}),headers={'Content-Type':'application/json'})
                with urllib.request.urlopen(request,timeout=0.5) as response:
                    if json.load(response)['result']=='0x7a69':break
            except (OSError,ValueError):pass
            assert time.monotonic()<until,'Owned chain startup timeout'
            time.sleep(0.1)
        to_guest,requester_write=os.pipe();requester_read,from_guest=os.pipe()
        wire_fds.extend([to_guest,requester_write,requester_read,from_guest])
        request={'rpc':rpc,'artifact':str(ROOT/'artifacts/ComputeEscrow.json'),'descriptor':descriptor,
            'execution':{'profile':profile,'source':{'python':fixture.PYTHON,'rootfs':str(base/'root'),'age':str(tools/'age'),
                'ciphertext':str(base/'job/workload.age'),'destination':str(base/'result.age')}},
            'run':{'runtimeSHA256':profile['runtime']['digestSHA256'],
                'taskSHA256':task_binding_sha256(descriptor['ciphertextSHA256'],0),'attempt':1,'rank':0,'worldSize':1,'acceleratorClass':'cpu'},
            'custody':{'python':fixture.PYTHON,'age':str(tools/'age'),'identity':str(identity),
                'capsule':str(base/'job/job-key.age'),'descriptor':str(base/'job/descriptor.json')},
            'ageKeygen':str(tools/'age-keygen'),'spec':workload,'assembled':str(base/'assembled'),
            'resultCustody':str(base/'result-key-custody.json'),'resultManifest':str(manifest),
            'resultsCLI':str(ROOT/'scripts/compute-results.mjs'),'resultBase':str(base/'requester-results'),
            'wireFDs':{'read':requester_read,'write':requester_write}}
        requester_proc=subprocess.Popen([str(tools/'node'),str(controller)],cwd=ROOT,env=env,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,pass_fds=(requester_read,requester_write))
        for fd in [requester_read,requester_write]:os.close(fd);wire_fds.remove(fd)
        requester_proc.stdin.write(canonical(request));requester_proc.stdin.close();requester_proc.stdin=None
        public=public_launch_frame(to_guest)
        authority_file=base/'owned-authorities.json';authority_file.write_bytes(canonical(public['authorities'])+b'\n');authority_file.chmod(0o600)
        verifier=base/'owned-authorize.mjs'
        verifier.write_text("import { readLaunchJSON, readRetainedLaunch, publicLaunchAdmission } from "+json.dumps((ROOT/'compute/guest_launch.mjs').as_uri())+";\n"
            +"process.stdout.write(JSON.stringify(publicLaunchAdmission(readRetainedLaunch(readLaunchJSON("+json.dumps(str(authority_file))+",{trusted:true}))))+'\\n');\n")
        verifier.chmod(0o600)
        snapshot_args=lambda signed:(canonical(signed)+b'\n',canonical(public['initialization'])+b'\n',canonical(public['request'])+b'\n')
        altered=copy.deepcopy(public['signedConfiguration']);altered['configuration']['transport']['maxCiphertextBytes']+=1
        with LaunchSnapshot(*snapshot_args(altered)) as invalid:
            try:authorize_launch(str(tools/'node'),fixture.sha(tools/'node'),str(verifier),fixture.sha(verifier),invalid.fd)
            except ValueError:pass
            else:raise AssertionError('Changed launch was accepted before allocation')
        assert not any(p.is_dir() for p in parent.iterdir())
        with LaunchSnapshot(*snapshot_args(public['signedConfiguration'])) as snapshot:
            admitted,deadline,transport,admitted_source=authorize_launch(str(tools/'node'),fixture.sha(tools/'node'),str(verifier),fixture.sha(verifier),snapshot.fd)
            assert admitted.value==profile
            assert admitted_source==request['execution']['source']
            with FrozenRuntime(admitted_source['rootfs'],admitted.value['runtime']['digestSHA256']) as prepared:
                deadline.check()
                prepared.verify()
                scope=GuestJobScope(parent,admitted.total,admitted.control,deadline=deadline)
                proc=scope.start(str(tools/'node'),fixture.sha(tools/'node'),str(guest_controller),fixture.sha(guest_controller),launch_fd=snapshot.fd)
                assert relay_guest(scope,proc,to_guest,from_guest,max_ciphertext_bytes=transport['maxCiphertextBytes'])['reason']=='finished'
        raw,_=requester_proc.communicate(timeout=30)
        code=requester_proc.returncode
        assert code==0, f'Owned funded controller exited {code}'
        assert proc.wait(timeout=5)==0, 'Separate guarded guest did not acknowledge delivery and exit'
        result=json.loads(raw)
        assert not list(parent.glob('job-*'))
        assert owner_secret.strip() not in raw
        result['wholeTreeCleanup']=True
        result['checks'].update(authorizationBeforeAllocation=True,changedLaunchRefusedBeforeAllocation=True,
            sealedLaunchReverifiedInControl=True,guardianMonitoredEncryptedRelay=True,
            authorizedRuntimePreparedBeforeControl=True,runtimeMountRetired=True)
        result['runtimeSource']='built image' if args.runtime else 'owned fixture'
        result['runtimeSHA256']=profile['runtime']['digestSHA256']
        result['kernel']=os.uname().release
        print(json.dumps(result))
    finally:
        if requester_proc and requester_proc.poll() is None:requester_proc.kill();requester_proc.wait(timeout=5)
        if scope:scope.close()
        for fd in wire_fds:os.close(fd)
        if chain:
            chain.terminate()
            try:chain.wait(timeout=5)
            except subprocess.TimeoutExpired:chain.kill();chain.wait(timeout=5)
        if chain_log:chain_log.close()
        # Own disposable groups only. The guardian must retire any admitted tree.
        assert not any(p.is_dir() for p in parent.iterdir())
        parent.rmdir()
        assert libc.umount2(os.fsencode(base),0)==0
        base.rmdir()


if __name__=='__main__':main()
