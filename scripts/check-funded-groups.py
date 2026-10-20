#!/usr/bin/env python3
"""Two guarded native sessions and separate ordinary operators; isolated funding.

Only disposable fixture custody and synthetic appraisals are used. This connects
the actual software boundaries, not confidential hardware or a genuine paid job.
"""
from dataclasses import asdict
import argparse
import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
from urllib.parse import urlparse
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from compute.client import canonical
from compute.job_keys import _new_identity,pack_job
from compute.guest_job import GuestJobScope
from compute.guest_launch_snapshot import LaunchSnapshot
from compute.guest_launcher import authorize_launch,relay_guest
from compute.guest_runtime import FrozenRuntime
from compute.guest_ciphertext import GuestCiphertextStorage
from compute.guest_resources import ResourceLimits,ResourceTreeLimits
from compute.guest_sandbox import tree_digest

MIB=1024**2
PYTHON=str(Path(sys.executable).resolve())


def module(name,file):
    spec=importlib.util.spec_from_file_location(name,file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


volume=module('owned_group_volume',ROOT/'operator/result_volume.py')
single=module('owned_single_funded',ROOT/'scripts/check-funded-native.py')


def sha(file):
    with Path(file).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]


def retained_script(base,name):
    source=ROOT/'test/helpers'/name;target=base/name
    text=re.sub(r"from '([.]/[^']+|[.][.]/[.][.]/[^']+)'",
                lambda m:"from '"+(source.parent/m.group(1)).resolve().as_uri()+"'",source.read_text())
    target.write_text(text);target.chmod(0o600);return target


def rank_run(base,parent,tools,public,config,reader,writer):
    """One separately executed supervisor; no requester custody in its input."""
    scope=operator=None;wire_fds=[];result_home=None;volume_ready=False
    try:
        result_home=Path(tempfile.mkdtemp(prefix='cannabis-group-results-',dir='/var/tmp'))
        volume.create_volume(result_home,96*MIB,4);volume_ready=True
        verifier=base/'authorize.mjs'
        verifier.write_text("import {readRetainedLaunch,publicLaunchAdmission} from "+json.dumps((ROOT/'compute/guest_launch.mjs').as_uri())+
                            ";process.stdout.write(JSON.stringify(publicLaunchAdmission(await readRetainedLaunch()))+'\\n');\n")
        verifier.chmod(0o600)
        guest=retained_script(base,'funded_native_guest.mjs');operator_script=retained_script(base,'funded_native_operator.mjs')
        args=[canonical(public['signedConfiguration'])+b'\n',canonical(public['initialization'])+b'\n',canonical(public['request'])+b'\n']
        with LaunchSnapshot(*args) as snapshot:
            admitted,deadline,transport,source=authorize_launch(str(tools/'node'),sha(tools/'node'),str(verifier),sha(verifier),snapshot.fd)
            assert admitted.value==config['execution']['profile'] and source==config['execution']['source']
            operator_read,relay_write=os.pipe();relay_read,operator_write=os.pipe()
            wire_fds.extend([operator_read,relay_write,relay_read,operator_write])
            spool=result_home/'mount/spool';report_file=base/'operator-report.json'
            operator_config={'public':public,'origin':config['resultOrigin'],'spool':str(spool),'report':str(report_file),
                'dispatchJournal':str(base/'dispatch.sqlite'),
                'fds':{'guestRead':operator_read,'guestWrite':operator_write,'requesterRead':reader,'requesterWrite':writer}}
            assert not any(word in canonical(operator_config) for word in (b'owned-requester.key',b'job-key.age'))
            with (base/'operator.log').open('wb') as log:
                operator=subprocess.Popen([str(tools/'node'),str(operator_script)],cwd=ROOT,
                    stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=log,pass_fds=(operator_read,operator_write,reader,writer),
                    env={'PATH':str(tools)+':/usr/bin:/bin','LANG':'C.UTF-8'})
                for fd in (operator_read,operator_write):os.close(fd);wire_fds.remove(fd)
                os.close(reader);reader=None;os.close(writer);writer=None
                operator.stdin.write(canonical(operator_config));operator.stdin.close();operator.stdin=None
                with FrozenRuntime(source['rootfs'],admitted.value['runtime']['digestSHA256']) as runtime,GuestCiphertextStorage(source,admitted.ciphertext) as storage:
                    deadline.check();runtime.verify();assert not list(storage.path.iterdir())
                    scope=GuestJobScope(parent,admitted.total,admitted.control,deadline=deadline)
                    process=scope.start(str(tools/'node'),sha(tools/'node'),str(guest),sha(guest),launch_fd=snapshot.fd)
                    assert relay_guest(scope,process,relay_read,relay_write,max_ciphertext_bytes=transport['maxCiphertextBytes'],
                                       max_input_ciphertext_bytes=admitted.ciphertext.inputBytes)['reason']=='finished'
                    assert process.wait(timeout=5)==0
                deadline.check()
                for fd in (relay_read,relay_write):os.close(fd);wire_fds.remove(fd)
                assert operator.wait(timeout=10)==0,'Owned operator failed'
            report=json.loads(report_file.read_text())
            required=['signatureForwarded','requesterStorageSignatureVerified','bookedTLSPeerAuthenticated','peerListenerDisposed',
                      'durableDispatchRetained','restartedDispatchRefused','localSpoolReservationRetained','physicalSpoolCapacityChecked',
                      'requesterChallengeHandedOff','operatingPrefixRetained','bootIntakeIsFixture']
            assert all(report[k] is True for k in required)
            assert report['paymentAuthorized'] is False and report['hardwareValidated'] is False
            assert Path(report['sourceFile']).is_file() and Path(report['directory']).parent==spool
        return {'rank':public['initialization']['binding']['rank'],'guestSessionAndNativeCompleted':True,
                'earlyKeyAndDowngradeRefused':True,'sessionReplayRefused':True,'operatorChecks':{k:True for k in required},
                'runtimeMountRetired':True,'ciphertextStorageRetired':not storage.path.exists(),'realPaidJob':False,'hardwareValidated':False}
    finally:
        if operator and operator.poll() is None:operator.kill();operator.wait(timeout=5)
        if scope:scope.close()
        for fd in wire_fds:os.close(fd)
        for fd in (reader,writer):
            if fd is not None:os.close(fd)
        if volume_ready:
            volume.unmount_volume(result_home)
            assert result_home.resolve().parent==Path('/var/tmp').resolve() and result_home.name.startswith('cannabis-group-results-')
            assert sorted(p.name for p in result_home.iterdir())==['mount','result-volume.ext4','volume.json']
            (result_home/'mount').rmdir();(result_home/'result-volume.ext4').unlink();(result_home/'volume.json').unlink();result_home.rmdir()
        elif result_home:print('Incomplete owned result-volume setup retained at '+str(result_home),file=sys.stderr)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--tools',type=Path,required=True)
    parser.add_argument('--node-path',type=Path);args=parser.parse_args()
    base=Path('/run')/('cannabis-funded-group-'+uuid.uuid4().hex);parent=Path('/sys/fs/cgroup')/base.name
    base.mkdir(mode=0o700);parent.mkdir(mode=0o700);libc=ctypes.CDLL(None,use_errno=True)
    assert libc.unshare(0x20000)==0 and libc.mount(None,b'/',None,0x4000|0x40000,None)==0
    assert libc.mount(b'tmpfs',os.fsencode(base),b'tmpfs',2|4,b'size=768m,nr_inodes=35000,mode=0700,noswap')==0
    requester=chain=None;wire_fds=[];children=[];logs=[]
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        tools=base/'tools';tools.mkdir()
        for name in ('node','age','age-keygen'):shutil.copyfile(args.tools/name,tools/name);(tools/name).chmod(0o755)
        kernel=module('owned_group_kernel',ROOT/'scripts/check-guest-groups.py')
        sandbox=module('owned_group_sandbox',ROOT/'scripts/check-guest-sandbox.py');sandbox.fixture(base/'root')
        runtime={'adapter':'native-group-linux-x86_64-v1','architecture':'x86_64','os':'linux','digestSHA256':tree_digest(base/'root'),
                 'collectiveBackend':'attested-tls-ip-v1'}
        resources={'cpus':1,'memoryMiB':128,'scratchMiB':8,'wallSeconds':60,'nodes':2}
        owner,recipient=_new_identity(str(tools/'age'))
        identity=base/'owned-requester.key';identity.write_bytes(owner);identity.chmod(0o600)
        source=base/'input';source.mkdir();(source/'program.py').write_text(kernel.PROGRAM)
        spec={'schema':'cannabis.workload.v1','id':'owned-funded-group','policySHA256':'12'*32,'resultRecipient':recipient,'files':['program.py'],
              'tasks':[{'id':'sum','runtime':runtime,'resources':resources,'outputScope':'per-rank',
                        'launch':{'argv':['/usr/bin/python3','-I','-B','/input/program.py'],'stdout':'stdout.txt'},
                        'outputs':['result.txt','stdout.txt'],'outputMaxBytes':4096}],
              'assembly':[{'task':'sum','rank':'all','output':name,'destination':'rank-{rank}/'+name} for name in ['result.txt','stdout.txt']]}
        descriptor=pack_job(spec,source,recipient,base/'job',str(tools/'age'))
        manifest=base/'workload.json';manifest.write_bytes(canonical(spec))
        profile={'schema':'cannabis.guest-native-service.v4','units':1,'runtime':runtime,'resources':resources,
                 'total':asdict(ResourceTreeLimits(3000,1024*MIB,192,120,3)),'control':asdict(ResourceLimits(1000,512*MIB,64,120)),
                 'helper':asdict(ResourceLimits(1000,256*MIB,64,60)),'processLimit':32,'scratchInodes':512,
                 'staging':{'bytes':16*MIB,'inodes':1024},'ciphertext':{'bytes':9*MIB,'inodes':64,'inputBytes':4*MIB,'outputBytes':4*MIB,'dependencyBytes':MIB},
                 'maxInputBytes':MIB,'maxDependencyBytes':MIB,
                 'tools':{'pythonSHA256':sha(PYTHON),'ageSHA256':sha(tools/'age'),'ageKeygenSHA256':sha(tools/'age-keygen')},
                 'group':{'protocol':'cannabis.group-tls-ip.v1','bindHost':'127.0.0.1','port':29501,'maxBufferedBytes':131072,'maxTrafficBytes':MIB}}
        ranks=[];guest_pipes=[]
        for rank in range(2):
            directory=base/f'rank-{rank}';directory.mkdir()
            own=copy.deepcopy(profile);own['group']['port']=port()
            incoming,requester_write=os.pipe();requester_read,outgoing=os.pipe()
            wire_fds.extend([incoming,requester_write,requester_read,outgoing]);guest_pipes.append((incoming,outgoing))
            ranks.append({'execution':{'profile':own,'source':{'python':PYTHON,'rootfs':str(base/'root'),'age':str(tools/'age'),
                          'ciphertext':str(directory/'ciphertext/workload.age'),'destination':str(directory/'ciphertext/result.age')}},
                          'fds':{'read':requester_read,'write':requester_write},'resultOrigin':'http://127.0.0.1:'+str(port())})
        rpc='http://127.0.0.1:'+str(port());env={'PATH':str(tools)+':/usr/bin:/bin','LANG':'C.UTF-8'}
        if args.node_path:env['NODE_PATH']=str(args.node_path)
        chain_log=(base/'chain.log').open('wb');logs.append(chain_log)
        chain=subprocess.Popen([str(tools/'node'),str(ROOT/'node_modules/hardhat/dist/src/cli.js'),'node','--hostname','127.0.0.1','--port',str(urlparse(rpc).port)],
                               cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=chain_log,stderr=subprocess.STDOUT)
        until=time.monotonic()+30
        while True:
            assert chain.poll() is None,'Owned group chain startup failed'
            try:
                request=urllib.request.Request(rpc,data=canonical({'jsonrpc':'2.0','id':1,'method':'eth_chainId','params':[]}),headers={'Content-Type':'application/json'})
                with urllib.request.urlopen(request,timeout=0.5) as response:
                    if json.load(response)['result']=='0x7a69':break
            except (OSError,ValueError):pass
            assert time.monotonic()<until,'Owned group chain startup expired';time.sleep(0.1)
        directory=base/'requester';directory.mkdir()
        request={'rpc':rpc,'ranks':ranks,'descriptor':descriptor,'spec':spec,'manifest':str(manifest),'directory':str(directory),
                 'assembled':str(base/'assembled'),'inputCiphertext':str(base/'job/workload.age'),'ageKeygen':str(tools/'age-keygen'),
                 'custody':{'python':PYTHON,'age':str(tools/'age'),'identity':str(identity),'capsule':str(base/'job/job-key.age'),'descriptor':str(base/'job/descriptor.json')}}
        requester_fds=tuple(fd for rank in ranks for fd in rank['fds'].values())
        log=(base/'requester.log').open('wb');logs.append(log)
        requester=subprocess.Popen([str(tools/'node'),str(ROOT/'test/helpers/funded_group_requester.mjs')],cwd=ROOT,env=env,
                                   stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,pass_fds=requester_fds)
        for fd in requester_fds:os.close(fd);wire_fds.remove(fd)
        requester.stdin.write(canonical(request));requester.stdin.close();requester.stdin=None
        public=[single.public_launch_frame(reader) for reader,_ in guest_pipes]
        # Exec fresh interpreters so even fixture requester custody is absent
        # from each supervisor's memory, config, environment and command line.
        for rank,((reader,writer),launch,config) in enumerate(zip(guest_pipes,public,ranks)):
            rank_input={'rank':rank,'base':str(base/f'rank-{rank}'),'parent':str(parent),'tools':str(tools),'public':launch,
                        'config':{'execution':config['execution'],'resultOrigin':config['resultOrigin']},
                        'reader':reader,'writer':writer,'report':str(base/f'rank-{rank}.json')}
            body=canonical(rank_input);assert owner.strip() not in body and str(identity).encode() not in body and b'job-key.age' not in body
            log=(base/f'rank-{rank}.log').open('wb');logs.append(log)
            child=subprocess.Popen([PYTHON,'-I','-B',str(Path(__file__).resolve()),'--rank'],
                                   stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=log,pass_fds=(reader,writer),
                                   start_new_session=True,env=env)
            children.append(child);child.stdin.write(body);child.stdin.close();child.stdin=None
        for fd in wire_fds:os.close(fd)
        wire_fds=[]
        raw,_=requester.communicate(timeout=180)
        assert requester.returncode==0,'Owned group requester did not complete'
        reports=[]
        for rank,child in enumerate(children):
            fd=os.pidfd_open(child.pid)
            try:assert select.select([fd],[],[],30)[0],'Owned rank did not retire'
            finally:os.close(fd)
            code=child.wait(timeout=5);children[rank]=None
            report=json.loads((base/f'rank-{rank}.json').read_text());assert code==0,report
            reports.append(report)
        result=json.loads(raw);assert owner.strip() not in raw
        assert all(r['guestSessionAndNativeCompleted'] and r['ciphertextStorageRetired'] for r in reports)
        assert not list(parent.glob('job-*'))
        result.update(rankReports=reports,wholeTreeCleanup=True,kernel=os.uname().release)
        print(json.dumps(result))
    finally:
        if requester and requester.poll() is None:requester.kill();requester.wait(timeout=5)
        for child in children:
            if child is not None:
                fd=os.pidfd_open(child.pid)
                try:
                    if not select.select([fd],[],[],15)[0]:os.killpg(child.pid,signal.SIGTERM)
                    if not select.select([fd],[],[],10)[0]:os.killpg(child.pid,signal.SIGKILL)
                    child.wait(timeout=5)
                finally:os.close(fd)
        for fd in wire_fds:os.close(fd)
        if chain:
            chain.terminate()
            try:chain.wait(timeout=5)
            except subprocess.TimeoutExpired:chain.kill();chain.wait(timeout=5)
        for log in logs:log.close()
        if sys.exc_info()[0] is not None:
            for log in [base/'requester.log',*base.glob('rank-*.log'),*base.glob('rank-*/operator.log')]:
                if log.is_file():print(log.name+': '+log.read_text(errors='replace')[-8192:],file=sys.stderr)
            for report in base.glob('rank-*.json'):print(report.read_text()[-8192:],file=sys.stderr)
        assert not any(p.is_dir() for p in parent.iterdir()),'Owned group tree did not retire'
        parent.rmdir();assert libc.umount2(os.fsencode(base),0)==0;base.rmdir()


if __name__=='__main__':
    if sys.argv[1:]==['--rank']:
        config=json.load(sys.stdin)
        def interrupted(*_): raise RuntimeError('Owned rank supervisor cancelled')
        signal.signal(signal.SIGTERM,interrupted)
        try:
            result=rank_run(Path(config['base']),Path(config['parent']),Path(config['tools']),config['public'],
                            config['config'],config['reader'],config['writer'])
            Path(config['report']).write_bytes(canonical(result))
        except BaseException:
            Path(config['report']).write_bytes(canonical({'rank':config['rank'],'failed':True,'ownedFixtureTrace':traceback.format_exc()}))
            raise
    else:
        def interrupted_main(*_): raise RuntimeError('Owned funded group check cancelled')
        signal.signal(signal.SIGTERM,interrupted_main)
        main()
