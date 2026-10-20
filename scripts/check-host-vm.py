#!/usr/bin/env python3
"""Owned Linux host lifecycle checks. No SNP admission, customer keys or payment.

Explicit TCG/-version adapters below exercise process ownership and rejection;
they are only in this diagnostic script, never selectable by production profiles.
"""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import types

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
module=types.ModuleType('cannabis_host');module.__path__=[str(ROOT/'operator')];sys.modules['cannabis_host']=module
from cannabis_host.snp_profile import SnpProfile,COMMAND,SEALS
from cannabis_host.host_vm import OwnedSnpVm,VmSlot,fork_qemu,request_checked
from compute.guest_guardian import GuardedResources
from compute.guest_deadline import ExecutionDeadline


class OrdinaryRefusalFixture(SnpProfile):
    def require_hardware(self):return {'fixture':True,'hardwareValidated':False}
    def arguments(self,snapshots,control,qmp,init_data):
        return ['qemu-system-x86_64','-no-user-config','-nodefaults','-machine','none,accel=tcg',
                '-display','none','-monitor','none','-serial','none','-S',
                '-chardev',f'socket,id=qmp,fd={qmp}','-mon','chardev=qmp,mode=control']


class ExecutableFixture(OrdinaryRefusalFixture):
    def arguments(self,*args):return ['qemu-system-x86_64','--version']


def fixture_files(root,parent):
    def record(path):return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    for name in ['firmware','kernel','initramfs']:(root/name).write_bytes(b'OWNED NONBOOTABLE ARTIFACT '+name.encode())
    (root/'cmdline').write_bytes(COMMAND.encode()+b'\n')
    boot={name:record(root/name) for name in ['firmware','kernel','initramfs','cmdline']}
    ref={'schema':'cannabis.snp-reference-candidate.v1','vcpuType':'EPYC-Milan','vcpus':4,'guestFeatures':'0x21',
        'kernelCommandLine':COMMAND,'commandLineHashIncludesNul':True,'expectedLaunchDigest':'11'*48,
        'firmware':{k:boot['firmware'][k] for k in ['bytes','sha256']},
        'guestImage':{key:{k:boot[name][k] for k in ['bytes','sha256']} for name,key in
            [('kernel','vmlinuz'),('initramfs','initramfs.cpio.gz'),('cmdline','cmdline')]}}
    (root/'reference.json').write_text(json.dumps(ref))
    value={'schema':'cannabis.host-snp-profile.v1','qemu':record(Path('/usr/bin/qemu-system-x86_64')),
        'boot':boot,'reference':record(root/'reference.json'),'machine':'pc-q35-9.1','cpu':'EPYC-Milan','cpus':4,'memoryMiB':4096,
        'snp':{'cbitpos':51,'reducedPhysBits':1,'policy':0x30000},'cgroupParent':str(parent),
        'limits':{'cpu_millis':4500,'memory_bytes':6*1024**3,'processes':128,'wall_seconds':15}}
    file=root/'profile.json';file.write_text(json.dumps(value));return file,value


def request():
    # Public framing fixture only. The real Node entry obtains this exclusively
    # from its genuine booked-channel ticket; no report is appraised here.
    init=json.dumps({'schema':'cannabis.guest-initialization.v2','tee':'snp','binding':{'rank':0,'worldSize':1}},sort_keys=True,separators=(',',':'))
    return {'schema':'cannabis.host-vm-request.v1','initialization':init,'initData':hashlib.sha256(init.encode()).hexdigest(),
        'expectedLaunchDigest':'11'*48,'serviceStart':int(time.time())-1,'serviceEnd':int(time.time())+12,'timeoutMs':10000}


def wait_pidfd(fd,seconds=10):
    if not select.select([fd],[],[],seconds)[0]:raise RuntimeError('Owned process did not terminate')


def owner(file,mode):
    profile=OrdinaryRefusalFixture(file);profile.init_data='22'*32
    slot=VmSlot(profile.value['cgroupParent'],profile.limits)
    guard=GuardedResources(profile.value['cgroupParent'],profile.limits,deadline=ExecutionDeadline(time.monotonic()+(3 if mode=='stall' else 12)))
    control,other=socket.socketpair();qmp,peer=socket.socketpair()
    pid=fork_qemu(profile,guard,other.fileno(),peer.fileno());other.close();peer.close()
    qmp.settimeout(5);assert b'QMP' in qmp.recv(4096)
    print(json.dumps({'pid':pid,'group':str(guard.path)}),flush=True)
    try:
        if os.read(0,1)!=b'C':raise EOFError()
        result=guard.close();os.waitpid(pid,0)
        assert result['removed'] and result['populated'] is False
    finally:
        control.close();qmp.close();profile.close();slot.close()


def main():
    if os.geteuid()!=0:raise ValueError('Require owned root Linux kernel checks')
    parent=Path('/sys/fs/cgroup')/('cannabis-host-'+uuid.uuid4().hex)
    parent.mkdir();checks={};root=None
    try:
        for key,value in {'cpu.max':'500000 100000','memory.max':str(6*1024**3),'memory.swap.max':'0',
                'pids.max':'128','cgroup.subtree_control':'+cpu +memory +pids'}.items():(parent/key).write_text(value+'\n')
        with tempfile.TemporaryDirectory(prefix='cannabis-host-',dir='/run') as directory:
            root=Path(directory);file,value=fixture_files(root,parent)
            os.link(root/'kernel',root/'vmlinuz');os.link(root/'initramfs',root/'initramfs.cpio.gz')
            prepared=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/prepare-host-vm.py'),
                '--qemu',value['qemu']['path'],'--firmware',str(root/'firmware'),'--image',str(root),
                '--reference',str(root/'reference.json'),'--machine','pc-q35-9.1','--cbitpos','51',
                '--reduced-phys-bits','1','--cgroup-parent',str(parent),'--output',str(root/'prepared.json')],
                capture_output=True,text=True,timeout=10,check=True)
            assert json.loads(prepared.stdout)['vmStarted'] is False
            prepared_profile=SnpProfile(str(root/'prepared.json'));prepared_profile.close()
            checks['profilePreparationPinsExactArtifacts']=True
            profile=SnpProfile(str(file))
            try:
                slot=VmSlot(parent,profile.limits)
                try:
                    try:VmSlot(parent,profile.limits)
                    except BlockingIOError:checks['oneOwnedSlot']=True
                    else:raise AssertionError('Duplicate VM slot admitted')
                finally:slot.close()
                (parent/'residual').mkdir()
                try:
                    try:VmSlot(parent,profile.limits)
                    except ValueError:checks['residualGroupRefused']=True
                    else:raise AssertionError('Residual VM slot adopted')
                finally:(parent/'residual').rmdir()
                data=request();owner_fd=os.pidfd_open(os.getpid());life,remote=socket.socketpair();control,guest=socket.socketpair()
                try:
                    # The group transport must match the retained rank count,
                    # profile and guest port before any VM slot is allocated.
                    group_init=json.loads(data['initialization']);group_init['binding']['worldSize']=2
                    group_init=json.dumps(group_init,sort_keys=True,separators=(',',':'))
                    grouped={**data,'initialization':group_init,'initData':hashlib.sha256(group_init.encode()).hexdigest()}
                    try:request_checked(grouped)
                    except ValueError:checks['groupRequestCannotDowngrade']=True
                    else:raise AssertionError('Group used the single-rank transport')
                    grouped.update(schema='cannabis.host-vm-request.v2',groupPort=29420)
                    try:OwnedSnpVm(profile,grouped,guest.fileno(),owner_fd,life.fileno())
                    except ValueError:checks['groupRequiresForwardingProfile']=not any(p.is_dir() for p in parent.iterdir())
                    else:raise AssertionError('Group used an unforwarded profile')
                    group_value={**value,'schema':'cannabis.host-snp-profile.v2',
                        'groupIngress':{'bindHost':'127.0.0.1','hostPort':29421,'guestPort':29420}}
                    group_file=root/'group-profile.json';group_file.write_text(json.dumps(group_value))
                    group_profile=SnpProfile(str(group_file))
                    try:
                        for label,changed in [('groupPortMismatchBeforeAllocation',{**grouped,'groupPort':29422}),
                                              ('singleRankCannotSelectGroupForwarding',data)]:
                            try:OwnedSnpVm(group_profile,changed,guest.fileno(),owner_fd,life.fileno())
                            except ValueError:checks[label]=not any(p.is_dir() for p in parent.iterdir())
                            else:raise AssertionError('Mismatched transport allocated a VM')
                        try:OwnedSnpVm(group_profile,grouped,guest.fileno(),owner_fd,life.fileno())
                        except (OSError,RuntimeError):checks['groupStillRequiresActualHardware']=not any(p.is_dir() for p in parent.iterdir())
                        else:raise AssertionError('Group admitted unsupported hardware')
                    finally:group_profile.close()
                    try:OwnedSnpVm(profile,data,guest.fileno(),owner_fd,life.fileno())
                    except (OSError,RuntimeError):checks['unsupportedHardwareRefusedBeforeAllocation']=not any(p.is_dir() for p in parent.iterdir())
                    else:raise AssertionError('This negative checkpoint requires a host without SNP')
                    # Exercise the fixed script's real framing and inherited fd4
                    # independently of the class checks. No VM can start here.
                    incoming,send=os.pipe();receive,outgoing=os.pipe()
                    raw=json.dumps(data).encode()
                    try:
                        pid=os.posix_spawn(sys.executable,[sys.executable,'-I','-B',str(ROOT/'scripts/compute-host-vm.py'),str(file),str(os.getpid())],
                            {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},file_actions=[
                                (os.POSIX_SPAWN_DUP2,incoming,0),(os.POSIX_SPAWN_DUP2,outgoing,1),
                                (os.POSIX_SPAWN_DUP2,guest.fileno(),4)])
                        os.write(send,len(raw).to_bytes(4,'big')+raw)
                        fd=os.pidfd_open(pid)
                        try:wait_pidfd(fd);_,status=os.waitpid(pid,0);assert os.WIFEXITED(status) and os.WEXITSTATUS(status)==1
                        finally:os.close(fd)
                        failure=json.loads(os.read(receive,4096));assert failure['schema']=='cannabis.host-vm-failure.v1'
                        assert failure['readyEmitted'] is False and failure['hardwareValidated'] is False
                        checks['fixedHostEntryRefusesUnsupportedMachine']=not any(p.is_dir() for p in parent.iterdir())
                    finally:
                        for fd in [incoming,send,receive,outgoing]:os.close(fd)
                    # Inject only a diagnostic ordinary VM. The actual supervisor
                    # must reject its QMP state and clean its newly owned tree.
                    ordinary=OrdinaryRefusalFixture(str(file))
                    try:
                        try:OwnedSnpVm(ordinary,data,guest.fileno(),owner_fd,life.fileno())
                        except ValueError as error:
                            assert 'selected SNP policy' in str(error);checks['ordinaryVMRejectedAndCleaned']=not any(p.is_dir() for p in parent.iterdir())
                        else:raise AssertionError('Ordinary VM accepted as SNP')
                    finally:ordinary.close()
                finally:os.close(owner_fd);life.close();remote.close();control.close();guest.close()
            finally:profile.close()
            # Child bootstrap executes a sealed copy of real QEMU in its leaf.
            executable=ExecutableFixture(str(file));executable.init_data='22'*32
            slot=VmSlot(parent,executable.limits);guard=GuardedResources(parent,executable.limits)
            a,b=socket.socketpair();c,d=socket.socketpair()
            try:
                pid=fork_qemu(executable,guard,b.fileno(),d.fileno());fd=os.pidfd_open(pid)
                try:wait_pidfd(fd);_,status=os.waitpid(pid,0);assert os.WIFEXITED(status) and os.WEXITSTATUS(status)==0
                finally:os.close(fd)
                report=guard.finish_after_exit();assert report['reason']=='finished' and report['removed']
                checks['sealedExecutableRunsInsideOwnedLeaf']=True
            finally:
                guard.close();slot.close();executable.close()
                for s in [a,b,c,d]:s.close()
            for mode in ['cancel','killed','stall']:
                proc=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).resolve()),'owner',str(file),mode],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                child=None
                try:
                    if not select.select([proc.stdout],[],[],10)[0]:raise RuntimeError('Owned VM did not start')
                    line=proc.stdout.readline(4096)
                    if not line:raise RuntimeError('Owned VM entry failed: '+proc.stderr.read(4096).decode())
                    state=json.loads(line);child=os.pidfd_open(state['pid'])
                    if mode=='cancel':proc.stdin.write(b'C');proc.stdin.flush()
                    elif mode=='killed':proc.kill()
                    else:os.kill(proc.pid,signal.SIGSTOP)
                    wait_pidfd(child)
                    until=time.monotonic()+5
                    while Path(state['group']).exists():
                        if time.monotonic()>until:raise RuntimeError('Owned tree removal not observed')
                        time.sleep(.02)
                    checks[{'cancel':'explicitCancellationCleansTree','killed':'ownerSIGKILLCleansTree','stall':'stoppedSupervisorDeadlineCleansTree'}[mode]]=True
                    if mode=='cancel':assert proc.wait(timeout=5)==0
                finally:
                    if proc.poll() is None:proc.kill()
                    proc.wait(timeout=5)
                    if child is not None:os.close(child)
            # Pinned artifacts and their references cannot be silently replaced.
            (root/'kernel').write_bytes(b'CHANGED')
            try:SnpProfile(str(file))
            except ValueError:checks['changedArtifactRefused']=True
            else:raise AssertionError('Changed artifact accepted')
        assert all(checks.values()) and not any(p.is_dir() for p in parent.iterdir())
        print(json.dumps({'schema':'cannabis.host-vm-component-check.v1','checks':checks,'wholeTreeCleanup':True,
            'snpVMStarted':False,'hardwareValidated':False,'realPaidJob':False,'customerKeysUsed':False}))
    finally:parent.rmdir()


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='owner':owner(sys.argv[2],sys.argv[3])
    else:main()
