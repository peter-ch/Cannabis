"""Own a single SNP VM process/tree. Local cleanup is not protected key erasure.

The selected empty cgroup parent is one exclusive VM slot. Other operator
services/metadata still require their own aggregate accounting before operation.
"""
import ctypes
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import time

from compute.guest_guardian import GuardedResources
from compute.guest_deadline import ExecutionDeadline
from compute.guest_resources import _directory,_read,_values,join_current_process
from .snp_profile import SnpProfile,exact,integer,unique


def request_checked(value):
    exact(value,['schema','initialization','initData','expectedLaunchDigest','serviceStart','serviceEnd','timeoutMs'])
    if (value['schema']!='cannabis.host-vm-request.v1' or type(value['initialization']) is not str
            or len(value['initialization'].encode())>65536 or not re.fullmatch('[0-9a-f]{96}',value['expectedLaunchDigest'])):
        raise ValueError('Invalid retained host request')
    init=json.loads(value['initialization'],object_pairs_hook=unique)
    if init.get('schema')!='cannabis.guest-initialization.v2' or init.get('tee')!='snp':raise ValueError('Require configured SNP initialization')
    canonical=json.dumps(init,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    if canonical!=value['initialization'] or hashlib.sha256(canonical.encode()).hexdigest()!=value['initData']:
        raise ValueError('Retained initialization digest mismatch')
    now=time.time()
    if (not integer(value['serviceStart'],1,math.floor(now)) or not integer(value['serviceEnd'],math.floor(now)+1,2**53-1)
            or not integer(value['timeoutMs'],1,3600000)):raise ValueError('Host request outside service interval')
    return time.monotonic()+min(value['timeoutMs']/1000,value['serviceEnd']-now)


class VmSlot:
    def __init__(self,parent,limits):
        self.fd=_directory(parent)
        try:
            # Lock the actual cgroup inode, not an alternate lock-file pathname.
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if (_read(self.fd,'cgroup.type')!='domain' or _read(self.fd,'cgroup.procs')
                    or not {'cpu','memory','pids'}<=set(_read(self.fd,'cgroup.subtree_control').split())
                    or _values(self.fd,'cgroup.events')['populated']
                    or any(stat.S_ISDIR(os.stat(n,dir_fd=self.fd,follow_symlinks=False).st_mode) for n in os.listdir(self.fd))):
                raise ValueError('VM slot is busy or requires reconciliation')
            quota,period=_read(self.fd,'cpu.max').split()
            memory=_read(self.fd,'memory.max');pids=_read(self.fd,'pids.max')
            if (quota=='max' or int(quota)*1000<int(period)*limits.cpu_millis or memory=='max' or int(memory)<limits.memory_bytes
                    or pids=='max' or int(pids)<limits.processes or _read(self.fd,'memory.swap.max')!='0'):
                raise ValueError('Require finite preconfigured VM pool capacity')
        except BaseException:self.close();raise

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


def fork_qemu(profile,guard,control,qmp):
    """Fixed executable/argv, no shell or remote command. No secret inputs."""
    parent=os.getpid();pid=os.fork()
    if pid:return pid
    try:
        # Cover the short fork-to-cgroup bootstrap window even if owner dies.
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:os._exit(125)
        os.setsid();join_current_process(guard.path,profile.limits)
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_MEMLOCK,(profile.limits.memory_bytes,profile.limits.memory_bytes))
        snaps=profile.snapshots()
        # QEMU's private guest memory itself uses memfd/ftruncate. A zero file
        # size rlimit would prevent protected memory allocation, not just disks.
        resource.setrlimit(resource.RLIMIT_FSIZE,(profile.limits.memory_bytes,profile.limits.memory_bytes))
        argv=profile.arguments(snaps,control,qmp,profile.init_data)
        keep={control,qmp,*snaps.values()}
        null=os.open('/dev/null',os.O_RDWR)
        for fd in [0,1,2]:os.dup2(null,fd)
        for name in os.listdir('/proc/self/fd'):
            fd=int(name)
            if fd>2 and fd not in keep:
                try:os.close(fd)
                except OSError:pass
        for fd in keep:os.set_inheritable(fd,True)
        os.execve(snaps['qemu'],argv,{'PATH':'/usr/bin:/bin','LANG':'C'})
    except BaseException:os._exit(125)


class OwnedSnpVm:
    """Serial supervisor with real pidfd/guardian handles, no imported report."""
    def __init__(self,profile,request,control_fd,owner_fd,lifeline):
        self.profile=profile;self.request=request;self.pid=None;self.pidfd=None;self.qmp=None
        self.guard=None;self.slot=None;self.terminal=None;self.started=False;self.local_cleanup=False
        self.owner=owner_fd;self.lifeline=lifeline;self.buffer=bytearray();self.qmp_bytes=0
        self.shutdown=False;self.responses={};self.last_wall=time.time();self.heartbeat=time.monotonic()+10
        self.deadline=request_checked(request)
        if request['expectedLaunchDigest']!=profile.reference['expectedLaunchDigest']:raise ValueError('Selected policy/reference mismatch')
        if self.deadline-time.monotonic()>profile.limits.wall_seconds:raise ValueError('Request exceeds retained host limit')
        profile.init_data=request['initData']
        control=socket.socket(fileno=os.dup(control_fd))
        try:
            if control.family!=socket.AF_UNIX or control.type!=socket.SOCK_STREAM:raise ValueError('Require inherited local control socket')
            control.getpeername()
        finally:control.close()
        self.profile.require_hardware() # No VM allocation or fallback before this.
        peer=None
        try:
            self.slot=VmSlot(profile.value['cgroupParent'],profile.limits)
            self.guard=GuardedResources(profile.value['cgroupParent'],profile.limits,deadline=ExecutionDeadline(self.deadline))
            self.qmp,peer=socket.socketpair();self.qmp.setblocking(False)
            self.active()
            self.pid=fork_qemu(profile,self.guard,control_fd,peer.fileno());self.started=True;self.pidfd=os.pidfd_open(self.pid)
            peer.close();peer=None
            # QMP grants no hardware authority. Only fixed configuration queries
            # and event observation are issued; no memory dump/migration APIs.
            self.until(lambda: 'greeting' in self.responses,5)
            self.send({'execute':'qmp_capabilities','id':'observe'})
            self.until(lambda:'observe' in self.responses,5)
            if self.responses['observe']!={}:raise ValueError('QMP observation refused')
            self.send({'execute':'query-sev','id':'snp'})
            self.until(lambda:'snp' in self.responses,5)
            sev=self.responses['snp']
            if (sev.get('enabled') is not True or sev.get('sev-type')!='sev-snp' or sev.get('state')!='running'
                    or sev.get('snp-policy')!=profile.value['snp']['policy']):raise ValueError('VM is not running the selected SNP policy')
        except BaseException:
            self.cancel();raise
        finally:
            if peer is not None:peer.close()

    def active(self):
        now=time.time()
        if now<self.last_wall or now>=self.request['serviceEnd'] or time.monotonic()>=self.deadline:
            raise TimeoutError('VM service deadline ended')
        self.last_wall=now
        if select.select([self.owner],[],[],0)[0]:raise RuntimeError('Operator owner exited')
        if time.monotonic()>=self.heartbeat:raise TimeoutError('Operator heartbeat stopped')
        self.guard.assert_alive()

    def send(self,value):
        self.active();raw=json.dumps(value,separators=(',',':')).encode()+b'\n'
        if len(raw)>256 or self.qmp.send(raw)!=len(raw):raise RuntimeError('QMP setup failed')

    def events(self):
        data=self.qmp.recv(8192)
        if not data:return False
        self.qmp_bytes+=len(data);self.buffer.extend(data)
        if self.qmp_bytes>65536 or len(self.buffer)>16384:raise ValueError('QMP observation exceeds bound')
        while b'\n' in self.buffer:
            line,_,tail=self.buffer.partition(b'\n');self.buffer[:]=tail
            value=json.loads(line,object_pairs_hook=unique)
            if 'QMP' in value:
                if 'greeting' in self.responses:raise ValueError('Repeated QMP greeting')
                self.responses['greeting']=True
            elif 'id' in value:
                if value['id'] not in ['observe','snp'] or value['id'] in self.responses or 'return' not in value:
                    raise ValueError('Unexpected QMP response')
                self.responses[value['id']]=value['return']
            elif value.get('event')=='SHUTDOWN':
                self.shutdown=value.get('data',{}).get('guest') is True and value['data'].get('reason')=='guest-shutdown'
            elif value.get('event') in ['GUEST_PANICKED','RESET']:raise RuntimeError('Guest reset or panic')
        return True

    def poll(self,seconds):
        self.active()
        ready,_,_=select.select([self.owner,self.lifeline,self.guard.fileno(),self.pidfd,self.qmp],[],[],max(0,min(seconds,.1)))
        if self.owner in ready or self.guard.fileno() in ready:raise RuntimeError('VM owner or guardian ended')
        if self.lifeline in ready:
            data=os.read(self.lifeline,64)
            if not data or len(data)>16 or any(b!=ord('H') for b in data):raise RuntimeError('Operator cancelled or lifeline ended')
            self.heartbeat=time.monotonic()+10
        if self.qmp in ready:self.events()
        self.active();return self.pidfd in ready

    def until(self,predicate,seconds):
        end=min(self.deadline,time.monotonic()+seconds)
        while not predicate():
            if time.monotonic()>=end or self.poll(.05):raise RuntimeError('VM ended before bounded setup')

    def wait(self):
        try:
            while not self.poll(.1):pass
            _,status=os.waitpid(self.pid,0);self.pid=None
            # Drain already-delivered QMP events before deciding shutdown cause.
            while select.select([self.qmp],[],[],0)[0]:
                if not self.events():break
            result=self.guard.finish_after_exit()
            self.local_cleanup=result.get('removed') is True and result.get('populated') is False
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status)!=0 or not self.shutdown or result['reason']!='finished':
                raise RuntimeError('VM did not complete guest-originated shutdown')
            self.terminal={'schema':'cannabis.host-vm-retirement.v1','localTreeStopped':True,
                'guestShutdownObserved':True,'protectedKeyRetirementVerified':False,'hardwareValidated':False}
            return self.terminal
        except BaseException:self.cancel();raise
        finally:self.dispose()

    def cancel(self):
        if self.local_cleanup and self.pid is None:self.dispose();return
        failure=None
        try:
            if self.pid is not None:
                try:os.kill(self.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            if self.guard is not None:
                result=self.guard.close();self.local_cleanup=result.get('removed') is True and result.get('populated') is False
            if self.pid is not None:
                # Guarded cgroup removal has already proven tree emptiness.
                os.waitpid(self.pid,0);self.pid=None
        except BaseException as error:failure=error
        finally:self.dispose()
        if failure:raise RuntimeError('VM cleanup is unverified; retain capacity and reconcile') from failure

    def dispose(self):
        if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None
        if self.qmp is not None:self.qmp.close();self.qmp=None
        # A failed cleanup leaves its cgroup. The next exclusive slot acquisition
        # refuses that residual state instead of starting work over uncertainty.
        if self.slot is not None:self.slot.close();self.slot=None
