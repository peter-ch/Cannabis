"""One-use measured VM supervision; no customer keys or workload interpretation.

The fixed PID-1 entry supplies the image budget and launcher. A transport supplied
by the host is untrusted: only bounded public configuration enters at boot. The
existing authorization, evidence and key-release protocols remain mandatory.
Guest shutdown does not prove hostile-host deletion, trusted time or no rollback.
"""
import ctypes
import math
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import time

from .guest_resources import _directory, _read, _write, _values, _verify
from .guest_vm import image_vm_budget

MAGIC=b'CANNABIS-BOOT\x01'
READY=b'CANNABIS-READY\x01'
STAGED=b'CANNABIS-STAGED\x01'
PUBLIC_FILES=(('configuration.json',256*1024),('initialization.json',65536),('request.json',16*1024**2))
PORT_NAME='org.cannabis.control'
LAUNCH=Path('/run/cannabis-launch')
GROUP_ROOT=Path('/sys/fs/cgroup')
FIXED_LAUNCHER='/opt/cannabis/scripts/compute-guest-launch.py'
BUFFER=65536


def _remaining(deadline):
    if not isinstance(deadline,(int,float)) or not math.isfinite(deadline):
        raise ValueError('Require a finite boot deadline')
    value=deadline-time.monotonic()
    if value<=0:raise TimeoutError('Guest boot or lifetime expired')
    return value


def encode_public_launch(configuration,initialization,request):
    """Host-side prefix only; these inputs must contain public launch metadata."""
    values=(configuration,initialization,request)
    if any(type(v) is not bytes or not 2<=len(v)<=limit for v,(_,limit) in zip(values,PUBLIC_FILES)):
        raise ValueError('Public boot file exceeds its bound')
    return MAGIC+struct.pack('!III',*(len(v) for v in values))+b''.join(values)


def receive_public_launch(reader,destination,deadline,*,watchdog=None):
    """Stream only the declared prefix; leave later protocol bytes unread."""
    destination=Path(destination)
    def take(count):
        while True:
            remaining=_remaining(deadline)
            ready,_,_=select.select([reader]+([] if watchdog is None else [watchdog]),[],[],min(remaining,0.1))
            if watchdog is not None and watchdog in ready:raise RuntimeError('VM watchdog ended')
            if reader not in ready:continue
            try:chunk=os.read(reader,min(count,BUFFER))
            except BlockingIOError:continue
            if not chunk:raise EOFError('Incomplete public launch prefix')
            _remaining(deadline)
            return chunk
    def exact(count):
        value=bytearray()
        while len(value)<count:value.extend(take(count-len(value)))
        return bytes(value)
    if exact(len(MAGIC))!=MAGIC:raise ValueError('Unknown public boot framing')
    sizes=struct.unpack('!III',exact(12))
    if any(not 2<=n<=limit for n,(_,limit) in zip(sizes,PUBLIC_FILES)):
        raise ValueError('Public boot file exceeds its bound')
    # The measured caller has already verified the protected /run mount. Never
    # adopt an existing directory or follow a replacement while writing files.
    destination.mkdir(mode=0o700)
    directory=os.open(destination,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for (name,_),size in zip(PUBLIC_FILES,sizes):
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400,dir_fd=directory)
            try:
                while size:
                    value=take(size);size-=len(value)
                    if os.write(fd,value)!=len(value):raise OSError('Incomplete public boot write')
                os.fsync(fd)
            finally:os.close(fd)
        _remaining(deadline)
    finally:os.close(directory)


def open_control_port():
    """Select one named virtio port, checking the kernel-reported device number."""
    candidates=[]
    ports=list(Path('/sys/class/virtio-ports').iterdir())
    if len(ports)>16:raise ValueError('Too many guest control devices')
    for entry in ports:
        with (entry/'name').open('rb') as stream:name=stream.read(128)
        if name==PORT_NAME.encode()+b'\n':candidates.append(entry)
    if len(candidates)!=1:raise ValueError('Require exactly one named guest control port')
    entry=candidates[0]
    major,minor=(int(v) for v in (entry/'dev').read_text().strip().split(':'))
    fd=os.open('/dev/'+entry.name,os.O_RDWR|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    info=os.fstat(fd)
    if not stat.S_ISCHR(info.st_mode) or info.st_rdev!=os.makedev(major,minor) or os.isatty(fd):
        os.close(fd);raise ValueError('Unexpected guest control device')
    return fd


def write_status(writer,message,deadline,watchdog):
    """Public storage/setup acknowledgement, not authorization or key admission."""
    if message not in [READY,STAGED]:raise ValueError('Unknown public boot status')
    pending=message
    while pending:
        ready,writable,_=select.select([watchdog],[writer],[],_remaining(deadline))
        if watchdog in ready:raise RuntimeError('VM watchdog ended')
        if writer not in writable:continue
        try:count=os.write(writer,pending)
        except BlockingIOError:continue
        if count<=0:raise EOFError('Boot staging acknowledgement failed')
        pending=pending[count:]
    _remaining(deadline)


class VmProcessTree:
    """Own only two freshly created groups; never adopt or alter unrelated work."""
    def __init__(self,budget,parent=GROUP_ROOT):
        self.budget,self.parent=budget,Path(parent)
        self.root=_directory(self.parent)
        self.groups={}
        self.names=[]
        self.closed=False
        try:
            if _read(self.root,'cgroup.type')!='domain' or not {'cpu','memory','pids'}<=set(_read(self.root,'cgroup.subtree_control').split()):
                raise ValueError('Require the configured VM controller root')
            for name,controls in [('cannabis-outer',budget.outer.controls()),('cannabis-jobs',budget.job_parent_controls())]:
                os.mkdir(name,0o700,dir_fd=self.root);self.names.append(name)
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root)
                self.groups[name]=fd
                for key,value in controls.items():_write(fd,key,value)
                if 'memory.zswap.max' in os.listdir(fd):_write(fd,'memory.zswap.max','0')
                if name=='cannabis-jobs':_write(fd,'cgroup.subtree_control','+cpu +memory +pids')
                _write(fd,'cgroup.kill','1')
            self.verify(empty=True)
        except BaseException:
            self.close();raise

    @property
    def outer(self):return self.parent/'cannabis-outer'
    @property
    def jobs(self):return self.parent/'cannabis-jobs'

    def verify(self,*,empty=False):
        if self.closed:raise ValueError('VM process tree is closed')
        for name,fd in self.groups.items():
            current=os.stat(name,dir_fd=self.root,follow_symlinks=False)
            retained=os.fstat(fd)
            if (current.st_dev,current.st_ino)!=(retained.st_dev,retained.st_ino):raise ValueError('VM group changed')
            if str(os.getpid()) in _read(fd,'cgroup.procs').split():raise ValueError('VM supervisor entered a job group')
            if empty and _values(fd,'cgroup.events')['populated']:raise ValueError('VM group is not empty')
        _verify(self.groups['cannabis-outer'],self.budget.outer)
        self.budget.verify_job_parent(self.groups['cannabis-jobs'],empty=empty)
        if (_values(self.groups['cannabis-outer'],'memory.events')['oom_kill']
                or _values(self.groups['cannabis-outer'],'pids.events')['max']):
            raise RuntimeError('Outer launcher exhausted reserved resources')

    def close(self):
        if self.closed:return
        self.closed=True
        try:
            end=time.monotonic()+5
            # Stop outer creators before retiring the job parent. Otherwise a
            # late child could move into a job group just after it was killed.
            for fd in self.groups.values():
                _write(fd,'cgroup.kill','1')
                while _values(fd,'cgroup.events')['populated']:
                    _remaining(end);time.sleep(0.01)
            def remove_children(fd,depth,remaining):
                children=[name for name in os.listdir(fd) if stat.S_ISDIR(os.stat(name,dir_fd=fd,follow_symlinks=False).st_mode)]
                if children and depth==0 or len(children)>remaining[0]:raise RuntimeError('Unexpected VM group descendants')
                for name in children:
                    remaining[0]-=1
                    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                    try:
                        if _values(child,'cgroup.events')['populated']:raise RuntimeError('VM descendant remains busy')
                        remove_children(child,depth-1,remaining)
                        info=os.stat(name,dir_fd=fd,follow_symlinks=False);old=os.fstat(child)
                        if (info.st_dev,info.st_ino)!=(old.st_dev,old.st_ino):raise RuntimeError('VM descendant replaced')
                        os.rmdir(name,dir_fd=fd)
                    finally:os.close(child)
            for name in reversed(self.names):
                fd=self.groups.get(name)
                if fd is not None:
                    remove_children(fd,2 if name=='cannabis-jobs' else 0,[self.budget.job.children+1])
                    current=os.stat(name,dir_fd=self.root,follow_symlinks=False);old=os.fstat(fd)
                    if (current.st_dev,current.st_ino)!=(old.st_dev,old.st_ino):raise RuntimeError('VM group replaced during retirement')
                os.rmdir(name,dir_fd=self.root)
        finally:
            for fd in self.groups.values():os.close(fd)
            self.groups.clear();os.close(self.root)

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


class VmRetirement:
    """Construct only at PID 1; an inherited watchdog may retire the same VM.

    In a test PID namespace reboot retires that namespace, not the host. No
    sysrq or host power-management fallback is used. An unexpected syscall
    return exits init; the measured operating boot sets immediate panic restart.
    """
    def __init__(self):
        if os.getpid()!=1 or os.geteuid()!=0:raise ValueError('VM retirement must originate at privileged PID 1')
        self.namespace=os.stat('/proc/self/ns/pid').st_ino

    def __call__(self):
        if os.stat('/proc/self/ns/pid').st_ino!=self.namespace:os._exit(127)
        libc=ctypes.CDLL(None,use_errno=True)
        libc.reboot.argtypes=[ctypes.c_int];libc.reboot.restype=ctypes.c_int
        libc.reboot(0x4321FEDC)  # LINUX_REBOOT_CMD_POWER_OFF
        os._exit(127)


def arm_watchdog(retire,deadline):
    """A separate key-free process watches owner death and the immutable expiry.

    Return its pid, pidfd and a parent-owned lifetime socket. Closing the socket
    is terminal, never a successful disarm. The caller must monitor the pidfd.
    """
    _remaining(deadline)
    owner=os.pidfd_open(os.getpid())
    parent,child=socket.socketpair()
    try:pid=os.fork()
    except BaseException:parent.close();child.close();os.close(owner);raise
    if pid==0:
        parent.close()
        keep={owner,child.fileno()}
        for name in os.listdir('/proc/self/fd'):
            fd=int(name)
            if fd not in keep:
                try:os.close(fd)
                except OSError:pass
        try:
            child.sendall(b'R')
            while True:
                ready,_,_=select.select([owner,child],[],[],_remaining(deadline))
                if ready:break
        except BaseException:pass
        finally:
            retire();os._exit(127)
    child.close();os.close(owner)
    pidfd=os.pidfd_open(pid)
    try:
        ready,_,_=select.select([parent,pidfd],[],[],min(5,_remaining(deadline)))
        if pidfd in ready or parent not in ready or parent.recv(1)!=b'R':raise RuntimeError('VM watchdog did not arm')
        _remaining(deadline)
        return pid,pidfd,parent
    except BaseException:
        parent.close();os.close(pidfd)
        # In production this path is immediately followed by VM retirement.
        # Wait is deliberately omitted: the watchdog itself may be retiring it.
        raise


def _reap_orphans(exclude):
    if os.getpid()!=1:return
    with Path('/proc/self/task/1/children').open('rb') as stream:raw=stream.read(8193)
    if len(raw)>8192:raise RuntimeError('Unexpected VM child count')
    for value in raw.split():
        pid=int(value)
        if pid not in exclude:
            try:os.waitpid(pid,os.WNOHANG)
            except ChildProcessError:pass


def supervise_launcher(tree,command,reader,writer,deadline,watchdog,*,watchdog_pid=None,busybox='/bin/busybox'):
    """Start a fixed trusted command after a tiny shell joins its fresh leaf.

    The shell's bounded bootstrap/shared pages belong to VM headroom. Exec of
    the Python launcher (and its subsequent allocations) occurs inside the leaf.
    Production passes a fixed command, never input from the public boot prefix.
    """
    tree.verify(empty=True);_remaining(deadline)
    if not command or any(not isinstance(v,str) or '\0' in v for v in command):raise ValueError('Invalid fixed launcher')
    # Positional arguments, not shell interpolation, carry the trusted path and
    # argv. The shell performs no command substitution or external utility call.
    shell='printf "0\\n" > "$1/cgroup.procs" || exit 125; shift; exec "$@"'
    proc=subprocess.Popen([busybox,'sh','-c',shell,'cannabis-boot',str(tree.outer),*command],
        stdin=reader,stdout=writer,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True,
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','HOME':'/run',
             'PYTHONDONTWRITEBYTECODE':'1','CANNABIS_AGE':'/usr/local/bin/age'})
    pidfd=os.pidfd_open(proc.pid)
    poll=select.poll();poll.register(reader,select.POLLHUP|select.POLLERR)
    try:
        while True:
            _reap_orphans({proc.pid,watchdog_pid})
            _remaining(deadline);tree.verify()
            ready,_,_=select.select([pidfd,watchdog],[],[],min(0.05,_remaining(deadline)))
            if watchdog in ready:raise RuntimeError('VM watchdog ended before retirement')
            if pidfd in ready:
                if proc.wait(timeout=1)!=0:raise RuntimeError('Fixed outer launcher failed')
                tree.verify(empty=True);_remaining(deadline)
                return
            if poll.poll(0):raise EOFError('Control transport ended before launcher completion')
    finally:
        try:
            try:
                # Stop and reap the bootstrap even if it has not yet joined the
                # outer leaf. It must not race group retirement by entering late.
                if proc.poll() is None:proc.kill()
                proc.wait(timeout=5)
            finally:
                # The outer cgroup covers detached and forked children as well.
                tree.close()
        finally:
            os.close(pidfd)


def run_pid1():
    retire=VmRetirement()
    control=None;lifeline=None;watchdog=None
    try:
        signal.signal(signal.SIGCHLD,signal.SIG_DFL)
        budget=image_vm_budget()
        lifetime=time.monotonic()+budget.outer.wall_seconds
        watchdog_pid,watchdog,lifeline=arm_watchdog(retire,lifetime)
        budget.verify_layout()
        control=open_control_port()
        intake_deadline=min(lifetime,time.monotonic()+30)
        write_status(control,READY,min(intake_deadline,time.monotonic()+5),watchdog)
        receive_public_launch(control,LAUNCH,intake_deadline,watchdog=watchdog)
        with VmProcessTree(budget) as tree:
            write_status(control,STAGED,min(lifetime,time.monotonic()+5),watchdog)
            supervise_launcher(tree,['/usr/bin/python3','-I','-B',FIXED_LAUNCHER],control,control,lifetime,watchdog,watchdog_pid=watchdog_pid)
        _remaining(lifetime)
    finally:
        # No network write, log flushing or potentially blocking close precedes
        # retirement. Kernel teardown disposes of all inherited descriptors.
        retire()
