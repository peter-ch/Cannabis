#!/usr/bin/env python3
"""Actual Linux isolation checks with owned programs, never customer content."""
import ctypes
import errno
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
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_sandbox import NativeSandbox, ScratchLimits, tree_digest, MOUNTS
from compute.guest_resources import ResourceLimits, ResourceCleanupError

SCRIPT = str(Path(__file__).resolve())


def fixture(root):
    """Copy only installed interpreter/library files into an owned tmpfs tree."""
    for name in [*MOUNTS, 'usr/bin', 'usr/lib', 'lib', 'lib64']:
        (root / name).mkdir(parents=True, exist_ok=True, mode=0o755)
    executable = Path(sys.executable).resolve()
    shutil.copyfile(executable, root / 'usr/bin/python3')
    stdlib = Path('/usr/lib') / ('python' + '.'.join(map(str, sys.version_info[:2])))
    shutil.copytree(stdlib, root / 'usr/lib' / stdlib.name, symlinks=False,
        ignore=shutil.ignore_patterns('__pycache__', 'test', 'tests', 'site-packages', 'dist-packages', 'ensurepip', 'idlelib', 'turtledemo'))
    # The installed ELF loader inspects only known interpreter/extensions.
    # This helper never accepts a customer runtime or invokes their executable.
    libraries = set()
    for binary in [executable, *stdlib.glob('lib-dynload/*.so')]:
        text = subprocess.check_output(['/lib64/ld-linux-x86-64.so.2', '--list', str(binary)], text=True)
        libraries.update(re.findall(r'(?:=>\s+|^\s*)(/[^\s()]+)', text, re.M))
    for name in libraries:
        target = root / name.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(name, target)
    for path in [root, *root.rglob('*')]:
        path.chmod(0o755 if path.is_dir() or path == root / 'usr/bin/python3' or '.so' in path.name else 0o644)


PROBE = r'''
import ctypes, errno, json, os, resource, socket
libc = ctypes.CDLL(None, use_errno=True)
def denied(number, *args):
    ctypes.set_errno(0)
    assert libc.syscall(number, *args) == -1 and ctypes.get_errno() == errno.EPERM, number
assert os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 65534
assert os.getgroups() == []
status = dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
assert int(status['CapEff'].strip(),16) == 0
assert int(status['CapPrm'].strip(),16) == 0
assert int(status['NoNewPrivs']) == 1 and int(status['Seccomp']) == 2
for name in ['/opt/cannabis', HOST_BASE+'/control-secret', HOST_BASE+'/control.sock', '/sys/fs/cgroup',
             '/dev/sev-guest', '/dev/tdx_guest', '/dev/kvm', '/dev/dri', '/dev/nvidia0', '/dev/mem']:
    assert not os.path.exists(name), name
assert os.listdir('/sys') == []
assert 'sentinel' not in os.environ and set(os.environ) <= {'PATH','HOME','LANG','TMPDIR','LC_CTYPE','PWD'}, sorted(os.environ)
assert open('/input/message').read() == 'owned input'
for name in ['/input/message','/usr/bin/python3','/new-root-file','/dev/new-device-file','/proc/sys/kernel/hostname']:
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        pass
    else:
        os.close(fd)
        raise AssertionError('write escaped: ' + name)
for family in [socket.AF_INET, socket.AF_INET6, socket.AF_NETLINK, socket.AF_PACKET, socket.AF_VSOCK]:
    for pair in [False, True]:
        try:
            value = socket.socketpair(family) if pair else socket.socket(family)
        except PermissionError:
            pass
        else:
            raise AssertionError('network domain permitted')
a,b = socket.socketpair()
a.send(b'local')
assert b.recv(5) == b'local'
a.close(); b.close()
for address in [HOST_BASE+'/control.sock', '\x00cannabis-owned-control']:
    s=socket.socket(socket.AF_UNIX)
    try:
        s.connect(address)
    except OSError:
        pass
    else:
        raise AssertionError('control socket reachable')
    s.close()
# mount, unshare, setns, ptrace, bpf, keyctl, userfaultfd, perf_event_open,
# process_vm_readv, open_by_handle_at, io_uring_setup, reboot, mknod, setuid.
for nr in [165,272,308,101,321,250,323,298,310,304,425,169,133,105]:
    denied(nr,0,0,0,0,0,0)
denied(56,0x10000000,0,0,0,0)  # clone(CLONE_NEWUSER)
ctypes.set_errno(0)
assert libc.syscall(435,0,0) == -1 and ctypes.get_errno() == errno.ENOSYS
assert resource.getrlimit(resource.RLIMIT_CORE) == (0,0)
assert resource.getrlimit(resource.RLIMIT_MEMLOCK) == (0,0)
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (1024,1024)
try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (2048,2048))
except (ValueError, OSError):
    pass
else:
    raise AssertionError('descriptor bound lifted')
# Inspection opens a transient fd; every retained descriptor must be stdio.
for name in os.listdir('/proc/self/fd'):
    try:
        target=os.readlink('/proc/self/fd/'+name)
    except FileNotFoundError:
        continue
    assert int(name) <= 2, (name,target)
for name in ['work','output','tmp','run','dev/shm']:
    with open('/'+name+'/probe','w') as out: out.write('owned output')
with open('/output/result','w') as out: json.dump({'isolated':True},out)
pid=os.fork()
if pid==0: os._exit(0)
assert os.waitpid(pid,0)[1]==0
import threading
thread=threading.Thread(target=lambda:None); thread.start(); thread.join()
print('owned stdout')
'''

STORAGE = r'''
import errno, os
count=0
try:
    for prefix in ['/work','/tmp','/run','/dev/shm','/output']:
        with open(prefix+'/large','wb',buffering=0) as out:
            for _ in range(64):
                count += out.write(b'x'*65536)
except OSError as error:
    assert error.errno == errno.ENOSPC
else:
    raise AssertionError('aggregate storage was unbounded')
assert 1024**2 <= count <= 8*1024**2
'''

INODES = r'''
import errno, os
for i in range(2048):
    try:
        fd=os.open('/output/f'+str(i),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.close(fd)
    except OSError as error:
        assert error.errno == errno.ENOSPC and i < 256
        break
else:
    raise AssertionError('inode capacity was unbounded')
'''

LOGS = r'''
import errno, os
count=0
try:
    for _ in range(256):
        for fd in [1,2]:
            count += os.write(fd,b'x'*65536)
except OSError as error:
    assert error.errno == errno.ENOSPC
else:
    raise AssertionError('stdout/stderr escaped aggregate storage quota')
assert 1024**2 <= count <= 8*1024**2
'''

HANG = "import os,time\nchild=os.fork()\nif child==0: os.setsid()\nopen('/output/started','w').write('owned')\ntime.sleep(90)\n"


def actor(parent, base, mode):
    base = Path(base)
    root, inputs = base / 'root', base / 'inputs'
    expected = tree_digest(root)
    if mode == 'changed-runtime':
        (root / 'changed').write_text('owned mutation')
        try:
            NativeSandbox(parent, root, inputs, expected, ResourceLimits(1000, 256*1024**2, 32, 30), ScratchLimits(8*1024**2))
        except ValueError:
            print(json.dumps({'refused':True}),flush=True)
            return
        raise AssertionError('Changed runtime was accepted')
    wall = 15 if mode == 'deadline' else 60
    with NativeSandbox(parent, root, inputs, expected, ResourceLimits(1000, 256*1024**2, 32, wall),
                       ScratchLimits(8*1024**2, 256)) as sandbox:
        print(json.dumps({'ready':True, 'group':str(sandbox._guard.path), 'path':str(sandbox._path),
                          'guardian':sandbox._guard._process.pid}),flush=True)
        scripts = {'isolation':PROBE, 'storage':STORAGE, 'inodes':INODES, 'logs':LOGS,
                   'deadline':HANG, 'owner-death':HANG, 'guardian-failure':HANG, 'cancel':HANG}
        class Cancel:
            def is_set(self):
                return (sandbox.output_directory/'started').exists()
        report = sandbox.run(['/usr/bin/python3','-I','-B','-c','HOST_BASE='+repr(str(base))+'\n'+scripts[mode]],
                             cancelled=Cancel() if mode == 'cancel' else None)
        # Only owned fixture diagnostics can leave this isolated check process.
        if not report['success'] and mode in ['isolation','storage','inodes','logs']:
            raise AssertionError(json.dumps(report)+' '+(sandbox._path/'stderr').read_text()[-4096:])
        if mode == 'isolation':
            assert json.loads((sandbox.output_directory/'result').read_text()) == {'isolated':True}
            assert (sandbox._path/'stdout').read_text() == 'owned stdout\n'
        if mode in ['deadline','cancel']:
            assert not report['success'] and report['reason'] == {'deadline':'deadline','cancel':'cancelled'}[mode]
        assert report['cleanup']['removed'] and not report['cleanup']['populated']
    print(json.dumps({'passed':True}),flush=True)


def line(proc, timeout=30):
    if not select.select([proc.stdout],[],[],timeout)[0]:
        raise AssertionError('Sandbox check startup expired')
    value=proc.stdout.readline(4097)
    if not value or len(value)>4096:
        raise AssertionError('Sandbox check failed: '+proc.stderr.read(8192).decode())
    return json.loads(value)


def main():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Use a disposable Linux root environment')
    base = Path('/run') / ('cannabis-sandbox-check-'+uuid.uuid4().hex)
    parent = Path('/sys/fs/cgroup') / base.name
    base.mkdir(mode=0o700)
    parent.mkdir(mode=0o700)
    # Fixtures use their own bounded, unswappable memory. No host swap setting
    # or shared mount is changed, even on a WSL system with swap enabled.
    libc=ctypes.CDLL(None,use_errno=True)
    assert libc.unshare(0x20000)==0
    assert libc.mount(None,b'/',None,0x4000|0x40000,None)==0
    assert libc.mount(b'tmpfs',os.fsencode(base),b'tmpfs',2|4,b'size=96m,nr_inodes=20000,mode=0700,noswap')==0
    control=socket.socket(socket.AF_UNIX)
    abstract=socket.socket(socket.AF_UNIX)
    checks={}
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        fixture(base/'root')
        (base/'inputs').mkdir(mode=0o700)
        (base/'inputs/message').write_text('owned input')
        (base/'control-secret').write_text('owned sentinel must stay outside')
        control.bind(str(base/'control.sock')); control.listen(1)
        abstract.bind('\0cannabis-owned-control'); abstract.listen(1)
        for mode in ['isolation','storage','inodes','logs','deadline','cancel','owner-death','guardian-failure','changed-runtime']:
            print('Owned sandbox check: '+mode,file=sys.stderr,flush=True)
            proc=subprocess.Popen([sys.executable,'-I','-B',SCRIPT,'actor',str(parent),str(base),mode],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','sentinel':'must-not-enter'},start_new_session=True)
            state=None
            try:
                state=line(proc)
                if mode in ['owner-death','guardian-failure']:
                    # Wait until actual descendant code ran. Inspect through
                    # the owned supervisor's mount namespace, never a host bind.
                    started=Path('/proc')/str(proc.pid)/'root'/str(state['path']).lstrip('/')/'output/started'
                    expiry=time.monotonic()+30
                    while not started.exists():
                        assert proc.poll() is None and time.monotonic()<expiry
                        time.sleep(0.05)
                    handle=os.pidfd_open(state['guardian'])
                    if mode == 'owner-death':
                        proc.kill(); proc.wait(timeout=5)
                    else:
                        signal.pidfd_send_signal(handle,signal.SIGKILL)
                    try:
                        assert select.select([handle],[],[],15)[0]
                    finally:
                        os.close(handle)
                    if mode == 'owner-death':
                        assert not Path(state['group']).exists()
                        # The private tmpfs dies with its last namespace user.
                        assert Path(state['path']).is_dir() and list(Path(state['path']).iterdir()) == []
                        Path(state['path']).rmdir()
                    else:
                        assert line(proc,15) == {'guardianFailureRefused':True}
                        assert proc.wait(timeout=5) == 0 and not Path(state['path']).exists() and not Path(state['group']).exists()
                elif mode == 'changed-runtime':
                    assert state == {'refused':True} and proc.wait(timeout=10) == 0
                else:
                    assert line(proc,90) == {'passed':True}
                    assert proc.wait(timeout=5) == 0
                    assert not Path(state['group']).exists() and not Path(state['path']).exists()
                checks[mode]=True
            finally:
                if proc.poll() is None: proc.kill()
                proc.wait(timeout=5)
                proc.stdout.close(); proc.stderr.close()
        print(json.dumps({'schema':'cannabis.guest-sandbox-check.v1','kernel':os.uname().release,
                          'checks':checks,'customerCodeExecuted':False,'hardwareValidated':False}))
    finally:
        control.close(); abstract.close()
        # Contain failed checks too, including deliberately simultaneous owner
        # and guardian loss. Only this invocation's newly created cgroup tree.
        if any(parent.iterdir()):
            (parent/'cgroup.kill').write_text('1')
            expiry=time.monotonic()+10
            while 'populated 1' in (parent/'cgroup.events').read_text():
                assert time.monotonic()<expiry
                time.sleep(0.05)
            for child in sorted(parent.rglob('*'),key=lambda p:len(p.parts),reverse=True):
                if child.is_dir(): child.rmdir()
        parent.rmdir()
        assert libc.umount2(os.fsencode(base),0)==0
        base.rmdir()


if __name__ == '__main__':
    if len(sys.argv)==5 and sys.argv[1]=='actor':
        try:
            actor(*sys.argv[2:])
        except ResourceCleanupError:
            if sys.argv[4] != 'guardian-failure': raise
            print(json.dumps({'guardianFailureRefused':True}),flush=True)
    else: main()
