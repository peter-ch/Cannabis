"""Native Linux sandbox primitive INSIDE a measured confidential guest.

Call only from a dedicated, single-threaded trusted supervisor process. Hardware,
assignment, adapter and key-release admission belong to the enclosing launcher.
This primitive has no host networking, accelerator or plaintext fallback.
"""
from dataclasses import dataclass
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import shutil
import stat
import subprocess
import sys
import time
import uuid

from .guest_guardian import GuardedResources
from .guest_resources import ResourceLimits, ResourceCleanupError, join_current_process

BWRAP = '/usr/bin/bwrap'
BWRAP_SHA256 = 'e318903862396f96de3df57264e0158682b952fd3fb53ac23d876413e7b30f71'
SECCOMP = '/usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.5'
SECCOMP_SHA256 = 'b4d9140a7797ccf3ac14f5d9d579b64f157111662940cb8330c632b11a8cea8e'
MOUNTS = ('proc', 'dev', 'sys', 'run', 'tmp', 'work', 'input', 'output')
_entered = False


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _call(result):
    if result != 0:
        raise OSError(ctypes.get_errno(), 'Guest isolation operation failed')


def _tmpfs(fd):
    buffer = (ctypes.c_long * 32)()
    _call(_libc().fstatfs(fd, ctypes.byref(buffer)))
    if buffer[0] != 0x01021994:
        raise ValueError('Protected guest storage must be memory-backed tmpfs')
    fields = dict(line.split(':', 1) for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines() if ':' in line)
    mount_id = fields.get('mnt_id', '').strip()
    matches = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[0] == mount_id]
    if len(matches) != 1 or 'noswap' not in matches[0][-1].split(','):
        raise ValueError('Protected tmpfs must explicitly disable swap')


def _directory(path, *, memory=True):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Require an absolute trusted directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Require root-owned directories without other writers')
        if memory:
            _tmpfs(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _pinned_file(path, expected):
    parent = _directory(Path(path).parent, memory=False)
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o6022:
            raise ValueError('Unsafe trusted executable or library')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        os.lseek(fd, 0, os.SEEK_SET)
        if actual != expected:
            raise ValueError('Trusted sandbox component changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def tree_digest(path, *, max_bytes=512 * 1024**2, max_entries=50000):
    """Canonical content/mode inventory for an immutable approved runtime tree.

    Never follow source links. A link is part of the pinned runtime content and
    resolves only inside the new root at runtime. Mount destinations must instead
    be real empty directories. Only trusted root may mutate a source tree.
    """
    fd = _directory(path)
    rows, used = [['', 'directory', os.fstat(fd).st_mode & 0o777]], 0
    device = os.fstat(fd).st_dev

    def walk(current, prefix):
        nonlocal used
        for name in sorted(os.listdir(current)):
            if '\n' in name or '\r' in name or len(name.encode()) > 255:
                raise ValueError('Invalid runtime entry name')
            relative = prefix + name
            info = os.stat(name, dir_fd=current, follow_symlinks=False)
            if info.st_uid != 0 or info.st_dev != device or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o6022):
                raise ValueError('Runtime tree must be immutable, root-owned and on one filesystem')
            if len(rows) >= max_entries:
                raise ValueError('Runtime inventory exceeds its bound')
            if stat.S_ISDIR(info.st_mode):
                rows.append([relative, 'directory', info.st_mode & 0o777])
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
                try:
                    walk(child, relative + '/')
                finally:
                    os.close(child)
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(name, dir_fd=current)
                if not target or len(target.encode()) > 4096:
                    raise ValueError('Invalid runtime symlink')
                rows.append([relative, 'symlink', target])
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                used += info.st_size
                if used > max_bytes:
                    raise ValueError('Runtime contents exceed their bound')
                item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
                with os.fdopen(item, 'rb') as stream:
                    opened = os.fstat(stream.fileno())
                    if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
                        raise ValueError('Runtime file changed during inspection')
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                rows.append([relative, 'file', info.st_size, info.st_mode & 0o777, digest])
            else:
                raise ValueError('Runtime special files and hard links are forbidden')
    try:
        walk(fd, '')
    finally:
        os.close(fd)
    return hashlib.sha256(json.dumps(rows, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def _filter():
    """An explicit native x86-64 CPU syscall profile; unknown calls fail closed."""
    if os.uname().machine != 'x86_64':
        raise ValueError('This native syscall profile requires x86-64')
    library_fd = _pinned_file(SECCOMP, SECCOMP_SHA256)
    try:
        lib = ctypes.CDLL(f'/proc/self/fd/{library_fd}', use_errno=True)
    finally:
        os.close(library_fd)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    class Compare(ctypes.Structure):
        _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int), ('a', ctypes.c_uint64), ('b', ctypes.c_uint64)]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(Compare)]
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    ctx = lib.seccomp_init(0x00050000 | errno.EPERM)
    if not ctx:
        raise RuntimeError('Could not prepare syscall policy')
    fd = os.memfd_create('cannabis-syscalls', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    def rule(name, action=0x7fff0000, comparisons=()):
        nr = lib.seccomp_syscall_resolve_name(name.encode())
        if nr < 0:
            raise ValueError('Unknown syscall in pinned native profile')
        values = (Compare * len(comparisons))(*(Compare(*x) for x in comparisons))
        if lib.seccomp_rule_add_array(ctx, action, nr, len(values), values) != 0:
            raise RuntimeError('Could not construct syscall rule')
    try:
        for name in '''read write readv writev pread64 pwrite64 preadv pwritev preadv2 pwritev2
            open openat close close_range lseek stat fstat lstat newfstatat statx access faccessat faccessat2
            getdents getdents64 readlink readlinkat getcwd chdir fchdir mkdir mkdirat rmdir unlink unlinkat
            rename renameat renameat2 link linkat symlink symlinkat chmod fchmod fchmodat
            truncate ftruncate fallocate fsync fdatasync sync_file_range statfs fstatfs
            utime utimes futimesat utimensat fcntl flock dup dup2 dup3 pipe pipe2
            poll ppoll select pselect6 epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait
            mmap mprotect munmap mremap madvise brk mincore msync membarrier
            rt_sigaction rt_sigprocmask rt_sigpending rt_sigtimedwait rt_sigqueueinfo rt_tgsigqueueinfo
            rt_sigsuspend rt_sigreturn sigaltstack kill tkill tgkill restart_syscall
            futex futex_waitv set_robust_list get_robust_list rseq
            clock_gettime clock_getres clock_nanosleep gettimeofday time nanosleep
            alarm setitimer getitimer timer_create timer_delete timer_gettime timer_getoverrun timer_settime
            timerfd_create timerfd_settime timerfd_gettime eventfd eventfd2 signalfd signalfd4
            getpid getppid gettid getuid geteuid getgid getegid getgroups getresuid getresgid
            getpgrp getpgid getsid setsid setpgid getrlimit getrusage times sysinfo uname getrandom
            sched_getaffinity sched_setaffinity sched_yield sched_getparam sched_getscheduler
            sched_get_priority_max sched_get_priority_min sched_rr_get_interval
            arch_prctl set_tid_address execve execveat wait4 waitid fork vfork exit exit_group
            sendmsg recvmsg sendto recvfrom shutdown getsockname getpeername
            getsockopt setsockopt bind listen accept accept4 connect memfd_create'''.split():
            rule(name)
        # Permit local UNIX IPC only. There is no IP, netlink, packet or vsock path.
        rule('socket', comparisons=[(0, 4, 1, 0)])  # SCMP_CMP_EQ AF_UNIX
        rule('socketpair', comparisons=[(0, 4, 1, 0)])
        # Ordinary processes/threads, without any new namespace flag.
        rule('clone', comparisons=[(0, 7, 0x7e020080, 0)])  # SCMP_CMP_MASKED_EQ
        rule('clone3', action=0x00050000 | errno.ENOSYS)  # let libc use the filtered clone
        # Read limits only: workloads cannot lift the launcher's hard limits.
        rule('prlimit64', comparisons=[(2, 4, 0, 0)])
        for request in [0x5401, 0x5413, 0x541b, 0x5421, 0x5450, 0x5451]:
            rule('ioctl', comparisons=[(1, 4, request, 0)])
        for option in [3, 15, 16, 21, 39]:
            rule('prctl', comparisons=[(0, 4, option, 0)])
        if lib.seccomp_export_bpf(ctx, fd) != 0:
            raise RuntimeError('Could not export syscall policy')
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise
    finally:
        lib.seccomp_release(ctx)


def enter_private_mount_namespace():
    global _entered
    if sys.platform != 'linux' or os.geteuid() != 0 or len(os.listdir('/proc/self/task')) != 1 or _entered:
        raise ValueError('Require one dedicated privileged single-threaded supervisor per sandbox')
    libc = _libc()
    _call(libc.unshare(0x00020000))  # CLONE_NEWNS
    _call(libc.mount(None, b'/', None, 0x4000 | 0x40000, None))  # recursive private propagation
    _entered = True


@dataclass(frozen=True)
class ScratchLimits:
    bytes: int
    inodes: int = 4096

    def __post_init__(self):
        if type(self.bytes) is not int or self.bytes % 4096 or not 1024**2 <= self.bytes <= 1024**4:
            raise ValueError('Invalid scratch byte quota')
        if type(self.inodes) is not int or not 32 <= self.inodes <= 1000000:
            raise ValueError('Invalid scratch inode quota')


class NativeSandbox:
    """One namespace, one resource group, one launch; encrypted delivery is external.

    Keep this context alive while the trusted result encoder consumes output and
    logs. Never print those plaintext files or pass them outside the protected VM.
    A non-success result is not accepted useful work. This is not a TEE verifier.
    """
    def __init__(self, parent, rootfs, inputs, expected_root, limits, scratch, *, workspace='/'):
        if not isinstance(limits, ResourceLimits) or not isinstance(scratch, ScratchLimits):
            raise ValueError('Require validated resource and storage limits')
        if not isinstance(expected_root, str) or len(expected_root) != 64 or any(c not in '0123456789abcdef' for c in expected_root):
            raise ValueError('Require the retained approved runtime digest')
        if tree_digest(rootfs) != expected_root:
            raise ValueError('Runtime root differs from the retained assignment')
        for name in MOUNTS:
            entry = Path(rootfs) / name
            if entry.is_symlink() or not entry.is_dir() or any(entry.iterdir()):
                raise ValueError('Runtime mount points must be real empty directories')
        # Inputs are already authenticated/decrypted by the guest workload path.
        # Inspect before copying; no FIFO, device, socket, hard link or outside mount.
        tree_digest(inputs, max_bytes=scratch.bytes, max_entries=scratch.inodes)
        self._fds, self._guard, self._process, self._path = [], None, None, None
        self._mounted = self._runtime_mounted = self._ran = False
        self._report = None
        self.limits, self.scratch = limits, scratch
        # The backing directory receives only an empty mount point. Plaintext
        # exists solely on the private noswap tmpfs mounted over it below.
        workspace_fd = _directory(workspace, memory=False)
        os.close(workspace_fd)
        if any(not p.stat().st_mode & 0o001 for p in [Path(workspace), *Path(workspace).parents]):
            raise ValueError('Sandbox handoff ancestors must permit directory traversal')
        enter_private_mount_namespace()
        try:
            self._guard = GuardedResources(parent, limits, startup_seconds=10)
            self._path = Path(workspace) / ('cannabis-sandbox-' + uuid.uuid4().hex)
            self._path.mkdir(mode=0o700)
            options = f'size={scratch.bytes},nr_inodes={scratch.inodes},mode=0711,noswap'.encode()
            _call(_libc().mount(b'tmpfs', os.fsencode(self._path), b'tmpfs', 2 | 4, options))  # nosuid,nodev
            self._mounted = True
            # bwrap canonicalizes bind-fd paths. Expose the approved tree through
            # a read-only alias inside ONLY this private mount namespace; its
            # protected source parents retain their original permissions.
            self._runtime = self._path / 'rootfs'
            self._runtime.mkdir(mode=0o755)
            source_fd = _directory(rootfs)
            try:
                _call(_libc().mount(f'/proc/self/fd/{source_fd}'.encode(), os.fsencode(self._runtime), None, 4096, None))
                self._runtime_mounted = True
                _call(_libc().mount(None, os.fsencode(self._runtime), None, 4096 | 32 | 1 | 2 | 4, None))
            finally:
                os.close(source_fd)
            # One writable filesystem supplies every output/temp/log path, so
            # multiple mounts cannot multiply the purchased scratch capacity.
            for name in ['work', 'output', 'tmp', 'run', 'shm']:
                directory = self._path / name
                directory.mkdir(mode=0o700)
                os.chown(directory, 65534, 65534)
            self.output_directory = self._path / 'output'
            # The read-only inputs snapshot retains executable intent and
            # becomes readable only through a passed directory descriptor.
            self._inputs = self._path / 'inputs'
            shutil.copytree(inputs, self._inputs, symlinks=True)
            for entry in [self._inputs, *self._inputs.rglob('*')]:
                if not entry.is_symlink():
                    entry.chmod(0o555 if entry.is_dir() or entry.stat().st_mode & 0o111 else 0o444)
            self._root = Path(rootfs)
            self._expected_root = expected_root
            self._guard.assert_alive()
        except BaseException:
            self.close()
            raise

    def run(self, argv, *, cancelled=None):
        if self._ran or self._guard is None:
            raise ValueError('Sandbox permits exactly one launch')
        if (not isinstance(argv, list) or not argv or len(argv) > 256 or
            any(not isinstance(x, str) or '\0' in x or len(x.encode()) > 16384 for x in argv) or
            not argv[0].startswith('/') or sum(len(x.encode()) + 1 for x in argv) > 131072):
            raise ValueError('Require a bounded absolute runtime command')
        if tree_digest(self._root) != self._expected_root:
            raise ValueError('Approved runtime changed before execution')
        self._ran = True
        self._guard.assert_alive()
        if cancelled is not None and cancelled.is_set():
            return {'reason': 'cancelled', 'exitCode': None, 'success': False, 'cleanup': self._guard.close()}
        root_fd = _directory(self._runtime)
        self._fds.append(root_fd)
        input_fd = _directory(self._inputs)
        self._fds.append(input_fd)
        bwrap_fd = _pinned_file(BWRAP, BWRAP_SHA256)
        self._fds.append(bwrap_fd)
        filter_fd = _filter()
        self._fds.append(filter_fd)
        args = [BWRAP, '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-net', '--unshare-uts',
            '--unshare-cgroup', '--disable-userns', '--assert-userns-disabled', '--new-session', '--die-with-parent',
            '--uid', '65534', '--gid', '65534', '--cap-drop', 'ALL', '--hostname', 'cannabis-workload',
            '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
            '--setenv', 'HOME', '/work', '--setenv', 'TMPDIR', '/tmp',
            '--ro-bind-fd', str(root_fd), '/', '--ro-bind-fd', str(input_fd), '/input',
            '--proc', '/proc', '--remount-ro', '/proc', '--dev', '/dev']
        for name, destination in [('work', '/work'), ('output', '/output'), ('tmp', '/tmp'), ('run', '/run'), ('shm', '/dev/shm')]:
            fd = os.open(self._path / name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self._fds.append(fd)
            args += ['--bind-fd', str(fd), destination]
        args += ['--remount-ro', '/dev', '--seccomp', str(filter_fd), '--chdir', '/work', '--', *argv]
        # Trusted launcher setup is a distinct process, never Python preexec_fn
        # in a possibly threaded application. No command or content is logged.
        settings = {'group': str(self._guard.path), 'limits': self.limits.__dict__, 'bwrapFD': bwrap_fd,
                    'args': args, 'keepFDs': self._fds, 'fileBytes': self.scratch.bytes}
        config_fd = os.memfd_create('cannabis-launch', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        self._fds.append(config_fd)
        os.write(config_fd, json.dumps(settings).encode())
        os.lseek(config_fd, 0, os.SEEK_SET)
        fcntl.fcntl(config_fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        stdout = (self._path / 'stdout').open('xb')
        stderr = (self._path / 'stderr').open('xb')
        try:
            script = Path(__file__).resolve().parents[1] / 'scripts/compute-guest-sandbox.py'
            self._process = subprocess.Popen([sys.executable, '-I', '-B', str(script), str(config_fd)],
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True, pass_fds=tuple(self._fds),
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, start_new_session=True)
        finally:
            stdout.close()
            stderr.close()
            for fd in self._fds:
                os.close(fd)
            self._fds.clear()
        pidfd = os.pidfd_open(self._process.pid)
        reason = 'failed'
        try:
            while True:
                if cancelled is not None and cancelled.is_set():
                    reason = 'cancelled'
                    cleanup = self._guard.close()
                    break
                ready = select.select([pidfd, self._guard.fileno()], [], [], 0.05)[0]
                if self._guard.fileno() in ready:
                    cleanup = self._guard.wait()
                    reason = cleanup['reason']
                    break
                if pidfd in ready:
                    self._process.wait(timeout=5)
                    # Descendants can outlive their leader. Finish cannot
                    # disarm a busy group and never means accepted useful work.
                    cleanup = self._guard.wait(action='finish')
                    reason = cleanup['reason']
                    break
                # The guardian owns the deadline; waiting for its checked reply
                # avoids racing that reply with the local clock at expiry.
                if time.monotonic() >= self._guard.deadline:
                    cleanup = self._guard.wait()
                    reason = cleanup['reason']
                    break
            self._process.wait(timeout=5)
            self._report = {'reason': reason, 'exitCode': self._process.returncode,
                'success': reason == 'finished' and self._process.returncode == 0,
                'cleanup': cleanup, 'hardwareAdmissionEstablished': False, 'paymentAccepted': False}
            return dict(self._report)
        finally:
            os.close(pidfd)

    def close(self):
        failure = None
        if self._guard is not None:
            try:
                self._guard.close()
            except Exception as error:
                failure = error
            self._guard = None
        if self._process is not None:
            try:
                self._process.wait(timeout=5)
            except Exception as error:
                failure = error
        for fd in self._fds:
            os.close(fd)
        self._fds.clear()
        if self._runtime_mounted:
            try:
                _call(_libc().umount2(os.fsencode(self._runtime), 0))
            except OSError as error:
                raise ResourceCleanupError('Runtime root did not unmount; retire the guest') from error
            self._runtime_mounted = False
        if self._mounted:
            # Never lazily detach: failure means the guest must be retired.
            try:
                _call(_libc().umount2(os.fsencode(self._path), 0))
            except OSError as error:
                raise ResourceCleanupError('Protected scratch did not unmount; retire the guest') from error
            self._mounted = False
        if self._path is not None:
            self._path.rmdir()
            self._path = None
        if failure is not None:
            raise ResourceCleanupError('Runtime cleanup requires guest retirement') from failure

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def launch_from_fd(fd):
    """Trusted trampoline, invoked before any untrusted instruction can run."""
    raw = os.read(fd, 262145)
    os.close(fd)
    if len(raw) > 262144:
        raise ValueError('Launch contract exceeds its bound')
    config = json.loads(raw)
    join_current_process(config['group'], ResourceLimits(**config['limits']))
    for kind, maximum in [(resource.RLIMIT_CORE, 0), (resource.RLIMIT_RTPRIO, 0),
                          (resource.RLIMIT_MEMLOCK, 0), (resource.RLIMIT_NOFILE, 1024),
                          (resource.RLIMIT_FSIZE, config['fileBytes'])]:
        resource.setrlimit(kind, (maximum, maximum))
    os.setgroups([])
    os.chdir('/')
    os.setresgid(65534, 65534, 65534)
    os.setresuid(65534, 65534, 65534)
    _call(_libc().prctl(38, 1, 0, 0, 0))  # no_new_privs before bwrap itself
    for item in config['keepFDs']:
        if item != fd:
            os.set_inheritable(item, item != config['bwrapFD'])
    os.execve(config['bwrapFD'], config['args'], {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
