"""Linux cgroup-v2 resource boundary for a trusted, measured guest launcher.

This module does not launch customer code or supply a filesystem/network sandbox.
The caller must isolate workloads from the control plane and every cgroup handle.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import os
from pathlib import Path
import sys
import time
import uuid


class ResourceCleanupError(RuntimeError):
    """The guest must be retired; cleanup has not been proven."""


@dataclass(frozen=True)
class ResourceLimits:
    cpu_millis: int
    memory_bytes: int
    processes: int
    wall_seconds: int

    def __post_init__(self):
        for name, low, high in [('cpu_millis', 10, 4096000),
                                ('memory_bytes', 16 * 1024**2, 1024**4),
                                ('processes', 1, 65536), ('wall_seconds', 1, 2592000)]:
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError('Invalid guest resource limit: ' + name)
        if self.memory_bytes % 4096:
            raise ValueError('Memory limit must be page aligned')

    @classmethod
    def from_task(cls, resources, *, process_limit):
        """Use retained task resources and an explicit measured adapter PID limit.

        Scratch, nodes and devices are enforced separately. This never silently
        clamps an unfulfillable job to a smaller amount of purchased resources.
        """
        if not isinstance(resources, dict) or any(type(resources.get(k)) is not int for k in ['cpus', 'memoryMiB', 'wallSeconds']):
            raise ValueError('Require retained integer task limits')
        return cls(resources['cpus'] * 1000, resources['memoryMiB'] * 1024**2,
                   process_limit, resources['wallSeconds'])

    def controls(self):
        return {'cpu.max': f'{self.cpu_millis * 100} 100000', 'cpu.max.burst': '0',
                'memory.max': str(self.memory_bytes), 'memory.swap.max': '0',
                'memory.oom.group': '1', 'pids.max': str(self.processes),
                'cgroup.max.depth': '0', 'cgroup.max.descendants': '0'}


def _directory(path):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Require the privileged Linux guest control plane')
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Require an absolute trusted cgroup path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        # Resolve one component at a time without following links, including
        # intermediate links. Trusted roots must not be writable by workloads.
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Cgroup path must remain owned and writable only by root')
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
        libc.fstatfs.restype = ctypes.c_int
        buffer = (ctypes.c_long * 32)()
        if libc.fstatfs(fd, ctypes.byref(buffer)) != 0 or buffer[0] != 0x63677270:
            raise ValueError('Require the real cgroup-v2 filesystem')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(fd, name):
    item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        value = os.read(item, 65537)
        if len(value) > 65536:
            raise ValueError('Cgroup response exceeds its bound')
        return value.decode('ascii').strip()
    finally:
        os.close(item)


def _write(fd, name, value):
    item = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        data = (value + '\n').encode('ascii')
        if os.write(item, data) != len(data):
            raise OSError('Incomplete cgroup control write')
    finally:
        os.close(item)


def _values(fd, name):
    result = {}
    for line in _read(fd, name).splitlines():
        key, value = line.split()
        if key in result or not value.isdecimal():
            raise ValueError('Unexpected cgroup counter')
        result[key] = int(value)
    return result


def _verify(fd, limits):
    if _read(fd, 'cgroup.type') != 'domain':
        raise ValueError('Require a domain cgroup')
    for name, value in limits.controls().items():
        if _read(fd, name) != value:
            raise ValueError('Guest resource control changed: ' + name)
    if 'memory.zswap.max' in os.listdir(fd) and _read(fd, 'memory.zswap.max') != '0':
        raise ValueError('Guest compressed swap must be disabled')


def join_current_process(path, limits):
    """Called by a trusted single-threaded launcher BEFORE any customer code.

    Move this process itself, rather than a PID from an untrusted source. Children
    then inherit membership. Close every control descriptor before runtime entry,
    drop privileges/capabilities and hide the hierarchy in the runtime sandbox.
    """
    if not isinstance(limits, ResourceLimits):
        raise ValueError('Require validated resource limits')
    fd = _directory(path)
    try:
        _verify(fd, limits)
        if len(os.listdir('/proc/self/task')) != 1:
            raise ValueError('Resource admission requires a single-threaded launcher')
        # Real-time scheduling bypasses cpu.max. The isolated runtime must keep
        # CAP_SYS_NICE and real-time rlimits unavailable after this gate.
        if os.sched_getscheduler(0) != os.SCHED_OTHER:
            raise ValueError('Require the normal CPU scheduler')
        _write(fd, 'cgroup.procs', '0')
        if str(os.getpid()) not in _read(fd, 'cgroup.procs').split():
            raise RuntimeError('Process did not enter its resource group')
    finally:
        os.close(fd)


class JobResourceGroup:
    """One fresh group, used serially by a live trusted supervisor.

    The parent is a preconfigured empty domain with cpu/memory/pids enabled.
    Creation never changes ancestor limits or moves unrelated processes.
    """
    def __init__(self, parent, limits):
        if not isinstance(limits, ResourceLimits):
            raise ValueError('Require validated resource limits')
        self.limits = limits
        self._fd = self._parent = None
        self._created = False
        self._configured = False
        self._report = None
        self._name = 'job-' + uuid.uuid4().hex
        self.path = Path(parent) / self._name
        self.deadline = time.monotonic() + limits.wall_seconds
        self._parent = _directory(parent)
        try:
            if _read(self._parent, 'cgroup.type') != 'domain' or _read(self._parent, 'cgroup.procs'):
                raise ValueError('Require an empty parent domain')
            if not {'cpu', 'memory', 'pids'} <= set(_read(self._parent, 'cgroup.subtree_control').split()):
                raise ValueError('CPU, memory and PID controllers must be enabled')
            os.mkdir(self._name, 0o700, dir_fd=self._parent)
            self._created = True
            self._fd = os.open(self._name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._parent)
            for name, value in limits.controls().items():
                _write(self._fd, name, value)
            if 'memory.zswap.max' in os.listdir(self._fd):
                _write(self._fd, 'memory.zswap.max', '0')
            _verify(self._fd, limits)
            self._configured = True
            # Verify the tree-kill primitive exists before admitting any child.
            _write(self._fd, 'cgroup.kill', '1')
            if self.populated:
                raise RuntimeError('Fresh resource group is unexpectedly populated')
        except BaseException:
            self.close()
            raise

    @property
    def populated(self):
        if self._fd is None:
            return False
        return _values(self._fd, 'cgroup.events')['populated'] != 0

    def snapshot(self):
        if self._fd is None:
            if self._report is None:
                raise RuntimeError('Resource group is unavailable')
            return dict(self._report)
        return {'cpu': _values(self._fd, 'cpu.stat'), 'memory': _values(self._fd, 'memory.events'),
                'pids': _values(self._fd, 'pids.events'),
                'memoryPeakBytes': int(_read(self._fd, 'memory.peak')),
                'populated': self.populated}

    def wait(self, *, cancelled=None):
        """After trusted admission, await empty, cancel or the monotonic deadline.

        Cancellation is a caller-supplied Event. A crashed supervisor requires
        an independent guest watchdog; this in-process loop cannot replace one.
        """
        if self._fd is None:
            raise RuntimeError('Resource group is closed')
        while True:
            if cancelled is not None and cancelled.is_set():
                return {'reason': 'cancelled', **self.close()}
            if time.monotonic() >= self.deadline:
                return {'reason': 'deadline', **self.close()}
            if not self.populated:
                return {'reason': 'empty', **self.close()}
            time.sleep(0.01)

    def close(self):
        """Kill the entire tree, prove it empty, then remove only our new group.

        A timeout or failed removal is fatal, not a successful cleanup report.
        Keep descriptors available for retry; the owner must retire the guest
        if an independent watchdog cannot complete cleanup.
        """
        if self._parent is None:
            return dict(self._report or {})
        if self._fd is not None and self._removed():
            # A trusted guardian can remove our exact group first. kernfs
            # unlinks only an empty group; never act on a replacement by name.
            os.close(self._fd)
            os.close(self._parent)
            self._fd = self._parent = None
            self._report = {'removed': True, 'populated': False, 'guardianRemoved': True}
            return dict(self._report)
        if self._fd is not None:
            try:
                _write(self._fd, 'cgroup.kill', '1')
                deadline = time.monotonic() + 5
                while self.populated:
                    if time.monotonic() >= deadline:
                        raise ResourceCleanupError('Guest process tree did not become empty')
                    time.sleep(0.01)
                # Partial construction may not expose every controller. Only
                # record counters for a fully configured group.
                if self._report is None:
                    self._report = self.snapshot() if self._configured else {}
            except OSError as error:
                raise ResourceCleanupError('Guest process tree cleanup failed') from error
        if self._created:
            try:
                entry = os.stat(self._name, dir_fd=self._parent, follow_symlinks=False)
                if self._fd is not None:
                    opened = os.fstat(self._fd)
                    if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
                        raise ResourceCleanupError('Guest resource group identity changed')
                os.rmdir(self._name, dir_fd=self._parent)
            except OSError as error:
                raise ResourceCleanupError('Guest resource group removal failed') from error
        if self._fd is not None:
            os.close(self._fd)
        os.close(self._parent)
        self._fd = self._parent = None
        self._report = {**(self._report or {}), 'populated': False, 'removed': True}
        return dict(self._report)

    def _removed(self):
        """Verify removal of this retained kernel object, not just its name."""
        try:
            _read(self._fd, 'cgroup.events')
        except OSError as error:
            if error.errno not in [errno.ENOENT, errno.ENODEV]:
                raise
            return os.readlink(f'/proc/self/fd/{self._fd}').endswith('/' + self._name + ' (deleted)')
        return False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
