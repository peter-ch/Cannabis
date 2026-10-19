"""Two-phase native execution inside an already contained guest control plane.

Only the initialized, funded session may supply this configuration. The profile
hash must be independently approved and match the signed reservation. A readiness
frame is a local lifecycle gate, not evidence of confidential hardware admission.
"""
from dataclasses import asdict
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import stat
import sys
import time

from .client import canonical
from .guest_deadline import ExecutionDeadline
from .guest_native import NativeTaskPlan
from .guest_resources import ResourceLimits, ResourceTreeLimits, _directory, _read, _verify
from .guest_sandbox import ScratchLimits, _pinned_file, BWRAP, BWRAP_SHA256, SECCOMP, SECCOMP_SHA256
from .job_keys import RecoveredJobKey

REQUEST_MAX = 65536
RESPONSE_MAX = 5 * 1024**2
PROTOCOL = 'cannabis.guest-native.pipe.v1'


def exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError('Unexpected protected protocol fields')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate protected protocol field')
        result[key] = value
    return result


class NativeServiceProfile:
    """An explicit service unit includes control, helpers and runtime capacity.

    Memory conservatively reserves both tmpfs quotas in addition to process
    budgets. This is a process subtree profile; immutable guest/image/outer-owner
    overhead and whole-VM lifecycle must also be reserved by hardware admission.
    """
    def __init__(self, value, service_sha256, units):
        value = copy.deepcopy(value)
        exact(value, ['schema', 'units', 'runtime', 'resources', 'total', 'control',
                      'helper', 'processLimit', 'scratchInodes', 'staging', 'maxInputBytes', 'tools'])
        if (value['schema'] != 'cannabis.guest-native-service.v1' or type(units) is not int
                or units != 1 or type(value['units']) is not int or value['units'] != units
                or service_sha256 != '0x' + hashlib.sha256(canonical(value)).hexdigest()):
            raise ValueError('Native service profile differs from the signed service unit')
        exact(value['tools'], ['pythonSHA256', 'ageSHA256', 'ageKeygenSHA256'])
        if any(not isinstance(h, str) or not re.fullmatch('[0-9a-f]{64}', h) for h in value['tools'].values()):
            raise ValueError('Require measured tool pins')
        self.total = ResourceTreeLimits(**value['total'])
        self.control = ResourceLimits(**value['control'])
        self.helper = ResourceLimits(**value['helper'])
        self.task = ResourceLimits.from_task(value['resources'], process_limit=value['processLimit'])
        self.staging = ScratchLimits(**value['staging'])
        self.scratch = ScratchLimits(value['resources']['scratchMiB'] * 1024**2, value['scratchInodes'])
        if self.total.children < 3:
            raise ValueError('Control, native sandbox and sealing helper need three leaves')
        for name in ['cpu_millis', 'processes']:
            if sum(getattr(v, name) for v in [self.control, self.helper, self.task]) > getattr(self.total, name):
                raise ValueError('Service unit does not reserve concurrent process capacity')
        if (self.control.memory_bytes + self.helper.memory_bytes + self.task.memory_bytes
                + self.staging.bytes + self.scratch.bytes > self.total.memory_bytes):
            raise ValueError('Service unit does not reserve concurrent memory and protected storage')
        if any(v.wall_seconds > self.total.wall_seconds for v in [self.control, self.helper, self.task]):
            raise ValueError('Stage time exceeds the service unit')
        if type(value['maxInputBytes']) is not int or not 0 <= value['maxInputBytes'] <= self.staging.bytes:
            raise ValueError('Require a bounded extraction budget')
        self.value = value
        self.service_sha256 = service_sha256


class ParentLifetime:
    def __init__(self):
        parent = os.getppid()
        if parent <= 1:
            raise ValueError('Require the live containing control process')
        self.fd = os.pidfd_open(parent)
        if os.getppid() != parent or self.is_set():
            self.close()
            raise RuntimeError('Control parent changed during admission')
        self.pid = parent

    def is_set(self):
        return bool(select.select([self.fd], [], [], 0)[0])

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class PrivateFrames:
    def __init__(self, deadline, parent):
        self.deadline, self.parent = deadline, parent
        self.reader, self.writer = sys.stdin.fileno(), sys.stdout.fileno()
        if os.isatty(self.reader) or os.isatty(self.writer):
            raise ValueError('Require anonymous protected control pipes')
        # Named regular files must not become a key inbox or plaintext log.
        for fd in [self.reader, self.writer]:
            mode = os.fstat(fd).st_mode
            if stat.S_ISFIFO(mode) and os.readlink(f'/proc/self/fd/{fd}').startswith('pipe:['):
                continue
            # libuv implements child stdio using unnamed Unix socket pairs.
            if stat.S_ISSOCK(mode):
                with socket.socket(fileno=os.dup(fd)) as channel:
                    if (channel.family == socket.AF_UNIX and channel.type == socket.SOCK_STREAM
                            and channel.getsockname() in ['', b''] and channel.getpeername() in ['', b'']):
                        continue
            raise ValueError('Require anonymous protected pipes or local socket pairs')
        os.set_blocking(self.reader, False)
        os.set_blocking(self.writer, False)

    def _wait(self, writing=False):
        while True:
            self.deadline.check(self.parent)
            reads = [self.parent.fd] + ([] if writing else [self.reader])
            ready, writable, _ = select.select(reads, [self.writer] if writing else [], [], 0.05)
            self.deadline.check(self.parent)
            if self.reader in ready or self.writer in writable:
                return

    def _read(self, size):
        raw = bytearray()
        try:
            while len(raw) < size:
                self._wait()
                chunk = os.read(self.reader, size - len(raw))
                if not chunk:
                    raise ValueError('Protected frame ended early')
                raw.extend(chunk)
            return raw
        except BaseException:
            raw[:] = b'\0' * len(raw)
            raise

    def receive(self):
        length = int.from_bytes(self._read(4), 'big')
        if not 0 < length <= REQUEST_MAX:
            raise ValueError('Protected frame exceeds its bound')
        raw = self._read(length)
        try:
            def invalid_constant(_): raise ValueError('Nonfinite protected JSON value')
            return json.loads(raw, object_pairs_hook=_unique, parse_constant=invalid_constant)
        finally:
            raw[:] = b'\0' * len(raw)

    def end_input(self):
        self._wait()
        if os.read(self.reader, 1):
            raise ValueError('Unexpected extra protected frame')

    def send(self, value):
        raw = bytearray(canonical(value))
        try:
            if not 0 < len(raw) <= RESPONSE_MAX:
                raise ValueError('Protected response exceeds its bound')
            raw[:0] = len(raw).to_bytes(4, 'big')
            offset = 0
            while offset < len(raw):
                self._wait(writing=True)
                offset += os.write(self.writer, memoryview(raw)[offset:offset + 65536])
        finally:
            raw[:] = b'\0' * len(raw)


class NativeExecutionAdmission:
    """Retain real kernel objects, the profile and runtime before reading keys."""
    def __init__(self, request, deadline, parent):
        exact(request, ['protocol', 'operation', 'profile', 'serviceSHA256', 'units', 'source', 'binding', 'interval'])
        if request['protocol'] != PROTOCOL or request['operation'] != 'prepare':
            raise ValueError('Require native preparation before key release')
        self.profile = NativeServiceProfile(request['profile'], request['serviceSHA256'], request['units'])
        self.source, self.binding = copy.deepcopy(request['source']), copy.deepcopy(request['binding'])
        exact(self.binding, ['packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256',
                             'attempt', 'rank', 'worldSize', 'acceleratorClass'])
        if any(not isinstance(self.binding[k], str) or not re.fullmatch('[0-9a-f]{64}', self.binding[k])
               for k in ['packageSHA256', 'policySHA256', 'runtimeSHA256', 'taskSHA256']):
            raise ValueError('Invalid retained workload commitments')
        if (type(self.binding['attempt']) is not int or not 1 <= self.binding['attempt'] <= 1000000
                or type(self.binding['rank']) is not int or type(self.binding['worldSize']) is not int):
            raise ValueError('Invalid retained workload attempt or rank')
        exact(self.source, ['rootfs', 'age', 'ciphertext', 'destination'])
        if any(not isinstance(p, str) or not Path(p).is_absolute() or '..' in Path(p).parts or '\0' in p for p in self.source.values()):
            raise ValueError('Require trusted absolute guest paths')
        exact(request['interval'], ['start', 'end'])
        interval = ExecutionDeadline.from_service_interval(**request['interval'])
        # Clamping can only shorten the outer guardian's already-running deadline.
        self.deadline = ExecutionDeadline(min(deadline.monotonic_end, interval.monotonic_end))
        self.parent = parent
        self.tree = self.control = None
        try:
            self.path = Path(os.environ['CANNABIS_JOB_CGROUP'])
            self.control_path = Path(os.environ['CANNABIS_JOB_CONTROL'])
            if self.control_path.parent != self.path:
                raise ValueError('Control plane is not a direct leaf of the admitted job')
            if (json.loads(os.environ['CANNABIS_JOB_TOTAL']) != asdict(self.profile.total)
                    or json.loads(os.environ['CANNABIS_JOB_CONTROL_LIMITS']) != asdict(self.profile.control)):
                raise ValueError('Launcher resource profile differs from signed service')
            self.tree, self.control = _directory(self.path), _directory(self.control_path)
            self.verify()
            self.plan = NativeTaskPlan(self.source['rootfs'], self.profile.value['runtime'], self.profile.value['resources'],
                process_limit=self.profile.value['processLimit'], scratch_inodes=self.profile.value['scratchInodes'], deadline=self.deadline)
            pins = self.profile.value['tools']
            for name, expected in [(str(Path(sys.executable).resolve()), pins['pythonSHA256']),
                    (self.source['age'], pins['ageSHA256']),
                    (str(Path(self.source['age']).with_name('age-keygen')), pins['ageKeygenSHA256']),
                    (BWRAP, BWRAP_SHA256), (SECCOMP, SECCOMP_SHA256)]:
                fd = _pinned_file(name, expected)
                os.close(fd)
            if (self.binding.get('runtimeSHA256') != self.profile.value['runtime']['digestSHA256']
                    or self.binding.get('rank') != 0 or self.binding.get('worldSize') != 1
                    or self.binding.get('acceleratorClass') != 'cpu'):
                raise ValueError('Native service does not match the retained assignment')
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        self.deadline.check(self.parent)
        _verify(self.tree, self.profile.total)
        _verify(self.control, self.profile.control)
        if (_read(self.tree, 'cgroup.procs') or not {'cpu', 'memory', 'pids'} <= set(_read(self.tree, 'cgroup.subtree_control').split())
                or not {str(os.getpid()), str(self.parent.pid)} <= set(_read(self.control, 'cgroup.procs').split())):
            raise ValueError('Execution controller is outside the admitted job tree')
        leaves = [name for name in os.listdir(self.tree)
                  if stat.S_ISDIR(os.stat(name, dir_fd=self.tree, follow_symlinks=False).st_mode)]
        if leaves != [self.control_path.name]:
            raise ValueError('Execution tree contains another outstanding stage')
        for path, fd in [(self.path, self.tree), (self.control_path, self.control)]:
            current = _directory(path)
            try:
                if (os.fstat(current).st_dev, os.fstat(current).st_ino) != (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
                    raise ValueError('Retained execution cgroup was replaced')
            finally:
                os.close(current)

    def run(self, job):
        self.verify()
        exact(job, ['identity', 'jobId', 'packageSHA256', 'policySHA256', 'inputRecipient', 'resultRecipient'])
        key = RecoveredJobKey(job['identity'].encode('ascii'), job['jobId'], job['packageSHA256'],
                              job['policySHA256'], job['inputRecipient'], job['resultRecipient'])
        return self.plan.run(self.path, self.source['ciphertext'], key, self.binding, self.source['destination'],
            age=self.source['age'], helper_limits=self.profile.helper, staging_limits=self.profile.staging,
            max_input_bytes=self.profile.value['maxInputBytes'], cancelled=self.parent)

    def close(self):
        for name in ['tree', 'control']:
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


def execution_main():
    deadline = ExecutionDeadline(float(os.environ['CANNABIS_JOB_DEADLINE']))
    deadline.check()
    parent = ParentLifetime()
    admission = None
    try:
        frames = PrivateFrames(deadline, parent)
        admission = NativeExecutionAdmission(frames.receive(), deadline, parent)
        frames.deadline = admission.deadline
        nonce = secrets.token_hex(32)
        frames.send({'protocol':PROTOCOL, 'operation':'ready', 'nonce':nonce,
                     'serviceSHA256':admission.profile.service_sha256})
        delivered = frames.receive()
        exact(delivered, ['protocol', 'operation', 'nonce', 'job'])
        if delivered['protocol'] != PROTOCOL or delivered['operation'] != 'execute' or delivered['nonce'] != nonce:
            raise ValueError('Job key is not bound to this ready execution controller')
        frames.end_input()
        result = admission.run(delivered.pop('job'))
        admission.verify()
        frames.send({'protocol':PROTOCOL, 'operation':'complete', 'nonce':nonce,
                     'report':result.report, 'receipt':result.receipt})
    finally:
        if admission is not None: admission.close()
        parent.close()
