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
from .guest_ciphertext import CiphertextLimits, CiphertextAdmission

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
        grouped = value.get('schema') == 'cannabis.guest-native-service.v4'
        dependencies = value.get('schema') in ['cannabis.guest-native-service.v3', 'cannabis.guest-native-service.v4']
        exact(value, ['schema', 'units', 'runtime', 'resources', 'total', 'control',
                      'helper', 'processLimit', 'scratchInodes', 'staging', 'ciphertext', 'maxInputBytes', 'tools']
                      + (['maxDependencyBytes'] if dependencies else []) + (['group'] if grouped else []))
        if (value['schema'] not in ['cannabis.guest-native-service.v2', 'cannabis.guest-native-service.v3', 'cannabis.guest-native-service.v4'] or type(units) is not int
                or units != 1 or type(value['units']) is not int or value['units'] != units
                or service_sha256 != '0x' + hashlib.sha256(canonical(value)).hexdigest()):
            raise ValueError('Native service profile differs from the signed service unit')
        exact(value['tools'], ['pythonSHA256', 'ageSHA256', 'ageKeygenSHA256'])
        if any(not isinstance(h, str) or not re.fullmatch('[0-9a-f]{64}', h) for h in value['tools'].values()):
            raise ValueError('Require measured tool pins')
        self.total = ResourceTreeLimits(**value['total'])
        self.control = ResourceLimits(**value['control'])
        if grouped:
            group = value['group']
            exact(value['resources'], ['cpus', 'memoryMiB', 'scratchMiB', 'wallSeconds', 'nodes'])
            exact(value['runtime'], ['adapter', 'architecture', 'os', 'digestSHA256', 'collectiveBackend'])
            exact(group, ['protocol', 'bindHost', 'port', 'maxBufferedBytes', 'maxTrafficBytes'])
            nodes = value['resources'].get('nodes')
            if (group['protocol'] != 'cannabis.group-tls-ip.v1' or group['bindHost'] not in ['0.0.0.0', '127.0.0.1', '::', '::1']
                    or type(group['port']) is not int or not 1024 <= group['port'] <= 65535
                    or type(group['maxBufferedBytes']) is not int or not 131072 <= group['maxBufferedBytes'] <= 8 * 1024**2
                    or type(group['maxTrafficBytes']) is not int or not 1 <= group['maxTrafficBytes'] <= 1024**4
                    or type(nodes) is not int or not 2 <= nodes <= 64
                    or value['runtime'].get('adapter') != 'native-group-linux-x86_64-v1'
                    or value['runtime']['architecture'] != 'x86_64' or value['runtime']['os'] != 'linux'
                    or not isinstance(value['runtime']['digestSHA256'], str)
                    or not re.fullmatch('[0-9a-f]{64}', value['runtime']['digestSHA256'])
                    or value['runtime'].get('collectiveBackend') != 'attested-tls-ip-v1'):
                raise ValueError('Require an explicit bounded protected group profile')
            # Reserve baseline control memory plus both private packet queues,
            # per-peer frame/TLS buffers and namespace/packet-kernel headroom.
            minimum = 260 * 1024**2 + 2 * group['maxBufferedBytes'] + (nodes - 1) * (group['maxBufferedBytes'] + 262144)
            if self.control.memory_bytes < minimum or self.control.processes < 16:
                raise ValueError('Group control plane does not reserve its bounded network capacity')
        self.helper = ResourceLimits(**value['helper'])
        self.task = ResourceLimits.from_task(value['resources'], process_limit=value['processLimit'])
        self.staging = ScratchLimits(**value['staging'])
        exact(value['ciphertext'], ['bytes', 'inodes', 'inputBytes', 'outputBytes'] + (['dependencyBytes'] if dependencies else []))
        self.ciphertext = CiphertextLimits(**value['ciphertext'])
        if dependencies and self.ciphertext.dependencyBytes < 1:
            raise ValueError('Require separately reserved dependency ciphertext capacity')
        self.scratch = ScratchLimits(value['resources']['scratchMiB'] * 1024**2, value['scratchInodes'])
        if self.total.children < 3:
            raise ValueError('Control, native sandbox and sealing helper need three leaves')
        for name in ['cpu_millis', 'processes']:
            if sum(getattr(v, name) for v in [self.control, self.helper, self.task]) > getattr(self.total, name):
                raise ValueError('Service unit does not reserve concurrent process capacity')
        if (self.control.memory_bytes + self.helper.memory_bytes + self.task.memory_bytes
                + self.staging.bytes + self.scratch.bytes + self.ciphertext.bytes > self.total.memory_bytes):
            raise ValueError('Service unit does not reserve concurrent memory and protected storage')
        if any(v.wall_seconds > self.total.wall_seconds for v in [self.control, self.helper, self.task]):
            raise ValueError('Stage time exceeds the service unit')
        if type(value['maxInputBytes']) is not int or not 0 <= value['maxInputBytes'] <= self.staging.bytes:
            raise ValueError('Require a bounded extraction budget')
        if dependencies and (type(value['maxDependencyBytes']) is not int or value['maxDependencyBytes'] < 0
                or value['maxInputBytes'] + value['maxDependencyBytes'] > self.staging.bytes):
            raise ValueError('Dependency extraction exceeds the shared protected staging budget')
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
    def __init__(self, request, deadline, parent, *, inspect_only=False):
        exact(request, ['protocol', 'operation', 'profile', 'serviceSHA256', 'units', 'source', 'binding', 'interval']
              + (['dependency'] if 'dependency' in request else []) + (['group'] if 'group' in request else []))
        if request['protocol'] != PROTOCOL or request['operation'] != 'prepare':
            raise ValueError('Require native preparation before key release')
        self.profile = NativeServiceProfile(request['profile'], request['serviceSHA256'], request['units'])
        self.source, self.binding = copy.deepcopy(request['source']), copy.deepcopy(request['binding'])
        self.dependency = copy.deepcopy(request.get('dependency'))
        if 'dependency' in request:
            if self.profile.value['schema'] not in ['cannabis.guest-native-service.v3', 'cannabis.guest-native-service.v4']:
                raise ValueError('Dependency inputs need explicit service capacity')
            exact(self.dependency, ['schema','context','ciphertextSHA256','ciphertextBytes','format','recipient'])
            if (self.dependency['schema'] != 'cannabis.dependency-handoff.v1' or self.dependency['format'] != 'age-v1+ustar'
                    or any(self.dependency['context'].get(k) != self.binding[k] for k in self.binding)):
                raise ValueError('Retained dependency differs from the approved task')
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
        self.tree = self.control = self.ciphertext = self.group_network = None
        self._probe_sockets = []
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
            self.ciphertext = CiphertextAdmission(self.source,self.profile.ciphertext,self.binding['packageSHA256'],self.deadline,self.parent,
                {k:self.dependency[k] for k in ['ciphertextSHA256','ciphertextBytes']} if self.dependency else None)
            grouped = self.profile.value['schema'] == 'cannabis.guest-native-service.v4'
            if grouped:
                from .guest_group_network import GuestGroupNetwork
                group = copy.deepcopy(request.get('group'))
                if group is None:
                    if not inspect_only:
                        raise ValueError('Actual group execution requires the retained group approval')
                    group = {'schema': 'cannabis.guest-group-network.v1', 'rank': self.binding['rank'],
                             'worldSize': self.binding['worldSize'], 'groupDigest': '0x' + '11' * 32,
                             'maxBufferedBytes': self.profile.value['group']['maxBufferedBytes']}
                if (group.get('rank') != self.binding['rank'] or group.get('worldSize') != self.binding['worldSize']
                        or group.get('maxBufferedBytes') != self.profile.value['group']['maxBufferedBytes']):
                    raise ValueError('Protected group network differs from the retained rank')
                if inspect_only:
                    incoming, source = socket.socketpair(); destination, outgoing = socket.socketpair()
                    self._probe_sockets = [incoming, source, destination, outgoing]
                    self.group_network = GuestGroupNetwork.create(group, self.deadline, incoming.fileno(), outgoing.fileno())
                else:
                    self.group_network = GuestGroupNetwork.create(group, self.deadline)
            elif 'group' in request:
                raise ValueError('Single-rank service cannot receive a group network')
            self.plan = NativeTaskPlan(self.source['rootfs'], self.profile.value['runtime'], self.profile.value['resources'],
                process_limit=self.profile.value['processLimit'], scratch_inodes=self.profile.value['scratchInodes'], deadline=self.deadline,
                group_network=self.group_network)
            pins = self.profile.value['tools']
            for name, expected in [(str(Path(sys.executable).resolve()), pins['pythonSHA256']),
                    (self.source['age'], pins['ageSHA256']),
                    (str(Path(self.source['age']).with_name('age-keygen')), pins['ageKeygenSHA256']),
                    (BWRAP, BWRAP_SHA256), (SECCOMP, SECCOMP_SHA256)]:
                fd = _pinned_file(name, expected)
                os.close(fd)
            if (self.binding.get('runtimeSHA256') != self.profile.value['runtime']['digestSHA256']
                    or self.binding.get('rank') != (self.group_network.rank if self.group_network else 0)
                    or self.binding.get('worldSize') != (self.group_network.world_size if self.group_network else 1)
                    or self.binding.get('acceleratorClass') != 'cpu'):
                raise ValueError('Native service does not match the retained assignment')
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        self.deadline.check(self.parent)
        if self.group_network is not None:
            self.group_network.assert_alive()
        if self.ciphertext is not None:self.ciphertext.verify()
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
        admission = self
        class Cancellation:
            def is_set(self):
                return admission.parent.is_set() or (admission.group_network is not None and admission.group_network.is_set())
        return self.plan.run(self.path, self.source['ciphertext'], key, self.binding, self.source['destination'],
            age=self.source['age'], helper_limits=self.profile.helper, staging_limits=self.profile.staging,
            max_input_bytes=self.profile.value['maxInputBytes'], max_output_ciphertext_bytes=self.profile.ciphertext.outputBytes, cancelled=Cancellation(),
            dependency={'handoff':self.dependency,'ciphertext':str(Path(self.source['ciphertext']).with_name('dependency.age'))} if self.dependency else None,
            max_dependency_bytes=self.profile.value.get('maxDependencyBytes',0))

    def close(self):
        failure = None
        if self.group_network is not None:
            try:
                self.group_network.close()
            except Exception as error:
                failure = error
            self.group_network = None
        for channel in self._probe_sockets:
            channel.close()
        self._probe_sockets = []
        if self.ciphertext is not None:
            try:
                self.ciphertext.close()
            except Exception as error:
                failure = error
            self.ciphertext = None
        for name in ['tree', 'control']:
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)
        if failure is not None:
            raise failure


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
        grouped = admission.group_network is not None
        if not grouped:
            frames.end_input()
        result = admission.run(delivered.pop('job'))
        admission.verify()
        if grouped:
            frames.send({'protocol': PROTOCOL, 'operation': 'group-local-complete', 'nonce': nonce})
            retired = frames.receive()
            exact(retired, ['protocol', 'operation', 'nonce'])
            if retired != {'protocol': PROTOCOL, 'operation': 'group-retire', 'nonce': nonce}:
                raise ValueError('Group completion differs from the ready controller')
            frames.end_input()
            admission.close()
        frames.send({'protocol':PROTOCOL, 'operation':'complete', 'nonce':nonce,
                     'report':result.report, 'receipt':result.receipt})
    finally:
        if admission is not None: admission.close()
        parent.close()
