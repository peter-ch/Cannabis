"""Bound trusted decode/encode helpers inside the measured Linux guest.

These helpers are trusted parsers, not customer-code sandboxes. The calling
control plane and its outer VM still require independent lifecycle protection.
"""
from dataclasses import asdict
import json
import os
from pathlib import Path
import resource
import select
import subprocess
import sys
import uuid

from .guest_guardian import GuardedResources
from .guest_deadline import ExecutionDeadline
from .guest_resources import ResourceLimits, ResourceCleanupError, join_current_process
from .guest_sandbox import ScratchLimits, _call, _directory, _libc, enter_private_mount_namespace

MAX_CONTROL = 5 * 1024**2


class ProtectedStaging:
    """One explicitly budgeted, private noswap filesystem for trusted stages."""
    def __init__(self, limits, *, workspace='/'):
        if not isinstance(limits, ScratchLimits):
            raise ValueError('Require an explicit staging byte and inode budget')
        fd = _directory(workspace, memory=False)
        os.close(fd)
        enter_private_mount_namespace()
        self.path = Path(workspace) / ('cannabis-staging-' + uuid.uuid4().hex)
        self.path.mkdir(mode=0o700)
        self._mounted = False
        try:
            options = f'size={limits.bytes},nr_inodes={limits.inodes},mode=0700,noswap'.encode()
            _call(_libc().mount(b'tmpfs', os.fsencode(self.path), b'tmpfs', 2 | 4 | 8, options))
            self._mounted = True  # nosuid,nodev,noexec; customer code runs elsewhere
        except BaseException:
            self.path.rmdir()
            raise

    def close(self):
        if self._mounted:
            try:
                _call(_libc().umount2(os.fsencode(self.path), 0))
            except OSError as error:
                raise ResourceCleanupError('Protected staging did not unmount; retire the guest') from error
            self._mounted = False
            self.path.rmdir()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def run_guarded_helper(parent, limits, request, *, cancelled=None, deadline=None):
    """Anonymous bounded pipes; no private arguments, key file or helper logs.

    The child joins its verified group before reading any request byte. Its
    guardian remains outside that group and survives owner death or SIGSTOP.
    The complete group must be observed empty before a response is returned.
    """
    if not isinstance(limits, ResourceLimits):
        raise ValueError('Require explicit helper CPU, memory, process and time limits')
    if deadline is not None:
        if not isinstance(deadline, ExecutionDeadline):
            raise ValueError('Require a retained helper service deadline')
        deadline.check(cancelled)
    raw = bytearray(json.dumps(request, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode())
    response = bytearray()
    child = guard = None
    pidfd = None
    try:
        if not 0 < len(raw) <= MAX_CONTROL:
            raise ValueError('Protected helper request exceeds its bound')
        if cancelled is not None and cancelled.is_set():
            raise ValueError('Protected helper cancelled')
        guard = GuardedResources(parent, limits, deadline=deadline)
        script = Path(__file__).resolve().parents[1] / 'scripts/compute-guest-helper.py'
        # Only public resource numbers and an opaque kernel group path are in
        # argv. The script has a closed operation table, never an arbitrary exec.
        child = subprocess.Popen([sys.executable, '-I', '-B', str(script), str(guard.path),
            *map(str, asdict(limits).values())], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, close_fds=True, start_new_session=True,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        pidfd = os.pidfd_open(child.pid)
        os.set_blocking(child.stdin.fileno(), False)
        os.set_blocking(child.stdout.fileno(), False)
        sent, eof, cleanup = 0, False, None
        while True:
            if cancelled is not None and cancelled.is_set():
                raise ValueError('Protected helper cancelled')
            readers = ([] if cleanup else [pidfd, guard.fileno()]) + ([] if eof else [child.stdout])
            writers = [] if child.stdin.closed else [child.stdin]
            readable, writable, _ = select.select(readers, writers, [], 0.05)
            if cleanup is None and guard.fileno() in readable:
                # No finish has been requested; spontaneous readiness is a
                # deadline/channel/guardian failure, including simultaneous exit.
                guard.wait()
                raise ValueError('Protected helper stopped before checked completion')
            if child.stdin in writable:
                count = os.write(child.stdin.fileno(), memoryview(raw)[sent:sent + 65536])
                sent += count
                if sent == len(raw):
                    child.stdin.close()
                    raw[:] = b'\0' * len(raw)
            if child.stdout in readable:
                chunk = os.read(child.stdout.fileno(), min(65536, MAX_CONTROL + 1 - len(response)))
                if not chunk:
                    eof = True
                else:
                    response.extend(chunk)
                    if len(response) > MAX_CONTROL:
                        raise ValueError('Protected helper response exceeds its bound')
            if cleanup is None and pidfd in readable:
                child.wait(timeout=5)
                cleanup = guard.finish_after_exit(cancelled=cancelled)
                if cleanup['reason'] != 'finished' or child.returncode != 0 or sent != len(raw):
                    raise ValueError('Protected helper did not complete successfully')
            if cleanup is not None and eof:
                result = json.loads(response)
                if not isinstance(result, dict):
                    raise ValueError('Invalid protected helper response')
                if deadline is not None:
                    deadline.check(cancelled)
                return result
    except Exception:
        # Never carry a decoder exception, output path or customer value into
        # host-visible diagnostics. Cleanup failures remain fatal below.
        raise RuntimeError('Protected helper failed; discard this job staging') from None
    finally:
        raw[:] = b'\0' * len(raw)
        response[:] = b'\0' * len(response)
        try:
            if guard is not None:
                guard.close()
        finally:
            if pidfd is not None:
                os.close(pidfd)
            if child is not None:
                child.stdin.close()
                child.stdout.close()
                if child.poll() is None:
                    child.kill()  # Also contain a trusted trampoline stalled before joining.
                child.wait(timeout=5)


def helper_main(group, limits):
    """Trusted child entry point. Contain before importing decoders or reading keys."""
    join_current_process(group, limits)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    from .client import seal_result
    from .guest_workload import prepare_guest_workload
    from .guest_artifacts import copy_artifacts
    from .dependency_bundle import open_dependency_bundle
    from .job_keys import RecoveredJobKey
    raw = bytearray(sys.stdin.buffer.read(MAX_CONTROL + 1))
    try:
        if len(raw) > MAX_CONTROL:
            raise ValueError('Request bound exceeded')
        request = json.loads(raw)
    finally:
        raw[:] = b'\0' * len(raw)
    operation = request.pop('operation')
    if operation == 'decode' and set(request) == {'source', 'job', 'binding', 'destination', 'age', 'maxBytes'}:
        key = RecoveredJobKey(**request['job'])
        # JSON carries the secret only over the anonymous protected pipe.
        key = RecoveredJobKey(key.identity.encode('ascii'), key.job_id, key.package_sha256,
            key.policy_sha256, key.input_recipient, key.result_recipient)
        prepared = prepare_guest_workload(request['source'], key, request['binding'], request['destination'],
            age=request['age'], max_bytes=request['maxBytes'])
        result = {'report': prepared.report, 'workload': prepared.workload}
    elif operation == 'seal-result' and set(request) == {'spec', 'taskId', 'packageSHA256', 'root', 'recipient', 'destination', 'attempt', 'rank', 'age'}:
        result = seal_result(request['spec'], request['taskId'], request['packageSHA256'], request['root'],
            request['recipient'], request['destination'], attempt=request['attempt'], rank=request['rank'], age=request['age'])
    elif operation == 'copy-artifacts' and set(request) == {'root', 'items', 'destination', 'maxBytes'}:
        result = copy_artifacts(request['root'], request['items'], request['destination'], request['maxBytes'])
    elif operation == 'decode-dependency' and set(request) == {'spec','handoff','source','identity','destination','age'}:
        result = open_dependency_bundle(request['spec'], request['handoff'], request['source'], request['identity'].encode('ascii'),
            request['destination'], age=request['age'])
    else:
        raise ValueError('Unsupported protected helper operation')
    encoded = json.dumps(result, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > MAX_CONTROL:
        raise ValueError('Response bound exceeded')
    sys.stdout.buffer.write(encoded)
