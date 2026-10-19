"""Independent process-tree cleanup inside a trusted measured Linux guest.

The guardian does not load customer code or grant hardware admission. Both it
and its owner must be isolated from customer processes and attestation secrets.
"""
from dataclasses import asdict
import json
import math
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

from .guest_resources import JobResourceGroup, ResourceLimits, ResourceTreeLimits, ResourceCleanupError, _read, _verify


def _send(channel, value):
    raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')
    if len(raw) > 8192 or channel.send(raw) != len(raw):
        raise RuntimeError('Guardian control message failed')


def _receive(channel):
    raw, _, flags, _ = channel.recvmsg(8192)
    if not raw:
        raise EOFError('Guardian control channel closed')
    if flags & socket.MSG_TRUNC:
        raise ValueError('Oversized guardian message')
    return json.loads(raw)


def _dead(pidfd):
    return bool(select.select([pidfd], [], [], 0)[0])


def _adopt(parent_fd, group_fd, settings):
    """Retain only descriptors opened by the creating trusted control plane."""
    if set(settings) != {'name', 'limits', 'deadline', 'ownerPID'}:
        raise ValueError('Unexpected guardian startup data')
    name = settings['name']
    if not isinstance(name, str) or len(name) != 36 or not name.startswith('job-') or any(c not in '0123456789abcdef' for c in name[4:]):
        raise ValueError('Invalid owned resource group name')
    deadline = settings['deadline']
    if type(deadline) not in [int, float] or not math.isfinite(deadline):
        raise ValueError('Invalid monotonic deadline')
    limits_type = ResourceTreeLimits if 'children' in settings['limits'] else ResourceLimits
    limits = limits_type(**settings['limits'])
    if deadline > time.monotonic() + limits.wall_seconds:
        raise ValueError('Guardian deadline exceeds the retained limit')
    entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    opened = os.fstat(group_fd)
    if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino) or opened.st_uid != 0 or opened.st_mode & 0o022:
        raise ValueError('Guardian group identity mismatch')
    _verify(group_fd, limits)
    # Do not create a new group or reopen a host-supplied path. This second
    # process retains references to the very same kernel objects as its owner.
    group = JobResourceGroup.__new__(JobResourceGroup)
    group.limits = limits
    group._parent, group._fd = parent_fd, group_fd
    group._name = name
    group._created = group._configured = True
    group._report = None
    group.deadline = deadline
    return group


def guardian_main(channel_fd, owner_fd, parent_fd, group_fd):
    channel = socket.socket(fileno=channel_fd)
    channel.settimeout(5)
    group = None
    reason = 'startup-failed'
    try:
        settings = _receive(channel)
        group = _adopt(parent_fd, group_fd, settings)
        # The pidfd is opened by the owner before spawn, not reconstructed from
        # a PID after it might have exited or been reused.
        info = Path(f'/proc/self/fdinfo/{owner_fd}').read_text()
        fields = dict(line.split(':', 1) for line in info.splitlines() if ':' in line)
        pid = int(fields.get('Pid', '-2'))
        if (type(settings.get('ownerPID')) is not int or os.readlink(f'/proc/self/fd/{owner_fd}') != 'anon_inode:[pidfd]'
                or (pid != settings['ownerPID'] and not (pid == -1 and _dead(owner_fd)))):
            raise ValueError('Guardian owner process handle mismatch')
        if str(os.getpid()) in _read(group_fd, 'cgroup.procs').split():
            raise ValueError('Guardian must remain outside the workload group')
        if _dead(owner_fd):
            reason = 'owner-exited'
        elif time.monotonic() >= group.deadline:
            reason = 'deadline'
        else:
            _send(channel, {'ready': True})
            while True:
                # A stopped/hung owner cannot postpone this deadline. pidfd
                # readiness wins even if another process retained the socket.
                if _dead(owner_fd):
                    reason = 'owner-exited'
                    break
                remaining = group.deadline - time.monotonic()
                if remaining <= 0:
                    reason = 'deadline'
                    break
                readable = select.select([owner_fd, channel], [], [], min(remaining, 1))[0]
                if owner_fd in readable:
                    reason = 'owner-exited'
                    break
                if channel in readable:
                    try:
                        message = _receive(channel)
                    except EOFError:
                        reason = 'channel-closed'
                        break
                    if time.monotonic() >= group.deadline:
                        reason = 'deadline'
                    elif message == {'action': 'cancel'}:
                        reason = 'cancelled'
                    elif message == {'action': 'finish'}:
                        populated = group.populated
                        # Check time after observing emptiness. A descheduled
                        # guardian must not accept a late observation.
                        reason = 'deadline' if time.monotonic() >= group.deadline else ('not-empty' if populated else 'finished')
                    else:
                        reason = 'invalid-command'
                    break
        report = {'reason': reason, **group.close()}
        try:
            _send(channel, report)
            # A deadline may race the owner's finish/cancel message. Closing a
            # UNIX seqpacket socket with unread input can discard the queued
            # result with ECONNRESET. Keep the completed result available until
            # acknowledged, draining raced commands under a short fixed bound.
            end = time.monotonic() + 2
            while not _dead(owner_fd) and time.monotonic() < end:
                channel.settimeout(max(0.001, end - time.monotonic()))
                if _receive(channel) == {'ack': True}:
                    break
        except (OSError, EOFError):
            pass  # The kernel cleanup still completed after owner death.
    except BaseException:
        # An armed guardian never exits normally without attempting cleanup.
        if group is not None:
            group.close()
        raise
    finally:
        channel.close()
        os.close(owner_fd)


class GuardedResources:
    """Arm before key release or runtime startup; retain until job teardown.

    Serial API for the trusted supervisor. Unexpected guardian death is fatal:
    the retained parent descriptors provide cleanup, then the caller must retire
    the guest. This does not protect against simultaneous supervisor/guardian
    death, guest-kernel failure or a privileged attacker inside the guest.
    """
    def __init__(self, parent, limits, *, startup_seconds=5, deadline=None):
        if type(startup_seconds) not in [int, float] or not 0.1 <= startup_seconds <= 30:
            raise ValueError('Require a bounded guardian startup')
        if sys.platform != 'linux' or not hasattr(os, 'pidfd_open'):
            raise RuntimeError('Require Linux process handles')
        self._group = JobResourceGroup(parent, limits, deadline=deadline)
        self._process = self._channel = self._pidfd = None
        self._result = None
        self._broken = False
        self.path, self.limits, self.deadline = self._group.path, limits, self._group.deadline
        remote = owner_fd = None
        try:
            local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self._channel = local
            owner_fd = os.pidfd_open(os.getpid())
            local.settimeout(startup_seconds)
            # Queue startup atomically before spawn. An owner that dies during
            # child startup cannot leave the guardian waiting for its metadata.
            _send(local, {'name': self._group._name, 'limits': asdict(limits),
                          'deadline': self._group.deadline, 'ownerPID': os.getpid()})
            script = Path(__file__).resolve().parents[1] / 'scripts/compute-guest-guardian.py'
            descriptors = [remote.fileno(), owner_fd, self._group._parent, self._group._fd]
            self._process = subprocess.Popen([sys.executable, '-I', '-B', str(script), *map(str, descriptors)],
                pass_fds=descriptors, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
            self._pidfd = os.pidfd_open(self._process.pid)
            remote.close()
            if _receive(local) != {'ready': True}:
                raise RuntimeError('Guardian did not arm before the deadline')
            self.assert_alive()
        except BaseException:
            self._fallback()
            raise
        finally:
            if remote is not None:
                remote.close()
            if owner_fd is not None:
                os.close(owner_fd)

    def assert_alive(self):
        if self._broken or self._result is not None or self._pidfd is None or _dead(self._pidfd) or time.monotonic() >= self._group.deadline:
            self._broken = True
            self._fallback()
            raise RuntimeError('Guest guardian stopped or deadline expired; retire the guest')

    def fileno(self):
        """Select with the runtime's process handle; readable means inspect wait()."""
        if self._broken or self._channel is None:
            raise RuntimeError('Guest guardian is unavailable')
        return self._channel.fileno()

    def _fallback(self):
        # Keep parent references until the guardian has exited. Cleanup then
        # uses the original kernel object, never a process-name/PID search.
        failure = None
        try:
            if self._process is not None:
                if self._process.poll() is None:
                    self._process.kill()
                self._process.wait(timeout=5)
        except BaseException as error:
            failure = error
        try:
            self._group.close()
        finally:
            self._dispose()
        if failure is not None:
            raise ResourceCleanupError('Guardian did not stop; retire the guest') from failure

    def _dispose(self):
        if self._channel is not None:
            self._channel.close()
            self._channel = None
        if self._pidfd is not None:
            os.close(self._pidfd)
            self._pidfd = None

    def wait(self, *, action=None):
        """Wait independently, cancel, or request finish after confirmed exit.

        A finish request never disarms a running job. A timeout is a deadline
        result, not successful completion. All terminal results imply cleanup.
        """
        if action not in [None, 'finish', 'cancel']:
            raise ValueError('Unknown guardian action')
        if self._result is not None:
            return dict(self._result)
        if self._broken or self._channel is None:
            raise RuntimeError('Guest guardian is unavailable; retire the guest')
        try:
            # An explicit finish/cancel must not inherit a long job's remaining
            # wall time if the guardian itself stalls. Cleanup has a fixed
            # acknowledgement budget; timeout invokes retained-object fallback.
            self._channel.settimeout(10 if action is not None else max(1, self._group.deadline - time.monotonic()) + 10)
            if action is not None:
                try:
                    _send(self._channel, {'action': action})
                except BrokenPipeError:
                    pass  # A deadline result may already be queued.
            result = _receive(self._channel)
            try:
                _send(self._channel, {'ack': True})
            except BrokenPipeError:
                pass
            self._process.wait(timeout=5)
            allowed = {'finished', 'cancelled', 'deadline', 'not-empty', 'invalid-command', 'channel-closed'}
            if (self._process.returncode != 0 or not isinstance(result, dict) or result.get('reason') not in allowed
                    or result.get('removed') is not True or result.get('populated') is not False
                    or not self._group._removed()):
                raise ResourceCleanupError('Guardian cleanup did not verify')
            self._group.close()
            self._result = result
            self._dispose()
            return dict(result)
        except BaseException:
            self._broken = True
            self._fallback()
            raise

    def close(self):
        return self.wait(action='cancel')

    def finish_after_exit(self, *, cancelled=None):
        """After leader exit, briefly observe natural whole-tree completion.

        Launcher/monitor processes can finish just after the waited leader.
        Never extend the retained wall deadline, disarm a populated group, or
        treat killed stragglers as successful completion. Busy finish still
        rejects and kills the tree after this fixed two-second drain budget.
        """
        end = time.monotonic() + 2
        while self._result is None:
            if cancelled is not None and cancelled.is_set():
                return self.wait(action='cancel')
            if time.monotonic() >= self.deadline or select.select([self.fileno()], [], [], 0)[0]:
                return self.wait()
            try:
                empty = not self._group.populated
            except OSError:
                # A terminal guardian may have removed the retained group
                # between channel inspection and the kernel read. Still require
                # its checked acknowledgement, with the fixed action timeout.
                return self.wait(action='finish')
            if empty or time.monotonic() >= end:
                return self.wait(action='finish')
            select.select([self.fileno()], [], [], 0.02)
        return dict(self._result)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if not self._broken:
            self.close()
