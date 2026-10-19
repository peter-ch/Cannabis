"""Aggregate process reservation outside a job's key-holding control plane.

Create this scope before starting the initialized guest session. The outer owner
and guardian must hold no customer keys. The approved control-plane executable
joins its own leaf before importing the session, allocating staging or opening
keys. Every workload/helper leaf lives underneath the same bounded parent.
This enforces guest process limits, not hardware admission or VM disposal.
"""
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys

from .guest_deadline import ExecutionDeadline, bounded_stage_deadline
from .guest_guardian import GuardedResources
from .guest_resources import JobResourceGroup, ResourceLimits, ResourceTreeLimits, ResourceCleanupError
from .guest_sandbox import _pinned_file
from .guest_launch_snapshot import validate_snapshot


class GuestJobScope:
    def __init__(self, parent, total, control, *, deadline):
        if type(total) is not ResourceTreeLimits or type(control) is not ResourceLimits or not isinstance(deadline, ExecutionDeadline):
            raise ValueError('Require approved aggregate, control-plane and deadline limits')
        for name in ['cpu_millis', 'memory_bytes', 'processes', 'wall_seconds']:
            if getattr(control, name) > getattr(total, name):
                raise ValueError('Control-plane reservation exceeds total job capacity')
        deadline.check()
        self._guard = self._control = self._child = self._pidfd = None
        self._used = False
        self._closed = False
        self.deadline = ExecutionDeadline(bounded_stage_deadline(min(total.wall_seconds, control.wall_seconds), deadline))
        try:
            self._guard = GuardedResources(parent, total, deadline=self.deadline)
            self.deadline = ExecutionDeadline(self._guard.deadline)
            self._control = JobResourceGroup(self._guard.path, control, deadline=self.deadline)
            self.path = self._guard.path
        except BaseException:
            self.close()
            raise

    def start(self, executable, executable_sha256, script, script_sha256, *, launch_fd=None):
        """Start one pinned trusted control program, never a workload command.

        These independent pins must come from the measured launch configuration.
        Script arguments are closed. A sealed public launch descriptor may be
        inherited; later customer material crosses anonymous stdin/stdout only.
        The child environment carries only public cgroup/deadline descriptors.
        """
        if self._used or self._closed:
            raise ValueError('Job control program is single use')
        self._used = True
        self.assert_alive()
        handles = []
        try:
            launch_handles = () if launch_fd is None else (validate_snapshot(launch_fd),)
            for name, expected in [(executable, executable_sha256), (script, script_sha256)]:
                handles.append(_pinned_file(name, expected))
            launcher = Path(__file__).resolve().parents[1] / 'scripts/compute-guest-control.py'
            # Retain pinned open files through trampoline exec, eliminating a
            # path replacement between checking the approved bytes and entry.
            self._child = subprocess.Popen([sys.executable, '-I', '-B', str(launcher),
                str(self._control.path), json.dumps(asdict(self._control.limits), separators=(',', ':')),
                str(handles[0]), str(handles[1])],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                bufsize=0, close_fds=True, pass_fds=(*handles, *launch_handles), start_new_session=True,
                env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
                     'CANNABIS_JOB_CGROUP': str(self.path),
                     'CANNABIS_JOB_CONTROL': str(self._control.path),
                     'CANNABIS_JOB_DEADLINE': repr(self.deadline.monotonic_end),
                     'CANNABIS_JOB_TOTAL': json.dumps(asdict(self._guard.limits), separators=(',', ':')),
                     'CANNABIS_JOB_CONTROL_LIMITS': json.dumps(asdict(self._control.limits), separators=(',', ':')),
                     **({'CANNABIS_LAUNCH_FD': str(launch_fd)} if launch_fd is not None else {})})
            self._pidfd = os.pidfd_open(self._child.pid)
            self.assert_alive()
            return self._child
        except BaseException:
            self.close()
            raise
        finally:
            for fd in handles:
                os.close(fd)

    def assert_alive(self):
        if self._closed or self._guard is None:
            raise RuntimeError('Aggregate job scope is closed')
        self.deadline.check()
        self._guard.assert_alive()

    def monitor_handles(self):
        """Select alongside control stdout; guardian readiness is fatal until finish."""
        self.assert_alive()
        if self._pidfd is None:
            raise ValueError('Control program has not started')
        return self._pidfd, self._guard.fileno()

    def finish(self):
        """Accept control exit only after the entire job tree has become empty."""
        if self._child is None or self._child.poll() is None or self._child.returncode != 0:
            self.close()
            raise RuntimeError('Control program did not exit successfully')
        try:
            result = self._guard.finish_after_exit()
            if result['reason'] != 'finished':
                raise ResourceCleanupError('Aggregate job did not finish before its deadline')
            self.deadline.check()
            return result
        finally:
            self.close()

    def close(self):
        if self._closed:
            return
        try:
            if self._guard is not None:
                self._guard.close()
            if self._control is not None:
                self._control.close()
        finally:
            if self._child is not None:
                if self._child.poll() is None:
                    self._child.kill()  # Also stop a trampoline stalled before admission.
                self._child.wait(timeout=5)
                self._child.stdin.close()
                self._child.stdout.close()
            if self._pidfd is not None:
                os.close(self._pidfd)
                self._pidfd = None
            self._closed = True

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
