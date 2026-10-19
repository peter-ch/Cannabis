#!/usr/bin/env python3
"""Actual process-death and deadline checks with bounded owned programs."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_guardian import GuardedResources
from compute.guest_resources import ResourceLimits, join_current_process

SCRIPT = str(Path(__file__).resolve())


def spawn(args, *, pass_fds=()):
    return subprocess.Popen([sys.executable, '-I', '-B', SCRIPT, *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        pass_fds=pass_fds, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})


def line(proc):
    if not select.select([proc.stdout], [], [], 15)[0]:
        raise RuntimeError('Owned check readiness expired')
    raw = proc.stdout.readline(4097)
    if not raw or len(raw) > 4096:
        error = proc.stderr.read(4096).decode() if proc.poll() is not None else ''
        raise RuntimeError('Owned check did not become ready: ' + error)
    return json.loads(raw)


def worker(group, limits, leaked_fd=None):
    join_current_process(group, ResourceLimits(**json.loads(limits)))
    signal.alarm(30)
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(reader)
        os.setsid()
        os.write(writer, b'1')
        os.close(writer)
        time.sleep(25)
        os._exit(0)
    os.close(writer)
    assert os.read(reader, 1) == b'1'
    os.close(reader)
    print(json.dumps({'worker': os.getpid(), 'detached': child}), flush=True)
    time.sleep(25)


def actor(parent, mode):
    # Include slow-emulator startup in the reserved wall budget. The stopped
    # owner's deadline must still expire before the owned worker's safety exit.
    guard = GuardedResources(parent, ResourceLimits(1000, 64 * 1024**2, 16, 15 if mode == 'stopped' else 30), startup_seconds=10)
    # Deliberately retain the owner's socket in an owned workload. pidfd death
    # must still terminate it; EOF-only monitoring would miss this case.
    extra = [str(guard._channel.fileno())] if mode == 'leaked' else []
    work = spawn(['worker', str(guard.path), json.dumps(asdict(guard.limits)), *extra],
                 pass_fds=(guard._channel.fileno(),) if extra else ())
    state = line(work)
    if mode == 'exit':
        signal.signal(signal.SIGUSR1, lambda *_: os._exit(0))
    print(json.dumps({**state, 'group': str(guard.path), 'guardian': guard._process.pid}), flush=True)
    # The outer check controls this disposable process. No customer input.
    time.sleep(25)
    guard.close()


def ended(pidfd, timeout=20):
    assert select.select([pidfd], [], [], timeout)[0], 'Owned process survived cleanup'


def finish(proc):
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)
    proc.stdout.close()
    proc.stderr.close()


def run(parent):
    cases = {}
    limits = ResourceLimits(1000, 64 * 1024**2, 16, 30)
    # No worker exists: a finish acknowledgement can release the reserved group.
    with GuardedResources(parent, limits) as guard:
        assert not os.get_inheritable(guard.fileno())
        result = guard.wait(action='finish')
        assert result['reason'] == 'finished' and result['removed'] and not guard.path.exists()
        assert guard.close() == result
        cases['normalFinish'] = True
    for action, expected in [('cancel', 'cancelled'), ('finish', 'not-empty')]:
        with GuardedResources(parent, limits) as guard:
            work = spawn(['worker', str(guard.path), json.dumps(asdict(limits))])
            state = line(work)
            handles = [os.pidfd_open(state[k]) for k in ['worker', 'detached']]
            try:
                result = guard.wait(action=action)
                assert result['reason'] == expected and not guard.path.exists()
                for handle in handles:
                    ended(handle)
                cases['cancelTree' if action == 'cancel' else 'busyFinishRefused'] = True
            finally:
                for handle in handles:
                    os.close(handle)
                finish(work)
    for mode in ['killed', 'stopped', 'leaked', 'exit']:
        owner = spawn(['actor', str(parent), mode])
        state = line(owner)
        handles = [os.pidfd_open(state[k]) for k in ['worker', 'detached', 'guardian']]
        try:
            if mode == 'stopped':
                os.kill(owner.pid, signal.SIGSTOP)
            elif mode == 'exit':
                os.kill(owner.pid, signal.SIGUSR1)
                assert owner.wait(timeout=5) == 0
            else:
                owner.kill()
                owner.wait(timeout=5)
            for handle in handles:
                ended(handle)
            assert not Path(state['group']).exists()
            cases[{'killed': 'ownerSIGKILL', 'stopped': 'stoppedOwnerDeadline', 'leaked': 'leakedSocketOwnerDeath', 'exit': 'ownerExitWithoutFinalizer'}[mode]] = True
        finally:
            # SIGKILL also handles a stopped owner, without resuming execution.
            finish(owner)
            for handle in handles:
                os.close(handle)
    # A failed guardian is detected, never silently replaced or treated as an
    # empty successful job. The owner uses retained original group descriptors.
    guard = GuardedResources(parent, limits)
    work = spawn(['worker', str(guard.path), json.dumps(asdict(limits))])
    state = line(work)
    handles = [os.pidfd_open(state[k]) for k in ['worker', 'detached']]
    try:
        guard._process.kill()
        guard._process.wait(timeout=5)
        try:
            guard.assert_alive()
        except RuntimeError:
            pass
        else:
            raise AssertionError('Dead guardian was accepted')
        for handle in handles:
            ended(handle)
        assert not guard.path.exists()
        cases['guardianFailureRefusedAndCleaned'] = True
    finally:
        finish(work)
        for handle in handles:
            os.close(handle)
    # A long purchased interval must never become the timeout for cancellation
    # when the independent guardian itself is stopped.
    long_limits = ResourceLimits(1000, 64 * 1024**2, 16, 3600)
    guard = GuardedResources(parent, long_limits)
    work = spawn(['worker', str(guard.path), json.dumps(asdict(long_limits))])
    state = line(work)
    handles = [os.pidfd_open(state[k]) for k in ['worker', 'detached']]
    try:
        os.kill(guard._process.pid, signal.SIGSTOP)
        started = time.monotonic()
        try:
            guard.wait(action='cancel')
        except TimeoutError:
            pass
        else:
            raise AssertionError('Stopped guardian acknowledged cancellation')
        assert 9 <= time.monotonic() - started < 25
        assert not guard.path.exists() and guard._process.poll() is not None
        for handle in handles:
            ended(handle)
        cases['stoppedGuardianCancelBounded'] = True
    finally:
        if guard._process.poll() is None:
            guard._fallback()
        finish(work)
        for handle in handles:
            os.close(handle)
    with GuardedResources(parent, ResourceLimits(1000, 64 * 1024**2, 16, 5)) as guard:
        result = guard.wait()
        assert result['reason'] == 'deadline' and result['removed']
        cases['independentDeadline'] = True
    with GuardedResources(parent, ResourceLimits(1000, 64 * 1024**2, 16, 5)) as guard:
        time.sleep(5.1)
        result = guard.wait(action='finish')
        assert result['reason'] == 'deadline' and result['removed']
        cases['lateFinishRefused'] = True
    return cases


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Use a disposable Linux root environment')
    parent = Path('/sys/fs/cgroup') / ('cannabis-guardian-check-' + uuid.uuid4().hex)
    parent.mkdir(mode=0o700)
    try:
        (parent / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        checks = run(parent)
        print(json.dumps({'schema': 'cannabis.guest-guardian-check.v1', 'kernel': os.uname().release,
                          'checks': checks, 'customerCodeExecuted': False, 'hardwareValidated': False}))
    finally:
        parent.rmdir()


if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'worker':
        worker(*sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == 'actor':
        actor(*sys.argv[2:])
    else:
        main()
