#!/usr/bin/env python3
"""Exercise real kernel limits with bounded owned workloads, never customer jobs."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_resources import JobResourceGroup, ResourceLimits, join_current_process


def child(mode, group, limits):
    join_current_process(group, ResourceLimits(**json.loads(limits)))
    # Keep this owned check finite even if a resource-control regression occurs.
    import signal
    signal.alarm(15)
    print('admitted', flush=True)
    if mode == 'tree':
        if os.fork() == 0:
            os.setsid()
            print('detached', flush=True)
        time.sleep(12)
    elif mode == 'memory':
        if os.fork() == 0:
            os.setsid()
            time.sleep(12)
        time.sleep(0.1)
        data = bytearray(128 * 1024**2)
        print('memory-limit-bypassed', len(data), flush=True)
    elif mode == 'pids':
        children = []
        for _ in range(32):
            try:
                pid = os.fork()
            except BlockingIOError:
                print('fork-refused', flush=True)
                break
            if pid == 0:
                time.sleep(12)
                os._exit(0)
            children.append(pid)
        else:
            print('pid-limit-bypassed', flush=True)
        time.sleep(12)
    elif mode == 'cpu':
        os.fork()
        # Consume measured process CPU time. Wall time can pass while a slow
        # emulator is descheduled, without creating enough quota pressure.
        deadline = time.process_time() + 0.2
        while time.process_time() < deadline:
            pass
    elif mode == 'finish':
        print(sum(range(1000)), flush=True)
    else:
        raise ValueError('Unknown owned check')


def start(group, mode):
    proc = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                             '--child', mode, str(group.path), json.dumps(asdict(group.limits))],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            start_new_session=True, env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})
    try:
        if not select.select([proc.stdout], [], [], 5)[0] or proc.stdout.readline() != b'admitted\n':
            raise RuntimeError('Owned helper did not enter its resource group')
        return proc
    except BaseException:
        proc.kill()
        proc.wait(timeout=5)
        proc.stdout.close()
        raise


def finish(proc):
    try:
        proc.wait(timeout=5)
        return proc.stdout.read().decode('ascii')
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        proc.stdout.close()


def check(parent):
    results = {}
    base = ResourceLimits(250, 32 * 1024**2, 8, 30)
    with JobResourceGroup(parent, base) as group:
        proc = start(group, 'finish')
        report = group.wait()
        output = finish(proc)
        assert proc.returncode == 0 and output.strip() == '499500' and report['reason'] == 'empty'
        assert report['removed'] and not group.path.exists()
        results['normalExit'] = report
        assert group.close() == group.close()
    with JobResourceGroup(parent, base) as group:
        proc = start(group, 'cpu')
        report = group.wait()
        finish(proc)
        assert proc.returncode == 0 and report['cpu']['nr_throttled'] > 0, json.dumps({'returncode': proc.returncode, 'report': report})
        # Counter throttling, not an unreliable host-time performance assertion.
        results['cpuQuota'] = report
    with JobResourceGroup(parent, base) as group:
        proc = start(group, 'memory')
        report = group.wait()
        output = finish(proc)
        assert proc.returncode == -9 and report['memory']['oom_group_kill'] >= 1
        assert report['memory']['oom_kill'] >= 2 and 'memory-limit-bypassed' not in output
        results['wholeGroupOOM'] = report
    with JobResourceGroup(parent, base) as group:
        proc = start(group, 'pids')
        try:
            assert select.select([proc.stdout], [], [], 5)[0]
            assert proc.stdout.readline() == b'fork-refused\n'
            report = group.close()
            assert report['pids']['max'] >= 1
            results['forkLimit'] = report
        finally:
            group.close()
            finish(proc)
    with JobResourceGroup(parent, ResourceLimits(250, 32 * 1024**2, 8, 5)) as group:
        proc = start(group, 'tree')
        report = group.wait()
        output = finish(proc)
        assert report['reason'] == 'deadline' and proc.returncode == -9 and 'detached' in output
        assert report['removed'] and not group.path.exists()
        results['deadlineTreeKill'] = report
    with JobResourceGroup(parent, base) as group:
        proc = start(group, 'tree')
        cancel = threading.Event()
        cancel.set()
        report = group.wait(cancelled=cancel)
        finish(proc)
        assert report['reason'] == 'cancelled' and proc.returncode == -9
        results['cancelTreeKill'] = report
    # A broken/changed limit cannot become a launcher admission.
    with JobResourceGroup(parent, base) as group:
        (group.path / 'memory.max').write_text(str(64 * 1024**2))
        proc = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                               '--child', 'finish', str(group.path), json.dumps(asdict(base))],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
        assert proc.returncode != 0 and not proc.stdout and not group.populated
        results['changedLimitsRejected'] = True
    disabled = parent / ('disabled-' + uuid.uuid4().hex)
    disabled.mkdir(mode=0o700)
    try:
        try:
            JobResourceGroup(disabled, base)
        except ValueError:
            results['missingControllersRejected'] = True
        else:
            raise AssertionError('Missing controllers accepted')
        assert not [p for p in disabled.iterdir() if p.is_dir()]
    finally:
        disabled.rmdir()
    # Root-owned ordinary files and intermediate links cannot impersonate
    # the kernel control filesystem, even with plausible controller contents.
    with tempfile.TemporaryDirectory(prefix='cannabis-resource-check-', dir='/run') as temporary:
        ordinary = Path(temporary)
        (ordinary / 'cgroup.subtree_control').write_text('cpu memory pids')
        (ordinary / 'cgroup.type').write_text('domain')
        (ordinary / 'cgroup.procs').write_text('')
        linked = ordinary / 'linked'
        linked.symlink_to(parent, target_is_directory=True)
        for name, target in [('ordinaryFilesystemRejected', ordinary), ('intermediateSymlinkRejected', linked)]:
            try:
                JobResourceGroup(target, base)
            except (ValueError, OSError):
                results[name] = True
            else:
                raise AssertionError('Unsafe cgroup path accepted')
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--parent', type=Path, default=Path('/sys/fs/cgroup'))
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Kernel acceptance requires Linux root in a disposable environment')
    # The ancestor must already delegate controllers. Never modify global
    # limits, migrate unrelated processes or take over a system service group.
    if not {'cpu', 'memory', 'pids'} <= set((args.parent / 'cgroup.subtree_control').read_text().split()):
        raise RuntimeError('Acceptance parent must already enable cpu/memory/pids')
    parent = args.parent / ('cannabis-check-' + uuid.uuid4().hex)
    parent.mkdir(mode=0o700)
    try:
        (parent / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        results = check(parent)
        print(json.dumps({'schema': 'cannabis.guest-resources-check.v1', 'kernel': os.uname().release,
                          'checks': results, 'customerCodeExecuted': False, 'hardwareValidated': False}))
    finally:
        # No recursive delete: a nonempty hierarchy is a failed check.
        parent.rmdir()


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--child':
        child(*sys.argv[2:])
    else:
        main()
