#!/usr/bin/env python3
"""One owned encrypted DAG integration checkpoint on the real Linux kernel."""
import copy
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.client import pack_workload, task_binding_sha256, assemble_results
from compute.guest_deadline import ExecutionDeadline
from compute.guest_helpers import ProtectedStaging
from compute.guest_native import NativeTaskPlan, NATIVE_ADAPTER
from compute.guest_resources import ResourceLimits
from compute.guest_sandbox import ScratchLimits, tree_digest
from compute.job_keys import RecoveredJobKey, _new_identity

SCRIPT = str(Path(__file__).resolve())
AGE = os.environ.get('CANNABIS_AGE') or shutil.which('age') or '/usr/local/bin/age'
fixture_spec = importlib.util.spec_from_file_location('sandbox_fixture', Path(SCRIPT).with_name('check-guest-sandbox.py'))
fixture_module = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture_module)
MODES = ('success', 'single-command', 'failed-step', 'symlink-output', 'hardlink-output',
         'fifo-output', 'intermediate-quota', 'cancel-between-steps', 'shared-deadline')


def actor(parent, base, mode):
    before_mounts = set(Path('/').glob('cannabis-staging-*')) | set(Path('/').glob('cannabis-sandbox-*'))
    parent, base = Path(parent), Path(base)
    own = base / mode; own.mkdir(mode=0o700)
    source = own / 'source'; source.mkdir()
    # Deliberately include an unimported package secret and uncollected output.
    (source / 'private-unimported').write_text('owned hidden input')
    left = "from pathlib import Path\nassert not Path('/input/private-unimported').exists()\nPath('/output/part').write_text('11')\nPath('/output/hidden').write_text('owned hidden output')\n"
    if mode == 'failed-step': left = "raise RuntimeError('owned refusal')"
    if mode == 'symlink-output': left = "import os; os.symlink('/etc/passwd','/output/part')"
    if mode == 'hardlink-output': left = "import os; open('/output/hidden','w').write('11'); os.link('/output/hidden','/output/part')"
    if mode == 'fifo-output': left = "import os; os.mkfifo('/output/part')"
    if mode == 'intermediate-quota': left = "open('/output/part','w').write('x'*2048)"
    right = "open('/output/part','w').write('31')"
    if mode == 'shared-deadline':
        left = "import time; time.sleep(4); open('/output/part','w').write('11')"
        right = "import time; time.sleep(4); open('/output/part','w').write('31')"
    join = "from pathlib import Path\nassert set(p.name for p in Path('/input').iterdir()) == {'join.py','a','b'}\nassert not Path('/work/sentinel').exists()\nPath('/output/answer').write_text(str(int(Path('/input/a').read_text())+int(Path('/input/b').read_text())))\nprint('owned private graph log')\n"
    for name, program in [('left.py', left), ('right.py', right), ('join.py', join)]:
        (source / name).write_text(program)
    def step(name, program):
        return {'id': name, 'dependsOn': [], 'inputs': [{'package': program, 'destination': program}],
                'launch': {'argv': ['/usr/bin/python3', '-I', '-B', '/input/' + program]},
                'outputs': ['part'], 'outputMaxBytes': 1024}
    first, second, last = step('left', 'left.py'), step('right', 'right.py'), step('join', 'join.py')
    last.update(dependsOn=['left', 'right'], outputs=['answer', 'log'])
    last['launch']['stdout'] = 'log'
    last['inputs'] += [{'step': 'left', 'output': 'part', 'destination': 'a'}, {'step': 'right', 'output': 'part', 'destination': 'b'}]
    graph = {'schema': 'cannabis.native-step-graph.v1', 'steps': [last, first, second],
             'collect': [{'step': 'join', 'output': n, 'destination': n} for n in ['answer', 'log']]}
    runtime = {'adapter': NATIVE_ADAPTER, 'architecture': 'x86_64', 'os': 'linux', 'digestSHA256': tree_digest(base / 'root')}
    resources = {'cpus': 1, 'memoryMiB': 128, 'scratchMiB': 8, 'wallSeconds': 6 if mode == 'shared-deadline' else 60, 'nodes': 1}
    owner_secret, owner_public = _new_identity(AGE)
    job_secret, job_public = _new_identity(AGE)
    spec = {'schema': 'cannabis.workload.v1', 'id': 'owned-private-graph', 'policySHA256': '12'*32,
            'resultRecipient': owner_public, 'files': sorted(p.name for p in source.iterdir()),
            'tasks': [{'id': 'graph', 'runtime': runtime, 'resources': resources, 'launch': graph,
                       'outputs': ['answer', 'log'], 'outputMaxBytes': 1024}],
            'assembly': [{'task': 'graph', 'output': n, 'destination': n} for n in ['answer', 'log']]}
    if mode == 'single-command':
        spec['tasks'][0]['launch'] = {'argv': ['/usr/bin/python3', '-c', "open('/output/answer','w').write('42'); print('owned private graph log')"], 'stdout': 'log'}
    package = pack_workload(spec, source, job_public, own / 'input.age', age=AGE)
    binding = {'packageSHA256': package['ciphertextSHA256'], 'policySHA256': spec['policySHA256'],
               'runtimeSHA256': runtime['digestSHA256'], 'taskSHA256': task_binding_sha256(package['ciphertextSHA256'], 0),
               'attempt': 2, 'worldSize': 1, 'rank': 0, 'acceleratorClass': 'cpu'}
    key = RecoveredJobKey(job_secret, spec['id'], binding['packageSHA256'], spec['policySHA256'], job_public, owner_public)
    class Cancellation:
        observed = False
        def is_set(self):
            if mode != 'cancel-between-steps': return False
            self.observed |= any((p / 'graph/output-0').is_dir() for p in set(Path('/').glob('cannabis-staging-*')) - before_mounts)
            return self.observed
    cancellation = Cancellation()
    destination = own / 'result.age'; started = time.monotonic(); refused = False
    try:
        plan = NativeTaskPlan(base / 'root', runtime, resources, process_limit=32, scratch_inodes=512,
                              deadline=ExecutionDeadline(time.monotonic() + 120))
        result = plan.run(parent, own / 'input.age', key, binding, destination, age=AGE,
            helper_limits=ResourceLimits(1000, 256*1024**2, 64, 60), staging_limits=ScratchLimits(16*1024**2, 1024),
            max_input_bytes=1024**2, max_output_ciphertext_bytes=4*1024**2, cancelled=cancellation)
    except (RuntimeError, ValueError, OSError):
        if mode in ('success', 'single-command'): raise
        refused = True
    if mode in ('success', 'single-command'):
        assert not result.report['hardwareAdmissionEstablished'] and not result.report['paymentAccepted']
        assert b'owned private graph log' not in destination.read_bytes()
        report = assemble_results(spec, binding['packageSHA256'], [{'receipt': result.receipt, 'file': destination}],
                                  owner_secret, own / 'assembled', age=AGE)
        assert report['integrityVerified'] and not report['paymentAuthorized']
        assert sorted(p.name for p in (own / 'assembled').iterdir()) == ['answer', 'log']
        assert (own / 'assembled/answer').read_text() == '42'
        assert (own / 'assembled/log').read_text() == 'owned private graph log\n'
    else:
        assert refused and not destination.exists(), 'Failure published a graph result'
    if mode == 'cancel-between-steps': assert cancellation.observed
    if mode == 'shared-deadline': assert 6 <= time.monotonic() - started < 14
    assert not list(parent.glob('job-*')), 'Owned cgroup remains'
    assert before_mounts == set(Path('/').glob('cannabis-staging-*')) | set(Path('/').glob('cannabis-sandbox-*'))
    print(json.dumps({'mode': mode, 'passed': True}), flush=True)


def main(modes):
    if sys.platform != 'linux' or os.geteuid() != 0: raise RuntimeError('Use a disposable Linux root environment')
    if not modes or any(m not in MODES for m in modes): raise ValueError('Unknown owned graph check')
    base = Path('/run') / ('cannabis-graph-check-' + uuid.uuid4().hex)
    parent = Path('/sys/fs/cgroup') / base.name
    base.mkdir(mode=0o700); parent.mkdir(mode=0o700)
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.unshare(0x20000) == 0
    assert libc.mount(None, b'/', None, 0x4000 | 0x40000, None) == 0
    assert libc.mount(b'tmpfs', os.fsencode(base), b'tmpfs', 2 | 4, b'size=128m,nr_inodes=25000,mode=0700,noswap') == 0
    try:
        (parent / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        fixture_module.fixture(base / 'root')
        for mode in modes:
            result = subprocess.run([sys.executable, '-I', '-B', SCRIPT, 'actor', str(parent), str(base), mode],
                                     capture_output=True, text=True, timeout=150)
            if result.returncode:
                sys.stderr.write(result.stderr)
                raise RuntimeError('Owned graph check failed: ' + mode)
            print(result.stdout.strip(), flush=True)
    finally:
        # Exact owned paths; unmount before removing these empty mount points.
        assert not list(parent.iterdir()) or not list(parent.glob('job-*'))
        assert libc.umount2(os.fsencode(base), 0) == 0
        base.rmdir(); parent.rmdir()
    print(json.dumps({'checks': len(modes), 'cleanupVerified': True, 'hardwareAdmissionEstablished': False,
                      'realPaidJob': False, 'paymentAccepted': False}), flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'actor': actor(*sys.argv[2:])
    else: main(tuple(sys.argv[1:]) or MODES)
