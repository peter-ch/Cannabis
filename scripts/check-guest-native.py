#!/usr/bin/env python3
"""Owned encrypted execution and decoder lifecycle checks on the real kernel."""
import copy
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.client import pack_workload, task_binding_sha256, assemble_results
from compute.guest_helpers import run_guarded_helper, ProtectedStaging
from compute.guest_native import NativeTaskPlan, NATIVE_ADAPTER
from compute.guest_deadline import ExecutionDeadline
from compute.guest_resources import ResourceLimits
from compute.guest_sandbox import ScratchLimits, tree_digest
from compute.job_keys import RecoveredJobKey, _new_identity

SCRIPT = str(Path(__file__).resolve())
AGE = shutil.which('age') or '/usr/local/bin/age'
specification = importlib.util.spec_from_file_location('sandbox_fixture', Path(SCRIPT).with_name('check-guest-sandbox.py'))
sandbox_fixture = importlib.util.module_from_spec(specification)
specification.loader.exec_module(sandbox_fixture)


def actor(parent, base, mode):
    parent, base = Path(parent), Path(base)
    before_mountpoints = set(Path('/').glob('cannabis-staging-*')) | set(Path('/').glob('cannabis-sandbox-*'))
    own = base / mode
    own.mkdir(mode=0o700)
    source = own / 'source'
    source.mkdir()
    (source / 'input.txt').write_text('owned encrypted input')
    program = "import os; assert os.environ['OWNED_PRIVATE']=='private value'; open('/output/result.txt','w').write(open('/input/input.txt').read().upper()); print('owned private log')"
    if mode == 'missing-output':
        program = 'pass'
    if mode == 'symlink-output':
        program = "import os; os.symlink('/etc/passwd','/output/result.txt')"
    if mode == 'encode-quota':
        program = "open('/output/result.txt','wb').write(b'x'*(1024**2))"
    if mode == 'native-shared-deadline':
        program = "import time; open('/output/result.txt','w').write('owned runtime started'); time.sleep(120)"
    if mode == 'decode-quota':
        # Both plaintext and ciphertext fit individually, but their concurrent
        # authenticated staging cannot exceed the shared 1 MiB filesystem.
        (source / 'input.txt').write_bytes(b'x' * (700*1024))
    (source / 'program.py').write_text(program)
    runtime = {'adapter': NATIVE_ADAPTER, 'architecture': 'x86_64', 'os': 'linux', 'digestSHA256': tree_digest(base / 'root')}
    resources = {'cpus': 1, 'memoryMiB': 128, 'scratchMiB': 8, 'wallSeconds': 30, 'nodes': 1}
    if mode == 'native-shared-deadline':
        resources['wallSeconds'] = 120
    owner_secret, owner_public = _new_identity(AGE)
    job_secret, job_public = _new_identity(AGE)
    spec = {'schema': 'cannabis.workload.v1', 'id': 'owned-native-check', 'policySHA256': '12'*32,
        'resultRecipient': owner_public, 'files': ['input.txt', 'program.py'],
        'tasks': [{'id': 'owned-task', 'runtime': runtime, 'resources': resources,
            'launch': {'argv': ['/usr/bin/python3', '-I', '-B', '/input/program.py'],
                'environment': {'OWNED_PRIVATE': 'private value'}, 'stdout': 'logs/stdout.txt'},
            'outputs': ['result.txt', 'logs/stdout.txt'], 'outputMaxBytes': 4096}],
        'assembly': [{'task': 'owned-task', 'output': 'result.txt', 'destination': 'result.txt'},
                     {'task': 'owned-task', 'output': 'logs/stdout.txt', 'destination': 'stdout.txt'}]}
    if mode == 'dependency':
        extra = copy.deepcopy(spec['tasks'][0]); extra['id'] = 'upstream'
        spec['tasks'].append(extra)
        spec['tasks'][0]['dependsOn'] = ['upstream']
    if mode == 'encode-quota':
        spec['tasks'][0]['outputMaxBytes'] = 2*1024**2
    package = pack_workload(spec, source, job_public, own / 'input.age', age=AGE)
    binding = {'packageSHA256': package['ciphertextSHA256'], 'policySHA256': spec['policySHA256'],
        'runtimeSHA256': runtime['digestSHA256'], 'taskSHA256': task_binding_sha256(package['ciphertextSHA256'], 0),
        'attempt': 1, 'worldSize': 1, 'rank': 0, 'acceleratorClass': 'cpu'}
    key = RecoveredJobKey(job_secret, spec['id'], binding['packageSHA256'], spec['policySHA256'], job_public, owner_public)
    retained = copy.deepcopy(resources)
    if mode == 'metadata':
        retained['cpus'] = 2
    if mode == 'group':
        retained['nodes'] = 2
    destination = own / 'result.age'
    try:
        seconds = {'native-shared-deadline': 40, 'encoder-shared-deadline': 60, 'publication-deadline': 45}.get(mode, 120)
        deadline = (ExecutionDeadline(time.monotonic() - 1) if mode == 'expired-plan' else
                    ExecutionDeadline.from_service_interval(int(time.time()) - 1, int(time.time()) + seconds))
        plan = NativeTaskPlan(base / 'root', runtime, retained, process_limit=32, scratch_inodes=512, deadline=deadline)
        if mode == 'tampered':
            with (own / 'input.age').open('r+b') as stream:
                stream.seek(-1, 2); byte = stream.read(1); stream.seek(-1, 2); stream.write(bytes([byte[0] ^ 1]))
        if mode in ['helper-deadline', 'helper-owner-death', 'helper-owner-stop', 'helper-cancel']:
            fake = own / 'tools'; fake.mkdir()
            shutil.copyfile(Path(AGE).with_name('age-keygen'), fake / 'age-keygen')
            (fake / 'age-keygen').chmod(0o755)
            (fake / 'age').write_text('#!/usr/bin/python3\nimport os,time\n'
                + 'open(' + repr(str(own / 'started')) + ',"w").write(str(os.getpid()))\n'
                + 'if os.fork()==0:\n os.setsid()\n time.sleep(120)\n'
                + 'time.sleep(120)\n')
            (fake / 'age').chmod(0o755)
            # Include interpreter/key-check startup under slow CPU emulation.
            # This owned fixture still expires long before its 120-second stall.
            age, wall = str(fake / 'age'), 15
        else:
            age, wall = AGE, 30
        if mode == 'encoder-shared-deadline':
            fake = own / 'tools'; fake.mkdir()
            shutil.copyfile(Path(AGE).with_name('age-keygen'), fake / 'age-keygen')
            (fake / 'age-keygen').chmod(0o755)
            (fake / 'age').write_text('#!/usr/bin/python3\nimport os,sys,time\n'
                + 'if "-r" in sys.argv:\n'
                + ' open(' + repr(str(own / 'encoder-started')) + ',"w").write("owned encoder")\n'
                + ' time.sleep(120)\n'
                + 'os.execv(' + repr(AGE) + ',[' + repr(AGE) + ']+sys.argv[1:])\n')
            (fake / 'age').chmod(0o755)
            age, wall = str(fake / 'age'), 120
        if mode == 'publication-deadline':
            # Inject actual owner suspension after the real ciphertext write.
            # No production hook is added, and no private data enters the marker.
            original_open = Path.open
            class PausedOutput:
                def __init__(self, stream): self.stream = stream
                def __enter__(self): return self
                def __exit__(self, *args): return self.stream.__exit__(*args)
                def write(self, data):
                    count = self.stream.write(data); self.stream.flush()
                    (own / 'publication-started').write_text(str(deadline.monotonic_end))
                    os.kill(os.getpid(), signal.SIGSTOP)
                    return count
            def controlled_open(path, *args, **kwargs):
                stream = original_open(path, *args, **kwargs)
                return PausedOutput(stream) if path == destination and args and args[0] == 'xb' else stream
            Path.open = controlled_open
        class Cancellation:
            def is_set(self):
                if mode == 'native-shared-deadline':
                    for entry in set(Path('/').glob('cannabis-sandbox-*')) - before_mountpoints:
                        if (entry / 'output/result.txt').exists():
                            (own / 'native-started').write_text('owned runtime')
                    return False
                return (own / 'started').exists()
        result = plan.run(parent, own / 'input.age', key, binding, destination, age=age,
            helper_limits=ResourceLimits(1000, 256*1024**2, 64, wall),
            staging_limits=ScratchLimits((1 if mode in ['decode-quota', 'encode-quota'] else 16)*1024**2, 1024),
            max_input_bytes=1024**2, cancelled=Cancellation() if mode in ['helper-cancel', 'native-shared-deadline'] else None)
        assert mode == 'success', 'Expected refusal: ' + mode
        assert not result.report['paymentAccepted'] and not result.report['hardwareAdmissionEstablished']
        assert job_secret.strip() not in destination.read_bytes() and b'OWNED ENCRYPTED INPUT' not in destination.read_bytes()
        reconstructed = assemble_results(spec, binding['packageSHA256'], [{'receipt': result.receipt, 'file': destination}],
            owner_secret, own / 'assembled', age=AGE)
        assert reconstructed['integrityVerified'] and not reconstructed['paymentAuthorized']
        assert (own / 'assembled/result.txt').read_text() == 'OWNED ENCRYPTED INPUT'
        assert (own / 'assembled/stdout.txt').read_text() == 'owned private log\n'
        try:
            plan.run(parent, own / 'input.age', key, binding, own / 'again.age', age=AGE,
                helper_limits=ResourceLimits(1000, 256*1024**2, 64, 30), staging_limits=ScratchLimits(16*1024**2), max_input_bytes=1024**2)
        except ValueError:
            pass
        else:
            raise AssertionError('Consumed plan reused')
    except (ValueError, RuntimeError) as error:
        if mode == 'success':
            raise
        assert not destination.exists(), 'Rejected job published a result'
        if mode in ['expired-plan', 'native-shared-deadline', 'encoder-shared-deadline', 'publication-deadline']:
            assert deadline.monotonic_end <= time.monotonic() < deadline.monotonic_end + 10, 'Common deadline did not bound completion'
    assert not list(parent.glob('job-*')), 'Resource group survived completion'
    if mode in ['helper-deadline', 'helper-owner-stop', 'helper-cancel']:
        assert (own / 'started').exists(), 'The helper lifetime refusal was not exercised'
    for name, marker in [('native-shared-deadline', 'native-started'), ('encoder-shared-deadline', 'encoder-started'), ('publication-deadline', 'publication-started')]:
        if mode == name:
            assert (own / marker).exists(), 'The intended deadline stage was not exercised'
    after_mountpoints = set(Path('/').glob('cannabis-staging-*')) | set(Path('/').glob('cannabis-sandbox-*'))
    assert after_mountpoints == before_mountpoints, 'This job left a mount point'
    print(json.dumps({'passed': True, 'mode': mode}), flush=True)


def main():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Use a disposable Linux root environment')
    base = Path('/run') / ('cannabis-native-check-' + uuid.uuid4().hex)
    parent = Path('/sys/fs/cgroup') / base.name
    base.mkdir(mode=0o700); parent.mkdir(mode=0o700)
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.unshare(0x20000) == 0
    assert libc.mount(None, b'/', None, 0x4000 | 0x40000, None) == 0
    assert libc.mount(b'tmpfs', os.fsencode(base), b'tmpfs', 2 | 4, b'size=128m,nr_inodes=25000,mode=0700,noswap') == 0
    checks = {}
    try:
        (parent / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        sandbox_fixture.fixture(base / 'root')
        for mode in ['success', 'tampered', 'metadata', 'group', 'dependency', 'missing-output', 'symlink-output',
                'decode-quota', 'encode-quota', 'helper-deadline', 'helper-owner-death', 'helper-owner-stop', 'helper-cancel',
                'expired-plan', 'native-shared-deadline', 'encoder-shared-deadline', 'publication-deadline']:
            print('Owned encrypted execution check: ' + mode, file=sys.stderr, flush=True)
            proc = subprocess.Popen([sys.executable, '-I', '-B', SCRIPT, 'actor', str(parent), str(base), mode],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                if mode == 'publication-deadline':
                    marker = base / mode / 'publication-started'
                    expiry = time.monotonic() + 90
                    while not marker.exists():
                        if proc.poll() is not None or time.monotonic() >= expiry:
                            if proc.poll() is None: proc.kill()
                            _, error = proc.communicate(timeout=5)
                            raise AssertionError('Publication stage did not start: ' + error[-8192:].decode())
                        time.sleep(0.02)
                    _, status = os.waitpid(proc.pid, os.WUNTRACED)
                    assert os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP
                    assert (base / mode / 'result.age').stat().st_size > 0
                    time.sleep(max(0, float(marker.read_text()) - time.monotonic()) + 0.1)
                    os.kill(proc.pid, signal.SIGCONT)
                if mode in ['helper-owner-death', 'helper-owner-stop']:
                    expiry = time.monotonic() + 30
                    while not (base / mode / 'started').exists():
                        if proc.poll() is not None or time.monotonic() >= expiry:
                            if proc.poll() is None:
                                proc.kill()
                            _, error = proc.communicate(timeout=5)
                            raise AssertionError('Helper did not start: ' + error[-8192:].decode())
                        time.sleep(0.05)
                    # Track the exact directories created by this actor. Their
                    # mounts are private and die after its last namespace user.
                    entries = [Path(p) for p in Path('/proc', str(proc.pid), 'root').glob('cannabis-staging-*')]
                    underlying = [Path('/') / p.name for p in entries]
                    os.kill(proc.pid, signal.SIGKILL if mode == 'helper-owner-death' else signal.SIGSTOP)
                    expiry = time.monotonic() + 15
                    while list(parent.glob('job-*')):
                        assert time.monotonic() < expiry, 'Guardian did not remove helper tree'
                        time.sleep(0.05)
                    if mode == 'helper-owner-stop':
                        os.kill(proc.pid, signal.SIGCONT)
                    else:
                        assert proc.wait(timeout=5) == -signal.SIGKILL
                        expiry = time.monotonic() + 5
                        for entry in underlying:
                            while list(entry.iterdir()):
                                assert time.monotonic() < expiry
                                time.sleep(0.05)
                            entry.rmdir()
                out, err = proc.communicate(timeout=90)
                if mode != 'helper-owner-death':
                    assert proc.returncode == 0, err.decode()[-8192:]
                    assert json.loads(out) == {'passed': True, 'mode': mode}
                checks[mode] = True
            finally:
                if proc.poll() is None: proc.kill()
                proc.wait(timeout=5)
        print(json.dumps({'schema': 'cannabis.guest-native-check.v1', 'kernel': os.uname().release,
            'checks': checks, 'ownedEncryptedExecution': True, 'requesterReconstruction': True,
            'customerCodeExecuted': False, 'hardwareValidated': False, 'realPaidJob': False}))
    finally:
        if any(parent.iterdir()):
            (parent / 'cgroup.kill').write_text('1')
            expiry = time.monotonic() + 10
            while 'populated 1' in (parent / 'cgroup.events').read_text():
                assert time.monotonic() < expiry
                time.sleep(0.05)
            for child in sorted(parent.rglob('*'), key=lambda p: len(p.parts), reverse=True):
                if child.is_dir(): child.rmdir()
        parent.rmdir()
        assert libc.umount2(os.fsencode(base), 0) == 0
        base.rmdir()


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == 'actor':
        actor(*sys.argv[2:])
    else:
        main()
