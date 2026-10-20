"""Encrypted package -> native runtime -> encrypted result INSIDE a guest.

The enclosing measured launcher must admit the assignment, runtime and hardware
before supplying a key. This component never establishes funding or attestation.
"""
from dataclasses import asdict, dataclass, field
from contextlib import contextmanager
import copy
import hashlib
import os
from pathlib import Path

from .client import canonical, safe_name
from .guest_helpers import ProtectedStaging, run_guarded_helper
from .guest_deadline import ExecutionDeadline
from .guest_resources import ResourceLimits
from .guest_sandbox import NativeSandbox, ScratchLimits, tree_digest, _directory
from .job_keys import RecoveredJobKey
from .native_graph import SCHEMA as GRAPH_SCHEMA
from .guest_graph import run_native_graph

NATIVE_ADAPTER = 'native-linux-x86_64-v1'
GROUP_ADAPTER = 'native-group-linux-x86_64-v1'
GROUP_BACKEND = 'attested-tls-ip-v1'


@contextmanager
def _publication_scope(destination, deadline, cancelled):
    # Enter before staging so this observes its checked cleanup too. Destination
    # is a fresh path in the protected control plane, inaccessible to workloads.
    owned = [False]
    try:
        deadline.check(cancelled)
        yield owned
        deadline.check(cancelled)
    except BaseException:
        if owned[0]:
            destination.unlink()
        raise


@dataclass(frozen=True)
class NativeTaskResult:
    report: dict
    # Task names and the receipt belong to the private requester channel.
    receipt: dict = field(repr=False)
    ciphertext: Path = field(repr=False)


class NativeTaskPlan:
    """Retain the scheduler-approved runtime and task limits before key release.

    digestSHA256 means guest_sandbox.tree_digest's canonical inventory for this
    adapter, not a download/archive digest. A different adapter defines its own
    semantics. The caller must independently approve these retained values.
    """
    def __init__(self, rootfs, runtime, resources, *, process_limit, scratch_inodes, deadline, group_network=None):
        if not isinstance(deadline, ExecutionDeadline):
            raise ValueError('Require the retained signed-service deadline before key release')
        deadline.check()
        self._deadline = deadline
        if group_network is not None:
            from .guest_group_network import GuestGroupNetwork
            if not isinstance(group_network, GuestGroupNetwork):
                raise ValueError('Group execution requires its owned protected namespace')
            group_network.assert_alive()
        self._group_network = group_network
        runtime, resources = copy.deepcopy(runtime), copy.deepcopy(resources)
        runtime_keys = {'adapter', 'digestSHA256', 'architecture', 'os', 'features'}
        if group_network is not None:
            runtime_keys.add('collectiveBackend')
        if (not isinstance(runtime, dict) or set(runtime) - runtime_keys
                or runtime.get('adapter') != (GROUP_ADAPTER if group_network else NATIVE_ADAPTER) or runtime.get('architecture') != 'x86_64'
                or runtime.get('os') != 'linux' or runtime.get('features', []) != []):
            raise ValueError('Unsupported native runtime profile; another reviewed adapter is required')
        if group_network is not None and runtime.get('collectiveBackend') != GROUP_BACKEND:
            raise ValueError('Group runtime requires its protected IP transport')
        if (not isinstance(resources, dict) or set(resources) - {'cpus', 'memoryMiB', 'scratchMiB', 'wallSeconds', 'nodes', 'accelerators', 'acceleratorMemoryMiB'}
                or resources.get('nodes') != (group_network.world_size if group_network else 1)
                or resources.get('accelerators', 0) != 0 or resources.get('acceleratorMemoryMiB', 0) != 0
                or type(resources.get('scratchMiB')) is not int):
            raise ValueError('Native resources differ from the admitted CPU rank topology; never reduce a group or accelerator job')
        self._limits = ResourceLimits.from_task(resources, process_limit=process_limit)
        self._scratch = ScratchLimits(resources['scratchMiB'] * 1024**2, scratch_inodes)
        self._root = Path(rootfs)
        if tree_digest(self._root) != runtime.get('digestSHA256'):
            raise ValueError('Runtime tree differs from the approved inventory')
        deadline.check()
        self._runtime, self._resources, self._used = runtime, resources, False

    @contextmanager
    def _outputs(self, parent, task, spec, staging, helper_limits, staging_limits, cancelled, input_root, input_files):
        launch = task['launch']
        if launch.get('schema') == GRAPH_SCHEMA:
            if self._group_network is not None:
                raise ValueError('This group adapter requires one explicit rank entrypoint; task DAGs remain in the complete plan')
            yield run_native_graph(parent, self._root, self._runtime['digestSHA256'], task, input_files,
                input_root, staging.path / 'graph', limits=self._limits, scratch=self._scratch,
                helper_limits=helper_limits, staging_limits=staging_limits, deadline=self._deadline, cancelled=cancelled)
            return
        if set(launch) - {'argv', 'environment', 'stdout', 'stderr'} or 'argv' not in launch:
            raise ValueError('Unsupported native launch settings')
        if 'environment' in launch and not isinstance(launch['environment'], dict):
            raise ValueError('Native environment must be an explicit mapping')
        environment = dict(launch.get('environment', {}))
        if self._group_network is not None:
            self._group_network.assert_alive()
            reserved = {'RANK': str(self._group_network.rank), 'WORLD_SIZE': str(self._group_network.world_size),
                        'LOCAL_RANK': '0', 'LOCAL_WORLD_SIZE': '1', 'MASTER_ADDR': '10.211.0.1',
                        'CANNABIS_GROUP_IP': f'10.211.0.{self._group_network.rank + 1}',
                        'CANNABIS_GROUP_INTERFACE': 'cannabis0', 'GLOO_SOCKET_IFNAME': 'cannabis0'}
            if any(name in environment and environment[name] != value for name, value in reserved.items()):
                raise ValueError('Private rank environment conflicts with the approved group')
            environment.update(reserved)
            environment.setdefault('MASTER_PORT', '29500')
        log_names = [safe_name(launch[k]) for k in ('stdout', 'stderr') if k in launch]
        if len(set(log_names)) != len(log_names) or any(name not in task['outputs'] for name in log_names):
            raise ValueError('Returned logs must have distinct declared encrypted output paths')
        with NativeSandbox(parent, self._root, input_root, self._runtime['digestSHA256'],
                self._limits, self._scratch, deadline=self._deadline, group_network=self._group_network) as sandbox:
            executed = sandbox.run(launch['argv'], environment=environment, cancelled=cancelled)
            if not executed['success']:
                raise RuntimeError('Native task failed; no result accepted')
            self._deadline.check(cancelled)
            for stream in ('stdout', 'stderr'):
                if stream in launch:
                    target = sandbox.output_directory / launch[stream]
                    current = sandbox.output_directory
                    for part in Path(launch[stream]).parts[:-1]:
                        current = current / part
                        if not current.exists():
                            current.mkdir(mode=0o700)
                        if current.is_symlink() or not current.is_dir():
                            raise ValueError('Unsafe output log directory')
                    os.link(sandbox._path / stream, target, follow_symlinks=False)
            yield sandbox.output_directory

    def run(self, parent, ciphertext, key, binding, destination, *, age, helper_limits, staging_limits, max_input_bytes, max_output_ciphertext_bytes,
            cancelled=None, dependency=None, max_dependency_bytes=0):
        """Consume one guest-opened job key; publish only fully sealed ciphertext.

        helper_limits/staging_limits are explicit additional reservation budgets,
        not capacity silently borrowed from another customer. Each helper has a
        separate checked cgroup and guardian; native execution has its own.
        """
        binding = copy.deepcopy(binding)
        dependency = copy.deepcopy(dependency)
        if self._used or not isinstance(key, RecoveredJobKey):
            raise ValueError('Require an unused retained plan and guest-opened key')
        self._used = True
        self._deadline.check(cancelled)
        if (binding.get('runtimeSHA256') != self._runtime['digestSHA256']
                or binding.get('worldSize') != (self._group_network.world_size if self._group_network else 1)
                or binding.get('rank') != (self._group_network.rank if self._group_network else 0) or binding.get('acceleratorClass') != 'cpu'):
            raise ValueError('Delivered assignment differs from the retained runtime')
        if not isinstance(helper_limits, ResourceLimits) or not isinstance(staging_limits, ScratchLimits):
            raise ValueError('Require retained helper and staging budgets')
        if type(max_input_bytes) is not int or not 0 <= max_input_bytes <= staging_limits.bytes:
            raise ValueError('Require a bounded approved input size')
        if (type(max_dependency_bytes) is not int or max_dependency_bytes < 0
                or max_dependency_bytes+max_input_bytes > staging_limits.bytes):
            raise ValueError('Require a shared bounded dependency staging budget')
        if dependency is not None:
            if not isinstance(dependency,dict) or set(dependency) != {'handoff','ciphertext'}:
                raise ValueError('Require the retained authenticated dependency input')
            h=dependency['handoff'];context=h['context']
            if (context['jobId'] != key.job_id or h['recipient'] != key.input_recipient
                    or context['inputRecipient'] != key.input_recipient
                    or any(context.get(k) != v for k,v in binding.items())):
                raise ValueError('Dependency input differs from the opened job key or assignment')
        if type(max_output_ciphertext_bytes) is not int or not 1 <= max_output_ciphertext_bytes <= 1024**4:
            raise ValueError('Require a bounded approved encrypted output size')
        if tree_digest(self._root) != self._runtime['digestSHA256']:
            raise ValueError('Approved runtime changed before decoding')
        self._deadline.check(cancelled)
        destination = Path(destination)
        fd = _directory(destination.parent, memory=False)
        os.close(fd)
        if os.path.lexists(destination):
            raise FileExistsError('Encrypted result destination already exists')
        with _publication_scope(destination, self._deadline, cancelled) as publication, ProtectedStaging(staging_limits) as staging:
            job = asdict(key)
            job['identity'] = key.identity.decode('ascii')
            decoded = run_guarded_helper(parent, helper_limits, {'operation': 'decode', 'source': str(ciphertext),
                'job': job, 'binding': binding, 'destination': str(staging.path / 'inputs'), 'age': age,
                'maxBytes': max_input_bytes}, cancelled=cancelled, deadline=self._deadline)
            job.clear()
            self._deadline.check(cancelled)
            spec, decoded_report = decoded['workload'], decoded['report']
            task = spec['tasks'][decoded_report['taskIndex']]
            if self._group_network is not None and task.get('outputScope') != 'per-rank':
                raise ValueError('This group adapter requires explicit per-rank result receipts')
            if canonical(task['runtime']) != canonical(self._runtime) or canonical(task['resources']) != canonical(self._resources):
                raise ValueError('Private task differs from retained matching metadata')
            input_root, input_files = staging.path / 'inputs', list(spec['files'])
            if bool(task.get('dependsOn', [])) != bool(dependency):
                raise ValueError('Dependency tasks require their retained authenticated input')
            if dependency:
                if task.get('dependencyInputMaxBytes', max_dependency_bytes+1) > max_dependency_bytes:
                    raise ValueError('Private dependency budget exceeds the reserved service')
                run_guarded_helper(parent, helper_limits, {'operation':'decode-dependency','spec':spec,
                    'handoff':dependency['handoff'],'source':dependency['ciphertext'],'identity':key.identity.decode('ascii'),
                    'destination':str(staging.path/'dependencies'),'age':age},cancelled=cancelled,deadline=self._deadline)
                mappings=task['dependencyInputs']
                input_files += [m['destination'] for m in mappings]
                items=[{'source':'inputs/'+name,'destination':name} for name in spec['files']]
                items += [{'source':'dependencies/'+m['destination'],'destination':m['destination']} for m in mappings]
                input_root=staging.path/'combined'
                run_guarded_helper(parent,helper_limits,{'operation':'copy-artifacts','root':str(staging.path),'items':items,
                    'destination':str(input_root),'maxBytes':max_input_bytes+max_dependency_bytes},cancelled=cancelled,deadline=self._deadline)
            with self._outputs(parent, task, spec, staging, helper_limits, staging_limits, cancelled, input_root, input_files) as output_root:
                receipt = run_guarded_helper(parent, helper_limits, {'operation': 'seal-result', 'spec': spec,
                    'taskId': task['id'], 'packageSHA256': binding['packageSHA256'],
                    'root': str(output_root), 'recipient': key.result_recipient,
                    'destination': str(staging.path / 'result.age'), 'attempt': binding['attempt'], 'rank': binding['rank'],
                    'age': age}, cancelled=cancelled, deadline=self._deadline)
            self._deadline.check(cancelled)
            # No plaintext or private receipt is written outside the protected
            # scopes. Reserve only this invocation's ciphertext destination.
            created = False
            try:
                with destination.open('xb') as out:
                    created = True
                    publication[0] = True
                    os.chmod(destination, 0o600)
                    digest, count = hashlib.sha256(), 0
                    with (staging.path / 'result.age').open('rb') as incoming:
                        for chunk in iter(lambda: incoming.read(262144), b''):
                            self._deadline.check(cancelled)
                            count += len(chunk)
                            if count > min(staging_limits.bytes,max_output_ciphertext_bytes) or (cancelled is not None and cancelled.is_set()):
                                raise RuntimeError('Encrypted publication cancelled or exceeds budget')
                            digest.update(chunk)
                            out.write(chunk)
                            self._deadline.check(cancelled)
                    if count != receipt['ciphertextBytes'] or digest.hexdigest() != receipt['ciphertextSHA256']:
                        raise ValueError('Encrypted result changed during publication')
            except BaseException:
                if created:
                    destination.unlink()
                    publication[0] = False
                raise
        return NativeTaskResult({'schema': 'cannabis.guest-native-result.v1', 'executionCompleted': True,
            'resultEncrypted': True, 'runtimeCleanupVerified': True, 'hardwareAdmissionEstablished': False,
            'paymentAccepted': False}, receipt, destination)
