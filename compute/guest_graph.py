"""Run a private step DAG sequentially within one already admitted CPU booking."""
import shutil
import time

from .guest_deadline import ExecutionDeadline
from .guest_helpers import run_guarded_helper
from .guest_sandbox import NativeSandbox
from .native_graph import validate_native_graph


def run_native_graph(parent, rootfs, runtime_sha256, task, package_files, inputs, workspace,
                     *, limits, scratch, helper_limits, staging_limits, deadline, cancelled=None):
    graph = validate_native_graph(task['launch'], package_files, task['outputs'])
    # The task wall allowance covers the ENTIRE graph, not a fresh allowance for
    # each step. The signed booking deadline can only shorten that allowance.
    graph_deadline = ExecutionDeadline(min(deadline.monotonic_end, time.monotonic() + limits.wall_seconds))
    graph_deadline.check(cancelled)
    workspace.mkdir(mode=0o700)
    retained = {}

    def copy(root, items, destination, maximum):
        graph_deadline.check(cancelled)
        return run_guarded_helper(parent, helper_limits, {'operation': 'copy-artifacts',
            'root': str(root), 'items': items, 'destination': str(destination),
            'maxBytes': min(maximum, staging_limits.bytes)}, cancelled=cancelled, deadline=graph_deadline)

    for index, step in enumerate(graph['steps']):
        step_inputs = workspace / ('input-' + str(index))
        # A single helper copies from a common private root, retaining only the
        # explicit package/dependency allowlist. Source labels stay in the guest.
        mappings = []
        for item in step['inputs']:
            source = inputs / item['package'] if 'package' in item else retained[item['step']] / item['output']
            mappings.append({'source': source.relative_to(workspace.parent).as_posix(), 'destination': item['destination']})
        copy(workspace.parent, mappings, step_inputs, scratch.bytes)
        with NativeSandbox(parent, rootfs, step_inputs, runtime_sha256, limits, scratch, deadline=graph_deadline) as sandbox:
            launch = step['launch']
            result = sandbox.run(launch['argv'], environment=launch.get('environment'), cancelled=cancelled)
            if not result['success']:
                raise RuntimeError('Native graph step failed; no graph result accepted')
            graph_deadline.check(cancelled)
            logs = {launch[k]: k for k in ('stdout', 'stderr') if k in launch}
            target = workspace / ('output-' + str(index))
            copy(sandbox._path, [{'source': logs.get(name, 'output/' + name), 'destination': name}
                                for name in step['outputs']], target, step['outputMaxBytes'])
        graph_deadline.check(cancelled)
        retained[step['id']] = target
        shutil.rmtree(step_inputs)
    final = workspace / 'result'
    copy(workspace, [{'source': (retained[i['step']] / i['output']).relative_to(workspace).as_posix(),
                     'destination': i['destination']} for i in graph['collect']], final, task.get('outputMaxBytes', 1024**3))
    graph_deadline.check(cancelled)
    return final
