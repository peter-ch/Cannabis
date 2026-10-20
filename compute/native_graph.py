"""Private, sequential step graphs for the native adapter; no execution here."""
import copy
import re
from .client import ID, MAX_BYTES, MAX_FILES, MAX_MANIFEST, canonical, safe_name

SCHEMA = 'cannabis.native-step-graph.v1'


def _paths(names):
    if not isinstance(names, list) or len(names) > MAX_FILES:
        raise ValueError('Require bounded explicit graph paths')
    seen = set()
    for name in names:
        key = safe_name(name).casefold()
        if key in seen:
            raise ValueError('Graph path collision')
        seen.add(key)
    for name in seen:
        parts = name.split('/')
        if any('/'.join(parts[:i]) in seen for i in range(1, len(parts))):
            raise ValueError('Graph file/directory collision')


def validate_native_graph(launch, package_files, outputs):
    """Return a detached, deterministic schedule, never silently infer edges.

    All steps use the enclosing task's pinned runtime and purchased limits. A
    step cannot request another runtime, node, resource allocation or network.
    """
    if (not isinstance(launch, dict) or set(launch) != {'schema', 'steps', 'collect'}
            or launch['schema'] != SCHEMA or len(canonical(launch)) > MAX_MANIFEST):
        raise ValueError('Require a bounded native step graph')
    value = copy.deepcopy(launch)
    steps = value['steps']
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        raise ValueError('Declare 1..64 private native steps')
    by_id = {}
    for step in steps:
        if (not isinstance(step, dict) or set(step) != {'id', 'dependsOn', 'inputs', 'launch', 'outputs', 'outputMaxBytes'}
                or not isinstance(step['id'], str) or not ID.fullmatch(step['id']) or step['id'] in by_id):
            raise ValueError('Require unique explicitly declared native steps')
        by_id[step['id']] = step
        _paths(step['outputs'])
        if type(step['outputMaxBytes']) is not int or not 0 <= step['outputMaxBytes'] <= MAX_BYTES:
            raise ValueError('Require a bounded step output size')
        command = step['launch']
        if (not isinstance(command, dict) or set(command) - {'argv', 'environment', 'stdout', 'stderr'}
                or not isinstance(command.get('argv'), list) or not command['argv']):
            raise ValueError('Require an explicit native step command')
        argv, env = command['argv'], command.get('environment', {})
        if (len(argv) > 256 or any(not isinstance(a, str) or '\0' in a or len(a.encode()) > 16384 for a in argv)
                or not argv[0].startswith('/') or sum(len(a.encode()) + 1 for a in argv) > 131072):
            raise ValueError('Require a bounded absolute native step command')
        if (not isinstance(env, dict) or len(env) > 128
                or any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', k)
                       or not isinstance(v, str) or '\0' in v for k, v in env.items())
                or sum(len(k.encode()) + len(v.encode()) + 2 for k, v in env.items()) > 65536):
            raise ValueError('Require a bounded native step environment')
        logs = [command[k] for k in ('stdout', 'stderr') if k in command]
        _paths(logs)
        if any(name not in step['outputs'] for name in logs):
            raise ValueError('Graph logs must be declared encrypted outputs')
    for step in steps:
        deps = step['dependsOn']
        if (not isinstance(deps, list) or any(not isinstance(d, str) or d not in by_id or d == step['id'] for d in deps)
                or len(set(deps)) != len(deps)):
            raise ValueError('Invalid native graph dependencies')
        imports = step['inputs']
        if not isinstance(imports, list) or any(not isinstance(i, dict) for i in imports):
            raise ValueError('Require explicit graph input mappings')
        _paths([i.get('destination') for i in imports])
        for item in imports:
            if set(item) == {'package', 'destination'}:
                if item['package'] not in package_files:
                    raise ValueError('Graph input is outside the package allowlist')
            elif set(item) == {'step', 'output', 'destination'}:
                if item['step'] not in deps or item['output'] not in by_id[item['step']]['outputs']:
                    raise ValueError('Graph input needs a declared dependency output')
            else:
                raise ValueError('Unsupported graph input mapping')
    order, pending = [], dict(by_id)
    while pending:
        ready = [key for key, step in pending.items() if all(d in order for d in step['dependsOn'])]
        if not ready:
            raise ValueError('Native step graph contains a cycle')
        for key in ready:
            order.append(key)
            del pending[key]
    collect = value['collect']
    if (not isinstance(collect, list) or any(not isinstance(i, dict) or set(i) != {'step', 'output', 'destination'} for i in collect)):
        raise ValueError('Require explicit final graph output mappings')
    _paths([i['destination'] for i in collect])
    if set(i['destination'] for i in collect) != set(outputs):
        raise ValueError('Graph collection must exactly cover the enclosing task outputs')
    for item in collect:
        if item['step'] not in by_id or item['output'] not in by_id[item['step']]['outputs']:
            raise ValueError('Graph collection references an undeclared step output')
    value['steps'] = [by_id[key] for key in order]
    return value
