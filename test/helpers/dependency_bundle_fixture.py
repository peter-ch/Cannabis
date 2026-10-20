"""Owned ephemeral encryption fixtures; never hardware, funding or customer data."""
import copy
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from compute.client import create_identity, load_identity, seal_result, validate_workload
from compute.job_keys import pack_job, recover_job_key, _new_identity
from compute.dependency_bundle import open_dependency_bundle

r = json.load(sys.stdin)
root, age = Path(r['root']), r['age']
if r['action'] == 'setup':
    identity = root / 'owner.key'
    if os.name == 'nt':
        owner = create_identity(identity, age)['recipient']
    else:
        secret, owner = _new_identity(age)
        identity.write_bytes(secret)
        identity.chmod(0o600)
    runtime = {'adapter': 'custom-cpu-v1', 'architecture': 'x86_64', 'os': 'linux', 'digestSHA256': '04'*32, 'collectiveBackend': 'tcp'}
    resources = {'cpus': 1, 'memoryMiB': 128, 'scratchMiB': 8, 'wallSeconds': 60, 'nodes': 1}
    tasks = [{'id': name, 'runtime': runtime, 'resources': {**resources, 'nodes': 2 if i == 1 else 1},
              'launch': {'argv': ['owned-fixture']}, 'outputs': ['selected.txt', 'unselected.txt'],
              'outputScope': 'per-rank' if i == 1 else 'leader', 'outputMaxBytes': 1024,
              'dependsOn': ['first', 'second'] if i == 2 else []}
             for i, name in enumerate(['first', 'second', 'join'])]
    tasks[-1].update(dependencyInputs=[{'task': name, 'rank': rank, 'output': 'selected.txt', 'destination': f'inputs/{name}-{rank}.txt'}
                                     for name, rank in [('first', 0), ('second', 0), ('second', 1)]], dependencyInputMaxBytes=128)
    if r.get('native'):
        tasks[-1]['runtime'] = {**runtime, 'adapter': 'native-linux-x86_64-v1'}
        tasks[-1]['runtime'].pop('collectiveBackend')
    spec = {'schema': 'cannabis.workload.v1', 'id': 'owned-handoff', 'policySHA256': '03'*32,
            'resultRecipient': owner, 'tasks': tasks, 'files': ['program.txt'], 'assembly': []}
    artifacts = root / 'artifacts'; artifacts.mkdir()
    (artifacts / 'program.txt').write_text('owned non-executable fixture')
    descriptor = pack_job(spec, artifacts, owner, root / 'job', age)
    (root / 'workload.json').write_text(json.dumps(spec))
    results = []
    for task, rank in [('first', 0), ('second', 0), ('second', 1)]:
        out = root / f'{task}-{rank}'; out.mkdir()
        (out / 'selected.txt').write_text(f'{task}:{rank}:authenticated')
        (out / 'unselected.txt').write_text('This output must never enter the dependency capsule.')
        file = root / f'{task}-{rank}.age'
        receipt = seal_result(spec, task, descriptor['ciphertextSHA256'], out, owner, file, rank=rank, age=age)
        results.append({'file': str(file), 'receipt': receipt})
    print(json.dumps({'spec': spec, 'descriptor': descriptor, 'results': results}))
elif r['action'] == 'open':
    spec = json.loads((root / 'workload.json').read_text())
    descriptor = json.loads((root / 'job/descriptor.json').read_text())
    key = recover_job_key(root / 'job/job-key.age', load_identity(root / 'owner.key'), descriptor,
                          expected_package_sha256=descriptor['ciphertextSHA256'], expected_policy_sha256=descriptor['policySHA256'], age=age)
    destination = root / r['destination']
    report = open_dependency_bundle(r.get('spec', spec), r['handoff'], root / r['ciphertext'], key.identity, destination, age=age)
    report['files'] = {p.relative_to(destination).as_posix(): p.read_text() for p in destination.rglob('*') if p.is_file()}
    print(json.dumps(report))
elif r['action'] == 'mapping-refusals':
    spec = json.loads((root / 'workload.json').read_text())
    changes = [lambda t: t['dependencyInputs'][0].update(destination='program.txt'),
               lambda t: t['dependencyInputs'][0].update(destination='PROGRAM.TXT/child'),
               lambda t: t['dependencyInputs'][0].update(destination='inputs'),
               lambda t: t['dependencyInputs'][0].update(destination='../outside'),
               lambda t: t['dependencyInputs'][0].update(output='undeclared.txt'),
               lambda t: t['dependencyInputs'][0].update(task='join'),
               lambda t: t['dependencyInputs'][0].update(rank=1),
               lambda t: t['dependencyInputs'].pop(0),
               lambda t: t.update(dependencyInputMaxBytes=-1)]
    for change in changes:
        changed = copy.deepcopy(spec); change(changed['tasks'][-1])
        try: validate_workload(changed)
        except ValueError: continue
        raise AssertionError('Unsafe dependency mapping accepted')
    print(json.dumps({'refusals': len(changes)}))
else:
    raise ValueError('Unknown fixture operation')
