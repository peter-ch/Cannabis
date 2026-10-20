#!/usr/bin/env python3
"""Owned encrypted CPU training on the actual kernel; no hardware or payment."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'test/helpers'))
from compute.client import pack_workload, task_binding_sha256, assemble_results
from compute.guest_deadline import ExecutionDeadline
from compute.guest_native import NativeTaskPlan, NATIVE_ADAPTER
from compute.guest_resources import ResourceLimits
from compute.guest_sandbox import ScratchLimits, tree_digest, _call, _libc, enter_private_mount_namespace
from compute.job_keys import RecoveredJobKey, _new_identity
import pytorch_fixture

MIB = 1024**2


def run(parent, base, runtime_source, age):
    shutil.copytree(runtime_source, base / 'runtime', symlinks=True)
    runtime = {'adapter': NATIVE_ADAPTER, 'architecture': 'x86_64', 'os': 'linux',
               'digestSHA256': tree_digest(base / 'runtime')}
    source = base / 'input'
    source.mkdir()
    pytorch_fixture.prepare(source)
    owner_secret, owner_public = _new_identity(age)
    job_secret, job_public = _new_identity(age)
    resources = {'cpus': 1, 'memoryMiB': 512, 'scratchMiB': 32, 'wallSeconds': 120, 'nodes': 1}
    spec = {'schema': 'cannabis.workload.v1', 'id': 'owned-pytorch-training',
        'policySHA256': '12' * 32, 'resultRecipient': owner_public, 'files': ['program.py', 'training.json'],
        'tasks': [{'id': 'training', 'runtime': runtime, 'resources': resources,
            'launch': {'argv': ['/usr/bin/python3', '-I', '-B', '/input/program.py'],
                      'environment': pytorch_fixture.ENVIRONMENT, 'stdout': 'stdout.txt', 'stderr': 'stderr.txt'},
            'outputs': pytorch_fixture.OUTPUTS, 'outputMaxBytes': 65536}],
        'assembly': [{'task': 'training', 'output': name, 'destination': name} for name in pytorch_fixture.OUTPUTS]}
    package = pack_workload(spec, source, job_public, base / 'input.age', age=age)
    binding = {'packageSHA256': package['ciphertextSHA256'], 'policySHA256': spec['policySHA256'],
        'runtimeSHA256': runtime['digestSHA256'], 'taskSHA256': task_binding_sha256(package['ciphertextSHA256'], 0),
        'attempt': 1, 'worldSize': 1, 'rank': 0, 'acceleratorClass': 'cpu'}
    key = RecoveredJobKey(job_secret, spec['id'], binding['packageSHA256'], spec['policySHA256'], job_public, owner_public)
    deadline = ExecutionDeadline.from_service_interval(int(time.time()) - 1, int(time.time()) + 180)
    plan = NativeTaskPlan(base / 'runtime', runtime, resources, process_limit=64, scratch_inodes=2048, deadline=deadline)
    result = plan.run(parent, base / 'input.age', key, binding, base / 'result.age', age=age,
        helper_limits=ResourceLimits(1000, 256 * MIB, 64, 60), staging_limits=ScratchLimits(16 * MIB, 1024),
        max_input_bytes=MIB, max_output_ciphertext_bytes=4 * MIB)
    assert not result.report['paymentAccepted'] and not result.report['hardwareAdmissionEstablished']
    assembled = assemble_results(spec, binding['packageSHA256'],
        [{'receipt': result.receipt, 'file': result.ciphertext}], owner_secret, base / 'assembled', age=age)
    assert assembled['integrityVerified'] and not assembled['paymentAuthorized']
    pytorch_fixture.verify(base / 'assembled', 0, 1)
    assert not list(parent.glob('job-*'))
    return {'singleProcessTraining': True, 'encryptedInputAndResult': True,
            'numericCheckpointReconstruction': True, 'wholeTreeCleanup': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--age', required=True)
    args = parser.parse_args()
    enter_private_mount_namespace()
    base = Path('/run') / ('cannabis-pytorch-check-' + uuid.uuid4().hex)
    parent = Path('/sys/fs/cgroup') / base.name
    base.mkdir(mode=0o700)
    parent.mkdir(mode=0o700)
    _call(_libc().mount(b'tmpfs', os.fsencode(base), b'tmpfs', 2 | 4,
                       b'size=2048m,nr_inodes=50000,mode=0700,noswap'))
    try:
        (parent / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        checks = run(parent, base, args.runtime, args.age)
        print(json.dumps({'schema': 'cannabis.guest-pytorch-check.v1', 'checks': checks,
                          'hardwareValidated': False, 'realPaidJob': False}))
    finally:
        if any(p.is_dir() for p in parent.iterdir()):
            (parent / 'cgroup.kill').write_text('1')
            expiry = time.monotonic() + 10
            while 'populated 1' in (parent / 'cgroup.events').read_text():
                assert time.monotonic() < expiry
                time.sleep(0.05)
            for path in sorted(parent.rglob('*'), key=lambda p: len(p.parts), reverse=True):
                if path.is_dir():
                    path.rmdir()
        parent.rmdir()
        _call(_libc().umount2(os.fsencode(base), 0))
        base.rmdir()


if __name__ == '__main__':
    main()
