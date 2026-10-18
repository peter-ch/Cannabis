import dataclasses
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_resources import JobResourceGroup, ResourceLimits, join_current_process


class ResourceBoundaryTests(unittest.TestCase):
    def test_rejects_ambiguous_and_unbounded_limits(self):
        valid = dict(cpu_millis=1000, memory_bytes=64 * 1024**2, processes=128, wall_seconds=30)
        for name in valid:
            for value in [True, None, '1', 0, -1, 2**64]:
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    ResourceLimits(**{**valid, name: value})
        with self.assertRaises(ValueError):
            ResourceLimits(**{**valid, 'memory_bytes': 64 * 1024**2 + 1})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ResourceLimits(**valid).processes = 999

    def test_task_limits_are_not_silently_reduced(self):
        task = {'cpus': 4, 'memoryMiB': 512, 'wallSeconds': 60, 'scratchMiB': 128, 'nodes': 1}
        limits = ResourceLimits.from_task(task, process_limit=64)
        self.assertEqual(limits.cpu_millis, 4000)
        self.assertEqual(limits.memory_bytes, 512 * 1024**2)
        for key in ['cpus', 'memoryMiB', 'wallSeconds']:
            with self.assertRaises(ValueError):
                ResourceLimits.from_task({**task, key: True}, process_limit=64)
        with self.assertRaises(ValueError):
            ResourceLimits.from_task({**task, 'cpus': 8192}, process_limit=64)

    def test_plain_files_never_emulate_enforcement(self):
        limits = ResourceLimits(1000, 64 * 1024**2, 64, 30)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ['cgroup.controllers', 'cgroup.subtree_control']:
                (root / name).write_text('cpu memory pids')
            (root / 'cgroup.type').write_text('domain')
            (root / 'cgroup.procs').write_text('')
            before = sorted(root.iterdir())
            for operation in [lambda: JobResourceGroup(root, limits), lambda: join_current_process(root, limits)]:
                with self.assertRaises((ValueError, RuntimeError)):
                    operation()
            self.assertEqual(sorted(root.iterdir()), before)
            self.assertEqual((root / 'cgroup.procs').read_text(), '')

    def test_requires_validated_limits_before_paths(self):
        for invalid in [None, {}, {'memory_bytes': 1}]:
            with self.assertRaises(ValueError):
                JobResourceGroup('/never-created', invalid)
            with self.assertRaises(ValueError):
                join_current_process('/never-created', invalid)


if __name__ == '__main__':
    unittest.main()
