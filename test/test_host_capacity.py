"""Ensure host preparation cannot undersize a larger measured guest image."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_host_vm', ROOT / 'scripts/prepare-host-vm.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


def fixture(profile):
    value = json.loads((ROOT / 'compute/guest-image' / profile).read_text())
    budget = prepare.VmBudget(value)
    outputs = {name: {'bytes': n, 'sha256': str(n) * 64}
               for n, name in enumerate(['vmlinuz', 'initramfs.cpio.gz', 'cmdline'], 1)}
    build = {'schema': 'cannabis.guest-image-build.v1', 'operatingEntryConfigured': True,
             'executionAuthorized': False, 'outputs': outputs,
             'vmBudget': {'profile': value, 'minimumMemoryBytes': budget.minimum_memory,
                          'minimumCPUs': budget.minimum_cpus}}
    boot = {name: {'path': '/owned/' + key, **outputs[key]} for name, key in
            [('kernel', 'vmlinuz'), ('initramfs', 'initramfs.cpio.gz'), ('cmdline', 'cmdline')]}
    return build, boot


class HostCapacityTests(unittest.TestCase):
    def test_selected_runtime_changes_guest_capacity(self):
        for profile, expected in [('vm-profile.json', 4096), ('vm-profile-pytorch-cpu.json', 8192)]:
            build, boot = fixture(profile)
            self.assertEqual(prepare.image_memory(build, boot, 4), expected)

    def test_other_image_cannot_supply_capacity(self):
        build, boot = fixture('vm-profile-pytorch-cpu.json')
        boot['initramfs']['sha256'] = '00' * 32
        with self.assertRaises(ValueError):
            prepare.image_memory(build, boot, 4)

    def test_changed_minimum_and_undersized_reference_refused(self):
        build, boot = fixture('vm-profile-pytorch-cpu.json')
        for change in [lambda b: b['vmBudget'].update(minimumMemoryBytes=1),
                       lambda b: b['vmBudget'].update(minimumCPUs=1),
                       lambda b: b['vmBudget']['profile']['referenceVM'].update(memoryMiB=4096)]:
            changed = copy.deepcopy(build)
            change(changed)
            with self.assertRaises(ValueError):
                prepare.image_memory(changed, boot, 4)

    def test_insufficient_cpu_or_component_image_refused(self):
        build, boot = fixture('vm-profile-pytorch-cpu.json')
        for cpus in [3, True]:
            with self.assertRaises(ValueError):
                prepare.image_memory(build, boot, cpus)
        build['operatingEntryConfigured'] = False
        with self.assertRaises(ValueError):
            prepare.image_memory(build, boot, 4)


if __name__ == '__main__':
    unittest.main()
