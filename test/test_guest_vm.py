from dataclasses import asdict
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
if sys.platform!='linux':raise unittest.SkipTest('Measured guest capacity requires Linux')
from compute.guest_vm import VmBudget, unique
from compute.guest_resources import ResourceTreeLimits


class VmBudgetTests(unittest.TestCase):
    def profile(self):return json.loads((ROOT/'compute/guest-image/vm-profile.json').read_text())

    def test_boot_copy_and_archive_peak_are_reserved_separately_from_job(self):
        value=self.profile();budget=VmBudget(value)
        self.assertEqual(budget.minimum_memory,3280*1024**2)
        self.assertGreater(budget.boot_memory,budget.steady_memory)
        self.assertEqual(budget.minimum_cpus,4)
        value['root']['bytes']=4096
        self.assertEqual(budget.root.bytes,1024**3)
        self.assertIn('nr_inodes=',budget.mount_options('root'))
        for name in ['run','tmp','shm']:self.assertIn('noswap',budget.mount_options(name))

    def test_signed_jobs_cannot_borrow_from_boot_or_outer_capacity(self):
        budget=VmBudget(self.profile());budget.admit_service(budget.job)
        for key,increment in [('cpu_millis',1),('memory_bytes',4096),('processes',1),('wall_seconds',1),('children',1)]:
            with self.assertRaises(ValueError):
                budget.admit_service(ResourceTreeLimits(**{**asdict(budget.job),key:getattr(budget.job,key)+increment}))

    def test_underprovisioned_or_ambiguous_boot_profiles_are_refused(self):
        for change in [lambda p:p['referenceVM'].update(cpus=3),lambda p:p['referenceVM'].update(memoryMiB=2048),
                lambda p:p.update(kernelReserveBytes=0),lambda p:p.update(kernelReserveCPUMillis=True),
                lambda p:p['root'].update(inodes=0),lambda p:p['outer'].update(wall_seconds=30),
                lambda p:p.update(unknown=1)]:
            value=self.profile();change(value)
            with self.assertRaises(ValueError):VmBudget(value)
        with self.assertRaises(ValueError):json.loads('{"x":1,"x":2}',object_pairs_hook=unique)


if __name__=='__main__':unittest.main()
