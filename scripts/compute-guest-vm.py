#!/usr/bin/env python3
"""Fixed public budget query for the measured early/root boot scripts."""
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.guest_vm import image_vm_budget

try:
    if os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in ['root','run','tmp','shm']:
        raise ValueError('Require a fixed guest mount query')
    budget=image_vm_budget()
    budget.capacity()
    print(budget.mount_options(sys.argv[1]))
except BaseException:
    sys.stderr.write('Measured VM capacity refused\n');sys.exit(1)
