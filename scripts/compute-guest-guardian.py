#!/usr/bin/env python3
"""Private descriptor-only entry point for the measured guest guardian."""
from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_guardian import guardian_main

if __name__ == '__main__':
    if len(sys.argv) != 5 or sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit(2)
    guardian_main(*[int(value) for value in sys.argv[1:]])
