#!/usr/bin/env python3
"""Fixed operating PID-1 entry. No command, path, authority or hardware override."""
import os
from pathlib import Path
import sys

if sys.platform!='linux' or os.geteuid()!=0 or os.getpid()!=1 or len(sys.argv)!=1:
    raise SystemExit('Require the fixed measured operating PID-1 entry')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.guest_boot import run_pid1
run_pid1()
