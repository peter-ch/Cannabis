#!/usr/bin/env python3
"""Explicit local operator metadata volume setup; never starts a paid worker."""
from pathlib import Path
import sys
import types
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
module=types.ModuleType('cannabis_host');module.__path__=[str(ROOT/'operator')];sys.modules['cannabis_host']=module
from cannabis_host.state_volume import main
if __name__=='__main__':
    try:main()
    except Exception:
        print('Operator metadata volume unavailable; preserve backing and recovery state',file=sys.stderr);sys.exit(1)
