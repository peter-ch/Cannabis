"""Private trusted helper trampoline. Never accepts a customer command."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_resources import ResourceLimits
from compute.guest_helpers import helper_main

if __name__ == '__main__':
    try:
        if len(sys.argv) != 6 or sys.stdin.isatty() or sys.stdout.isatty():
            raise ValueError('Require the private helper protocol')
        helper_main(sys.argv[1], ResourceLimits(*map(int, sys.argv[2:])))
    except Exception:
        # The owner observes only failure; never emit customer parser details.
        raise SystemExit(1)
