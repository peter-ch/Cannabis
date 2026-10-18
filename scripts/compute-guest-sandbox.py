"""Private trusted trampoline; not a customer or host-facing execution API."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_sandbox import launch_from_fd

if len(sys.argv) != 2:
    raise SystemExit(2)
try:
    launch_from_fd(int(sys.argv[1]))
except BaseException:
    # Arguments, executable names and diagnostics can contain customer content.
    raise SystemExit(1) from None
