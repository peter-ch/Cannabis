"""Fixed native execution entry point; only anonymous protected frames."""
from pathlib import Path
import resource
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_execution import execution_main

if __name__ == '__main__':
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        execution_main()
    except Exception:
        sys.stderr.write('Protected native execution failed; retire the job\n')
        sys.exit(1)
