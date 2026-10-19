"""Trusted admission trampoline; no customer key is read before joining."""
import json
import os
from pathlib import Path
import resource
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_resources import ResourceLimits, join_current_process


def main():
    if len(sys.argv) != 5 or sys.stdin.isatty() or sys.stdout.isatty():
        raise ValueError('Require private control-plane launch descriptors')
    group, limits, executable, script = sys.argv[1:]
    join_current_process(group, ResourceLimits(**json.loads(limits)))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    # Prevent OOM-exempt control processes from escaping whole-job OOM handling.
    Path('/proc/self/oom_score_adj').write_text('0')
    executable, script = int(executable), int(script)
    for fd in [executable, script]:
        os.fstat(fd); os.set_inheritable(fd, True)
    os.execve(executable, [f'/proc/self/fd/{executable}', f'/proc/self/fd/{script}'], dict(os.environ))


if __name__ == '__main__':
    try: main()
    except Exception:
        sys.stderr.write('Protected job control startup failed\n')
        sys.exit(1)
