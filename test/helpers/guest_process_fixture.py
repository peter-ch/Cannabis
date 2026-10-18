"""Disposable process-tree faults; no workload, custody, or network access."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from compute.guest_process import contain_guest_helper


def record(root, name):
    temporary = root / (name + '.tmp')
    temporary.write_text(str(os.getpid()))
    temporary.replace(root / name)


def descendant(root, name):
    if os.name == 'posix':
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if name == 'child':
        subprocess.Popen([sys.executable, '-I', __file__, str(root), 'grandchild'])
    record(root, name)
    while True:
        time.sleep(0.1)


if len(sys.argv) > 1:
    descendant(Path(sys.argv[1]), sys.argv[2])
else:
    contain_guest_helper()
    request = json.load(sys.stdin)
    root = Path(request['directory'])
    mode = request['mode']
    record(root, 'helper')
    if mode != 'ok':
        subprocess.Popen([sys.executable, '-I', __file__, str(root), 'child'])
        until = time.monotonic() + 10
        while not (root / 'grandchild').exists():
            if time.monotonic() > until:
                raise RuntimeError('Fixture descendant did not start')
            time.sleep(0.01)
    if mode == 'error':
        sys.stderr.write('private fixture diagnostic must not reach parent errors\n')
        sys.exit(7)
    if mode == 'oversized':
        sys.stdout.write('x' * 65536)
        sys.stdout.flush()
    if mode in ('ok', 'ok-orphan'):
        print(json.dumps({'complete': True}))
    else:
        while True:
            time.sleep(0.1)
