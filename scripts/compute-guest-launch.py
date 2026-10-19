"""Fixed outer process entry; enclosing measured boot must retire its VM.

No command-line override, alternate authorities, customer-key input or sample
agent. This is not installed as the component image's PID 1 / boot entry.
"""
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.guest_job import GuestJobScope
from compute.guest_launcher import authorize_launch, relay_guest
from compute.guest_launch_snapshot import LaunchSnapshot, read_public_file
from compute.guest_execution import _unique

ROOT = Path('/opt/cannabis')
NODE = '/usr/local/bin/node'
VERIFIER = str(ROOT/'scripts/compute-guest-authorize.mjs')
ENTRY = str(ROOT/'scripts/compute-guest-session.mjs')


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or len(sys.argv) != 1 or sys.stdin.isatty() or sys.stdout.isatty():
        raise ValueError('Require the fixed protected guest launcher')
    # This manifest is covered by the reviewed image measurement; it is not a
    # host-selectable manifest or a substitute for checking that measurement.
    manifest = json.loads(read_public_file(ROOT/'image-files.json', 4*1024**2), object_pairs_hook=_unique)
    if not isinstance(manifest, list) or not 1 <= len(manifest) <= 50000:
        raise ValueError('Invalid measured file inventory')
    pins = {}
    for item in manifest:
        if (not isinstance(item, dict) or set(item) != {'path','sha256'} or not isinstance(item['path'],str)
                or item['path'] in pins or not isinstance(item['sha256'],str) or not re.fullmatch('[0-9a-f]{64}', item['sha256'])):
            raise ValueError('Ambiguous measured file inventory')
        pins[item['path']] = item['sha256']
    inputs = Path('/run/cannabis-launch')
    with LaunchSnapshot(read_public_file(inputs/'configuration.json',256*1024),
            read_public_file(inputs/'initialization.json',65536),read_public_file(inputs/'request.json',16*1024**2)) as snapshot:
        profile, deadline, transport = authorize_launch(NODE,pins[NODE],VERIFIER,pins[VERIFIER],snapshot.fd)
        with GuestJobScope('/sys/fs/cgroup',profile.total,profile.control,deadline=deadline) as scope:
            proc = scope.start(NODE,pins[NODE],ENTRY,pins[ENTRY],launch_fd=snapshot.fd)
            relay_guest(scope,proc,sys.stdin.fileno(),sys.stdout.fileno(),max_ciphertext_bytes=transport['maxCiphertextBytes'])


if __name__ == '__main__':
    try: main()
    except BaseException:
        sys.stderr.write('Guest launch failed; enclosing boot must retire the VM\n')
        sys.exit(1)
