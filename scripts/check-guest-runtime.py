#!/usr/bin/env python3
"""Owned kernel checks for image runtime preparation; no customer keys."""
import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from compute.guest_runtime import FrozenRuntime, image_runtime
from compute.guest_sandbox import MOUNTS, NativeSandbox, ScratchLimits, tree_digest, _call, _libc, enter_private_mount_namespace
from compute.guest_resources import ResourceLimits


def refused(call):
    try:
        call()
    except (ValueError, OSError):
        return
    raise AssertionError('Invalid runtime was accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, help='Build from these public image inputs for a local check')
    args = parser.parse_args()
    enter_private_mount_namespace()
    base = Path('/run') / ('cannabis-runtime-' + uuid.uuid4().hex)
    base.mkdir(mode=0o755)
    _call(_libc().mount(b'tmpfs', os.fsencode(base), b'tmpfs', 2 | 4,
                       b'size=256m,nr_inodes=30000,mode=0755,noswap'))
    checks = {}
    parent = Path('/sys/fs/cgroup') / base.name
    parent.mkdir(mode=0o700)
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        if args.image_root:
            spec = importlib.util.spec_from_file_location('runtime_recipe', ROOT/'scripts/build-guest-runtime.py')
            recipe = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(recipe)
            manifest = recipe.build_runtime(args.image_root, base/'runtime')
            repeat = recipe.build_runtime(args.image_root, base/'repeat')
            assert manifest == repeat
            runtime = base/'runtime'
        else:
            manifest = image_runtime(ROOT/'runtime.json')
            runtime = Path(manifest['path'])
        digest = manifest['runtime']['digestSHA256']
        assert tree_digest(runtime, max_bytes=manifest['fileBytes'], max_entries=manifest['inventoryEntries']) == digest
        checks['embeddedInventoryMatches'] = True

        small = base/'small'
        small.mkdir(mode=0o755)
        for name in MOUNTS:
            (small/name).mkdir(mode=0o755)
        content = small/'owned.txt'
        content.write_text('original')
        content.chmod(0o644)
        original = tree_digest(small)
        content.write_text('changed')
        refused(lambda: FrozenRuntime(small, original))
        content.write_text('original')
        checks['changedContentsRefused'] = True
        content.chmod(0o666)
        refused(lambda: FrozenRuntime(small, original))
        content.chmod(0o644)
        checks['unsafePermissionsRefused'] = True
        os.link(content, small/'hardlink')
        refused(lambda: FrozenRuntime(small, original))
        (small/'hardlink').unlink()
        checks['hardlinksRefused'] = True
        (small/'input').rmdir()
        (small/'input').symlink_to('output')
        # Even an approved digest cannot turn a symlink into a mount destination.
        refused(lambda: FrozenRuntime(small, tree_digest(small)))
        (small/'input').unlink()
        (small/'input').mkdir(mode=0o755)
        checks['symlinkDestinationRefused'] = True
        (small/'input/occupied').write_text('owned')
        refused(lambda: FrozenRuntime(small, tree_digest(small)))
        (small/'input/occupied').unlink()
        checks['occupiedDestinationRefused'] = True
        refused(lambda: FrozenRuntime('/proc', original))
        checks['ordinaryStorageRefused'] = True

        inputs = base/'inputs'
        inputs.mkdir(mode=0o755)
        with FrozenRuntime(runtime, digest, max_bytes=manifest['fileBytes'],
                           max_entries=manifest['inventoryEntries']) as prepared:
            try:
                (runtime/'unexpected').write_text('must fail')
            except OSError as error:
                assert error.errno == errno.EROFS
            else:
                raise AssertionError('Runtime mount remained writable')
            checks['rootWriteRefused'] = True
            _call(_libc().mount(None, os.fsencode(runtime), None, 4096 | 32 | 2 | 4, None))
            refused(prepared.verify)
            _call(_libc().mount(None, os.fsencode(runtime), None, 4096 | 32 | 1 | 2 | 4, None))
            prepared.verify()
            checks['mountDowngradeRefused'] = True
            with NativeSandbox(parent, runtime, inputs, digest,
                    ResourceLimits(1000, 128*1024**2, 32, 45), ScratchLimits(4*1024**2, 512)) as sandbox:
                result = sandbox.run(['/usr/bin/python3', '-I', '-B', '-c',
                    "import ctypes,ssl,sqlite3,lzma,bz2,hashlib,os; "
                    "assert os.getuid()==65534 and not os.path.exists('/opt/cannabis'); "
                    "open('/output/result','w').write(hashlib.sha256(b'owned image runtime').hexdigest())"])
                assert result['success']
                assert (sandbox.output_directory/'result').read_text() == '2c63f30c979a5d57a6be211f1f9652cf4cef3c2d2b373129c9639459061cc017'
            checks['nativeProgramExecuted'] = True
        assert not prepared._mounted and prepared._fd is None
        checks['checkedMountRetirement'] = True
        print(json.dumps({'schema':'cannabis.guest-runtime-check.v1', 'kernel':os.uname().release,
            'runtime':manifest, 'checks':checks, 'customerCodeExecuted':False,
            'hardwareValidated':False, 'realPaidJob':False}))
    finally:
        assert not any(p.is_dir() for p in parent.iterdir())
        parent.rmdir()
        _call(_libc().umount2(os.fsencode(base), 0))
        base.rmdir()


if __name__ == '__main__':
    main()
