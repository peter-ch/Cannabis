"""Verify and freeze an embedded runtime before the job controller exists.

No download, extraction or executable inspection happens here. Only the measured
image supplies runtime files; the independently authorized service selects their
inventory. Runtime pages still need a whole-VM reservation outside the job tree.
"""
import json
import os
from pathlib import Path

from .guest_execution import exact, _unique
from .guest_launch_snapshot import read_public_file
from .guest_resources import ResourceCleanupError
from .guest_sandbox import _call, _directory, _libc, MOUNTS, tree_digest, enter_private_mount_namespace


def image_runtime(file):
    value = json.loads(read_public_file(file, 65536), object_pairs_hook=_unique)
    exact(value, ['schema', 'path', 'runtime', 'fileBytes', 'inventoryEntries'])
    exact(value['runtime'], ['adapter', 'architecture', 'os', 'digestSHA256'])
    if (value['schema'] != 'cannabis.guest-image-runtime.v1' or value['path'] != '/opt/cannabis/runtime'
            or value['runtime']['adapter'] != 'native-linux-x86_64-v1'
            or value['runtime']['architecture'] != 'x86_64' or value['runtime']['os'] != 'linux'
            or type(value['fileBytes']) is not int or not 1 <= value['fileBytes'] <= 512 * 1024**2
            or type(value['inventoryEntries']) is not int or not 1 <= value['inventoryEntries'] <= 50000):
        raise ValueError('Unsupported embedded runtime recipe')
    return value


def _mount(fd):
    fields = dict(line.split(':', 1) for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines() if ':' in line)
    rows = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
            if line.split()[0] == fields.get('mnt_id', '').strip()]
    if len(rows) != 1:
        raise ValueError('Runtime mount is ambiguous')
    return rows[0]


class FrozenRuntime:
    """A checked read-only bind in the launcher's private mount namespace."""
    def __init__(self, path, expected, *, max_bytes=512 * 1024**2, max_entries=50000):
        self.path, self._mounted, self._fd = Path(path), False, None
        self._expected, self._max_bytes, self._max_entries = expected, max_bytes, max_entries
        # Never let an operator-supplied path or inventory replace the signed
        # service's digest. tree_digest also checks ownership, noswap and links.
        if tree_digest(path, max_bytes=max_bytes, max_entries=max_entries) != expected:
            raise ValueError('Embedded runtime differs from the authorized service')
        for name in MOUNTS:
            entry = self.path / name
            if entry.is_symlink() or not entry.is_dir() or any(entry.iterdir()):
                raise ValueError('Runtime destinations must be empty real directories')
        enter_private_mount_namespace()
        source = _directory(self.path)
        try:
            _call(_libc().mount(f'/proc/self/fd/{source}'.encode(), os.fsencode(self.path), None, 4096, None))
            self._mounted = True
            _call(_libc().mount(None, os.fsencode(self.path), None, 4096 | 32 | 1 | 2 | 4, None))
            self._fd = _directory(self.path)
            self.verify()
        except BaseException:
            self.close()
            raise
        finally:
            os.close(source)

    def verify(self):
        current = _directory(self.path)
        try:
            original, now = os.fstat(self._fd), os.fstat(current)
            if ((original.st_dev, original.st_ino) != (now.st_dev, now.st_ino)
                    or _mount(current)[0] != _mount(self._fd)[0]
                    or not {'ro', 'nosuid', 'nodev'} <= set(_mount(current)[5].split(','))
                    or tree_digest(self.path, max_bytes=self._max_bytes, max_entries=self._max_entries) != self._expected):
                raise ValueError('Protected runtime changed after preparation')
        finally:
            os.close(current)

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        if self._mounted:
            try:
                _call(_libc().umount2(os.fsencode(self.path), 0))
            except OSError as error:
                raise ResourceCleanupError('Runtime mount did not retire; dispose of the VM') from error
            self._mounted = False

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
