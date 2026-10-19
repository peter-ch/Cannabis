"""One immutable public launch package, shared before and after containment.

No authority or customer secret belongs in this descriptor. Sealing prevents
replacement between signature verification and allocation; it is not approval.
"""
import fcntl
import json
import os
from pathlib import Path
import stat

from .guest_sandbox import _directory

MAX_SNAPSHOT = 17 * 1024**2
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def validate_snapshot(fd):
    if type(fd) is not int or fd < 3:
        raise ValueError('Require an inherited immutable launch descriptor')
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_SNAPSHOT
            or os.readlink(f'/proc/self/fd/{fd}') != '/memfd:cannabis-public-launch (deleted)'
            or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & SEALS != SEALS):
        raise ValueError('Launch package is not sealed')
    return fd


def read_public_file(file, limit):
    """Read only a bounded, root-owned regular file under protected parents."""
    parent = _directory(Path(file).parent, memory=False)
    try:
        fd = os.open(Path(file).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not 0 < info.st_size <= limit:
            raise ValueError('Unsafe public launch file')
        raw = bytearray()
        while len(raw) <= info.st_size:
            chunk = os.read(fd, min(65536, info.st_size + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != info.st_size:
            raise ValueError('Public launch file changed during read')
        return bytes(raw)
    finally:
        os.close(fd)


class LaunchSnapshot:
    def __init__(self, configuration, initialization, request):
        # Preserve the ORIGINAL UTF-8 file bytes as strings. The established JS
        # canonical validators, not Python's JSON encoding, interpret each one.
        values = [configuration, initialization, request]
        for value, limit in zip(values, [256*1024, 65536, 16*1024**2]):
            if type(value) is not bytes or not 0 < len(value) <= limit:
                raise ValueError('Public launch input exceeds its bound')
        raw = json.dumps(dict(zip(['configuration', 'initialization', 'request'],
            [v.decode('utf-8', errors='strict') for v in values])), separators=(',', ':'), ensure_ascii=False).encode()
        if len(raw) > MAX_SNAPSHOT:
            raise ValueError('Launch snapshot exceeds its bound')
        self.fd = os.memfd_create('cannabis-public-launch', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            position = 0
            while position < len(raw):
                position += os.write(self.fd, raw[position:])
            os.lseek(self.fd, 0, os.SEEK_SET)
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, SEALS)
            validate_snapshot(self.fd)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
