"""Bounded allowlist copies between trusted graph stages INSIDE the guest."""
import os
from pathlib import Path
import shutil
import stat

from .client import MAX_BYTES, regular_source, safe_name
from .native_graph import _paths


def copy_artifacts(root, items, destination, max_bytes):
    """Called only by a guarded helper after the workload group is empty.

    Sources may be untrusted output, so reject links (including hard links),
    devices and FIFOs. No customer process remains to mutate these paths. Copy
    only declared files, never follow a tree recursively or preserve ownership.
    """
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_BYTES or not isinstance(items, list):
        raise ValueError('Require a bounded artifact copy')
    if any(not isinstance(i, dict) or set(i) != {'source', 'destination'} for i in items):
        raise ValueError('Require exact artifact mappings')
    _paths([i['destination'] for i in items])
    root, destination = Path(root), Path(destination)
    # Exclusive creation; cleanup never adopts an existing destination.
    destination.mkdir(mode=0o700)
    used = 0
    try:
        for item in items:
            source = regular_source(root, safe_name(item['source']))
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(descriptor, 'rb') as incoming:
                before = os.fstat(incoming.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > max_bytes - used:
                    raise ValueError('Unsafe or oversized graph artifact')
                target = destination / safe_name(item['destination'])
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                count = 0
                with target.open('xb') as outgoing:
                    os.chmod(target, 0o700 if before.st_mode & 0o111 else 0o600)
                    for chunk in iter(lambda: incoming.read(262144), b''):
                        count += len(chunk)
                        if count > before.st_size or used + count > max_bytes:
                            raise ValueError('Graph artifact changed or exceeds its bound')
                        outgoing.write(chunk)
                after = os.fstat(incoming.fileno())
                if (count != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
                        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)):
                    raise ValueError('Graph artifact changed while copying')
                used += count
        return {'files': len(items), 'bytes': used}
    except BaseException:
        shutil.rmtree(destination)
        raise
