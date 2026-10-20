"""Assemble the first native runtime exclusively from the pinned image tree.

This recipe selects installed public files; it never executes a package, resolves
a host dependency or accepts customer software. Other runtimes need their own
reviewed recipes and inventory digests. Ownership and protected-memory checks
remain mandatory in the guest, independently of this build-time inventory.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

MOUNTS = ('proc', 'dev', 'sys', 'run', 'tmp', 'work', 'input', 'output')
EXCLUDED = {'test', 'tests', 'site-packages', 'dist-packages', 'ensurepip', 'idlelib', 'turtledemo'}


def image_file(image, name):
    """Resolve image links against the image root, including absolute links."""
    pending, current, links = list(Path(name).parts), [], 0
    while pending:
        part = pending.pop(0)
        if part in ('/', '.', ''):
            continue
        if part == '..':
            if not current:
                raise ValueError('Runtime input escapes the image')
            current.pop()
            continue
        candidate = image.joinpath(*current, part)
        if candidate.is_symlink():
            links += 1
            if links > 40:
                raise ValueError('Runtime input link cycle')
            target = os.readlink(candidate)
            if target.startswith('/'):
                current = []
            pending = list(Path(target).parts) + pending
        else:
            current.append(part)
    result = image.joinpath(*current)
    if not result.is_file() or not stat.S_ISREG(result.stat().st_mode):
        raise ValueError('Runtime input is not an image regular file')
    return result


def inventory(root):
    """Same inventory format as tree_digest, without claiming guest admission."""
    rows, used = [['', 'directory', 0o755]], 0

    def walk(directory, prefix):
        nonlocal used
        for item in sorted(directory.iterdir()):
            name = prefix + item.name
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode):
                rows.append([name, 'symlink', os.readlink(item)])
            elif stat.S_ISDIR(info.st_mode):
                rows.append([name, 'directory', info.st_mode & 0o777])
                walk(item, name + '/')
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                used += info.st_size
                with item.open('rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                rows.append([name, 'file', info.st_size, info.st_mode & 0o777, digest])
            else:
                raise ValueError('Unexpected runtime entry')
            if len(rows) > 50000 or used > 1024**3:
                raise ValueError('Runtime exceeds the native inventory limits')
    walk(root, '')
    digest = hashlib.sha256(json.dumps(rows, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    return digest, used, len(rows)


def build_runtime(image, destination, *, wheel_lock=None, wheel_cache=None):
    image, destination = Path(image), Path(destination)
    destination.mkdir(mode=0o755)
    for name in [*MOUNTS, 'usr/bin', 'usr/lib/python3.12', 'usr/lib/x86_64-linux-gnu', 'usr/lib64']:
        (destination / name).mkdir(parents=True, exist_ok=True, mode=0o755)
    for name, target in {'bin': 'usr/bin', 'lib': 'usr/lib', 'lib64': 'usr/lib64'}.items():
        (destination / name).symlink_to(target)

    def copy(source, target):
        original = image_file(image, source)
        output = destination / target
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(original, output)
        output.chmod(0o755 if original.stat().st_mode & 0o111 else 0o644)

    copy('usr/bin/python3.12', 'usr/bin/python3')
    for item in sorted((image / 'usr/lib/python3.12').rglob('*')):
        relative = item.relative_to(image)
        if not EXCLUDED.intersection(relative.parts) and not item.is_dir():
            copy(relative, relative)
    # Include the image's pinned shared libraries, never the builder's loader or
    # ldd output. Dereference aliases within this image and copy distinct files.
    for item in sorted((image / 'usr/lib/x86_64-linux-gnu').glob('*.so*')):
        copy(item.relative_to(image), item.relative_to(image))
    copy('usr/lib64/ld-linux-x86-64.so.2', 'usr/lib64/ld-linux-x86-64.so.2')
    if wheel_lock is not None:
        import importlib.util
        spec = importlib.util.spec_from_file_location('guest_wheel_recipe', Path(__file__).with_name('build-guest-wheels.py'))
        recipe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recipe)
        recipe.add_wheels(destination, recipe.load_lock(wheel_lock), wheel_cache)
    # The caller may have umask 077; runtime traversal must still be canonical.
    for item in [destination, *destination.rglob('*')]:
        if item.is_dir() and not item.is_symlink():
            item.chmod(0o755)
    digest, size, count = inventory(destination)
    return {'schema': 'cannabis.guest-image-runtime.v1', 'path': '/opt/cannabis/runtime',
        'runtime': {'adapter': 'native-linux-x86_64-v1', 'architecture': 'x86_64',
                    'os': 'linux', 'digestSHA256': digest},
        'fileBytes': size, 'inventoryEntries': count}
