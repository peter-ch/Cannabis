"""Expand pinned runtime wheels without executing package or installer code.

This is an image recipe, not a runtime package manager. No dependency resolution,
entry-point generation, bytecode compilation or setup/lifecycle script runs.
The reviewed lock supplies the complete dependency closure for CPython 3.12.
"""
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
from zipfile import ZipFile

SITE = PurePosixPath('usr/lib/python3/dist-packages')
MAX_BYTES = 1024**3
MAX_ENTRIES = 50000


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_lock(path):
    value = json.loads(Path(path).read_text())
    if (value.get('schema') != 'cannabis.python-wheel-lock.v1'
            or value.get('profile') != 'pytorch-cpu' or value.get('python') != 'cp312'
            or value.get('platform') != 'linux-x86_64'
            or value.get('roots') != ['torch', 'numpy']
            or not isinstance(value.get('packages'), list) or not 2 <= len(value['packages']) <= 64):
        raise ValueError('Unsupported pinned wheel recipe')
    names = set()
    for item in value['packages']:
        if (not isinstance(item, dict) or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', item['name'])
                or item['name'] in names or not re.fullmatch('[0-9a-f]{64}', item['sha256'])
                or type(item['bytes']) is not int or not 1 <= item['bytes'] <= MAX_BYTES
                or type(item['unpackedBytes']) is not int or not 1 <= item['unpackedBytes'] <= MAX_BYTES
                or type(item['entries']) is not int or not 1 <= item['entries'] <= MAX_ENTRIES
                or not item['url'].startswith('https://')):
            raise ValueError('Invalid pinned wheel')
        names.add(item['name'])
    if not {'torch', 'numpy'} <= names:
        raise ValueError('Missing runtime root package')
    if (sum(item['unpackedBytes'] for item in value['packages']) > MAX_BYTES
            or sum(item['entries'] for item in value['packages']) > MAX_ENTRIES):
        raise ValueError('Wheel closure exceeds runtime inventory bounds')
    return value


def destination(name):
    parts = PurePosixPath(name).parts
    if (not parts or name.startswith('/') or '\\' in name or ':' in name or '\0' in name
            or any(p in ('', '.', '..') for p in name.rstrip('/').split('/'))):
        raise ValueError('Unsafe wheel member path')
    if parts[0].endswith('.data'):
        if len(parts) < 3:
            raise ValueError('Unsupported wheel data member')
        category, rest = parts[1], PurePosixPath(*parts[2:])
        if category in ('purelib', 'platlib'):
            return SITE / rest
        if category == 'data':
            return PurePosixPath('usr') / rest
        # No shell wrappers or host-interpreter scripts are generated or run.
        raise ValueError('Wheel requires an unsupported installation scheme')
    return SITE / PurePosixPath(*parts)


def add_wheels(runtime, lock, cache):
    runtime, cache = Path(runtime), Path(cache)
    if runtime.is_symlink() or not runtime.is_dir():
        raise ValueError('Require the newly assembled native runtime')
    plans, files, directories, actual_bytes = [], set(), set(), 0
    # Validate all archives, metadata and destinations before writing any file.
    for item in lock['packages']:
        wheel = cache / item['sha256']
        if wheel.stat().st_size != item['bytes'] or digest(wheel) != item['sha256']:
            raise ValueError('Wheel hash or size differs from the lock')
        with ZipFile(wheel) as archive:
            members = archive.infolist()
            names = archive.namelist()
            if len(names) != len(set(names)) or len(members) != item['entries']:
                raise ValueError('Ambiguous wheel inventory')
            if sum(member.file_size for member in members) != item['unpackedBytes']:
                raise ValueError('Wheel expanded size differs')
            metadata = [name for name in names if name.count('/') == 1 and name.endswith('.dist-info/METADATA')]
            if len(metadata) != 1:
                raise ValueError('Wheel package metadata is ambiguous')
            package = BytesParser().parsebytes(archive.read(metadata[0]))
            normalized = re.sub(r'[-_.]+', '-', package['Name']).lower()
            if normalized != item['name'] or package['Version'] != item['version']:
                raise ValueError('Wheel identity differs from the lock')
            plan = []
            for member in members:
                mode = member.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or member.flag_bits & 1:
                    raise ValueError('Special or encrypted wheel member refused')
                target = destination(member.filename)
                if member.is_dir():
                    if target in files:
                        raise ValueError('Wheel directory collides with a file')
                    directories.add(target)
                    continue
                if target in files or target in directories:
                    raise ValueError('Wheel file collides with another member')
                for parent in target.parents:
                    if parent in files:
                        raise ValueError('Wheel parent is a file')
                    directories.add(parent)
                files.add(target)
                actual_bytes += member.file_size
                if actual_bytes > MAX_BYTES:
                    raise ValueError('Wheel closure exceeds byte limit')
                output = runtime / target
                for parent in [output, *output.parents]:
                    if parent == runtime:
                        break
                    if parent.is_symlink():
                        raise ValueError('Wheel destination traverses a link')
                if output.exists():
                    raise ValueError('Wheel overwrites an image file')
                plan.append((member.filename, target, mode & 0o111))
            plans.append((wheel, plan))
    for wheel, plan in plans:
        with ZipFile(wheel) as archive:
            for name, relative, executable in plan:
                target = runtime / relative
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with archive.open(name) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                target.chmod(0o755 if executable else 0o644)
    for directory in directories:
        target = runtime / directory
        if target.is_dir():
            target.chmod(0o755)
    return {'packages': len(plans), 'files': len(files), 'fileBytes': actual_bytes,
            'packageCodeExecutedDuringAssembly': False}
