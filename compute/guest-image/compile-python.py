"""Compile only the staged guest's pinned Python sources with its interpreter."""
import compileall
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import py_compile
import sys
import types


def main():
    if len(sys.argv) != 2 or sys.version_info[:2] != (3, 12) or sys.flags.optimize != 0:
        raise ValueError('Require the pinned unoptimized guest Python compiler')
    tree = Path(sys.argv[1]).resolve()
    if Path(sys.prefix).resolve() != tree / 'usr':
        raise ValueError('Compiler is using libraries outside the staged guest')
    roots = [tree / 'usr/lib/python3.12', tree / 'usr/lib/python3',
             tree / 'opt/cannabis/compute', tree / 'opt/cannabis/scripts']
    for root in roots:
        if not root.is_dir() or not root.resolve().is_relative_to(tree):
            raise ValueError('Missing contained Python source tree')
        if not compileall.compile_dir(root, force=True, quiet=1, optimize=0,
                invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
                stripdir=str(tree), prependdir='/', limit_sl_dest=str(tree)):
            raise ValueError('Guest source compilation failed')
    compiled = [p for root in roots for p in root.rglob('*.pyc')]
    if not compiled:
        raise ValueError('Guest bytecode caches are missing')
    for cached in compiled:
        source = Path(importlib.util.source_from_cache(str(cached)))
        if not source.is_file() or not source.resolve().is_relative_to(tree):
            raise ValueError('Bytecode source is outside the guest')
        data = cached.read_bytes()
        if (data[:4] != importlib.util.MAGIC_NUMBER or data[4:8] != b'\x03\0\0\0'
                or data[8:16] != importlib.util.source_hash(source.read_bytes())):
            raise ValueError('Bytecode is not validated against the pinned source')
        codes = [marshal.loads(data[16:])]
        filename = '/' + source.relative_to(tree).as_posix()
        while codes:
            code = codes.pop()
            if not isinstance(code, types.CodeType) or code.co_filename != filename:
                raise ValueError('Bytecode contains a build-machine source path')
            codes.extend(v for v in code.co_consts if isinstance(v, types.CodeType))
        cached.chmod(0o644)
    with Path(sys.executable).open('rb') as stream:
        compiler = hashlib.file_digest(stream, 'sha256').hexdigest()
    print(json.dumps({'schema': 'cannabis.guest-python-bytecode.v1',
        'pythonSHA256': compiler, 'pythonVersion': list(sys.version_info[:3]),
        'cacheTag': sys.implementation.cache_tag, 'magicHex': importlib.util.MAGIC_NUMBER.hex(),
        'invalidation': 'checked-hash', 'optimization': 0, 'compiledFiles': len(compiled)}))


if __name__ == '__main__':
    main()
