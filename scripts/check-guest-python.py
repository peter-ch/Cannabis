"""Check the actual guest's source-validated caches without reading customer data."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import sys
import tempfile


def main():
    root = Path('/opt/cannabis')
    expected = json.loads((root / 'python-bytecode.json').read_text())
    with Path(sys.executable).open('rb') as stream:
        compiler = hashlib.file_digest(stream, 'sha256').hexdigest()
    assert expected['schema'] == 'cannabis.guest-python-bytecode.v1'
    assert expected['pythonSHA256'] == compiler
    assert expected['cacheTag'] == sys.implementation.cache_tag
    assert expected['magicHex'] == importlib.util.MAGIC_NUMBER.hex()
    assert expected['invalidation'] == 'checked-hash' and expected['compiledFiles'] > 0
    assert expected['optimization'] == sys.flags.optimize == 0 and sys.dont_write_bytecode
    sys.path.insert(0, str(root))
    loader = importlib.machinery.SourceFileLoader
    original = loader.source_to_code
    def no_compilation(*args, **kwargs):
        raise AssertionError('Guest control import unexpectedly compiled source')
    loader.source_to_code = no_compilation
    try:
        # Successful imports must consume the generated caches, rather than
        # silently compiling source again during the guardian's startup window.
        import compute.guest_guardian, compute.guest_native  # noqa: F401
        import compute.guest_job, compute.guest_execution  # noqa: F401
    finally:
        loader.source_to_code = original
    with tempfile.TemporaryDirectory(prefix='cannabis-cache-check-', dir='/run') as directory:
        source = Path(directory) / 'owned.py'
        source.write_text('VALUE = 1\n')
        cached = Path(py_compile.compile(str(source), doraise=True, optimize=0,
            invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH))
        before = cached.read_bytes()
        stamp = source.stat()
        source.write_text('VALUE = 2\n')  # Same size and timestamps; only its content changes.
        os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        namespace = {}
        exec(loader('owned_cache_check', str(source)).get_code('owned_cache_check'), namespace)
        assert namespace['VALUE'] == 2 and cached.read_bytes() == before
    print(json.dumps({'schema': 'cannabis.guest-python-check.v1',
        'cachedControlImports': True, 'changedSourceInvalidatesCache': True,
        'assertionsPreserved': True, 'customerKeysUsed': False, 'hardwareValidated': False}))


if __name__ == '__main__':
    main()
