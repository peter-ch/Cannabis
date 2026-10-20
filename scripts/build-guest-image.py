#!/usr/bin/env python3
"""Assemble pinned guest boot components; never provision or authorize a worker."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / 'compute/guest-image'
sys.path.insert(0,str(ROOT))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def download(entry, cache):
    target = cache / entry['sha256']
    if not target.exists():
        if not entry['url'].startswith('https://'):
            raise ValueError('HTTPS source required')
        partial = cache / (entry['sha256'] + '.partial')
        with urlopen(entry['url'], timeout=60) as response, partial.open('xb') as out:
            if not response.url.startswith('https://'):
                raise ValueError('Unencrypted download redirect')
            shutil.copyfileobj(response, out)
        if digest(partial) != entry['sha256']:
            raise ValueError('Downloaded input hash differs')
        partial.rename(target)
    if digest(target) != entry['sha256'] or ('bytes' in entry and target.stat().st_size != entry['bytes']):
        raise ValueError('Cached input hash or size differs')
    return target


def copy_text(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(source.read_text(encoding='utf-8-sig'), encoding='utf-8', newline='\n')
    destination.chmod(0o644)


def write_initramfs(tree, output, epoch):
    """Deterministic Linux newc archive: fixed ownership, time and inode order."""
    with output.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=9) as archive:
        def entry(name, inode, mode, data=b'', links=1):
            encoded = name.encode() + b'\0'
            values = [inode, mode, 0, 0, links, epoch, len(data), 0, 0, 0, 0, len(encoded), 0]
            header = b'070701' + b''.join(f'{value:08x}'.encode() for value in values)
            archive.write(header + encoded)
            archive.write(b'\0' * (-(len(header) + len(encoded)) % 4))
            archive.write(data)
            archive.write(b'\0' * (-len(data) % 4))
        paths = [tree, *sorted(tree.rglob('*'))]
        for inode, path in enumerate(paths, 1):
            name = '.' if path == tree else './' + path.relative_to(tree).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                entry(name, inode, stat.S_IFLNK | 0o777, os.readlink(path).encode())
            elif stat.S_ISDIR(mode):
                entry(name, inode, stat.S_IFDIR | (mode & 0o777), links=2)
            elif stat.S_ISREG(mode):
                entry(name, inode, stat.S_IFREG | (mode & 0o777), path.read_bytes())
            else:
                raise ValueError('Unexpected special file in guest input')
        entry('TRAILER!!!', len(paths) + 1, 0)


def main():
    os.umask(0o022)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--guest-services', type=Path, required=True)
    parser.add_argument('--operating', action='store_true', help='Use the one-use operating PID-1 entry with bilateral booked-launch consent')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.uname().machine != 'x86_64':
        raise ValueError('Use Linux x86_64 with Python 3.12+, dpkg-deb and depmod')
    from compute.guest_vm import VmBudget
    vm_budget=VmBudget(json.loads((INPUTS/'vm-profile.json').read_text()))
    out, cache, services = (p.resolve() for p in (args.output, args.cache, args.guest_services))
    if out.exists() or ROOT in out.parents or ROOT in cache.parents or out == ROOT or cache == ROOT:
        raise ValueError('Require a new output and external cache outside the public repository')
    if out == cache or out in cache.parents or cache in out.parents:
        raise ValueError('Output and cache must be separate trees')
    lock = json.loads((INPUTS / 'inputs.json').read_text())
    for name, expected in lock['guestServices'].items():
        if digest(services / name) != expected:
            raise ValueError('Guest service differs from the recorded build')
    if digest(INPUTS / 'package-lock.json') != lock['npmLockSHA256']:
        raise ValueError('Guest JavaScript dependency lock differs')
    out.mkdir(parents=True)
    cache.mkdir(parents=True, exist_ok=True)
    tree = out / 'rootfs'
    tree.mkdir()
    for directory in ['usr/bin', 'usr/sbin', 'usr/lib', 'usr/lib64', 'usr/local/bin', 'proc', 'sys', 'dev', 'run', 'tmp', 'opt/cannabis', 'etc', 'root']:
        (tree / directory).mkdir(parents=True, exist_ok=True)
    for name, target in {'bin': 'usr/bin', 'sbin': 'usr/sbin', 'lib': 'usr/lib', 'lib64': 'usr/lib64'}.items():
        (tree / name).symlink_to(target)
    inputs = [*lock['packages'], lock['node'], lock['age']]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda item: download(item, cache), inputs))
    for package in lock['packages']:
        subprocess.run(['dpkg-deb', '--extract', str(cache / package['sha256']), str(tree)], check=True)
    # Debian archives can contain legacy directories and replace pre-created
    # aliases. Merge only this fresh staging tree, then restore usr-merge links.
    for name in ['bin', 'sbin', 'lib', 'lib64']:
        legacy, merged = tree / name, tree / 'usr' / name
        if not legacy.is_symlink():
            if legacy.resolve().parent != tree.resolve():
                raise ValueError('Unexpected staging-directory target')
            shutil.copytree(legacy, merged, symlinks=True, dirs_exist_ok=True)
            shutil.rmtree(legacy)
            legacy.symlink_to('usr/' + name)
    kernel = tree / 'boot' / ('vmlinuz-' + lock['kernelRelease'])
    shutil.copyfile(kernel, out / 'vmlinuz')
    # The kernel is already passed separately to the VMM; do not duplicate its
    # image and map in the initramfs. Only this newly created staging tree changes.
    for path in (tree / 'boot').iterdir():
        if path.is_file():
            path.unlink()
    node_prefix = out / 'node-build-tools'
    node_prefix.mkdir()
    with tarfile.open(cache / lock['node']['sha256']) as archive:
        archive.extractall(node_prefix, filter='data')
    node_prefix = node_prefix / ('node-v' + lock['node']['version'] + '-linux-x64')
    shutil.copyfile(node_prefix / 'bin/node', tree / 'usr/local/bin/node')
    (tree / 'usr/local/bin/node').chmod(0o755)
    with tarfile.open(cache / lock['age']['sha256']) as archive:
        for name in ['age', 'age-keygen']:
            source = archive.extractfile('age/' + name)
            if source is None:
                raise ValueError('Missing age binary')
            (tree / 'usr/local/bin' / name).write_bytes(source.read())
            (tree / 'usr/local/bin' / name).chmod(0o755)
    project = tree / 'opt/cannabis'
    copy_text(ROOT / 'LICENSE', project / 'LICENSE')
    copy_text(INPUTS / 'inputs.json', project / 'image-inputs.json')
    copy_text(INPUTS / 'inputs.json', project / 'compute/guest-image/inputs.json')
    copy_text(INPUTS / 'vm-profile.json', project / 'vm-profile.json')
    shutil.copyfile(node_prefix / 'LICENSE', tree / 'usr/local/bin/node.LICENSE')
    for name in ['package.json', 'package-lock.json']:
        shutil.copyfile(INPUTS / name, project / name)
    env = {'PATH':str(node_prefix / 'bin') + ':/usr/bin:/bin', 'HOME':str(out), 'npm_config_cache':str(cache / 'npm'), 'LANG':'C.UTF-8', 'TZ':'UTC'}
    subprocess.run([str(node_prefix / 'bin/node'), str(node_prefix / 'lib/node_modules/npm/bin/npm-cli.js'), 'ci', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund'], cwd=project, env=env, check=True)
    for source in sorted((ROOT / 'compute').iterdir()):
        if source.is_file() and source.suffix in ['.mjs', '.py', '.json']:
            copy_text(source, project / 'compute' / source.name)
    for name in ['compute-guest-probe.mjs', 'check-guest-initialization.mjs', 'check-guest-resources.py', 'check-guest-guardian.py', 'compute-guest-guardian.py', 'check-guest-sandbox.py', 'compute-guest-sandbox.py', 'check-guest-native.py', 'compute-guest-helper.py', 'compute-guest-workload-pipe.py', 'compute-key-capsule-pipe.py', 'compute-plan.mjs', 'compute-escrow.mjs', 'compute-guest-control.py', 'check-guest-job.py', 'compute-guest-native-pipe.py', 'check-guest-execution.py', 'compute-guest-admission.py', 'compute-guest-session.mjs']:
        copy_text(ROOT / 'scripts' / name, project / 'scripts' / name)
    copy_text(ROOT / 'scripts/check-guest-python.py', project / 'scripts/check-guest-python.py')
    copy_text(ROOT / 'scripts/check-guest-graph.py', project / 'scripts/check-guest-graph.py')
    copy_text(ROOT / 'scripts/check-guest-dependencies.py', project / 'scripts/check-guest-dependencies.py')
    for name in ['compute-guest-launch.py','compute-guest-authorize.mjs','check-guest-launcher.py','check-guest-runtime.py','check-guest-ciphertext.py','compute-guest-vm.py','check-guest-vm.py','compute-guest-boot.py','check-guest-boot.py']:
        copy_text(ROOT / 'scripts' / name, project / 'scripts' / name)
    for name in lock['guestServices']:
        shutil.copyfile(services / name, tree / 'usr/local/bin' / name)
        (tree / 'usr/local/bin' / name).chmod(0o755)
    copy_text(INPUTS / 'early-init', tree / 'init')
    (tree / 'init').chmod(0o755)
    copy_text(INPUTS / ('init-operating' if args.operating else 'init'), project / 'guest-init')
    (project / 'guest-init').chmod(0o755)
    copy_text(INPUTS / 'prepare-init', project / 'prepare-init')
    copy_text(INPUTS / 'boot-check.py', project / 'boot-check.py')
    (tree / 'etc/passwd').write_text('root:x:0:0:root:/root:/usr/sbin/nologin\ncannabis:x:1000:1000:workload:/run/workload:/usr/sbin/nologin\n')
    (tree / 'etc/group').write_text('root:x:0:\ncannabis:x:1000:\n')
    (tree / 'etc/shadow').write_text('root:!:0:0:99999:7:::\ncannabis:!:0:0:99999:7:::\n')
    (tree / 'etc/shadow').chmod(0o600)
    (tree / 'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
    (tree / 'etc/resolv.conf').unlink(missing_ok=True)
    (tree / 'etc/resolv.conf').write_text('nameserver 10.0.2.3\noptions timeout:2 attempts:2\n')
    (tree / 'etc/nsswitch.conf').write_text('hosts: files dns\n')
    if not (tree / 'usr/bin/sh').exists():
        (tree / 'usr/bin/sh').symlink_to('busybox')
    subprocess.run(['/usr/sbin/depmod', '-b', str(tree), lock['kernelRelease']], check=True)
    # Avoid repeated source compilation inside bounded guardian/helper startup.
    # Use the image's pinned interpreter and libraries, hash-checked caches,
    # runtime filenames and optimization level zero (assertions stay enabled).
    compiler_script = INPUTS / 'compile-python.py'
    compiled = subprocess.run([str(tree / 'usr/bin/python3'), '-I', '-B', str(compiler_script), str(tree)],
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'},
        check=True, capture_output=True, timeout=120)
    bytecode = json.loads(compiled.stdout)
    bytecode['compilerScriptSHA256'] = digest(compiler_script)
    (project / 'python-bytecode.json').write_text(json.dumps(bytecode, separators=(',', ':')) + '\n')
    recipe = ROOT / 'scripts/build-guest-runtime.py'
    spec = importlib.util.spec_from_file_location('guest_runtime_recipe', recipe)
    runtime_builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime_builder)
    runtime = runtime_builder.build_runtime(tree, project / 'runtime')
    (project / 'runtime.json').write_text(json.dumps(runtime, separators=(',', ':')) + '\n')
    # Record all embedded regular-file contents. This is a build manifest, not
    # remote attestation; firmware must cover the kernel/initrd/cmdline chain.
    manifest = [{'path':'/' + p.relative_to(tree).as_posix(), 'sha256':digest(p)} for p in sorted(tree.rglob('*')) if p.is_file() and not p.is_symlink()]
    (project / 'image-files.json').write_text(json.dumps(manifest, separators=(',', ':')) + '\n')
    # tmpfs allocates file data in pages. Include every final entry and a page
    # for each symlink conservatively; inode metadata belongs to kernel headroom.
    payload=list(tree.rglob('*'))
    root_pages=sum((p.stat().st_size+4095)//4096*4096 if p.is_file() and not p.is_symlink()
                   else 4096 if p.is_symlink() else 0 for p in payload)
    if root_pages>vm_budget.root.bytes or len(payload)+1>vm_budget.root.inodes:
        raise ValueError('Image cannot fit its measured root byte/inode ceilings')
    cmdline = 'console=null panic=-1 quiet loglevel=0 init=/init' if args.operating else 'console=ttyS0 panic=-1 quiet loglevel=3 init=/init'
    (out / 'cmdline').write_text(cmdline + '\n')
    write_initramfs(tree, out / 'initramfs.cpio.gz', lock['sourceDateEpoch'])
    if (out/'initramfs.cpio.gz').stat().st_size>vm_budget.value['bootArchiveBytes']:
        raise ValueError('Compressed archive exceeds the measured boot allowance')
    report = {'schema':'cannabis.guest-image-build.v1', 'kernelRelease':lock['kernelRelease'], 'inputsSHA256':digest(INPUTS / 'inputs.json'), 'builderSHA256':digest(Path(__file__)), 'embeddedFiles':len(manifest), 'outputs':{name:{'sha256':digest(out/name), 'bytes':(out/name).stat().st_size} for name in ['vmlinuz', 'initramfs.cpio.gz', 'cmdline']}, 'bootPurpose':'component acceptance; powers off without workload intake', 'hardwareValidated':False, 'executionAuthorized':False, 'independentReproduction':False}
    report['pythonBytecode'] = bytecode
    report['operatingEntryConfigured']=args.operating
    if args.operating:report['bootPurpose']='one-use operating PID-1 entry; protected execution still requires independent admission'
    report['nativeRuntime'] = runtime
    report['runtimeRecipeSHA256'] = digest(recipe)
    report['vmBudget']={'profile':vm_budget.value,'minimumMemoryBytes':vm_budget.minimum_memory,
        'minimumCPUs':vm_budget.minimum_cpus,'rootFilePageBytes':root_pages,'rootEntries':len(payload)+1}
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
