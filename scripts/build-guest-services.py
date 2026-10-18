"""Build pinned guest evidence services. Does not construct or attest a VM."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

PROJECT = Path(__file__).resolve().parents[1]


def sha(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def capture(command, cwd=None, env=None):
    return subprocess.check_output(command, cwd=cwd, env=env, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='Pinned upstream Git checkout')
    parser.add_argument('--rust-prefix', type=Path, required=True, help='Installed pinned Rust toolchain')
    parser.add_argument('--build-root', type=Path, required=True, help='Private Linux build directory outside this repository')
    parser.add_argument('--label', choices=['first', 'second'], required=True)
    parser.add_argument('--offline', action='store_true', help='Forbid dependency downloads with Cargo --frozen')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or not 1 <= args.jobs <= 16:
        raise ValueError('Use Linux x86_64 with 1–16 build jobs')
    lock = json.loads((PROJECT / 'compute/guest-service-build.json').read_text())
    host = platform.freedesktop_os_release()
    if host.get('ID') != lock['buildHost']['distribution'] or host.get('VERSION_ID') != lock['buildHost']['version']:
        raise ValueError('This recorded build profile requires Ubuntu 24.04')
    source = args.source.resolve(strict=True)
    compiler = args.rust_prefix.resolve(strict=True)
    root = args.build_root.resolve()
    if any(any(character.isspace() for character in str(p)) for p in [source, compiler, root]):
        raise ValueError('Use Linux build paths without whitespace for this profile')
    if root == PROJECT or PROJECT in root.parents:
        raise ValueError('Keep build outputs and operational records outside the public repository')
    # A trusted build host is still required. Version/commit checks do not attest
    # that host or replace verification of the compiler distribution archive.
    version = capture([str(compiler / 'bin/rustc'), '--version'])
    if not version.startswith('rustc ' + lock['compiler']['version'] + ' '):
        raise ValueError('Unexpected Rust compiler version')
    if capture(['git', 'rev-parse', 'HEAD'], source) != lock['source']['revision']:
        raise ValueError('Source revision differs from the reviewed guest protocol')
    if capture(['git', 'describe', '--exact-match', '--tags', 'HEAD'], source) != lock['source']['tag']:
        raise ValueError('Source version tag differs from the guest protocol')
    if capture(['git', 'status', '--porcelain'], source) or sha(source / 'Cargo.lock') != lock['source']['cargoLockSHA256']:
        raise ValueError('Source or locked dependencies changed')
    root.mkdir(parents=True, exist_ok=True)
    work = root / ('guest-agent-' + args.label)
    target = root / ('guest-agent-target-' + args.label)
    cargo_home = root / 'cargo'
    clean_build = not target.exists()
    report_file = root / ('guest-services-' + args.label + '.json')
    artifacts = root / ('guest-agent-artifacts-' + args.label)
    if report_file.exists() or artifacts.exists():
        raise FileExistsError('Preserve the previous build report and artifacts before another run')
    if not work.exists():
        subprocess.run(['git', 'worktree', 'add', '--detach', str(work), lock['source']['revision']], cwd=source, check=True)
    if (capture(['git', 'rev-parse', 'HEAD'], work) != lock['source']['revision']
            or capture(['git', 'status', '--porcelain'], work)
            or sha(work / 'Cargo.lock') != lock['source']['cargoLockSHA256']):
        raise ValueError('Build worktree differs from the pinned clean source')
    epoch = capture(['git', 'show', '-s', '--format=%ct', 'HEAD'], work)
    if not re.fullmatch('[0-9]+', epoch):
        raise ValueError('Invalid pinned source timestamp')
    remaps = [(work, '/usr/src/guest-components'), (target, '/usr/build/guest-components'),
              (cargo_home, '/usr/share/cargo'), (compiler, '/opt/rust')]
    environment = {'HOME': os.environ['HOME'], 'PATH': str(compiler / 'bin') + ':/usr/bin:/bin',
                   'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'SOURCE_DATE_EPOCH': epoch,
                   'CARGO_HOME': str(cargo_home), 'CARGO_TARGET_DIR': str(target),
                   'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': str(args.jobs), 'CARGO_NET_GIT_FETCH_WITH_CLI': 'true',
                   'RUSTFLAGS': ' '.join('--remap-path-prefix=' + str(a) + '=' + b for a, b in remaps),
                   'CFLAGS': ' '.join('-ffile-prefix-map=' + str(a) + '=' + b for a, b in remaps),
                   'CC': '/usr/bin/cc', 'AR': '/usr/bin/ar'}
    mode = '--frozen' if args.offline else '--locked'
    commands = [
        [str(compiler / 'bin/cargo'), 'build', mode, '--release', '--no-default-features',
         '-p', 'attestation-agent', '--bin', 'ttrpc-aa', '--features', ','.join(lock['agentFeatures'])],
        [str(compiler / 'bin/cargo'), 'build', mode, '--release', '-p', 'api-server-rest', '--bin', 'api-server-rest']
    ]
    for command in commands:
        subprocess.run(command, cwd=work, env=environment, check=True)
    if capture(['git', 'status', '--porcelain'], work):
        raise ValueError('Upstream build changed tracked source; inspect before accepting its version')
    artifacts.mkdir()
    outputs = {}
    for name in lock['binaries']:
        raw = target / 'release' / name
        file = artifacts / name
        subprocess.run([lock['packaging']['tool'], *lock['packaging']['arguments'], str(raw), str(file)], env=environment, check=True)
        outputs[name] = {'bytes': file.stat().st_size, 'sha256': sha(file),
                         'unstrippedSHA256': sha(raw),
                         'version': capture([str(file), '--version'], env=environment),
                         'dynamicDependencies': capture(['ldd', str(file)], env=environment)}
    if outputs['api-server-rest']['version'] != 'api-server-rest Guest Components Version: ' + lock['source']['tag']:
        raise ValueError('REST bridge does not identify the pinned guest protocol')
    record = {'schema': 'cannabis.guest-services-build.v1',
              'builtAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'label': args.label, 'cleanTargetAtStart': clean_build, 'offline': args.offline,
              'sourceRevision': lock['source']['revision'], 'cargoLockSHA256': lock['source']['cargoLockSHA256'],
              'sourceDateEpoch': epoch, 'features': lock['agentFeatures'], 'outputs': outputs,
              'compiler': capture([str(compiler / 'bin/rustc'), '-vV']),
              'compilerExecutableSHA256': sha(compiler / 'bin/rustc'),
              'cargoExecutableSHA256': sha(compiler / 'bin/cargo'),
              'packaging': lock['packaging'], 'packagingVersion': capture(['objcopy', '--version']).splitlines()[0],
              'hostPackages': capture(['dpkg-query', '-W', 'build-essential', 'gcc-13', 'libc6-dev', 'libssl-dev', 'pkg-config', 'binutils']),
              'hardwareValidated': False, 'guestImageBuilt': False}
    with report_file.open('x') as output:
        json.dump(record, output, indent=2); output.write('\n')
    print(json.dumps({'report': str(report_file), 'binaries': {name: value['sha256'] for name, value in outputs.items()},
                      'cleanTargetAtStart': clean_build, 'hardwareValidated': False}))


if __name__ == '__main__':
    main()
