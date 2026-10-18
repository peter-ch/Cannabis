#!/usr/bin/env python3
"""Build the pinned direct-kernel AMD firmware profile from committed sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'compute/guest-firmware-build.json'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def git(directory, *args):
    return subprocess.check_output(['git', '-C', str(directory), *args], text=True).strip()


def export(directory, revision, destination, prefix='', excludes=()):
    process = subprocess.Popen(['git', '-C', str(directory), 'archive', '--format=tar', '--prefix=' + prefix, revision, *[':(exclude)' + path for path in excludes]], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            archive.extractall(destination, filter='data')
    except BaseException:
        process.stdout.close()
        process.wait()
        raise
    process.stdout.close()
    if process.wait() != 0:
        raise ValueError('Pinned source export failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.uname().machine != 'x86_64' or not 1 <= args.jobs <= 16:
        raise ValueError('Use Linux x86_64 and 1..16 build jobs')
    os.umask(0o022)
    source, output = args.source.resolve(), args.output.resolve()
    if output.exists() or output == ROOT or ROOT in output.parents or any(c.isspace() for c in str(output)):
        raise ValueError('Require a fresh output outside the public repository, without whitespace')
    lock = json.loads(LOCK.read_text())
    revision = lock['source']['revision']
    if git(source, 'rev-parse', 'HEAD') != revision or git(source, 'rev-parse', lock['source']['tag']) != revision:
        raise ValueError('Firmware source revision differs')
    if git(source, 'show', '-s', '--format=%ct', revision) != str(lock['source']['sourceDateEpoch']):
        raise ValueError('Source timestamp differs')
    for relative, expected in lock['submodules'].items():
        if git(source / relative, 'rev-parse', 'HEAD') != expected:
            raise ValueError('Firmware submodule revision differs: ' + relative)
    output.mkdir(parents=True)
    tree = output / 'source'
    tree.mkdir()
    export(source, revision, tree, excludes=lock['sourceExcludes'])
    for relative, expected in lock['submodules'].items():
        export(source / relative, expected, tree, relative + '/')
    # These three explicit edits remove the embedded disk-boot fallback and its
    # build hook. They do not change the upstream blob verification library.
    edits = []
    for relative, lines in lock['removeLines'].items():
        file = tree / relative
        before = sha(file)
        text = file.read_text()
        for line in lines:
            if text.count(line + '\n') != 1:
                raise ValueError('Expected firmware configuration line differs')
            text = text.replace(line + '\n', '')
        file.write_text(text, newline='\n')
        edits.append({'path':relative, 'beforeSHA256':before, 'afterSHA256':sha(file)})
    environment = {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin', 'HOME':str(output), 'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8', 'TZ':'UTC', 'SOURCE_DATE_EPOCH':str(lock['source']['sourceDateEpoch']), 'PYTHONHASHSEED':'0', 'PYTHON_COMMAND':'python3', 'WORKSPACE':str(tree)}
    command = ['build', '-p', lock['platform'], '-a', lock['architecture'], '-b', lock['target'], '-t', lock['toolchain'], '-n', str(args.jobs)]
    for define in lock['defines']:
        command += ['-D', define]
    with (output / 'build.log').open('w') as log:
        subprocess.run(['make','-C','BaseTools','-j' + str(args.jobs)], cwd=tree, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
        subprocess.run(['/bin/bash','-c','source ./edksetup.sh --reconfig && exec "$@"','firmware-build', *command], cwd=tree, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    artifact = tree / 'Build/AmdSev/RELEASE_GCC/FV/OVMF.fd'
    shutil.copyfile(artifact, output / 'OVMF.fd')
    packages = subprocess.check_output(['dpkg-query','-W','-f=${Package}\t${Version}\n','gcc-13','g++-13','binutils','make','nasm','acpica-tools','uuid-dev','python3'], text=True)
    report = {'schema':'cannabis.guest-firmware-build-result.v1', 'sourceRevision':revision, 'sourceDateEpoch':lock['source']['sourceDateEpoch'], 'submodules':lock['submodules'], 'lockSHA256':sha(LOCK), 'builderSHA256':sha(Path(__file__)), 'configurationEdits':edits, 'command':command, 'hostPackages':packages, 'compiler':subprocess.check_output(['gcc','--version'],text=True).splitlines()[0], 'output':{'file':'OVMF.fd','sha256':sha(artifact),'bytes':artifact.stat().st_size}, 'hardwareValidated':False, 'measuredLaunchVerified':False, 'executionAuthorized':False}
    (output / 'build.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
