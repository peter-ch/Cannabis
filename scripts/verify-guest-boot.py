#!/usr/bin/env python3
"""Boot the component image in an isolated, non-confidential QEMU VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    image, out = args.image.resolve(), args.output.resolve()
    if sys.platform != 'linux' or not 30 <= args.timeout <= 600:
        raise ValueError('Use Linux and a 30..600 second boot deadline')
    if out.exists() or root == out or root in out.parents:
        raise ValueError('Require a new private output directory')
    qemu = shutil.which('qemu-system-x86_64')
    if not qemu:
        raise ValueError('Install qemu-system-x86_64')
    report = json.loads((image / 'build.json').read_text())
    if report['schema'] != 'cannabis.guest-image-build.v1' or report['executionAuthorized'] is not False:
        raise ValueError('Require the component acceptance image')
    for name in ['vmlinuz', 'initramfs.cpio.gz', 'cmdline']:
        with (image / name).open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != report['outputs'][name]['sha256'] or (image / name).stat().st_size != report['outputs'][name]['bytes']:
            raise ValueError('Image artifact changed')
    cmdline = (image / 'cmdline').read_text().strip()
    if cmdline != 'console=ttyS0 panic=-1 quiet loglevel=3 init=/init':
        raise ValueError('Unexpected boot configuration')
    out.mkdir(parents=True)
    log = out / 'serial.log'
    # No disks, shared filesystem, NIC, monitor, QMP, GDB or incoming migration.
    # TCG intentionally cannot provide confidential-hardware acceptance evidence.
    command = [qemu, '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '2', '-m', '2048', '-nodefaults', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot', '-kernel', str(image / 'vmlinuz'), '-initrd', str(image / 'initramfs.cpio.gz'), '-append', cmdline]
    with log.open('xb') as stream:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            raise ValueError('Guest boot deadline expired; inspect private serial log') from None
    text = log.read_text(errors='replace')
    lines = [line[len('CANNABIS_BOOT_RESULT '):] for line in text.splitlines() if line.startswith('CANNABIS_BOOT_RESULT ')]
    if code != 0 or len(lines) != 1 or 'CANNABIS_BOOT_CHECK' in text:
        raise ValueError('Guest boot check failed; inspect private serial log')
    result = json.loads(lines[0])
    expected_initialization = {'schema':'cannabis.guest-initialization-check.v1',
        'profiles':[{'profile':p, 'unsupportedHardwareRejected':True, 'servicesStopped':True} for p in ['snp','tdx']],
        'cancellationRejected':True, 'changedBinaryRejected':True, 'occupiedPortRejected':True,
        'requestedEvidence':False, 'acceptedJobKeys':False, 'hardwareValidated':False}
    if result.get('initializationChecks') != expected_initialization:
        raise ValueError('Initialization enforcement did not pass its negative checks')
    resources = result.get('resourceChecks', {})
    checks = resources.get('checks', {})
    refusals = {'changedLimitsRejected', 'missingControllersRejected', 'ordinaryFilesystemRejected', 'intermediateSymlinkRejected'}
    expected_checks = {'normalExit', 'cpuQuota', 'wholeGroupOOM', 'forkLimit', 'deadlineTreeKill', 'cancelTreeKill', 'lateObservationRejected'} | refusals
    if resources.get('schema') != 'cannabis.guest-resources-check.v1' or resources.get('kernel') != report['kernelRelease'] or resources.get('customerCodeExecuted') is not False or resources.get('hardwareValidated') is not False or set(checks) != expected_checks:
        raise ValueError('Guest resource enforcement checks are missing')
    for name in expected_checks - refusals:
        if checks[name].get('removed') is not True or checks[name].get('populated') is not False:
            raise ValueError('Guest resource cleanup did not complete')
    if (checks['cpuQuota']['cpu']['nr_throttled'] < 1 or checks['wholeGroupOOM']['memory']['oom_group_kill'] < 1
            or checks['wholeGroupOOM']['memory']['oom_kill'] < 2 or checks['forkLimit']['pids']['max'] < 1
            or checks['deadlineTreeKill']['reason'] != 'deadline' or checks['cancelTreeKill']['reason'] != 'cancelled'
            or checks['lateObservationRejected']['reason'] != 'deadline'
            or checks['normalExit']['reason'] != 'empty' or any(checks[name] is not True for name in refusals)):
        raise ValueError('Guest kernel did not enforce its resource limits')
    if result['schema'] != 'cannabis.guest-boot-check.v1' or result['kernel'] != report['kernelRelease'] or result['imageFilesVerified'] != report['embeddedFiles'] or result['tee'] != 'sample' or result['profileChecks'] != [{'profile':p, 'unsupportedHardwareRejected':True} for p in ['snp','tdx']] or any(result[k] is not False for k in ['requestedEvidence','acceptedJobKeys','launchedCustomerWork','hardwareValidated']):
        raise ValueError('Unexpected guest result')
    final = {'checkedAt':datetime.now(timezone.utc).isoformat(), 'qemuVersion':subprocess.check_output([qemu,'--version'],text=True).splitlines()[0], 'image':report['outputs'], 'result':result, 'networkAttached':False, 'hostFilesystemsAttached':False, 'bootFirmware':'local QEMU direct kernel boot; not a confidential measured launch', 'hardwareValidated':False}
    (out / 'verification.json').write_text(json.dumps(final,indent=2)+'\n')
    print(json.dumps(final))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
