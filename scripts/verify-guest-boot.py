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
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    image, out = args.image.resolve(), args.output.resolve()
    if sys.platform != 'linux' or not 30 <= args.timeout <= 900:
        raise ValueError('Use Linux and a 30..900 second boot deadline')
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
    guardian = result.get('guardianChecks', {})
    guardian_cases = {'normalFinish', 'cancelTree', 'busyFinishRefused', 'ownerSIGKILL', 'stoppedOwnerDeadline',
                      'leakedSocketOwnerDeath', 'ownerExitWithoutFinalizer', 'guardianFailureRefusedAndCleaned',
                      'independentDeadline', 'lateFinishRefused', 'stoppedGuardianCancelBounded'}
    if (guardian.get('schema') != 'cannabis.guest-guardian-check.v1' or guardian.get('kernel') != report['kernelRelease']
            or guardian.get('customerCodeExecuted') is not False or guardian.get('hardwareValidated') is not False
            or guardian.get('checks') != {name: True for name in guardian_cases}):
        raise ValueError('Independent guest cleanup checks did not pass')
    sandbox = result.get('sandboxChecks', {})
    sandbox_cases = {'isolation', 'storage', 'inodes', 'logs', 'deadline', 'cancel', 'owner-death', 'guardian-failure', 'changed-runtime'}
    if (sandbox.get('schema') != 'cannabis.guest-sandbox-check.v1' or sandbox.get('kernel') != report['kernelRelease']
            or sandbox.get('customerCodeExecuted') is not False or sandbox.get('hardwareValidated') is not False
            or sandbox.get('checks') != {name: True for name in sandbox_cases}):
        raise ValueError('Guest runtime isolation checks did not pass')
    native = result.get('nativeChecks', {})
    native_cases = {'success', 'tampered', 'metadata', 'group', 'dependency', 'missing-output', 'symlink-output',
                    'decode-quota', 'encode-quota', 'helper-deadline', 'helper-owner-death', 'helper-owner-stop', 'helper-cancel'}
    if (native.get('schema') != 'cannabis.guest-native-check.v1' or native.get('kernel') != report['kernelRelease']
            or native.get('checks') != {name: True for name in native_cases}
            or any(native.get(k) is not False for k in ['customerCodeExecuted', 'hardwareValidated', 'realPaidJob'])
            or any(native.get(k) is not True for k in ['ownedEncryptedExecution', 'requesterReconstruction'])):
        raise ValueError('Encrypted guest execution checks did not pass')
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
