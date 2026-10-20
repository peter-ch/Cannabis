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


def validate_boot_result(report, budget, result):
    """Validate the exact complete report, also usable on retained boot evidence."""
    vm=result.get('vmChecks',{})
    vm_cases={'measuredCapacityAndLayout','smallerCpuSetRefused','changedMountQuotaRefused','outerAdmission',
              'uncontainedLauncherRefused','changedOuterLimitRefused','changedJobParentRefused','oversizedJobRefused','outerTreeRetired'}
    if (vm.get('schema')!='cannabis.guest-vm-check.v1' or vm.get('kernel')!=report['kernelRelease']
            or vm.get('profile')!=budget.value or vm.get('checks')!={name:True for name in vm_cases}
            or vm.get('capacity',{}).get('minimumMemoryBytes')!=budget.minimum_memory
            or vm.get('capacity',{}).get('minimumCPUs')!=budget.minimum_cpus
            or any(vm.get(k) is not False for k in ['hardwareValidated','providerCapacityCommitted','realPaidJob','customerKeysUsed'])):
        raise ValueError('Measured VM budget acceptance did not pass')
    if result.get('configuredEntryClosed') is not True or result.get('outerLauncherClosed') is not True:
        raise ValueError('Fixed configured entry did not refuse the unprepared boot')
    supervision=result.get('supervisionChecks',{})
    supervision_cases={'actualControllerRootRecognized','retirementOutsidePID1Refused','boundedPrefixAndStreamBoundary','oversizedPrefixRefused',
        'truncatedPrefixRefused','intakeDeadline','intakeWatchdogLoss','existingGroupPreserved',
        'boundedLauncherAndRetirement','failedLauncherRetired','detachedTailRefusedAndRetired',
        'stoppedLauncherDeadline','changedControlsRefused','outerOOMAndSeparateJobRetired',
        'watchdogLossRetiresLauncher','transportLossRetiresLauncher','PID1NamespacePoweroff',
        'watchdogRetiresHungPID1','ownerLifelineLossRetiresNamespace','watchdogFailureRetiresNamespace'}
    if (supervision.get('schema')!='cannabis.guest-boot-supervision-check.v1'
            or supervision.get('kernel')!=report['kernelRelease']
            or supervision.get('checks')!={name:True for name in supervision_cases}
            or any(supervision.get(k) is not False for k in ['realVMRetirementChecked','hardwareValidated','customerKeysUsed','realPaidJob'])):
        raise ValueError('VM supervision acceptance checks did not pass')
    runtime = result.get('runtimeChecks', {})
    runtime_cases = {'embeddedInventoryMatches', 'changedContentsRefused', 'unsafePermissionsRefused',
        'hardlinksRefused', 'symlinkDestinationRefused', 'occupiedDestinationRefused', 'ordinaryStorageRefused',
        'rootWriteRefused', 'mountDowngradeRefused', 'nativeProgramExecuted', 'checkedMountRetirement'}
    if (runtime.get('schema') != 'cannabis.guest-runtime-check.v1' or runtime.get('kernel') != report['kernelRelease']
            or runtime.get('runtime') != report.get('nativeRuntime')
            or runtime.get('checks') != {name: True for name in runtime_cases}
            or any(runtime.get(k) is not False for k in ['customerCodeExecuted','hardwareValidated','realPaidJob'])):
        raise ValueError('Embedded runtime preparation checks did not pass')
    if result.get('pythonChecks') != {'schema': 'cannabis.guest-python-check.v1',
            'cachedControlImports': True, 'changedSourceInvalidatesCache': True,
            'assertionsPreserved': True, 'customerKeysUsed': False, 'hardwareValidated': False}:
        raise ValueError('Pinned Python cache loading and source validation did not pass')
    ciphertext = result.get('ciphertextChecks', {})
    ciphertext_cases = {'verifiedInputAndRetirement','changedInputRefused','writableInputRefused',
        'hardlinkInputRefused','symlinkInputRefused','oversizedInputRefused','retainedInputReplacementRefused',
        'dependency-normal','dependency-changed','dependency-size','dependency-replacement','dependency-unreserved',
        'changedQuotaRefused','kernelByteQuota','kernelInodeQuota','unreservedDirectoryRefused','busyRetirementRefused'}
    if (ciphertext.get('schema') != 'cannabis.guest-ciphertext-check.v1' or ciphertext.get('kernel') != report['kernelRelease']
            or ciphertext.get('checks') != {name:True for name in ciphertext_cases}
            or any(ciphertext.get(k) is not False for k in ['customerKeysUsed','hardwareValidated','realPaidJob'])):
        raise ValueError('Ciphertext storage acceptance checks did not pass')
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
                      'independentDeadline', 'lateFinishRefused', 'stoppedGuardianCancelBounded',
                      'naturalTailDrain', 'lingeringTailRefused', 'stoppedOwnerSharedDeadline', 'sequentialSharedDeadline'}
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
                    'decode-quota', 'encode-quota', 'output-limit', 'helper-deadline', 'helper-owner-death', 'helper-owner-stop', 'helper-cancel',
                    'expired-plan', 'native-shared-deadline', 'encoder-shared-deadline', 'publication-deadline'}
    if (native.get('schema') != 'cannabis.guest-native-check.v1' or native.get('kernel') != report['kernelRelease']
            or native.get('checks') != {name: True for name in native_cases}
            or any(native.get(k) is not False for k in ['customerCodeExecuted', 'hardwareValidated', 'realPaidJob'])
            or any(native.get(k) is not True for k in ['ownedEncryptedExecution', 'requesterReconstruction'])):
        raise ValueError('Encrypted guest execution checks did not pass')
    workflow_cases = {
        'graph': {'success', 'single-command', 'failed-step', 'symlink-output', 'hardlink-output',
                  'fifo-output', 'intermediate-quota', 'cancel-between-steps', 'shared-deadline'},
        'dependencies': {'success', 'wrong-context', 'altered-ciphertext', 'missing-capsule', 'input-budget',
                         'combined-quota', 'cancel-after-input', 'deadline', 'channel-success', 'channel-input-refusal'}}
    for name, cases in workflow_cases.items():
        expected = {'schema': 'cannabis.guest-' + name + '-check.v1', 'kernel': report['kernelRelease'],
                    'checks': {case: True for case in cases}, 'cleanupVerified': True,
                    'hardwareAdmissionEstablished': False, 'realPaidJob': False, 'paymentAccepted': False}
        if result.get(name + 'Checks') != expected:
            raise ValueError('Guest workflow acceptance checks did not pass: ' + name)
    group_cases={
        'group':('cannabis.guest-group-check.v1',{'twoRankTcpComputation','perRankCiphertextReconstruction',
            'unapprovedSocketRefusals','privateTunDeviceHidden','privateInterfaceQueryAndMutationRefusal','wholeTreeCleanup'}),
        'groupFailure':('cannabis.guest-group-failure-check.v1',{'pumpDeath','queuedHeartbeatStall','inputEof',
            'invalidFrame','wrongRankPacket','serviceExpiry','namespaceReplacement','nonPrivateDescriptor',
            'creationFailureCleanup','ownerDeath','cancellation','wholeTreeCleanup'})}
    for name,(schema,cases) in group_cases.items():
        expected={'schema':schema,'kernel':report['kernelRelease'],'checks':{case:True for case in cases},
                  'hardwareValidated':False,'realPaidJob':False}
        if result.get(name+'Checks')!=expected:
            raise ValueError('Protected group acceptance checks did not pass: '+name)
    if report.get('runtimeProfile') == 'pytorch-cpu':
        pytorch_cases={
            'single':('cannabis.guest-pytorch-check.v1',{'singleProcessTraining','encryptedInputAndResult',
                'numericCheckpointReconstruction','wholeTreeCleanup'}),
            'group':('cannabis.guest-group-check.v1',{'twoRankGlooTraining','synchronizedWeights',
                'numericCheckpointReconstruction','perRankCiphertextReconstruction','unapprovedSocketRefusals',
                'privateTunDeviceHidden','privateInterfaceQueryAndMutationRefusal','wholeTreeCleanup'})}
        expected={name:{'schema':schema,'kernel':report['kernelRelease'],
                       'checks':{case:True for case in cases},'hardwareValidated':False,'realPaidJob':False}
                  for name,(schema,cases) in pytorch_cases.items()}
        if result.get('pytorchChecks') != expected:
            raise ValueError('Complete CPU PyTorch training checks did not pass')
    elif result.get('pytorchChecks') is not None:
        raise ValueError('Unexpected PyTorch evidence in the minimal runtime')
    job_cases = {'childCountBound', 'parentEntryRejected', 'retainedLeafHandlesAfterParentCleanup',
        'partialLeafCleanup', 'aggregateOOMKillsAllLeaves', 'aggregatePIDLimit', 'pinnedControlAndWorkloadCompletion',
        'busyControlExitRefused', 'stoppedControlAndDetachedWorkloadRetired', 'wholeTreeDeadline',
        'shorterControlDeadlineBoundsWholeTree', 'stoppedOuterOwnerDeadline', 'outerOwnerDeathRetiresControlAndWorkload'}
    execution_cases = {'success', 'resource-change', 'profile-underbudget', 'runtime-change', 'input-change', 'storage-change', 'owner-death', 'deadline'}
    launcher_cases = {'kernelSealsPreventMutation','publicInputTypeAndSizeRefusals','success','failed-exit',
        'backpressure','stopped-control','guardian-death','guardian-reaped','busy-exit'}
    for field, schema, cases in [('jobChecks','cannabis.guest-job-check.v1',job_cases),
                                 ('launcherChecks','cannabis.guest-launcher-check.v1',launcher_cases),
                                 ('executionChecks','cannabis.guest-execution-check.v1',execution_cases)]:
        component = result.get(field, {})
        if (component.get('schema') != schema or component.get('kernel') != report['kernelRelease']
                or component.get('checks') != {name: True for name in cases}
                or any(component.get(k) is not False for k in ['customerCodeExecuted','hardwareValidated','realPaidJob'])):
            raise ValueError('Aggregate execution acceptance checks did not pass')
    if result['executionChecks'].get('requesterReconstruction') is not True:
        raise ValueError('Protected channel requester reconstruction did not pass')
    if result['schema'] != 'cannabis.guest-boot-check.v1' or result['kernel'] != report['kernelRelease'] or result['imageFilesVerified'] != report['embeddedFiles'] or result['tee'] != 'sample' or result['profileChecks'] != [{'profile':p, 'unsupportedHardwareRejected':True} for p in ['snp','tdx']] or any(result[k] is not False for k in ['requestedEvidence','acceptedJobKeys','launchedCustomerWork','hardwareValidated']):
        raise ValueError('Unexpected guest result')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, help='Bounded boot deadline; defaults to the selected runtime profile')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root))
    from compute.guest_vm import VmBudget
    image, out = args.image.resolve(), args.output.resolve()
    if sys.platform != 'linux' or args.timeout is not None and not 30 <= args.timeout <= 3600:
        raise ValueError('Use Linux and a bounded 30..3600 second boot deadline')
    if out.exists() or root == out or root in out.parents:
        raise ValueError('Require a new private output directory')
    qemu = shutil.which('qemu-system-x86_64')
    if not qemu:
        raise ValueError('Install qemu-system-x86_64')
    report = json.loads((image / 'build.json').read_text())
    maximum_timeout = 3600 if report.get('runtimeProfile') == 'pytorch-cpu' else 1800
    if args.timeout is None:
        args.timeout = maximum_timeout
    elif args.timeout > maximum_timeout:
        raise ValueError('Boot deadline exceeds the selected runtime profile')
    if (report['schema'] != 'cannabis.guest-image-build.v1' or report['executionAuthorized'] is not False
            or report.get('operatingEntryConfigured') is not False):
        raise ValueError('Require the component acceptance image')
    budget=VmBudget(report['vmBudget']['profile'])
    reference=budget.value['referenceVM']
    if (report['vmBudget']['minimumMemoryBytes']!=budget.minimum_memory
            or report['vmBudget']['minimumCPUs']!=budget.minimum_cpus or budget.minimum_cpus<2):
        raise ValueError('Unexpected measured VM budget')
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
    command = [qemu, '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', str(reference['cpus']), '-m', str(reference['memoryMiB']), '-nodefaults', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot', '-kernel', str(image / 'vmlinuz'), '-initrd', str(image / 'initramfs.cpio.gz'), '-append', cmdline]
    capacity_refusals={}
    # The refusal VM must unpack the selected image before PID 1 can reject its
    # complete reservation. A fixed 2 GiB VM cannot even unpack larger runtime
    # images; test just below this profile's actual minimum instead.
    for name,option,value in [('insufficientMemory','-m',budget.minimum_memory//1024**2-128),
                              ('insufficientCPUs','-smp',budget.minimum_cpus-1)]:
        changed=list(command);changed[changed.index(option)+1]=str(value)
        refusal_log=out/(name+'.log')
        with refusal_log.open('xb') as stream:
            process=subprocess.Popen(changed,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10)
                raise ValueError('Insufficient-capacity guest did not retire') from None
        text=refusal_log.read_text(errors='replace')
        if (code!=0 or 'Measured VM capacity refused' not in text or 'CANNABIS_BOOT_CHECK root_handoff_failure' not in text
                or 'CANNABIS_CHECK_PHASE' in text or 'CANNABIS_BOOT_RESULT' in text or 'Traceback' in text):
            raise ValueError('Early capacity refusal was not verified')
        capacity_refusals[name]={'refusedBeforeRootCopy':True,'poweredOff':True,'setting':{option:value}}
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
    validate_boot_result(report, budget, result)
    final = {'checkedAt':datetime.now(timezone.utc).isoformat(), 'qemuVersion':subprocess.check_output([qemu,'--version'],text=True).splitlines()[0], 'image':report['outputs'], 'result':result, 'referenceVM':reference, 'earlyCapacityRefusals':capacity_refusals, 'networkAttached':False, 'hostFilesystemsAttached':False, 'bootFirmware':'local QEMU direct kernel boot; not a confidential measured launch', 'hardwareValidated':False}
    (out / 'verification.json').write_text(json.dumps(final,indent=2)+'\n')
    print(json.dumps(final))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
