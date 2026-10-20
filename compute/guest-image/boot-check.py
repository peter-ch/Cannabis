"""Boot acceptance check: actual guest services, no evidence or job-key request."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.request

PHASE = 'start'


def phase(name):
    global PHASE
    PHASE = name
    # This entry point runs owned checks only. Bounded phase markers distinguish
    # slow emulation from a stalled check without any customer/evidence content.
    print('CANNABIS_CHECK_PHASE ' + name, flush=True)


def owned_workflow_checks(name, modes, timeout, extra_summary=None):
    """Accept every named case and the final cleanup report, with no omissions."""
    phase(name)
    check = subprocess.run(['/usr/bin/python3', '-I', '-B',
                            '/opt/cannabis/scripts/check-guest-' + name + '.py'],
                           capture_output=True, timeout=timeout)
    if check.returncode:
        print('CANNABIS_' + name.upper() + '_FAILURE ' +
              check.stderr.decode(errors='replace')[-8192:].replace('\n', ' | '), flush=True)
        raise RuntimeError('Owned workflow acceptance failed')
    if len(check.stdout) > 65536:
        raise RuntimeError('Oversized owned workflow report')
    rows = [json.loads(line) for line in check.stdout.splitlines()]
    summary = {'checks': len(modes), 'cleanupVerified': True,
               'hardwareAdmissionEstablished': False, 'realPaidJob': False}
    summary.update(extra_summary or {})
    expected = [{'mode': mode, 'passed': True} for mode in modes] + [summary]
    if rows != expected:
        raise RuntimeError('Incomplete or unexpected owned workflow report')
    return {'schema': 'cannabis.guest-' + name + '-check.v1', 'kernel': os.uname().release,
            'checks': {mode: True for mode in modes}, 'cleanupVerified': True,
            'hardwareAdmissionEstablished': False, 'realPaidJob': False,
            'paymentAccepted': False}


def owned_group_checks(name, schema, cases, timeout, tools=False, arguments=()):
    phase(name)
    command=['/usr/bin/python3','-I','-B','/opt/cannabis/scripts/check-guest-'+name+'.py']
    if tools: command+=['--tools','/usr/local/bin']
    command+=list(arguments)
    checked=subprocess.run(command,capture_output=True,timeout=timeout)
    if checked.returncode:
        print('CANNABIS_GROUP_FAILURE '+checked.stderr.decode(errors='replace')[-8192:].replace('\n',' | '),flush=True)
        raise RuntimeError('Protected group kernel acceptance failed')
    expected={'schema':schema,'checks':{case:True for case in cases},'hardwareValidated':False,'realPaidJob':False}
    if len(checked.stdout)>65536 or json.loads(checked.stdout)!=expected:
        raise RuntimeError('Incomplete protected group kernel report')
    return {**expected,'kernel':os.uname().release}


def main():
    os.umask(0o077)
    processes = []
    try:
        phase('ephemeral_root')
        root_mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4] == '/']
        if (len(root_mounts) != 1 or root_mounts[0][-3] != 'tmpfs'
                or 'noswap' not in root_mounts[0][-1].split(',')
                or not {'nosuid', 'nodev'} <= set(root_mounts[0][5].split(','))):
            raise RuntimeError('Guest root was not handed off to protected memory storage')
        phase('embedded_files')
        manifest = json.loads(Path('/opt/cannabis/image-files.json').read_text())
        for entry in manifest:
            path = Path(entry['path'])
            if hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
                raise RuntimeError('embedded component changed')
        phase('measured_vm_budget')
        vm=subprocess.run(['/usr/bin/python3','-I','-B','/opt/cannabis/scripts/check-guest-vm.py'],
            capture_output=True,timeout=180)
        if vm.returncode:
            print('CANNABIS_VM_FAILURE '+vm.stderr.decode(errors='replace')[-8192:].replace('\n',' | '),flush=True)
            raise RuntimeError('Measured VM budget checks failed')
        vm_checks=json.loads(vm.stdout)
        phase('vm_supervision')
        supervision=subprocess.run(['/usr/bin/python3','-I','-B','/opt/cannabis/scripts/check-guest-boot.py'],
            capture_output=True,timeout=120)
        if supervision.returncode:
            print('CANNABIS_SUPERVISION_FAILURE '+supervision.stderr.decode(errors='replace')[-8192:].replace('\n',' | '),flush=True)
            raise RuntimeError('VM supervision checks failed')
        supervision_checks=json.loads(supervision.stdout)
        # These imports exercise the actual image's interpreter and extension
        # libraries; no customer package or participant custody is consulted.
        phase('python_runtime')
        import ctypes, ssl, sqlite3, lzma, bz2  # noqa: F401
        phase('python_cached_runtime')
        cached = subprocess.run(['/usr/bin/python3', '-I', '-B', '/opt/cannabis/scripts/check-guest-python.py'],
            capture_output=True, timeout=30, check=True)
        python_checks = json.loads(cached.stdout)
        phase('embedded_runtime_preparation')
        runtime = subprocess.run(['/usr/bin/python3','-I','-B','/opt/cannabis/scripts/check-guest-runtime.py'],
            capture_output=True, timeout=180)
        if runtime.returncode:
            print('CANNABIS_RUNTIME_FAILURE '+runtime.stderr.decode(errors='replace')[-8192:].replace('\n',' | '),flush=True)
            raise RuntimeError('Embedded runtime preparation failed')
        runtime_checks = json.loads(runtime.stdout)
        phase('ciphertext_storage')
        ciphertext = subprocess.run(['/usr/bin/python3','-I','-B','/opt/cannabis/scripts/check-guest-ciphertext.py'],
            capture_output=True, timeout=60)
        if ciphertext.returncode:
            print('CANNABIS_CIPHERTEXT_FAILURE '+ciphertext.stderr.decode(errors='replace')[-8192:].replace('\n',' | '),flush=True)
            raise RuntimeError('Ciphertext storage acceptance failed')
        ciphertext_checks = json.loads(ciphertext.stdout)
        phase('configured_entry_closed')
        # No launch request, configured runtime or customer intake is staged in
        # the component boot. The fixed entry must import and fail closed.
        entry=subprocess.run(['/usr/local/bin/node','--no-warnings','/opt/cannabis/scripts/compute-guest-session.mjs'],capture_output=True,timeout=20)
        if (entry.returncode!=1 or entry.stdout or not entry.stderr.decode().splitlines()
                or entry.stderr.decode().splitlines()[-1]!='Configured guest session failed; retire the whole job'):
            raise RuntimeError('Configured entry did not refuse the unprepared boot')
        outer=subprocess.run(['/usr/bin/python3','-I','-B','/opt/cannabis/scripts/compute-guest-launch.py'],capture_output=True,timeout=20)
        if outer.returncode!=1 or outer.stdout or outer.stderr.decode()!='Guest launch failed; enclosing boot must retire the VM\n':
            raise RuntimeError('Outer launcher did not refuse the unprepared boot')
        phase('age_runtime')
        subprocess.run(['/usr/local/bin/age', '--version'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(subprocess.Popen(['/usr/local/bin/ttrpc-aa', '--attestation_sock', 'unix:///run/confidential-containers/attestation-agent/check.sock'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True))
        phase('agent_socket')
        sock = Path('/run/confidential-containers/attestation-agent/check.sock')
        deadline = time.monotonic() + 20
        while not sock.exists():
            if processes[0].poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('agent unavailable')
            time.sleep(0.1)
        processes.append(subprocess.Popen(['/usr/local/bin/api-server-rest', '--features', 'attestation', '--aa_addr', 'unix://' + str(sock), '--bind', '127.0.0.1:8006'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True))
        phase('bridge_info')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while True:
            try:
                with opener.open('http://127.0.0.1:8006/info', timeout=1) as response:
                    raw = response.read(4097)
                if len(raw) > 4096:
                    raise RuntimeError('oversized agent response')
                info = json.loads(raw)
                if info != {'version': 'Guest Components Version: v0.22.0', 'tee': 'sample', 'feature': 'attestation'}:
                    raise RuntimeError('separate hardware acceptance required')
                break
            except (OSError, ValueError):
                if processes[1].poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('bridge unavailable')
                time.sleep(0.1)
        checks = []
        for tee in ['snp', 'tdx']:
            phase(tee + '_production_probe')
            result = subprocess.run(['/usr/local/bin/node', '/opt/cannabis/scripts/compute-guest-probe.mjs', tee], capture_output=True, timeout=20)
            # Do not mistake a missing runtime/import failure for the intended
            # production-profile refusal. Require its exact structured error.
            try:
                output = json.loads(result.stderr.decode().splitlines()[-1]) if result.returncode else json.loads(result.stdout)
            except (ValueError, IndexError):
                raise RuntimeError('production probe did not run') from None
            if info.get('tee') == 'sample':
                if result.returncode != 1 or output != {'error': 'Guest agent profile mismatch; no alternate TEE or accelerator fallback'}:
                    raise RuntimeError('unsupported profile accepted')
            else:
                # This image has no operational launcher. Real hardware is a
                # separate acceptance run; never report this as authorization.
                raise RuntimeError('protected hardware requires its reviewed acceptance run')
            checks.append({'profile': tee, 'unsupportedHardwareRejected': True})
        phase('initialization_gate')
        initialized = subprocess.run(['/usr/local/bin/node', '/opt/cannabis/scripts/check-guest-initialization.mjs'], capture_output=True, timeout=90, check=True)
        initialization_checks = json.loads(initialized.stdout)
        phase('resource_enforcement')
        resources = subprocess.run(['/usr/bin/python3', '-I', '-B', '/opt/cannabis/scripts/check-guest-resources.py'], capture_output=True, timeout=90)
        if resources.returncode:
            # This command runs only checked-in owned programs. Its bounded
            # diagnostics contain no customer input, evidence or job keys.
            print('CANNABIS_RESOURCE_FAILURE ' + resources.stderr.decode(errors='replace')[-4096:].replace('\n', ' | '), flush=True)
            raise RuntimeError('Kernel resource acceptance failed')
        resource_checks = json.loads(resources.stdout)
        phase('guardian_cleanup')
        guardian = subprocess.run(['/usr/bin/python3', '-I', '-B', '/opt/cannabis/scripts/check-guest-guardian.py'], capture_output=True, timeout=180)
        if guardian.returncode:
            print('CANNABIS_GUARDIAN_FAILURE ' + guardian.stderr.decode(errors='replace')[-4096:].replace('\n', ' | '), flush=True)
            raise RuntimeError('Guardian acceptance failed')
        guardian_checks = json.loads(guardian.stdout)
        phase('runtime_isolation')
        sandbox = subprocess.run(['/usr/bin/python3', '-I', '-B', '/opt/cannabis/scripts/check-guest-sandbox.py'], capture_output=True, timeout=180)
        if sandbox.returncode:
            print('CANNABIS_SANDBOX_FAILURE ' + sandbox.stderr.decode(errors='replace')[-8192:].replace('\n', ' | '), flush=True)
            raise RuntimeError('Runtime isolation acceptance failed')
        sandbox_checks = json.loads(sandbox.stdout)
        phase('encrypted_native_execution')
        native = subprocess.run(['/usr/bin/python3', '-I', '-B', '/opt/cannabis/scripts/check-guest-native.py'], capture_output=True, timeout=540)
        if native.returncode:
            print('CANNABIS_NATIVE_FAILURE ' + native.stderr.decode(errors='replace')[-8192:].replace('\n', ' | '), flush=True)
            raise RuntimeError('Encrypted native execution acceptance failed')
        native_checks = json.loads(native.stdout)
        graph_checks = owned_workflow_checks('graph',
            ('success', 'single-command', 'failed-step', 'symlink-output', 'hardlink-output',
             'fifo-output', 'intermediate-quota', 'cancel-between-steps', 'shared-deadline'),
            540, {'paymentAccepted': False})
        dependency_checks = owned_workflow_checks('dependencies',
            ('success', 'wrong-context', 'altered-ciphertext', 'missing-capsule', 'input-budget',
             'combined-quota', 'cancel-after-input', 'deadline', 'channel-success', 'channel-input-refusal'),
            900)
        group_checks=owned_group_checks('groups','cannabis.guest-group-check.v1',
            ('twoRankTcpComputation','perRankCiphertextReconstruction','unapprovedSocketRefusals',
             'privateTunDeviceHidden','privateInterfaceQueryAndMutationRefusal','wholeTreeCleanup'),180,tools=True)
        pytorch_checks=None
        if Path('/opt/cannabis/pytorch-cpu-wheels.json').exists():
            pytorch_checks={
                'single':owned_group_checks('pytorch','cannabis.guest-pytorch-check.v1',
                    ('singleProcessTraining','encryptedInputAndResult','numericCheckpointReconstruction','wholeTreeCleanup'),
                    300,arguments=('--runtime','/opt/cannabis/runtime','--age','/usr/local/bin/age')),
                'group':owned_group_checks('groups','cannabis.guest-group-check.v1',
                    ('twoRankGlooTraining','synchronizedWeights','numericCheckpointReconstruction',
                     'perRankCiphertextReconstruction','unapprovedSocketRefusals','privateTunDeviceHidden',
                     'privateInterfaceQueryAndMutationRefusal','wholeTreeCleanup'),
                    360,tools=True,arguments=('--pytorch-runtime','/opt/cannabis/runtime'))}
        group_failure_checks=owned_group_checks('group-failures','cannabis.guest-group-failure-check.v1',
            ('pumpDeath','queuedHeartbeatStall','inputEof','invalidFrame','wrongRankPacket','serviceExpiry',
             'namespaceReplacement','nonPrivateDescriptor','creationFailureCleanup','ownerDeath','cancellation','wholeTreeCleanup'),180)
        phase('aggregate_job_boundary')
        job = subprocess.run(['/usr/bin/python3', '-I', '-B', '/opt/cannabis/scripts/check-guest-job.py'], capture_output=True, timeout=180)
        if job.returncode:
            print('CANNABIS_JOB_FAILURE ' + job.stderr.decode(errors='replace')[-8192:].replace('\n', ' | '), flush=True)
            raise RuntimeError('Aggregate job boundary acceptance failed')
        job_checks = json.loads(job.stdout)
        phase('native_execution_channel')
        execution = subprocess.run(['/usr/bin/python3', '-I', '-B', '/opt/cannabis/scripts/check-guest-execution.py'], capture_output=True, timeout=300)
        if execution.returncode:
            print('CANNABIS_EXECUTION_FAILURE ' + execution.stderr.decode(errors='replace')[-8192:].replace('\n', ' | '), flush=True)
            raise RuntimeError('Native execution channel acceptance failed')
        execution_checks = json.loads(execution.stdout)
        phase('outer_launch_transport')
        launcher = subprocess.run(['/usr/bin/python3','-I','-B','/opt/cannabis/scripts/check-guest-launcher.py'],capture_output=True,timeout=90)
        if launcher.returncode:
            print('CANNABIS_LAUNCHER_FAILURE '+launcher.stderr.decode(errors='replace')[-8192:].replace('\n',' | '),flush=True)
            raise RuntimeError('Outer launch transport checks failed')
        launcher_checks=json.loads(launcher.stdout)
        print('CANNABIS_BOOT_RESULT ' + json.dumps({'schema': 'cannabis.guest-boot-check.v1', 'kernel': os.uname().release, 'tee': info['tee'], 'profileChecks': checks, 'initializationChecks': initialization_checks, 'resourceChecks': resource_checks, 'guardianChecks': guardian_checks, 'sandboxChecks': sandbox_checks, 'nativeChecks': native_checks, 'graphChecks': graph_checks, 'dependenciesChecks': dependency_checks, 'groupChecks':group_checks,'pytorchChecks':pytorch_checks, 'groupFailureChecks':group_failure_checks, 'jobChecks': job_checks, 'executionChecks': execution_checks, 'launcherChecks':launcher_checks, 'runtimeChecks':runtime_checks, 'ciphertextChecks':ciphertext_checks, 'vmChecks':vm_checks, 'supervisionChecks':supervision_checks, 'pythonChecks': python_checks, 'configuredEntryClosed': True, 'outerLauncherClosed':True, 'imageFilesVerified': len(manifest), 'requestedEvidence': False, 'acceptedJobKeys': False, 'launchedCustomerWork': False, 'hardwareValidated': False}), flush=True)
    finally:
        for process in reversed(processes):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('CANNABIS_BOOT_CHECK failed stage=' + PHASE, flush=True)
        raise SystemExit(1)
