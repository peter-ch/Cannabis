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

def main():
    global PHASE
    os.umask(0o077)
    processes = []
    try:
        PHASE = 'embedded_files'
        manifest = json.loads(Path('/opt/cannabis/image-files.json').read_text())
        for entry in manifest:
            path = Path(entry['path'])
            if hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
                raise RuntimeError('embedded component changed')
        # These imports exercise the actual image's interpreter and extension
        # libraries; no customer package or participant custody is consulted.
        PHASE = 'python_runtime'
        import ctypes, ssl, sqlite3, lzma, bz2  # noqa: F401
        PHASE = 'age_runtime'
        subprocess.run(['/usr/local/bin/age', '--version'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(subprocess.Popen(['/usr/local/bin/ttrpc-aa', '--attestation_sock', 'unix:///run/confidential-containers/attestation-agent/check.sock'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True))
        PHASE = 'agent_socket'
        sock = Path('/run/confidential-containers/attestation-agent/check.sock')
        deadline = time.monotonic() + 20
        while not sock.exists():
            if processes[0].poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('agent unavailable')
            time.sleep(0.1)
        processes.append(subprocess.Popen(['/usr/local/bin/api-server-rest', '--features', 'attestation', '--aa_addr', 'unix://' + str(sock), '--bind', '127.0.0.1:8006'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True))
        PHASE = 'bridge_info'
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
            PHASE = tee + '_production_probe'
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
        PHASE = 'initialization_gate'
        initialized = subprocess.run(['/usr/local/bin/node', '/opt/cannabis/scripts/check-guest-initialization.mjs'], capture_output=True, timeout=90, check=True)
        initialization_checks = json.loads(initialized.stdout)
        PHASE = 'resource_enforcement'
        resources = subprocess.run(['/usr/bin/python3', '-I', '-B', '/opt/cannabis/scripts/check-guest-resources.py'], capture_output=True, timeout=90)
        if resources.returncode:
            # This command runs only checked-in owned programs. Its bounded
            # diagnostics contain no customer input, evidence or job keys.
            print('CANNABIS_RESOURCE_FAILURE ' + resources.stderr.decode(errors='replace')[-4096:].replace('\n', ' | '), flush=True)
            raise RuntimeError('Kernel resource acceptance failed')
        resource_checks = json.loads(resources.stdout)
        print('CANNABIS_BOOT_RESULT ' + json.dumps({'schema': 'cannabis.guest-boot-check.v1', 'kernel': os.uname().release, 'tee': info['tee'], 'profileChecks': checks, 'initializationChecks': initialization_checks, 'resourceChecks': resource_checks, 'imageFilesVerified': len(manifest), 'requestedEvidence': False, 'acceptedJobKeys': False, 'launchedCustomerWork': False, 'hardwareValidated': False}), flush=True)
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
