"""Public authorization and bounded transport outside a contained guest job.

This owner holds no customer keys. The enclosing measured boot must supply the
protected runtime/storage, whole-VM capacity, authenticated transport, trustworthy
time and unconditional VM disposal. Process cleanup alone does not supply those.
"""
import json
import os
import select
import signal
import subprocess
import time

from .guest_deadline import ExecutionDeadline
from .guest_execution import NativeServiceProfile, exact, _unique
from .guest_launch_snapshot import validate_snapshot
from .guest_sandbox import _pinned_file

BUFFER = 65536


def authorize_launch(node, node_sha256, verifier, verifier_sha256, snapshot_fd):
    """Run only measured signature verification before creating the job tree."""
    validate_snapshot(snapshot_fd)
    started = time.monotonic()
    handles, proc = [], None
    try:
        handles.append(_pinned_file(node, node_sha256))
        handles.append(_pinned_file(verifier, verifier_sha256))
        proc = subprocess.Popen([f'/proc/self/fd/{handles[0]}', f'/proc/self/fd/{handles[1]}'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            pass_fds=(*handles, snapshot_fd), close_fds=True, start_new_session=True, bufsize=0,
            env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','CANNABIS_LAUNCH_FD':str(snapshot_fd)})
        raw = bytearray()
        while True:
            remaining = started + 60 - time.monotonic()
            if remaining <= 0 or not select.select([proc.stdout], [], [], remaining)[0]:
                raise RuntimeError('Public authorization deadline expired')
            chunk = os.read(proc.stdout.fileno(), min(BUFFER, BUFFER + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > BUFFER:
                raise ValueError('Public authorization response exceeds its bound')
        if proc.wait(timeout=max(0.001, started+60-time.monotonic())) != 0 or time.monotonic() >= started+60:
            raise ValueError('Public launch authorization failed')
        value = json.loads(raw, object_pairs_hook=_unique)
        exact(value, ['schema','profile','serviceSHA256','units','interval','transport'])
        if value['schema'] != 'cannabis.guest-launch-admission.v1':
            raise ValueError('Unexpected launch authorization response')
        profile = NativeServiceProfile(value['profile'], value['serviceSHA256'], value['units'])
        exact(value['interval'], ['start','end'])
        exact(value['transport'], ['timeoutMs','maxCiphertextBytes'])
        transport = value['transport']
        for field, maximum in [('timeoutMs',3600000),('maxCiphertextBytes',1024**4)]:
            if type(transport[field]) is not int or not 1 <= transport[field] <= maximum:
                raise ValueError('Invalid authorized transport bound')
        service = ExecutionDeadline.from_service_interval(**value['interval'])
        # Charge authorization time against transport too. Never restart either
        # the signed service interval or the launch allowance after verification.
        deadline = ExecutionDeadline(min(service.monotonic_end, started+transport['timeoutMs']/1000))
        deadline.check()
        return profile, deadline, transport
    finally:
        if proc is not None:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=5)
            proc.stdout.close()
        for fd in handles:
            os.close(fd)


def relay_guest(scope, proc, reader, writer, *, max_ciphertext_bytes):
    """Relay opaque bytes with bounded queues while watching both lifetimes.

    The protocol endpoints authenticate messages. This pump cannot acknowledge
    results, decrypt, authorize payment or declare success before checked cleanup.
    """
    if type(max_ciphertext_bytes) is not int or not 1 <= max_ciphertext_bytes <= 1024**4:
        raise ValueError('Require the authorized ciphertext bound')
    descriptors = [reader, writer, proc.stdin.fileno(), proc.stdout.fileno()]
    if len(set(descriptors)) != len(descriptors) or any(os.isatty(fd) for fd in descriptors):
        raise ValueError('Require distinct nonterminal transport descriptors')
    blocking = {fd:os.get_blocking(fd) for fd in descriptors}
    child_pidfd, guardian = scope.monitor_handles()
    pending_in, pending_out = bytearray(), bytearray()
    incoming_open = outgoing_open = child_input_open = True
    received = sent = 0
    # Envelopes, evidence and acknowledgements have their own stricter protocol
    # bounds. This additional stream ceiling includes fixed public frame overhead.
    stream_limit = max_ciphertext_bytes + 32*1024**2
    try:
        for fd in descriptors: os.set_blocking(fd, False)
        while True:
            scope.assert_alive()
            exited = proc.poll() is not None
            if exited and (proc.returncode != 0 or pending_in):
                raise RuntimeError('Contained control process failed or left input unread')
            if exited and not outgoing_open and not pending_out:
                return scope.finish()
            reads = [guardian] + ([] if exited else [child_pidfd])
            if incoming_open and not exited and len(pending_in) < BUFFER: reads.append(reader)
            if outgoing_open and len(pending_out) < BUFFER: reads.append(proc.stdout.fileno())
            writes = []
            if pending_in and child_input_open and not exited: writes.append(proc.stdin.fileno())
            if pending_out: writes.append(writer)
            ready, writable, _ = select.select(reads, writes, [], 0.05)
            scope.assert_alive()
            if guardian in ready:
                raise RuntimeError('Aggregate guardian ended during transport')
            for source, buffer, direction in [(reader,pending_in,'in'),(proc.stdout.fileno(),pending_out,'out')]:
                if source not in ready: continue
                try: chunk = os.read(source, BUFFER-len(buffer))
                except BlockingIOError: continue
                if not chunk:
                    if direction == 'in': incoming_open = False
                    else: outgoing_open = False
                    continue
                buffer.extend(chunk)
                if direction == 'in': received += len(chunk)
                else: sent += len(chunk)
                if max(received, sent) > stream_limit:
                    raise ValueError('Encrypted transport exceeds the approved stream bound')
            for destination, buffer in [(proc.stdin.fileno() if child_input_open else -1,pending_in),(writer,pending_out)]:
                if destination not in writable: continue
                try: count = os.write(destination, buffer)
                except BlockingIOError: continue
                if count <= 0: raise RuntimeError('Encrypted transport made no progress')
                del buffer[:count]
            if not incoming_open and not pending_in and child_input_open:
                proc.stdin.close()
                child_input_open = False
    finally:
        # finish() closes the child pipes; restore only caller-owned descriptors.
        try:
            for fd in [reader, writer]: os.set_blocking(fd, blocking[fd])
        finally:
            scope.close()
