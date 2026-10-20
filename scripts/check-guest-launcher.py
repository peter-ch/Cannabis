#!/usr/bin/env python3
"""Owned immutable-launch and relay fault checks on actual Linux cgroups."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from compute.guest_deadline import ExecutionDeadline
from compute.guest_job import GuestJobScope
from compute.guest_launcher import relay_guest
from compute.guest_launch_snapshot import LaunchSnapshot, validate_snapshot, read_public_file
from compute.guest_resources import ResourceLimits, ResourceTreeLimits

PYTHON=str(Path(sys.executable).resolve())
def sha(file):
    with open(file,'rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def run(parent,base):
    checks={}
    with LaunchSnapshot(b'{}\n',b'{}\n',b'{}\n') as snapshot:
        expected=os.pread(snapshot.fd,4096,0)
        for mutation in [lambda:os.pwrite(snapshot.fd,b'x',0),lambda:os.ftruncate(snapshot.fd,0),
                         lambda:fcntl.fcntl(snapshot.fd,fcntl.F_ADD_SEALS,0)]:
            try:mutation()
            except OSError:pass
            else:raise AssertionError('Sealed launch mutated')
        assert os.pread(snapshot.fd,4096,0)==expected
        unsealed=os.memfd_create('cannabis-public-launch',os.MFD_ALLOW_SEALING)
        try:
            os.write(unsealed,expected)
            try:validate_snapshot(unsealed)
            except ValueError:pass
            else:raise AssertionError('Unsealed launch admitted')
        finally:os.close(unsealed)
        checks['kernelSealsPreventMutation']=True
    source=base/'public.json';source.write_bytes(b'{}\n');source.chmod(0o600)
    assert read_public_file(source,16)==b'{}\n'
    link=base/'link';link.symlink_to(source)
    fifo=base/'fifo';os.mkfifo(fifo,0o600)
    for file,limit in [(link,16),(fifo,16),(source,1),(base,16)]:
        try:read_public_file(file,limit)
        except (OSError,ValueError):pass
        else:raise AssertionError('Unsafe public input accepted')
    checks['publicInputTypeAndSizeRefusals']=True
    for mode in ['success','failed-exit','backpressure','stopped-control','guardian-death','guardian-reaped','busy-exit']:
        print('Owned outer-launch check: '+mode,file=sys.stderr,flush=True)
        marker=base/(mode+'.ready')
        program=base/(mode+'.py')
        program.write_text("import os,sys,time\nfrom pathlib import Path\n"
            +f"Path({str(marker)!r}).write_text(str(os.getpid()))\n"
            +("assert os.read(0,4)==b'PING'\nos.write(1,b'PONG')\n" if mode=='success' else
              "sys.exit(2)\n" if mode=='failed-exit' else
              "while True:os.write(1,b'x'*65536)\n" if mode=='backpressure' else
              "if os.fork()==0:\n os.setsid();time.sleep(30);os._exit(0)\nos._exit(0)\n" if mode=='busy-exit' else
              "time.sleep(30)\n"))
        program.chmod(0o600)
        to_guest,peer_write=os.pipe();peer_read,from_guest=os.pipe()
        scope=GuestJobScope(parent,ResourceTreeLimits(1000,128*1024**2,32,30,3),
            ResourceLimits(1000,64*1024**2,16,30),deadline=ExecutionDeadline(time.monotonic()+6))
        try:
            proc=scope.start(PYTHON,sha(PYTHON),str(program),sha(program))
            until=time.monotonic()+4
            while not marker.exists() and time.monotonic()<until:time.sleep(0.01)
            assert marker.exists(),'Owned relay child did not become ready'
            if mode=='success':os.write(peer_write,b'PING')
            if mode=='stopped-control':os.kill(proc.pid,signal.SIGSTOP)
            if mode in ['guardian-death','guardian-reaped']:
                os.kill(scope._guard._process.pid,signal.SIGKILL)
                if mode=='guardian-reaped':scope._guard._process.wait(timeout=5)
            os.close(peer_write);peer_write=None
            try:
                result=relay_guest(scope,proc,to_guest,from_guest,max_ciphertext_bytes=1024,max_input_ciphertext_bytes=1024)
            except EOFError:
                assert mode in ['guardian-death','guardian-reaped']
            except (RuntimeError,ValueError,OSError):
                assert mode!='success'
            else:
                assert mode=='success' and result['reason']=='finished'
                assert os.read(peer_read,4)==b'PONG'
            assert proc.poll() is not None and not scope.path.exists()
            assert scope._control._fd is None and scope._control._parent is None
            assert os.get_blocking(to_guest) and os.get_blocking(from_guest)
            checks[mode]=True
        finally:
            scope.close()
            for fd in [to_guest,peer_write,peer_read,from_guest]:
                if fd is not None:os.close(fd)
    return checks


def main():
    parent=Path('/sys/fs/cgroup')/('cannabis-launcher-check-'+uuid.uuid4().hex)
    parent.mkdir(mode=0o700)
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        with tempfile.TemporaryDirectory(prefix='cannabis-launcher-check-',dir='/run') as directory:
            checks=run(parent,Path(directory))
        print(json.dumps({'schema':'cannabis.guest-launcher-check.v1','kernel':os.uname().release,'checks':checks,
            'hardwareValidated':False,'customerKeysUsed':False,'customerCodeExecuted':False,'realPaidJob':False}))
    finally:parent.rmdir()


if __name__=='__main__':main()
