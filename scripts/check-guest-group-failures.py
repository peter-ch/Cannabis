#!/usr/bin/env python3
"""Owned Linux lifecycle checks for private group networking, without workload keys."""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from compute.guest_deadline import ExecutionDeadline
from compute.guest_group_network import GuestGroupNetwork
from compute.guest_job import GuestJobScope
from compute.guest_resources import ResourceLimits, ResourceTreeLimits

CASES=('pumpDeath','queuedHeartbeatStall','inputEof','invalidFrame','wrongRankPacket',
       'serviceExpiry','namespaceReplacement','nonPrivateDescriptor','creationFailureCleanup','ownerDeath','cancellation')
GROUP={'schema':'cannabis.guest-group-network.v1','rank':0,'worldSize':2,
       'groupDigest':'0x'+'31'*32,'maxBufferedBytes':131072}


def wait_dead(network):
    assert select.select([network.pidfd],[],[],3)[0], 'Owned pump did not terminate'
    assert network.is_set(), 'Dead pump was accepted'


def child():
    case=json.loads(sys.stdin.readline())['case']
    assert case in CASES
    incoming,writer=socket.socketpair()
    reader,outgoing=socket.socketpair()
    network=None
    try:
        deadline=ExecutionDeadline(time.monotonic()+(1.5 if case=='serviceExpiry' else 25))
        if case=='creationFailureCleanup':
            real_fork=os.fork
            for fail_at in (1,2):
                calls=0
                before=set(os.listdir('/proc/self/fd'))
                def refused_fork():
                    nonlocal calls
                    calls+=1
                    if calls==fail_at: raise OSError('Owned process-capacity refusal')
                    return real_fork()
                os.fork=refused_fork
                try:
                    try: GuestGroupNetwork.create(GROUP,deadline,incoming.fileno(),outgoing.fileno())
                    except OSError: pass
                    else: raise AssertionError('Owned fork refusal was ignored')
                finally: os.fork=real_fork
                assert set(os.listdir('/proc/self/fd'))==before, 'Creation failure leaked a descriptor'
            print(json.dumps({'case':case,'passed':True}),flush=True)
            return
        if case=='nonPrivateDescriptor':
            before=set(os.listdir('/proc/self/fd'))
            with open('/dev/null','rb') as invalid:
                try: GuestGroupNetwork.create(GROUP,deadline,invalid.fileno(),outgoing.fileno())
                except RuntimeError: pass
                else: raise AssertionError('Non-private input descriptor accepted')
            assert set(os.listdir('/proc/self/fd'))==before
            print(json.dumps({'case':case,'passed':True}),flush=True)
            return
        network=GuestGroupNetwork.create(GROUP,deadline,incoming.fileno(),outgoing.fileno())
        if case in ('ownerDeath','cancellation'):
            print(json.dumps({'case':case,'pump':network.pid}),flush=True)
            while True: signal.pause()
        if case=='pumpDeath':
            os.kill(network.pid,signal.SIGKILL);wait_dead(network)
        elif case=='queuedHeartbeatStall':
            # Leave real heartbeats queued before stopping the producer. Reading
            # those stale messages must not reset the consumer's freshness clock.
            time.sleep(0.7);os.kill(network.pid,signal.SIGSTOP);time.sleep(5.2)
            assert network.is_set(), 'Queued old heartbeat revived a stopped pump'
        elif case=='inputEof':
            writer.close();wait_dead(network)
        elif case=='invalidFrame':
            writer.sendall(struct.pack('!I',1281));wait_dead(network)
        elif case=='wrongRankPacket':
            packet=bytearray(28);packet[0]=0x45;struct.pack_into('!H',packet,2,len(packet));packet[8]=64;packet[9]=17
            packet[12:16]=bytes([10,211,0,3]);packet[16:20]=bytes([10,211,0,1]);struct.pack_into('!H',packet,24,8)
            writer.sendall(struct.pack('!I',len(packet))+packet);wait_dead(network)
        elif case=='serviceExpiry':
            time.sleep(max(0,deadline.monotonic_end-time.monotonic())+0.1);wait_dead(network)
        elif case=='namespaceReplacement':
            fd=os.open('/proc/self/ns/net',os.O_RDONLY)
            try: os.dup2(fd,network.namespace_fd)
            finally: os.close(fd)
            assert network.is_set(), 'Changed namespace descriptor accepted'
        if case not in ('queuedHeartbeatStall','namespaceReplacement'):
            try: network.close()
            except RuntimeError: pass
            else: raise AssertionError('Failed pump reported clean retirement')
        else:
            network.close(failed=True)
        assert network.closed and network.pid is None and network.pidfd is None and network.namespace_fd is None and network.tun_fd is None
        print(json.dumps({'case':case,'passed':True}),flush=True)
    finally:
        if network: network.close(failed=True)
        for channel in (incoming,writer,reader,outgoing): channel.close()


def sha(file):
    with Path(file).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parent=Path('/sys/fs/cgroup')/('cannabis-group-failure-'+uuid.uuid4().hex)
    parent.mkdir(mode=0o700)
    owned=Path(tempfile.mkdtemp(prefix='cannabis-group-failure-',dir='/run'))
    try:
        script=owned/'control.py'
        original=Path(__file__).read_text().splitlines();root_line='ROOT=Path(__file__).resolve().parents[1]'
        assert original.count(root_line)==1
        script.write_text('\n'.join('ROOT=Path('+repr(str(ROOT))+')' if line==root_line else line for line in original)+'\n')
        script.chmod(0o600)
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        checks={}
        for case in CASES:
            scope=GuestJobScope(parent,ResourceTreeLimits(1000,192*1024**2,48,30,2),
                ResourceLimits(1000,128*1024**2,32,30),deadline=ExecutionDeadline(time.monotonic()+30))
            pumpfd=None
            try:
                python=str(Path(sys.executable).resolve())
                proc=scope.start(python,sha(python),str(script),sha(script))
                proc.stdin.write((json.dumps({'case':case})+'\n').encode());proc.stdin.close()
                assert select.select([proc.stdout],[],[],20)[0], 'Owned failure case did not report'
                raw=proc.stdout.readline(4097)
                assert raw and len(raw)<=4096, 'Owned failure case ended without its result: '+case
                report=json.loads(raw)
                assert report['case']==case
                if case in ('ownerDeath','cancellation'):
                    pumpfd=os.pidfd_open(report['pump'])
                    if case=='ownerDeath':
                        proc.kill();assert select.select([pumpfd],[],[],3)[0], 'Pump outlived its owner'
                    scope.close()
                    assert select.select([pumpfd],[],[],0)[0], 'Pump survived rank cancellation'
                    proc.wait(timeout=5)
                else:
                    assert report=={'case':case,'passed':True} and proc.wait(timeout=5)==0, report
                    assert scope.finish()['reason']=='finished'
                checks[case]=True
            finally:
                scope.close()
                if pumpfd is not None: os.close(pumpfd)
            assert not list(parent.glob('job-*')), 'Failure left a rank job tree'
        checks['wholeTreeCleanup']=True
        print(json.dumps({'schema':'cannabis.guest-group-failure-check.v1','checks':checks,
                          'hardwareValidated':False,'realPaidJob':False}))
    finally:
        parent.rmdir()
        script.unlink();owned.rmdir()


if __name__=='__main__':
    if os.environ.get('CANNABIS_JOB_CONTROL'):
        try: child()
        except BaseException:
            import traceback
            print(json.dumps({'failed':True,'ownedFixtureTrace':traceback.format_exc()[-4096:]}),flush=True)
            raise SystemExit(1)
    else: main()
