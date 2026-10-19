#!/usr/bin/env python3
"""Owned kernel checks for boot intake, outer supervision and PID-namespace retirement.

Power-off checks first create a fresh PID namespace. They cannot power off the
machine running these checks. No customer keys, hardware evidence or paid job.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from compute.guest_boot import (MAGIC,STAGED,VmProcessTree,VmRetirement,arm_watchdog,
    encode_public_launch,receive_public_launch,supervise_launcher)
from compute.guest_resources import JobResourceGroup,ResourceLimits,ResourceTreeLimits,_read,_verify,_write
from compute.guest_vm import VmBudget


def budget():
    profile=ROOT/'vm-profile.json'
    if not profile.is_file():profile=ROOT/'compute/guest-image/vm-profile.json'
    value=json.loads(profile.read_text())
    value['outer'].update(memory_bytes=64*1024**2,processes=16,wall_seconds=15)
    value['job'].update(memory_bytes=128*1024**2,processes=32,wall_seconds=15)
    return VmBudget(value)


def actor(mode,parent):
    owned=budget();outer=Path(parent)/'cannabis-outer';slot=Path(parent)/'cannabis-jobs'
    assert str(os.getpid()) in (outer/'cgroup.procs').read_text().split()
    assert (outer/'memory.max').read_text().strip()==str(owned.outer.memory_bytes)
    assert all('cgroup' not in os.readlink('/proc/self/fd/'+fd) for fd in os.listdir('/proc/self/fd')
               if fd.isdigit() and int(fd)>2 and Path('/proc/self/fd/'+fd).exists())
    os.write(1,b'R')
    if mode=='normal':return
    if mode=='failed':raise SystemExit(3)
    if mode=='busy':
        if os.fork()==0:
            os.setsid();time.sleep(60);os._exit(0)
        return
    if mode=='changed':
        (outer/'cpu.max').write_text('1000 100000')
    if mode=='stopped':os.kill(os.getpid(),signal.SIGSTOP)
    if mode=='oom':
        total=JobResourceGroup(slot,owned.job)
        leaf=JobResourceGroup(total.path,ResourceLimits(100,32*1024**2,4,15))
        r,w=os.pipe()
        child=os.fork()
        if child==0:
            os.close(r)
            (leaf.path/'cgroup.procs').write_text('0')
            os.write(w,b'J');os.close(w);time.sleep(60);os._exit(0)
        os.close(w)
        assert os.read(r,1)==b'J';os.close(r)
        guardian=os.fork()
        if guardian==0:time.sleep(60);os._exit(0)
        # The actual outer group OOM kills its owner and inherited guardian.
        # The separate job leaf must still be killed by the surviving supervisor.
        data=bytearray(128*1024**2)
        for n in range(0,len(data),4096):data[n]=1
        raise AssertionError('Outer OOM did not occur')
    time.sleep(60)


def namespace_case(mode):
    assert os.getpid()!=1
    libc=ctypes.CDLL(None,use_errno=True)
    assert libc.unshare(0x20000000|0x20000)==0  # New PID and mount namespaces.
    assert libc.mount(None,b'/',None,ctypes.c_ulong(16384|262144),None)==0
    child=os.fork()
    if child==0:
        assert os.getpid()==1
        assert libc.mount(b'proc',b'/proc',b'proc',ctypes.c_ulong(2|4|8),None)==0
        retire=VmRetirement()
        if mode=='direct':retire()
        pid,fd,lifeline=arm_watchdog(retire,time.monotonic()+2)
        if mode=='lifeline':lifeline.close()
        if mode=='watchdog-loss':
            os.kill(pid,signal.SIGKILL)
            assert select.select([fd],[],[],5)[0]
            retire()
        time.sleep(60)
        os._exit(99)
    _,status=os.waitpid(child,0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGINT, status
    print(json.dumps({'namespaceRetired':True,'mode':mode}))


def intake_checks(directory):
    checks={}
    good=(b'{"public":true}',b'{}',b'{"request":"owned"}')
    for mode in ['success','oversize','truncated','deadline','watchdog']:
        a,b=socket.socketpair();guard,held=socket.socketpair()
        path=directory/mode
        try:
            prefix=encode_public_launch(*good)
            if mode=='oversize':prefix=MAGIC+struct.pack('!III',256*1024+1,2,2)
            if mode=='truncated':prefix=prefix[:-2]
            if mode=='deadline':prefix=MAGIC[:2]
            b.sendall(prefix+(b'UNREAD' if mode=='success' else b''))
            if mode=='truncated':b.shutdown(socket.SHUT_WR)
            if mode=='watchdog':held.close()
            error=None
            try:receive_public_launch(a.fileno(),path,time.monotonic()+(0.15 if mode=='deadline' else 5),watchdog=guard.fileno())
            except (ValueError,EOFError,TimeoutError,RuntimeError) as caught:error=caught
            if mode=='success':
                assert error is None,error
                assert tuple((path/name).read_bytes() for name in ['configuration.json','initialization.json','request.json'])==good
                assert all(stat.S_IMODE(p.stat().st_mode)==0o400 for p in path.iterdir())
                assert os.read(a.fileno(),6)==b'UNREAD'
            else:
                assert error is not None,mode
                if mode in ['oversize','watchdog']:assert not path.exists()
            checks[{'success':'boundedPrefixAndStreamBoundary','oversize':'oversizedPrefixRefused',
                'truncated':'truncatedPrefixRefused','deadline':'intakeDeadline','watchdog':'intakeWatchdogLoss'}[mode]]=True
        finally:a.close();b.close();guard.close();held.close()
    return checks


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--busybox',default='/bin/busybox')
    args=parser.parse_args()
    assert os.geteuid()==0 and sys.platform=='linux' and os.getpid()!=1
    assert Path(args.busybox).is_file()
    checks={}
    try:VmRetirement()
    except ValueError:checks['retirementOutsidePID1Refused']=True
    else:raise AssertionError('Host retirement guard bypassed')
    with tempfile.TemporaryDirectory(prefix='cannabis-boot-check-') as tmp:
        checks.update(intake_checks(Path(tmp)))
    parent=Path('/sys/fs/cgroup')/('cannabis-boot-check-'+uuid.uuid4().hex)
    parent.mkdir(mode=0o700)
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        occupied=parent/'cannabis-jobs';occupied.mkdir(mode=0o700)
        try:
            try:VmProcessTree(budget(),parent)
            except FileExistsError:pass
            else:raise AssertionError('Existing group was adopted')
            assert occupied.exists() and not (parent/'cannabis-outer').exists()
            checks['existingGroupPreserved']=True
        finally:occupied.rmdir()
        for mode,name in [('normal','boundedLauncherAndRetirement'),('failed','failedLauncherRetired'),
                ('busy','detachedTailRefusedAndRetired'),('stopped','stoppedLauncherDeadline'),
                ('changed','changedControlsRefused'),('oom','outerOOMAndSeparateJobRetired'),
                ('watchdog','watchdogLossRetiresLauncher'),('disconnect','transportLossRetiresLauncher')]:
            tree=VmProcessTree(budget(),parent)
            a,b=socket.socketpair();reader,writer=os.pipe();guard,held=socket.socketpair()
            try:
                if mode=='watchdog':held.close()
                if mode=='disconnect':b.close()
                failure=None
                try:
                    supervise_launcher(tree,[sys.executable,'-I','-B',str(Path(__file__).resolve()),'actor',
                        mode,str(parent)],a.fileno(),writer,time.monotonic()+(1 if mode=='stopped' else 15),
                        guard.fileno(),busybox=args.busybox)
                except (ValueError,RuntimeError,TimeoutError,EOFError) as error:failure=error
                if mode=='normal':assert failure is None,failure
                else:assert failure is not None,mode
                assert tree.closed and not tree.outer.exists() and not tree.jobs.exists()
                os.close(writer);writer=None
                observed=os.read(reader,4096)
                if mode not in ['watchdog','disconnect','stopped']:assert observed==b'R',(mode,observed)
                checks[name]=True
            finally:
                tree.close();a.close();b.close();guard.close();held.close();os.close(reader)
                if writer is not None:os.close(writer)
        assert all(not p.is_dir() for p in parent.iterdir())
    finally:parent.rmdir()
    for mode,name in [('direct','PID1NamespacePoweroff'),('deadline','watchdogRetiresHungPID1'),
            ('lifeline','ownerLifelineLossRetiresNamespace'),('watchdog-loss','watchdogFailureRetiresNamespace')]:
        result=subprocess.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),'namespace',mode],
            capture_output=True,text=True,timeout=15)
        assert result.returncode==0,(mode,result.stderr[-2048:])
        assert json.loads(result.stdout)=={'namespaceRetired':True,'mode':mode}
        checks[name]=True
    print(json.dumps({'schema':'cannabis.guest-boot-supervision-check.v1','kernel':os.uname().release,
        'checks':checks,'realVMRetirementChecked':False,'hardwareValidated':False,'customerKeysUsed':False,'realPaidJob':False}))


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='actor':actor(*sys.argv[2:])
    elif len(sys.argv)>1 and sys.argv[1]=='namespace':namespace_case(*sys.argv[2:])
    else:main()
