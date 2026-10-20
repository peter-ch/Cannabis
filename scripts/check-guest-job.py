#!/usr/bin/env python3
"""Real kernel checks for aggregate jobs and key-holding process lifetime."""
from dataclasses import asdict
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from compute.guest_deadline import ExecutionDeadline
from compute.guest_guardian import GuardedResources
from compute.guest_job import GuestJobScope
from compute.guest_resources import JobResourceGroup, ResourceLimits, ResourceTreeLimits, join_current_process

SCRIPT = str(Path(__file__).resolve())
PYTHON = str(Path(sys.executable).resolve())
MIB = 1024**2


def ready(proc, seconds=15):
    if not select.select([proc.stdout], [], [], seconds)[0]:
        raise RuntimeError('Owned control readiness expired')
    line = proc.stdout.readline(4097)
    if not line or len(line) > 4096:
        raise RuntimeError('Owned control did not become ready')
    return json.loads(line)


def dispose(proc):
    if proc.poll() is None: proc.kill()
    proc.wait(timeout=5)
    for stream in [proc.stdin, proc.stdout, proc.stderr]:
        if stream: stream.close()


def member(path, limits, mode):
    join_current_process(path, ResourceLimits(**json.loads(limits)))
    signal.alarm(60)
    print(json.dumps({'pid':os.getpid()}), flush=True)
    sys.stdin.readline()
    if mode == 'memory':
        allocation = bytearray(40*MIB)
        time.sleep(45)
    elif mode == 'pids':
        children = []
        blocked = False
        for _ in range(10):
            try: pid = os.fork()
            except BlockingIOError:
                blocked = True
                break
            if pid == 0:
                os.setsid(); time.sleep(45); os._exit(0)
            children.append(pid)
        print(json.dumps({'forked':len(children),'blocked':blocked}), flush=True)
        time.sleep(45)


def spawn_member(group, mode):
    return subprocess.Popen([PYTHON, '-I', '-B', SCRIPT, '--member', str(group.path),
        json.dumps(asdict(group.limits)), mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True)


def make_program(base):
    path = base/'owned-control.py'
    path.write_text('''import json,os,sys,time
from pathlib import Path
sys.path.insert(0, ROOT)
from compute.guest_resources import JobResourceGroup,ResourceLimits,join_current_process
request=json.loads(sys.stdin.readline(4096))
limits=ResourceLimits(1000,128*1024**2,16,60)
group=JobResourceGroup(os.environ['CANNABIS_JOB_CGROUP'],limits)
reader,writer=os.pipe()
child=os.fork()
if child==0:
 os.close(reader)
 join_current_process(group.path,limits)
 os.setsid()
 os.write(writer,b'1');os.close(writer)
 time.sleep(45);os._exit(0)
os.close(writer);assert os.read(reader,1)==b'1';os.close(reader)
print(json.dumps({'control':os.getpid(),'workload':child,'leaf':str(group.path),'controlGroup':os.environ['CANNABIS_JOB_CONTROL']}),flush=True)
if request['mode']=='success':
 group.close();os.waitpid(child,0);sys.exit(0)
if request['mode']=='exit-busy':
 os._exit(0)
time.sleep(45)
'''.replace('ROOT', repr(str(ROOT))), encoding='utf-8')
    path.chmod(0o600)
    return path


def start_scope(parent, program, mode, seconds=30, control_seconds=60):
    scope = GuestJobScope(parent, ResourceTreeLimits(1000,256*MIB,64,60,4),
                          ResourceLimits(1000,192*MIB,48,control_seconds), deadline=ExecutionDeadline(time.monotonic()+seconds))
    proc = scope.start(PYTHON, hashlib.sha256(Path(PYTHON).read_bytes()).hexdigest(),
                       str(program), hashlib.sha256(program.read_bytes()).hexdigest())
    proc.stdin.write(json.dumps({'mode':mode}).encode()+b'\n'); proc.stdin.flush()
    return scope,proc


def owner(parent, program):
    scope,proc=start_scope(parent,Path(program),'sleep')
    state=ready(proc)
    print(json.dumps({**state,'tree':str(scope.path),'guardian':scope._guard._process.pid}),flush=True)
    time.sleep(45)
    scope.close()


def run(parent, base):
    checks={}
    total=ResourceTreeLimits(1000,64*MIB,16,30,2)
    leaf=ResourceLimits(1000,128*MIB,16,30)
    with GuardedResources(parent,total) as guard:
        a,b=JobResourceGroup(guard.path,leaf),JobResourceGroup(guard.path,leaf)
        try:
            try: JobResourceGroup(guard.path,leaf)
            except OSError: checks['childCountBound']=True
            else: raise AssertionError('Extra child group admitted')
            try: join_current_process(guard.path,total)
            except ValueError: checks['parentEntryRejected']=True
            else: raise AssertionError('Controller parent accepted a process')
        finally:
            guard.close();a.close();b.close()
        assert not guard.path.exists()
        checks['retainedLeafHandlesAfterParentCleanup']=True
    with GuardedResources(parent,total) as guard:
        # The creator may die immediately after mkdir, before writing controls.
        (guard.path/'partially-created').mkdir(mode=0o700)
        guard.close(); assert not guard.path.exists()
        checks['partialLeafCleanup']=True
    for mode in ['memory','pids']:
        limits=ResourceTreeLimits(1000,64*MIB if mode=='memory' else 256*MIB,4 if mode=='pids' else 16,45,2)
        with GuardedResources(parent,limits) as guard:
            groups=[JobResourceGroup(guard.path,leaf) for _ in range(2)]
            processes=[spawn_member(g,mode) for g in groups]
            try:
                for proc in processes: ready(proc)
                for proc in processes: proc.stdin.write(b'begin\n');proc.stdin.flush()
                if mode=='memory':
                    for proc in processes: assert proc.wait(timeout=20)==-signal.SIGKILL
                    snapshot=guard._group.snapshot()
                    assert snapshot['memory']['oom_group_kill']>0 and snapshot['memory']['oom_kill']>=2
                    checks['aggregateOOMKillsAllLeaves']=True
                else:
                    spawned=[ready(proc) for proc in processes]
                    # Older kernels attribute a failed fork to the originating
                    # leaf's pids.events. Observe actual aggregate occupancy and
                    # both refused fork calls, without assuming counter locality.
                    assert sum(s['forked'] for s in spawned)==2 and all(s['blocked'] for s in spawned)
                    assert int((guard.path/'pids.current').read_text())==4
                    checks['aggregatePIDLimit']=True
                guard.close()
                assert not guard.path.exists()
            finally:
                guard.close()
                for proc in processes: dispose(proc)
                for group in groups: group.close()
    program=make_program(base)
    for mode in ['success','exit-busy','stopped-control','deadline','short-control']:
        scope,proc=start_scope(parent,program,mode,15 if mode in ['stopped-control','deadline'] else 30,
                               6 if mode=='short-control' else 60)
        state=ready(proc)
        descriptors=[os.pidfd_open(state[k]) for k in ['control','workload']]
        try:
            assert state['controlGroup'].startswith(str(scope.path)+'/')
            if mode=='success':
                assert proc.wait(timeout=5)==0
                assert scope.finish()['reason']=='finished'
                checks['pinnedControlAndWorkloadCompletion']=True
            elif mode=='exit-busy':
                assert proc.wait(timeout=5)==0
                try: scope.finish()
                except RuntimeError: checks['busyControlExitRefused']=True
                else: raise AssertionError('Living workload accepted after control exit')
            else:
                # The scope owner remains responsive; the key-holding process
                # is the stopped control child. The guardian's own deadline wins.
                if mode=='stopped-control': os.kill(state['control'],signal.SIGSTOP)
                result=scope._guard.wait()
                assert result['reason']=='deadline'
                name = {'stopped-control':'stoppedControlAndDetachedWorkloadRetired',
                        'short-control':'shorterControlDeadlineBoundsWholeTree'}.get(mode,'wholeTreeDeadline')
                checks[name]=True
            for fd in descriptors: assert select.select([fd],[],[],5)[0]
            assert not scope.path.exists()
        finally:
            for fd in descriptors: os.close(fd)
            scope.close()
    for stop in [False,True]:
        actor=subprocess.Popen([PYTHON,'-I','-B',SCRIPT,'--owner',str(parent),str(program)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,bufsize=0,start_new_session=True)
        state=ready(actor)
        descriptors=[os.pidfd_open(state[k]) for k in ['control','workload']]
        try:
            os.kill(actor.pid,signal.SIGSTOP if stop else signal.SIGKILL)
            for fd in descriptors: assert select.select([fd],[],[],40 if stop else 10)[0]
            end=time.monotonic()+5
            while Path(state['tree']).exists() and time.monotonic()<end: time.sleep(0.02)
            assert not Path(state['tree']).exists()
            checks['stoppedOuterOwnerDeadline' if stop else 'outerOwnerDeathRetiresControlAndWorkload']=True
        finally:
            for fd in descriptors: os.close(fd)
            dispose(actor)
    return checks


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--parent',type=Path,default=Path('/sys/fs/cgroup'))
    args=parser.parse_args()
    parent=args.parent/('cannabis-job-check-'+uuid.uuid4().hex)
    parent.mkdir(mode=0o700)
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        with tempfile.TemporaryDirectory(prefix='cannabis-job-check-',dir='/run') as directory:
            checks=run(parent,Path(directory))
        print(json.dumps({'schema':'cannabis.guest-job-check.v1','kernel':os.uname().release,
            'checks':checks,'customerCodeExecuted':False,'hardwareValidated':False,'realPaidJob':False}))
    finally: parent.rmdir()


if __name__=='__main__':
    if len(sys.argv)==5 and sys.argv[1]=='--member': member(*sys.argv[2:])
    elif len(sys.argv)==4 and sys.argv[1]=='--owner': owner(*sys.argv[2:])
    else: main()
