#!/usr/bin/env python3
"""Actual measured-layout and outer-admission checks inside the owned guest VM."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from compute.guest_vm import image_vm_budget, VmAdmission
from compute.guest_resources import JobResourceGroup, ResourceTreeLimits, join_current_process
from compute.guest_sandbox import enter_private_mount_namespace, _call, _libc


def actor(mode,path=None,slot=None):
    budget=image_vm_budget()
    if mode=='cpu':
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        try:budget.capacity()
        except ValueError:return
        raise AssertionError('Insufficient allowed CPUs accepted')
    if mode=='mount':
        enter_private_mount_namespace()
        _call(_libc().mount(b'tmpfs',b'/tmp',b'tmpfs',2|4|8,b'size=32m,nr_inodes=4096,mode=1777,noswap'))
        try:budget.verify_layout()
        except ValueError:return
        raise AssertionError('Changed actual mount quota accepted')
    if mode!='uncontained':join_current_process(path,budget.outer)
    print('ready',flush=True)
    if sys.stdin.readline()!='continue\n':raise ValueError('Missing owned gate')
    try:
        with VmAdmission(budget,outer=path,jobs=slot) as admitted:
            total=budget.job
            if mode=='overbudget':total=ResourceTreeLimits(**{**asdict(total),'memory_bytes':total.memory_bytes+4096})
            admitted.budget.admit_service(total)
            if mode=='normal':
                with JobResourceGroup(slot,budget.job) as aggregate:
                    with JobResourceGroup(aggregate.path,budget.outer):pass
            admitted.verify()
    except ValueError:
        if mode in ['uncontained','changed','slot-changed','overbudget']:return
        raise
    if mode!='normal':raise AssertionError('Unsafe outer admission accepted')


def main():
    budget=image_vm_budget();observed=budget.verify_layout()
    checks={'measuredCapacityAndLayout':True}
    script=str(Path(__file__).resolve())
    for mode,name in [('cpu','smallerCpuSetRefused'),('mount','changedMountQuotaRefused')]:
        subprocess.run([sys.executable,'-I','-B',script,'actor',mode],check=True,timeout=30)
        budget.verify_layout()  # Child-only changes must not change the boot layout.
        checks[name]=True
    parent=Path('/sys/fs/cgroup')/('cannabis-vm-check-'+uuid.uuid4().hex)
    parent.mkdir(mode=0o700)
    slot=parent/'slot'
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        slot.mkdir(mode=0o700)
        for name,value in budget.job_parent_controls().items():(slot/name).write_text(value)
        if (slot/'memory.zswap.max').exists():(slot/'memory.zswap.max').write_text('0')
        (slot/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        for mode,name in [('normal','outerAdmission'),('uncontained','uncontainedLauncherRefused'),
                          ('changed','changedOuterLimitRefused'),('slot-changed','changedJobParentRefused'),('overbudget','oversizedJobRefused')]:
            group=JobResourceGroup(parent,budget.outer);proc=None
            try:
                proc=subprocess.Popen([sys.executable,'-I','-B',script,'actor',mode,str(group.path),str(slot)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                if not select.select([proc.stdout],[],[],15)[0] or proc.stdout.readline()!='ready\n':
                    raise RuntimeError('Owned outer admission did not become ready')
                if mode=='changed':(group.path/'memory.max').write_text(str(budget.outer.memory_bytes-4096))
                if mode=='slot-changed':(slot/'memory.max').write_text(str(budget.job.memory_bytes-4096))
                proc.stdin.write('continue\n');proc.stdin.flush()
                out,error=proc.communicate(timeout=30)
                if proc.returncode or out or error:raise RuntimeError('Owned outer admission failed: '+error[-2048:])
            finally:
                if proc:
                    if proc.poll() is None:proc.kill()
                    proc.wait(timeout=5)
                    for stream in [proc.stdin,proc.stdout,proc.stderr]:
                        if stream:stream.close()
                group.close()
                if mode=='slot-changed':(slot/'memory.max').write_text(str(budget.job.memory_bytes))
            assert not group.path.exists()
            checks[name]=True
        slot.rmdir()
        assert all(not p.is_dir() for p in parent.iterdir())
        checks['outerTreeRetired']=True
    finally:
        if slot.exists():slot.rmdir()
        parent.rmdir()
    print(json.dumps({'schema':'cannabis.guest-vm-check.v1','kernel':os.uname().release,
        'checks':checks,'capacity':observed,'profile':budget.value,
        'hardwareValidated':False,'providerCapacityCommitted':False,'realPaidJob':False,'customerKeysUsed':False}))


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='actor':actor(*sys.argv[2:])
    else:main()
