"""Measured guest capacity/layout admission, distinct from host commitments.

The budget includes root/runtime pages, both early root copies, the boot archive,
volatile mounts, the outer launcher, the job and explicit kernel/PID-1 headroom.
Kernel views and ceilings do not prove confidential hardware, physical provider
reservations, a hard kernel-memory bound, or whole-VM disposal/rollback protection.
"""
from dataclasses import asdict
import copy
import json
import os
from pathlib import Path
import stat

from .guest_resources import ResourceLimits, ResourceTreeLimits, _directory, _read, _verify
from .guest_sandbox import ScratchLimits, _tmpfs
from .guest_launch_snapshot import read_public_file

PROFILE=Path('/opt/cannabis/vm-profile.json')
OUTER=Path('/sys/fs/cgroup/cannabis-outer')
JOBS=Path('/sys/fs/cgroup/cannabis-jobs')
MOUNTS={'root':('/',0o755,False),'run':('/run',0o700,False),
        'tmp':('/tmp',0o1777,True),'shm':('/dev/shm',0o700,True)}


def exact(value, names):
    if not isinstance(value,dict) or set(value)!=set(names):raise ValueError('Invalid measured VM budget')


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Ambiguous VM budget')
        result[key]=value
    return result


class VmBudget:
    def __init__(self,value):
        value=copy.deepcopy(value)
        exact(value,['schema','root','volatile','outer','job','kernelReserveBytes',
                     'kernelReserveCPUMillis','bootArchiveBytes','referenceVM'])
        if value['schema']!='cannabis.guest-vm-budget.v1':raise ValueError('Unsupported VM budget')
        exact(value['volatile'],['run','tmp','shm'])
        exact(value['referenceVM'],['cpus','memoryMiB'])
        self.root=ScratchLimits(**value['root'])
        self.volatile={name:ScratchLimits(**item) for name,item in value['volatile'].items()}
        self.outer=ResourceLimits(**value['outer']);self.job=ResourceTreeLimits(**value['job'])
        for name,low,high in [('kernelReserveBytes',64*1024**2,1024**4),
                ('bootArchiveBytes',16*1024**2,1024**4),('kernelReserveCPUMillis',100,4096000)]:
            n=value[name]
            if type(n) is not int or not low<=n<=high or name.endswith('Bytes') and n%4096:
                raise ValueError('Require explicit bounded boot/kernel headroom')
        if self.job.wall_seconds>self.outer.wall_seconds:raise ValueError('Outer lifetime cannot cover job')
        common=self.root.bytes+sum(v.bytes for v in self.volatile.values())+self.outer.memory_bytes+value['kernelReserveBytes']
        self.steady_memory=common+self.job.memory_bytes
        self.boot_memory=common+self.root.bytes+value['bootArchiveBytes']
        self.minimum_memory=max(self.steady_memory,self.boot_memory)
        self.minimum_cpus=(self.job.cpu_millis+self.outer.cpu_millis+value['kernelReserveCPUMillis']+999)//1000
        ref=value['referenceVM']
        if (type(ref['cpus']) is not int or not self.minimum_cpus<=ref['cpus']<=256
                or type(ref['memoryMiB']) is not int or not self.minimum_memory<=ref['memoryMiB']*1024**2<=1024**4):
            raise ValueError('Reference VM cannot cover the complete budget')
        self.value=value

    def admit_service(self,total):
        if type(total) is not ResourceTreeLimits:raise ValueError('Require the signed aggregate job profile')
        if any(n>asdict(self.job)[key] for key,n in asdict(total).items()):
            raise ValueError('Signed job exceeds the measured VM budget')

    def job_parent_controls(self):
        # One aggregate job and its bounded leaves live below an empty slot.
        # The VM boot, not the per-job scope, creates and owns this parent.
        return {**self.job.controls(),'cgroup.max.depth':'2',
                'cgroup.max.descendants':str(self.job.children+1)}

    def verify_job_parent(self,fd):
        if (_read(fd,'cgroup.type')!='domain' or _read(fd,'cgroup.procs')
                or not {'cpu','memory','pids'}<=set(_read(fd,'cgroup.subtree_control').split())
                or any(_read(fd,k)!=v for k,v in self.job_parent_controls().items())
                or 'memory.zswap.max' in os.listdir(fd) and _read(fd,'memory.zswap.max')!='0'
                or any(stat.S_ISDIR(os.stat(p,dir_fd=fd,follow_symlinks=False).st_mode) for p in os.listdir(fd))):
            raise ValueError('Require the empty, bounded VM job parent')

    def mount_options(self,name):
        _,mode,noexec=MOUNTS[name]
        limits=self.root if name=='root' else self.volatile[name]
        return f'nosuid,nodev,noswap,{"noexec," if noexec else ""}mode={mode:04o},size={limits.bytes},nr_inodes={limits.inodes}'

    def capacity(self):
        rows={}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key,value=line.split(':',1);rows[key]=value.strip()
        def memory(name):
            fields=rows[name].split()
            if len(fields)!=2 or fields[1]!='kB' or not fields[0].isdecimal():raise ValueError('Invalid kernel memory view')
            return int(fields[0])*1024
        memory_bytes=memory('MemTotal');cpus=len(os.sched_getaffinity(0))
        if memory_bytes<self.minimum_memory or cpus<self.minimum_cpus:
            raise ValueError('Guest-visible memory or CPUs cannot cover the measured budget')
        if memory('SwapTotal')!=0 or len(Path('/proc/swaps').read_text().splitlines())!=1:
            raise ValueError('Guest swap must be absent')
        return {'memoryBytes':memory_bytes,'availableCPUs':cpus,
                'minimumMemoryBytes':self.minimum_memory,'minimumCPUs':self.minimum_cpus}

    def verify_layout(self):
        observed=self.capacity()
        for name,(path,mode,noexec) in MOUNTS.items():
            limits=self.root if name=='root' else self.volatile[name]
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                _tmpfs(fd)
                info,space=os.fstat(fd),os.fstatvfs(fd)
                fields=dict(line.split(':',1) for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines() if ':' in line)
                rows=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
                      if line.split()[0]==fields.get('mnt_id','').strip()]
                required={'rw','nosuid','nodev'}|({'noexec'} if noexec else set())
                if (len(rows)!=1 or rows[0][4]!=path or not required<=set(rows[0][5].split(','))
                        or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=mode
                        or space.f_blocks*space.f_frsize!=limits.bytes or space.f_files!=limits.inodes):
                    raise ValueError('Guest mount differs from the measured VM budget')
            finally:os.close(fd)
        return observed


def image_vm_budget():
    return VmBudget(json.loads(read_public_file(PROFILE,16384),object_pairs_hook=unique))


class VmAdmission:
    """Retain the actual outer leaf; the fixed entry supplies the measured budget.

    The operating boot must create this leaf and start the launcher inside it.
    Admission never moves an already-running unbounded launcher into a group:
    earlier allocations would remain charged to its previous group.
    """
    def __init__(self,budget,*,outer=OUTER,jobs=JOBS):
        if not isinstance(budget,VmBudget):raise ValueError('Require the measured VM budget')
        self.budget,self.path,self.fd=budget,Path(outer),None
        self.job_parent,self.job_fd=Path(jobs),None
        try:
            self.fd=_directory(self.path)
            self.job_fd=_directory(self.job_parent)
            self.verify()
        except BaseException:self.close();raise

    def verify(self):
        self.budget.verify_layout()
        _verify(self.fd,self.budget.outer)
        self.budget.verify_job_parent(self.job_fd)
        current=_directory(self.path)
        try:
            if ((os.fstat(current).st_dev,os.fstat(current).st_ino)!=(os.fstat(self.fd).st_dev,os.fstat(self.fd).st_ino)
                    or str(os.getpid()) not in _read(self.fd,'cgroup.procs').split()
                    or os.sched_getscheduler(0)!=os.SCHED_OTHER):
                raise ValueError('Outer launcher is not inside its retained normal-scheduler group')
        finally:os.close(current)
        current=_directory(self.job_parent)
        try:
            if (os.fstat(current).st_dev,os.fstat(current).st_ino)!=(os.fstat(self.job_fd).st_dev,os.fstat(self.job_fd).st_ino):
                raise ValueError('VM job parent changed')
        finally:os.close(current)

    def admit(self,profile):
        self.verify();self.budget.admit_service(profile.total)

    def close(self):
        for name in ['fd','job_fd']:
            fd=getattr(self,name,None)
            if fd is not None:os.close(fd);setattr(self,name,None)
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
