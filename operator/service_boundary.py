"""Kernel-observed aggregate resources for one fixed systemd-owned operator.

Ordinary host accounting, not attestation or billing. PID 1 owns cleanup outside
the unit; all application supervisors/guardians/VMs remain inside its ceiling.
"""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from compute.guest_resources import ResourceLimits,_directory,_read,_write,_values,_verify
from .snp_profile import exact,integer,root_file,root_directory,read_fd,file_digest,unique
from .state_volume import inspect_state
from .result_volume import inspect_volume,mount_entries,mount_for

MIB=1024**2
ROOT=Path(__file__).resolve().parents[1]
CONTROLLERS={'cpu','memory','pids'}


def json_file(file,limit=65536):
    fd=root_file(file,limit)
    try:return json.loads(read_fd(fd,limit),object_pairs_hook=unique)
    finally:os.close(fd)


class BoundaryProfile:
    def __init__(self,file):
        self.file=str(file);v=json_file(file)
        self.profile_sha256=hashlib.sha256(Path(file).read_bytes()).hexdigest()
        exact(v,['schema','unit','configuration','node','sourceRoot','consolePort','stateVolume','control','vm'])
        if v['schema']!='cannabis.operator-boundary.v1' or not re.fullmatch(r'cannabis-operator-[a-z0-9-]{1,64}\.service',v['unit']):
            raise ValueError('Require a retained operator unit')
        if not integer(v['consolePort'],1024,65535) or v['sourceRoot']!=str(ROOT):raise ValueError('Operator entry differs from installed source')
        fd=root_directory(ROOT);os.close(fd)
        for key,limit in [('configuration',16384),('node',256*MIB)]:
            record=v[key];exact(record,['path','bytes','sha256'])
            if not integer(record['bytes'],1,limit) or not re.fullmatch('[0-9a-f]{64}',record['sha256']):raise ValueError('Invalid artifact pin')
            fd=root_file(record['path'],limit)
            try:
                if os.fstat(fd).st_size!=record['bytes']:raise ValueError('Artifact size changed')
                if key=='configuration':file_digest(fd,record)
            finally:os.close(fd)
        config=json_file(v['configuration']['path'],16384)
        if config.get('resources')!=str(file):raise ValueError('Configuration must retain this boundary profile')
        state=Path(v['stateVolume'])/'mount/state'
        if (config.get('approvals')!=str(state/'approvals') or config.get('dispatch')!=str(state/'dispatch.sqlite') or
                config.get('relay',{}).get('orders')!=str(state/'orders.sqlite') or config['relay'].get('results')!=str(state/'results.sqlite')):
            raise ValueError('All service metadata must stay on the retained state volume')
        self.control=self.limits(v['control']);self.vm=self.limits(v['vm'])
        if self.control.memory_bytes<256*MIB or self.control.processes<32 or self.control.cpu_millis<100:
            raise ValueError('Insufficient control-plane reservation')
        self.total=ResourceLimits(self.control.cpu_millis+self.vm.cpu_millis,
            self.control.memory_bytes+self.vm.memory_bytes,self.control.processes+self.vm.processes,2592000)
        self.cgroup=Path('/sys/fs/cgroup/system.slice')/v['unit'];self.config=config;self.value=v
        host=json_file(config['profile'])
        host_limits=ResourceLimits(**host['limits'])
        if (host.get('schema')!='cannabis.host-snp-profile.v1' or host.get('cgroupParent')!=str(self.cgroup/'vm') or
                any(getattr(host_limits,k)>getattr(self.vm,k) for k in ['cpu_millis','memory_bytes','processes'])):
            raise ValueError('VM slot is outside the retained aggregate reservation')

    @staticmethod
    def limits(value):
        exact(value,['cpu_millis','memory_bytes','processes'])
        return ResourceLimits(**value,wall_seconds=2592000)

    def manager(self,pid):
        names=['MainPID','ControlGroup','Delegate','DelegateSubgroup','KillMode','OOMPolicy','Restart','TimeoutStopUSec',
               'ProtectSystem','PrivateTmp','NoNewPrivileges','StandardOutput','StandardError','DevicePolicy','DeviceAllow']
        run=subprocess.run(['/usr/bin/systemctl','show',self.value['unit'],'--property='+','.join(names)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,
            env={'PATH':'/usr/bin:/bin','LANG':'C'},check=True)
        if len(run.stdout)>8192 or run.stderr:raise ValueError('Manager observation unavailable')
        actual={};devices=[]
        for line in run.stdout.decode().splitlines():
            key,value=line.split('=',1)
            if key=='DeviceAllow':devices.append(value)
            else:
                if key in actual:raise ValueError('Repeated manager property')
                actual[key]=value
        expected={'MainPID':str(pid),'ControlGroup':'/system.slice/'+self.value['unit'],'Delegate':'yes',
            'DelegateSubgroup':'control','KillMode':'control-group','OOMPolicy':'kill','Restart':'no','TimeoutStopUSec':'45s',
            'ProtectSystem':'strict','PrivateTmp':'no','NoNewPrivileges':'yes','StandardOutput':'null','StandardError':'null','DevicePolicy':'closed'}
        if actual!=expected:raise ValueError('System manager policy or owning process differs: '+json.dumps(actual))
        if set(devices)!=self.devices():raise ValueError('System manager device policy differs: '+json.dumps({'actual':devices,'required':sorted(self.devices())}))

    def devices(self):
        state=inspect_state(self.value['stateVolume']);spool=Path(self.config['spool']).parent
        inspect_volume(spool.parent)
        loop_devices={state['loopDevice'],mount_for(spool,exact=True)['source']}
        if any(not re.fullmatch(r'/dev/loop[0-9]+',p) for p in loop_devices):raise ValueError('Unexpected storage device')
        # ProtectClock adds the same read-only RTC group rule in systemd.
        return {'/dev/kvm rw','/dev/sev rw','char-rtc r',*(p+' r' for p in loop_devices)}

    def membership(self,pid):
        if not integer(pid,1,2**31-1):raise ValueError('Invalid owner PID')
        membership=Path(f'/proc/{pid}/cgroup').read_text().strip()
        if membership!='0::/system.slice/'+self.value['unit']+'/control':raise ValueError('Owner escaped aggregate control group')
        if Path(f'/proc/{pid}/ns/mnt').stat().st_ino!=Path('/proc/self/ns/mnt').stat().st_ino:
            raise ValueError('Observe resources inside the owning mount namespace')
        if os.sched_getscheduler(pid)!=os.SCHED_OTHER:raise ValueError('Require normal CPU scheduling')

    def configure(self):
        """Only the fixed single-threaded main bootstrap can configure children."""
        self.manager(os.getpid());self.membership(os.getpid())
        if len(os.listdir('/proc/self/task'))!=1:raise ValueError('Require single-threaded bootstrap')
        parent=_directory(self.cgroup)
        try:
            if _read(parent,'cgroup.procs') or _read(parent,'cgroup.type')!='domain':raise ValueError('Invalid delegated parent')
            self._aggregate(parent)
            children=[n for n in os.listdir(parent) if stat.S_ISDIR(os.stat(n,dir_fd=parent,follow_symlinks=False).st_mode)]
            if set(children)!={'control'}:raise ValueError('Residual operator groups require reconciliation')
            _write(parent,'cgroup.max.depth','2');_write(parent,'cgroup.max.descendants','3')
            _write(parent,'cgroup.subtree_control','+cpu +memory +pids')
            control=_directory(self.cgroup/'control')
            try:
                if _read(control,'cgroup.procs')!=str(os.getpid()):raise ValueError('Unexpected bootstrap process')
                for name,value in self.control.controls().items():_write(control,name,value)
                if 'memory.zswap.max' in os.listdir(control):_write(control,'memory.zswap.max','0')
                _verify(control,self.control)
            finally:os.close(control)
            os.mkdir('vm',0o700,dir_fd=parent);pool=_directory(self.cgroup/'vm')
            try:
                for name,value in self.vm.controls().items():_write(pool,name,value)
                _write(pool,'cgroup.max.depth','1');_write(pool,'cgroup.max.descendants','1')
                if 'memory.zswap.max' in os.listdir(pool):_write(pool,'memory.zswap.max','0')
                _write(pool,'cgroup.subtree_control','+cpu +memory +pids')
            finally:os.close(pool)
        finally:os.close(parent)

    def _aggregate(self,fd):
        quota,period=_read(fd,'cpu.max').split()
        if (quota=='max' or int(quota)*1000!=int(period)*self.total.cpu_millis or
                _read(fd,'memory.max')!=str(self.total.memory_bytes) or _read(fd,'memory.swap.max')!='0' or
                _read(fd,'memory.oom.group')!='1' or _read(fd,'pids.max')!=str(self.total.processes)):
            raise ValueError('Aggregate kernel limits differ from retained reservation')
        if 'memory.zswap.max' in os.listdir(fd) and _read(fd,'memory.zswap.max')!='0':
            raise ValueError('Compressed swap must be disabled')

    def observe(self,pid,*,bootstrap=False):
        self.manager(pid);self.membership(pid)
        if not bootstrap:
            node=root_file(self.value['node']['path'],256*MIB)
            try:
                a=os.fstat(node);b=os.stat(f'/proc/{pid}/exe')
                if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino):raise ValueError('Unexpected operator executable')
            finally:os.close(node)
        parent=_directory(self.cgroup);control=pool=None
        try:
            self._aggregate(parent)
            if (_read(parent,'cgroup.procs') or _read(parent,'cgroup.type')!='domain' or
                    _read(parent,'cgroup.max.depth')!='2' or _read(parent,'cgroup.max.descendants')!='3' or
                    not CONTROLLERS<=set(_read(parent,'cgroup.subtree_control').split())):raise ValueError('Aggregate tree changed')
            control=_directory(self.cgroup/'control');_verify(control,self.control)
            pool=_directory(self.cgroup/'vm')
            for name,value in self.vm.controls().items():
                wanted={'cgroup.max.depth':'1','cgroup.max.descendants':'1'}.get(name,value)
                if _read(pool,name)!=wanted:raise ValueError('VM pool limit changed')
            if _read(pool,'cgroup.procs') or not CONTROLLERS<=set(_read(pool,'cgroup.subtree_control').split()):raise ValueError('VM pool ancestry changed')
            state=inspect_state(self.value['stateVolume'])
            lease=os.stat(f'/proc/{pid}/fd/3')
            if (lease.st_dev,lease.st_ino)!=(state['rootDevice'],state['recoveryInode']):
                raise ValueError('Operator recovery reserve lease changed')
            lock=Path(f'/proc/{pid}/fdinfo/3').read_text()
            if not re.search(r'^lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+READ\s+'+str(pid)+r'\s+\S+:'+str(lease.st_ino)+r'\s+0\s+EOF$',lock,re.M):
                raise ValueError('Require the actual owning process reserve lock')
            spool=Path(self.config['spool']);result=inspect_volume(spool.parent.parent)
            for rule in self.devices():
                device,access=rule.split()
                if access=='r' and device.startswith('/dev/loop'):
                    try:fd=os.open(device,os.O_WRONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
                    except PermissionError:pass
                    else:os.close(fd);raise ValueError('Raw writes bypass the selected filesystem ceiling')
            allowed={str(Path(self.value['stateVolume'])/'mount'),str(spool.parent)}
            # Observe the mounted sandbox, not just ProtectSystem's setting.
            for m in mount_entries():
                # systemd may stack a read-only bind over a writable mount.
                # mountinfo retains the hidden lower entry; statvfs resolves the
                # active path and its actual write flag inside this namespace.
                if os.statvfs(m['mount']).f_flag&os.ST_RDONLY:continue
                if m['fs']=='cgroup2' and 'rw' in m['flags'] and m['mount']!=str(self.cgroup):
                    raise ValueError('Writable cgroup hierarchy escapes the selected unit')
                if 'rw' in m['flags'] and m['fs'] not in {'proc','sysfs','cgroup2','devtmpfs','devpts','tmpfs','mqueue'} and m['mount'] not in allowed:
                    raise ValueError('Writable filesystem escapes bounded volumes: '+m['fs']+' '+m['mount'])
                if m['fs']=='tmpfs' and 'rw' in m['flags'] and not m['mount'].startswith('/dev/'):
                    raise ValueError('Writable temporary filesystem escapes metadata volume: '+m['mount'])
            fd_info=os.fstat(parent)
            return {'schema':'cannabis.operator-boundary-observation.v1','unit':self.value['unit'],
                'profileSHA256':self.profile_sha256,'configurationSHA256':self.value['configuration']['sha256'],
                'cgroupDevice':fd_info.st_dev,'cgroupInode':fd_info.st_ino,'control':self.value['control'],'vm':self.value['vm'],
                'aggregate':{k:getattr(self.total,k) for k in ['cpu_millis','memory_bytes','processes']},
                'memoryCurrentBytes':int(_read(parent,'memory.current')),'pidsCurrent':int(_read(parent,'pids.current')),
                'memoryEvents':_values(parent,'memory.events'),'stateVolume':{k:state[k] for k in state if k not in ['schema','loopDevice']},
                'resultImageBytes':result['limits']['imageBytes'],'recoveryLeaseHeld':True,'rawStorageWritesDenied':True,
                'hardwareValidated':False,'paymentAuthorized':False}
        finally:
            for fd in [pool,control,parent]:
                if fd is not None:os.close(fd)

    def unit_text(self):
        """Reviewable unit only; never install/start it from configuration parsing."""
        def argument(value):
            value=str(value)
            if value!='/' and not re.fullmatch(r'/[A-Za-z0-9_./-]+',value):raise ValueError('Use unambiguous private installation paths')
            return value
        source=argument(ROOT);profile=argument(self.file);state=argument(Path(self.value['stateVolume'])/'mount')
        spool=argument(Path(self.config['spool']).parent);temp=state+'/state/tmp';group=argument(self.cgroup)
        # A read-only ancestor does not make every nested mount read-only.
        # Retain explicit installation mount paths except the bounded volumes;
        # runtime observation still refuses any newly introduced writable mount.
        readonly={'/','/dev','/sys','/sys/fs/cgroup','/run','/tmp','/var/tmp'}
        readonly.add(state+'/recovery.reserve')
        readonly.update(m['mount'] for m in mount_entries() if m['mount'] not in {state,spool,group})
        readonly_text=' '.join('-'+argument(p) for p in sorted(readonly))
        device_text='\n'.join('DeviceAllow='+rule for rule in sorted(self.devices()))
        return f'''[Unit]
Description=Cannabis independent booked operator
After=network-online.target
RequiresMountsFor={state} {spool}

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -I -B {source}/scripts/start-operator.py {profile}
WorkingDirectory={source}
Slice=system.slice
Delegate=cpu memory pids
DelegateSubgroup=control
CPUQuota={self.total.cpu_millis/10:g}%
CPUQuotaPeriodSec=100ms
MemoryMax={self.total.memory_bytes}
MemorySwapMax=0
MemoryZSwapMax=0
TasksMax={self.total.processes}
OOMPolicy=kill
KillMode=control-group
TimeoutStopSec=45s
SendSIGKILL=yes
Restart=no
UMask=0077
LimitCORE=0
LimitMEMLOCK={self.vm.memory_bytes}
LimitNOFILE=4096
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_IPC_LOCK
DevicePolicy=closed
{device_text}
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=no
PrivateIPC=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallFilter=~@mount
SystemCallErrorNumber=EPERM
ReadOnlyPaths={readonly_text}
ReadWritePaths={state} {spool} {group}
Environment=TMPDIR={temp} SQLITE_TMPDIR={temp} PYTHONDONTWRITEBYTECODE=1
StandardInput=null
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
'''
