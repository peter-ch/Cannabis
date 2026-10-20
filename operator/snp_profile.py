"""Locally retained QEMU/SNP launch profile; no hardware admission authority.

Only a fixed SNP adapter is supported here. The requester still verifies its
actual protected report against the selected policy before any content key.
"""
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from compute.guest_resources import ResourceLimits

COMMAND='console=null panic=-1 quiet loglevel=0 init=/init'
BOOT=('firmware','kernel','initramfs','cmdline')
MAXIMUM={'qemu':128*1024**2,'firmware':16*1024**2,'kernel':64*1024**2,'initramfs':512*1024**2,'cmdline':4096,'reference':65536}
SEALS=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE


def exact(value,names):
    if type(value) is not dict or set(value)!=set(names):raise ValueError('Invalid retained SNP profile')


def integer(value,low,high):
    return type(value) is int and low<=value<=high


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate profile member')
        result[key]=value
    return result


def root_directory(path):
    p=Path(path)
    if not p.is_absolute() or '..' in p.parts:raise ValueError('Require an absolute retained path')
    directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in p.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            os.close(directory);directory=child;info=os.fstat(child)
            if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Untrusted profile parent')
        return directory
    except BaseException:os.close(directory);raise


def root_file(path,maximum):
    """Open one root-owned regular file through non-writable, non-link parents."""
    p=Path(path);directory=root_directory(p.parent)
    try:
        fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or not 1<=info.st_size<=maximum:
            os.close(fd);raise ValueError('Untrusted or oversized retained file')
        return fd
    finally:os.close(directory)


def read_fd(fd,maximum):
    data=os.pread(fd,maximum+1,0)
    if not 1<=len(data)<=maximum or len(data)!=os.fstat(fd).st_size:raise ValueError('Changed retained file')
    return data


def file_digest(fd,record):
    state=hashlib.sha256();total=0
    while total<=record['bytes']:
        part=os.pread(fd,min(1024**2,record['bytes']+1-total),total)
        if not part:break
        state.update(part);total+=len(part)
    if total!=record['bytes'] or state.hexdigest()!=record['sha256']:raise ValueError('Pinned artifact differs')


class SnpProfile:
    def __init__(self,file):
        self.fds={}
        descriptor=root_file(file,65536)
        try:value=json.loads(read_fd(descriptor,65536),object_pairs_hook=unique)
        finally:os.close(descriptor)
        grouped=value.get('schema')=='cannabis.host-snp-profile.v2'
        exact(value,['schema','qemu','boot','reference','machine','cpu','cpus','memoryMiB','snp','limits','cgroupParent']+(['groupIngress'] if grouped else []))
        if value['schema'] not in ['cannabis.host-snp-profile.v1','cannabis.host-snp-profile.v2']:raise ValueError('Unsupported host profile')
        if grouped:
            ingress=value['groupIngress'];exact(ingress,['bindHost','hostPort','guestPort'])
            if (ingress['bindHost'] not in ['127.0.0.1','0.0.0.0'] or not integer(ingress['hostPort'],1024,65535)
                    or not integer(ingress['guestPort'],1024,65535)):raise ValueError('Require one fixed group TLS ingress')
        exact(value['boot'],BOOT);exact(value['snp'],['cbitpos','reducedPhysBits','policy'])
        if (type(value['machine']) is not str or not re.fullmatch(r'pc-q35-[0-9]{1,2}\.[0-9]{1,2}',value['machine'])
                or value['cpu']!='EPYC-Milan' or not integer(value['cpus'],4,256)
                or not integer(value['memoryMiB'],4096,1024*1024)
                or not integer(value['snp']['cbitpos'],32,63) or not integer(value['snp']['reducedPhysBits'],1,16)
                or value['snp']['policy']!=0x30000):raise ValueError('Unsupported fixed SNP machine profile')
        self.limits=ResourceLimits(**value['limits'])
        records={'qemu':value['qemu'],'reference':value['reference'],**value['boot']}
        try:
            for name,record in records.items():
                exact(record,['path','bytes','sha256'])
                if (not integer(record['bytes'],1,MAXIMUM[name]) or type(record['sha256']) is not str
                        or not re.fullmatch('[0-9a-f]{64}',record['sha256'])):raise ValueError('Invalid pinned artifact')
                fd=root_file(record['path'],MAXIMUM[name]);self.fds[name]=fd;file_digest(fd,record)
            info=os.fstat(self.fds['qemu'])
            if not info.st_mode&0o111 or info.st_mode&0o6000 or Path(value['qemu']['path']).name!='qemu-system-x86_64':
                raise ValueError('Require the retained QEMU executable')
            if read_fd(self.fds['cmdline'],4096)!=COMMAND.encode()+b'\n':raise ValueError('Operating command line differs')
            reference=json.loads(read_fd(self.fds['reference'],65536),object_pairs_hook=unique)
            if (reference.get('schema')!='cannabis.snp-reference-candidate.v1' or reference.get('vcpuType')!=value['cpu']
                    or reference.get('vcpus')!=value['cpus'] or reference.get('guestFeatures')!='0x21'
                    or reference.get('kernelCommandLine')!=COMMAND or reference.get('commandLineHashIncludesNul') is not True
                    or not re.fullmatch('[0-9a-f]{96}',reference.get('expectedLaunchDigest',''))):raise ValueError('Reference machine differs')
            for name,key in [('kernel','vmlinuz'),('initramfs','initramfs.cpio.gz'),('cmdline','cmdline')]:
                if reference['guestImage'][key]!={k:records[name][k] for k in ['bytes','sha256']}:raise ValueError('Reference image differs')
            if any(reference['firmware'][k]!=records['firmware'][k] for k in ['bytes','sha256']):raise ValueError('Reference firmware differs')
            # Boot snapshots are charged inside the VM leaf before QEMU exec.
            minimum=value['memoryMiB']*1024**2+512*1024**2+sum(records[k]['bytes'] for k in ['qemu',*BOOT])
            if self.limits.memory_bytes<minimum or self.limits.cpu_millis<value['cpus']*1000+500 or self.limits.processes<32:
                raise ValueError('Host limits cannot cover VM, snapshots and QEMU overhead')
            self.value=copy.deepcopy(value);self.reference=reference;self.records=records
        except BaseException:self.close();raise

    def require_hardware(self):
        """Host capability observation only; never substitute for attestation."""
        if os.geteuid()!=0 or os.uname().machine!='x86_64':raise RuntimeError('Require an x86_64 Linux SNP host')
        for name in ['kvm','sev']:
            fd=os.open('/dev/'+name,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                info=os.fstat(fd);major,minor=map(int,Path('/sys/class/misc/'+name+'/dev').read_text().strip().split(':'))
                if not stat.S_ISCHR(info.st_mode) or info.st_rdev!=os.makedev(major,minor):raise ValueError('Wrong protected device')
            finally:os.close(fd)
        if Path('/sys/module/kvm_amd/parameters/sev_snp').read_text().strip() not in ['Y','1']:
            raise RuntimeError('Host SNP is disabled')
        fd=self.fds['qemu']
        result=subprocess.run(['/proc/self/fd/'+str(fd),'-object','sev-snp-guest,help'],pass_fds=(fd,),
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=5,
            env={'PATH':'/usr/bin:/bin','LANG':'C'},check=True)
        if len(result.stdout)>65536 or any(key not in result.stdout for key in [b'host-data',b'kernel-hashes',b'policy']):
            raise RuntimeError('Retained QEMU lacks the required SNP properties')
        return {'snpDeviceObserved':True,'qemuSnpObjectObserved':True,'hardwareValidated':False}

    def snapshots(self):
        """Only call inside the owned resource leaf, before QEMU allocation."""
        opened={}
        try:
            for name in ['qemu',*BOOT]:
                fd=os.memfd_create('cannabis-vm-'+name,os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);opened[name]=fd
                total=0;state=hashlib.sha256();record=self.records[name]
                while total<=record['bytes']:
                    data=os.pread(self.fds[name],min(1024**2,record['bytes']+1-total),total)
                    if not data:break
                    if os.write(fd,data)!=len(data):raise OSError('Incomplete boot snapshot')
                    total+=len(data);state.update(data)
                if total!=record['bytes'] or state.hexdigest()!=record['sha256']:raise ValueError('Boot snapshot changed')
                os.fchmod(fd,0o500 if name=='qemu' else 0o400);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS)
                if fcntl.fcntl(fd,fcntl.F_GET_SEALS)!=SEALS:raise ValueError('Boot snapshot sealing failed')
            return opened
        except BaseException:
            for fd in opened.values():os.close(fd)
            raise

    def arguments(self,snapshots,control,qmp,init_data):
        if not re.fullmatch('[0-9a-f]{64}',init_data):raise ValueError('Require the retained initialization digest')
        v=self.value;s=v['snp'];p=lambda name:'/proc/self/fd/'+str(snapshots[name])
        net='user,id=controlnet,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,ipv6=off'
        if 'groupIngress' in v:
            g=v['groupIngress']
            # Forward opaque TLS only to the measured guest controller. No
            # workload port, plaintext proxy or host content key is configured.
            net+=f",hostfwd=tcp:{g['bindHost']}:{g['hostPort']}-10.0.2.15:{g['guestPort']}"
        snp={'qom-type':'sev-snp-guest','id':'sev0','cbitpos':s['cbitpos'],'reduced-phys-bits':s['reducedPhysBits'],
             'policy':s['policy'],'host-data':base64.b64encode(bytes.fromhex(init_data)).decode(),'kernel-hashes':True}
        return ['qemu-system-x86_64','-no-user-config','-nodefaults','-machine',v['machine']+',accel=kvm,confidential-guest-support=sev0,vmport=off',
            '-object',json.dumps(snp,separators=(',',':')),'-cpu',v['cpu'],'-smp',f"{v['cpus']},sockets=1,cores={v['cpus']},threads=1,maxcpus={v['cpus']}",
            '-m',str(v['memoryMiB']),'-bios',p('firmware'),'-kernel',p('kernel'),'-initrd',p('initramfs'),'-append',COMMAND,
            '-display','none','-serial','none','-monitor','none','-no-reboot',
            '-chardev',f'socket,id=qmp,fd={qmp}','-mon','chardev=qmp,mode=control',
            '-chardev',f'socket,id=control,fd={control}','-device','virtio-serial-pci,id=controlbus',
            '-device','virtserialport,chardev=control,name=org.cannabis.control',
            '-netdev',net,
            '-device','virtio-net-pci,netdev=controlnet,mac=52:54:00:ca:42:00,romfile=']

    def close(self):
        for fd in self.fds.values():os.close(fd)
        self.fds.clear()
