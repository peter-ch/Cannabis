#!/usr/bin/env python3
"""Prepare a local SNP profile; never start a VM or authorize hardware/keys."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import types

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
module=types.ModuleType('cannabis_host');module.__path__=[str(ROOT/'operator')];sys.modules['cannabis_host']=module
from cannabis_host.snp_profile import SnpProfile,root_file,root_directory,read_fd,MAXIMUM,unique


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['qemu','firmware','image','reference','output','cgroup-parent']:parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--machine',required=True);parser.add_argument('--cbitpos',type=int,required=True)
    parser.add_argument('--reduced-phys-bits',type=int,required=True)
    parser.add_argument('--group-host-port',type=int);parser.add_argument('--group-guest-port',type=int)
    parser.add_argument('--group-bind-host',choices=['127.0.0.1','0.0.0.0'],default='127.0.0.1')
    args=parser.parse_args();out=args.output
    grouped=args.group_host_port is not None
    if grouped != (args.group_guest_port is not None) or grouped and not all(1024<=p<=65535 for p in [args.group_host_port,args.group_guest_port]):
        raise ValueError('Specify both fixed group ports in 1024..65535')
    if os.geteuid()!=0 or not out.is_absolute() or out.exists() or ROOT==out or ROOT in out.parents:
        raise ValueError('Require a new private root-owned profile destination')
    def artifact(p,name):
        fd=root_file(str(p),MAXIMUM[name])
        try:
            total=os.fstat(fd).st_size;state=hashlib.sha256();offset=0
            while offset<total:
                chunk=os.pread(fd,min(1024**2,total-offset),offset)
                if not chunk:raise ValueError('Artifact changed')
                state.update(chunk);offset+=len(chunk)
            return {'path':str(p),'bytes':total,'sha256':state.hexdigest()}
        finally:os.close(fd)
    reference_fd=root_file(str(args.reference),65536)
    try:reference=json.loads(read_fd(reference_fd,65536),object_pairs_hook=unique)
    finally:os.close(reference_fd)
    cpus=reference['vcpus']
    profile={'schema':'cannabis.host-snp-profile.v1','qemu':artifact(args.qemu,'qemu'),
        'boot':{name:artifact(p,name) for name,p in [('firmware',args.firmware),('kernel',args.image/'vmlinuz'),
               ('initramfs',args.image/'initramfs.cpio.gz'),('cmdline',args.image/'cmdline')]},
        'reference':artifact(args.reference,'reference'),'machine':args.machine,'cpu':reference['vcpuType'],'cpus':cpus,'memoryMiB':4096,
        'snp':{'cbitpos':args.cbitpos,'reducedPhysBits':args.reduced_phys_bits,'policy':0x30000},
        'limits':{'cpu_millis':cpus*1000+500,'memory_bytes':6*1024**3,'processes':128,'wall_seconds':3600},
        'cgroupParent':str(args.cgroup_parent)}
    if grouped:
        profile['schema']='cannabis.host-snp-profile.v2'
        profile['groupIngress']={'bindHost':args.group_bind_host,'hostPort':args.group_host_port,'guestPort':args.group_guest_port}
    directory=root_directory(out.parent)
    try:
        fd=os.open(out.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            raw=(json.dumps(profile,indent=2)+'\n').encode();offset=0
            while offset<len(raw):
                count=os.write(fd,raw[offset:])
                if count<=0:raise OSError('Incomplete profile write')
                offset+=count
            os.fsync(fd)
        finally:os.close(fd)
        os.fsync(directory)
    finally:os.close(directory)
    retained=SnpProfile(str(out))
    try:print(json.dumps({'profile':str(out),'expectedLaunchDigest':retained.reference['expectedLaunchDigest'],
        'hardwareValidated':False,'executionAuthorized':False,'vmStarted':False}))
    finally:retained.close()


if __name__=='__main__':main()
