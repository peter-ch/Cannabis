#!/usr/bin/env python3
"""Fixed SNP host process entry. stdin is public request then owner heartbeat."""
import json
import os
from pathlib import Path
import select
import sys
import time
import types

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
# Avoid shadowing Python's standard-library operator module.
module=types.ModuleType('cannabis_host');module.__path__=[str(ROOT/'operator')];sys.modules['cannabis_host']=module
from cannabis_host.host_vm import OwnedSnpVm
from cannabis_host.snp_profile import SnpProfile,unique


def main():
    if len(sys.argv)==3 and sys.argv[1]=='--inspect':
        profile=SnpProfile(sys.argv[2])
        try:
            observation=profile.require_hardware()
            print(json.dumps({'schema':'cannabis.host-snp-observation.v1',**observation}),flush=True)
        finally:profile.close()
        return
    if len(sys.argv)!=3 or os.geteuid()!=0 or not sys.argv[2].isdigit():raise ValueError('Require retained profile and actual parent')
    parent=int(sys.argv[2])
    if parent!=os.getppid():raise ValueError('Operator parent changed')
    owner=os.pidfd_open(parent);vm=None;profile=None;ready=False
    try:
        end=time.monotonic()+5
        def read(count):
            data=bytearray()
            while len(data)<count:
                left=end-time.monotonic()
                if left<=0:raise TimeoutError('Host request intake expired')
                readable,_,_=select.select([0,owner],[],[],left)
                if owner in readable:raise EOFError('Owner exited during intake')
                if 0 in readable:
                    chunk=os.read(0,count-len(data))
                    if not chunk:raise EOFError('Host request incomplete')
                    data.extend(chunk)
            return data
        size=int.from_bytes(read(4),'big')
        if not 2<=size<=131072:raise ValueError('Host request too large')
        request=json.loads(read(size),object_pairs_hook=unique)
        profile=SnpProfile(sys.argv[1])
        vm=OwnedSnpVm(profile,request,4,owner,0);ready=True
        print(json.dumps({'schema':'cannabis.host-vm-ready.v1','initData':request['initData'],
            'expectedLaunchDigest':request['expectedLaunchDigest'],'hardwareValidated':False}),flush=True)
        report=vm.wait();print(json.dumps(report),flush=True)
    except BaseException:
        if vm is not None:vm.cancel()
        print(json.dumps({'schema':'cannabis.host-vm-failure.v1','readyEmitted':ready,
            'localTreeStopped':vm.local_cleanup if vm else False,'protectedKeyRetirementVerified':False,
            'hardwareValidated':False}),flush=True)
        raise
    finally:
        if profile is not None:profile.close()
        os.close(owner)


if __name__=='__main__':
    try:main()
    except BaseException:sys.exit(1)
