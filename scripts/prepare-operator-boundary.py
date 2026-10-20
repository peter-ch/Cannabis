#!/usr/bin/env python3
"""Prepare a new private aggregate profile and reviewable systemd unit; no start."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import types
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
module=types.ModuleType('cannabis_host');module.__path__=[str(ROOT/'operator')];sys.modules['cannabis_host']=module
from cannabis_host.service_boundary import BoundaryProfile,json_file
from cannabis_host.snp_profile import root_file,root_directory,read_fd
from cannabis_host.state_volume import inspect_state

def exclusive(file,data):
    parent=root_directory(file.parent)
    try:
        fd=os.open(file.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            offset=0
            while offset<len(data):
                n=os.write(fd,data[offset:])
                if n<=0:raise OSError('Incomplete retained profile')
                offset+=n
            os.fsync(fd)
        finally:os.close(fd)
        os.fsync(parent)
    finally:os.close(parent)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['configuration','node','state-volume','output','unit-output']:parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--unit',required=True);parser.add_argument('--console-port',type=int,default=4201)
    parser.add_argument('--control-cpu-millis',type=int,default=1000);parser.add_argument('--control-memory-mib',type=int,default=1024)
    parser.add_argument('--control-processes',type=int,default=128);args=parser.parse_args()
    if os.geteuid()!=0 or args.output.exists() or args.unit_output.exists() or args.unit_output.name!=args.unit:
        raise ValueError('Require new private profile and matching unit filename')
    def record(file,limit):
        fd=root_file(file,limit)
        try:
            value=read_fd(fd,limit);return {'path':str(file),'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()}
        finally:os.close(fd)
    config=json_file(args.configuration,16384);host=json_file(config['profile']);inspect_state(args.state_volume)
    if config.get('resources')!=str(args.output):raise ValueError('Retain the output profile path in the configuration first')
    value={'schema':'cannabis.operator-boundary.v1','unit':args.unit,'configuration':record(args.configuration,16384),
        'node':record(args.node,256*1024**2),'sourceRoot':str(ROOT),'consolePort':args.console_port,'stateVolume':str(args.state_volume),
        'control':{'cpu_millis':args.control_cpu_millis,'memory_bytes':args.control_memory_mib*1024**2,'processes':args.control_processes},
        'vm':{k:host['limits'][k] for k in ['cpu_millis','memory_bytes','processes']}}
    exclusive(args.output,(json.dumps(value,indent=2)+'\n').encode())
    profile=BoundaryProfile(str(args.output));exclusive(args.unit_output,profile.unit_text().encode())
    print(json.dumps({'prepared':True,'unit':args.unit,'serviceStarted':False,'hardwareValidated':False}))

if __name__=='__main__':main()
