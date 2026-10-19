#!/usr/bin/env python3
"""One disposable physical result-storage checkpoint; no live hardware/custody."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('result_volume',ROOT/'operator/result_volume.py')
volume=importlib.util.module_from_spec(spec);spec.loader.exec_module(volume)

def refused(action):
    try:action()
    except (ValueError,OSError):return
    raise AssertionError('Invalid physical result store accepted')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--node',default=shutil.which('node'))
    parser.add_argument('--console',action='store_true',help='Exercise the retained-result console and replacement delivery instead of filesystem pressure cases')
    parser.add_argument('--browser-config',type=Path);parser.add_argument('--stop-file',type=Path)
    args=parser.parse_args();assert args.node and os.geteuid()==0
    libc=ctypes.CDLL(None,use_errno=True)
    assert libc.unshare(0x20000)==0
    assert libc.mount(None,b'/',None,0x4000|0x40000,None)==0
    base=Path(tempfile.mkdtemp(prefix='cannabis-physical-spool-',dir='/var/tmp'))
    home=base/'volume';home.mkdir(mode=0o700);mounted=False
    try:
        initial=volume.create_volume(home,32*1024**2,2);mounted=True
        assert initial['backingAllocatedBytes']>=initial['limits']['imageBytes']
        if args.console:
            command=[args.node,'--disable-warning=ExperimentalWarning',str(ROOT/'test/helpers/worker_recovery_workflow.mjs'),str(home)]
            if args.browser_config:
                assert args.stop_file and args.browser_config.is_absolute() and args.stop_file.is_absolute()
                command.extend([str(args.browser_config),str(args.stop_file)])
            run=subprocess.run(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                               timeout=360 if args.browser_config else 120)
            assert run.returncode==0,run.stderr[-4096:]
            result=json.loads(run.stdout);assert all(result['checks'].values())
            volume.unmount_volume(home);mounted=False;result['checks']['ownedVolumeUnmounted']=True
            print(json.dumps(result));return
        def node(mode):
            run=subprocess.run([args.node,'--disable-warning=ExperimentalWarning',
                str(ROOT/'test/helpers/physical_spool_workflow.mjs'),mode,str(home),str(base/'record.json')],
                cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=120)
            assert run.returncode==0,run.stderr[-4096:]
            result=json.loads(run.stdout);assert all(result.values());return result
        checks=node('exercise')
        volume.unmount_volume(home);mounted=False
        assert (home/'result-volume.ext4').is_file()
        refused(lambda:volume.inspect_volume(home))
        old=(home/'volume.json').read_bytes();wrong=json.loads(old);wrong['imageInode']+=1
        (home/'volume.json').write_text(json.dumps(wrong))
        try:refused(lambda:volume.mount_volume(home))
        finally:(home/'volume.json').write_bytes(old)
        volume.mount_volume(home);mounted=True
        checks.update(node('recover'))

        sparse=base/'sparse';sparse.mkdir(mode=0o700);(sparse/'mount').mkdir(mode=0o700)
        with (sparse/'result-volume.ext4').open('xb') as out:out.truncate(initial['limits']['imageBytes'])
        s=(sparse/'result-volume.ext4').stat();v=json.loads(old);v['imageDevice']=s.st_dev;v['imageInode']=s.st_ino
        (sparse/'volume.json').write_text(json.dumps(v))
        refused(lambda:volume.mount_volume(sparse))
        volume.unmount_volume(home);mounted=False
        checks.update(preallocatedBacking=True,unmountedStoreRefused=True,changedBackingRefused=True,sparseBackingRefused=True,
                      checkedUnmount=True,backingPreserved=True)
        print(json.dumps({'checks':checks,'actualHardwareValidated':False,'realPaidJob':False}))
    finally:
        if mounted:volume.unmount_volume(home)
        # Solely this test's randomly named private directory; no real results.
        assert base.resolve().parent==Path('/var/tmp').resolve() and base.name.startswith('cannabis-physical-spool-')
        assert not any(m['mount']==str(base) or m['mount'].startswith(str(base)+'/') for m in volume.mount_entries())
        shutil.rmtree(base)

if __name__=='__main__':main()
