#!/usr/bin/env python3
"""Owned storage/admission failures on the real kernel, without customer keys."""
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.guest_ciphertext import CiphertextLimits, GuestCiphertextStorage, CiphertextAdmission, verify_storage
from compute.guest_deadline import ExecutionDeadline
from compute.guest_resources import ResourceCleanupError
from compute.guest_sandbox import _call, _libc


def refused(action):
    try:action()
    except (ValueError,OSError,ResourceCleanupError):return
    raise AssertionError('Unsafe ciphertext storage was accepted')


def main():
    base=Path('/run')/('cannabis-ciphertext-'+uuid.uuid4().hex)
    base.mkdir(mode=0o700)
    limits=CiphertextLimits(1024**2,32,512*1024,512*1024)
    expected=hashlib.sha256(b'owned encrypted bytes').hexdigest()
    checks={}
    def source(name):return {'ciphertext':str(base/name/'workload.age'),'destination':str(base/name/'result.age')}
    def populate(storage):
        p=storage.path/'workload.age';p.write_bytes(b'owned encrypted bytes');p.chmod(0o400)
    def admit(name,digest=expected):
        return CiphertextAdmission(source(name),limits,digest,ExecutionDeadline(time.monotonic()+30),None)
    try:
        with GuestCiphertextStorage(source('normal'),limits) as storage:
            populate(storage);admission=admit('normal')
            try:admission.verify()
            finally:admission.close()
        assert not storage.path.exists()
        storage.close()  # Retirement is idempotent.
        checks['verifiedInputAndRetirement']=True
        for mode in ['changed','writable','hardlink','symlink','oversized']:
            with GuestCiphertextStorage(source(mode),limits) as storage:
                populate(storage);p=storage.path/'workload.age'
                if mode=='changed':p.write_bytes(b'altered encrypted bytes')
                if mode=='writable':p.chmod(0o600)
                if mode=='hardlink':os.link(p,storage.path/'linked')
                if mode=='symlink':p.rename(storage.path/'original');p.symlink_to('original')
                if mode=='oversized':p.write_bytes(b'x'*(limits.inputBytes+1));p.chmod(0o400)
                refused(lambda:admit(mode))
            checks[mode+'InputRefused']=True
        with GuestCiphertextStorage(source('replacement'),limits) as storage:
            populate(storage);admission=admit('replacement')
            try:
                (storage.path/'workload.age').unlink();populate(storage)
                refused(admission.verify)
            finally:admission.close()
        checks['retainedInputReplacementRefused']=True
        with GuestCiphertextStorage(source('quota'),limits) as storage:
            _call(_libc().mount(None,os.fsencode(storage.path),None,32|2|4|8,b'size=2m,nr_inodes=32,noswap'))
            refused(lambda:verify_storage(storage.path,limits))
        checks['changedQuotaRefused']=True
        with GuestCiphertextStorage(source('bytes'),limits) as storage:
            count=0
            try:
                with (storage.path/'fill').open('wb',buffering=0) as out:
                    for _ in range(64):count+=out.write(b'x'*65536)
            except OSError as error:assert error.errno==errno.ENOSPC
            else:raise AssertionError('Ciphertext byte quota was not enforced')
            assert count==limits.bytes
        checks['kernelByteQuota']=True
        with GuestCiphertextStorage(source('inodes'),limits) as storage:
            count=0
            try:
                for i in range(128):
                    with (storage.path/str(i)).open('xb'):pass
                    count+=1
            except OSError as error:assert error.errno==errno.ENOSPC
            else:raise AssertionError('Ciphertext inode quota was not enforced')
            assert 1<=count<limits.inodes
        checks['kernelInodeQuota']=True
        ordinary=base/'ordinary';ordinary.mkdir(mode=0o700)
        refused(lambda:verify_storage(ordinary,limits));ordinary.rmdir()
        checks['unreservedDirectoryRefused']=True
        with GuestCiphertextStorage(source('busy'),limits) as storage:
            descriptor=os.open(storage.path,os.O_RDONLY|os.O_DIRECTORY)
            try:refused(storage.close)
            finally:os.close(descriptor)
            assert storage._mounted
        checks['busyRetirementRefused']=True
        assert not list(base.iterdir())
        print(json.dumps({'schema':'cannabis.guest-ciphertext-check.v1','kernel':os.uname().release,
            'checks':checks,'customerKeysUsed':False,'hardwareValidated':False,'realPaidJob':False}))
    finally:
        base.rmdir()


if __name__=='__main__':main()
