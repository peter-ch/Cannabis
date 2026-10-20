"""Inspect actual containment/runtime before starting a configured guest session.

Public metadata only. Actual execution repeats admission before opening a key.
"""
import json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.guest_deadline import ExecutionDeadline
from compute.guest_execution import NativeExecutionAdmission,ParentLifetime,_unique

def main():
    if sys.stdin.isatty() or sys.stdout.isatty():raise ValueError('Require pipes')
    deadline=ExecutionDeadline(float(os.environ['CANNABIS_JOB_DEADLINE']));deadline.check()
    parent=ParentLifetime();admission=None
    try:
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536:raise ValueError('Admission input bound')
        request=json.loads(raw,object_pairs_hook=_unique)
        admission=NativeExecutionAdmission(request,deadline,parent,inspect_only=True);admission.verify()
        print(json.dumps({'schema':'cannabis.guest-admission-check.v1','serviceSHA256':admission.profile.service_sha256,
            'controlContained':True,'runtimeVerified':True,'ciphertextVerified':True,'ciphertextStorageVerified':True,
            'hardwareValidated':False,'executionAuthorized':False}))
    finally:
        if admission:admission.close()
        parent.close()

if __name__=='__main__':
    try:main()
    except Exception:sys.stderr.write('Guest launch admission failed\n');sys.exit(1)
