"""Disposable encrypted workload for local verification; no operational keys."""
import json,os,shutil
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from compute.client import create_identity,dpapi
from compute.job_keys import _new_identity,pack_job

root=Path(sys.argv[1]);age=os.environ.get('CANNABIS_AGE') or shutil.which('age')
if not age:raise RuntimeError('Install age 1.3.2 and age-keygen or set CANNABIS_AGE')
source=root/'source';source.mkdir();(source/'program.bin').write_bytes(b'disposable verification program')
if os.name=='nt':
    identity=root/'requester.dpapi.json';public=create_identity(identity,age)['recipient']
else:
    # Disposable fixture only: standard protected local native age identity.
    secret,public=_new_identity(age);identity=root/'requester.age-identity'
    with os.fdopen(os.open(identity,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:f.write(secret)
spec={'schema':'cannabis.workload.v1','id':'private-workload','policySHA256':sys.argv[2],
    'files':['program.bin'],'tasks':[{'id':'work','runtime':{'adapter':'opaque-runtime','digestSHA256':'b'*64,'architecture':'amd64','os':'linux'},
    'launch':{'program':'program.bin'},'resources':{'cpus':1,'memoryMiB':512,'scratchMiB':512,'wallSeconds':60,'nodes':1},'outputs':[]}],
    'assembly':[]}
descriptor=pack_job(spec,source,public,root/'job',age)
print(json.dumps({'descriptor':descriptor,'ownerRecipient':public,'source':{'python':sys.executable,'age':age,'identity':str(identity),
    'capsule':str(root/'job/job-key.age'),'descriptor':str(root/'job/descriptor.json')}}))
