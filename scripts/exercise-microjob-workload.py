"""Run fixed local fixtures through packaging and requester-side reconstruction.

This harness owns its nonsensitive inputs and ephemeral keys. Its local decoder
is deliberately NOT a worker adapter and cannot admit customer jobs or establish
confidential execution. No user-supplied source, launch command or endpoint.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.client import age_binary,pack_workload,open_archive,seal_result,assemble_results

def digest(data):return hashlib.sha256(data).hexdigest()

def run(kind):
    if kind not in ('matrix','dag','regression'):raise ValueError('Choose a fixed fixture')
    age=age_binary();keygen=Path(age).with_name('age-keygen.exe' if os.name=='nt' else 'age-keygen')
    identity=subprocess.run([str(keygen)],capture_output=True,check=True,timeout=15).stdout
    recipient=subprocess.run([str(keygen),'-y'],input=identity,capture_output=True,check=True,timeout=15).stdout.decode().strip()
    program=Path(__file__).with_name('fixtures').joinpath('microjob-program.py').read_bytes()
    if kind=='matrix':
        inputs=[{'operation':'matrix','a':[[1,2],[3,4]],'b':[[5,6],[7,8]]}]
    elif kind=='dag':
        inputs=[{'operation':'sum-squares','first':1,'last':5000},{'operation':'sum-squares','first':5001,'last':10000}]
    else:
        inputs=[{'operation':'fit-line','points':[[x,3*x+2] for x in range(-10,11)]}]
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='cannabis-owned-microjob-') as temporary:
        root=Path(temporary);source=root/'source';source.mkdir()
        (source/'program.py').write_bytes(program)
        files=['program.py'];tasks=[];assembly=[]
        for i,data in enumerate(inputs):
            filename=f'input-{i}.json';files.append(filename)
            (source/filename).write_text(json.dumps(data),encoding='utf-8')
            tasks.append({'id':f'part-{i}','dependsOn':[],
              'runtime':{'adapter':'owned-arithmetic-fixture','digestSHA256':digest(program),'architecture':'amd64','os':'portable'},
              'launch':{'fixtureInput':filename},
              'resources':{'cpus':1,'memoryMiB':128,'scratchMiB':16,'wallSeconds':30,'nodes':1,'accelerators':0},
              'outputs':['answer.json'],'outputMaxBytes':4096})
            assembly.append({'task':f'part-{i}','output':'answer.json','destination':f'part-{i}.json'})
        spec={'schema':'cannabis.workload.v1','id':'owned-'+kind,'policySHA256':digest(b'LOCAL FIXTURE, NOT ATTESTATION'),
          'resultRecipient':recipient,'files':files,'tasks':tasks,'assembly':assembly}
        package=root/'package.age';descriptor=pack_workload(spec,source,recipient,package,age)
        assert not descriptor['executionAuthorized'] and not descriptor['keyReleaseAuthorized']
        decoded=root/'fixture-decoder'
        manifest=open_archive(package,identity,decoded,descriptor['ciphertextSHA256'],age=age)
        assert manifest['context']==spec
        def execute(index):
            work=root/f'part-{index}';work.mkdir()
            (work/'program.py').write_bytes((decoded/'program.py').read_bytes())
            (work/'input.json').write_bytes((decoded/f'input-{index}.json').read_bytes())
            subprocess.run([sys.executable,'-I','program.py'],cwd=work,check=True,capture_output=True,timeout=30)
            encrypted=root/f'result-{index}.age'
            receipt=seal_result(spec,f'part-{index}',descriptor['ciphertextSHA256'],work,recipient,encrypted,age=age)
            assert receipt['executionAttested'] is False
            return {'file':str(encrypted),'receipt':receipt}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(execute,range(len(inputs))))
        assembled=root/'requester-results'
        reconstruction=assemble_results(spec,descriptor['ciphertextSHA256'],results,identity,assembled,age=age)
        values=[json.loads((assembled/f'part-{i}.json').read_text(encoding='utf-8')) for i in range(len(inputs))]
        if kind=='matrix':accepted=values[0]==[[19,22],[43,50]]
        elif kind=='dag':accepted=sum(values)==10000*10001*20001//6
        else:accepted=abs(values[0]['weight']-3)<1e-9 and abs(values[0]['bias']-2)<1e-9 and values[0]['mse']<1e-18
        if not accepted:raise ValueError('Independent requester acceptance failed')
        # Authenticated encryption must reject tampering even if an attacker also
        # changes the public ciphertext hash to match the damaged bytes.
        damaged=root/'damaged.age';raw=bytearray(Path(results[0]['file']).read_bytes());raw[-1]^=1;damaged.write_bytes(raw)
        spoof=[dict(item) for item in results]
        spoof[0]={'file':str(damaged),'receipt':{**results[0]['receipt'],'ciphertextSHA256':digest(raw)}}
        try:
            assemble_results(spec,descriptor['ciphertextSHA256'],spoof,identity,root/'tampered-output',age=age)
        except Exception:
            if (root/'tampered-output').exists():raise AssertionError('Unverified output exposed')
        else:raise AssertionError('Tampered ciphertext accepted')
        try:assemble_results(spec,'f'*64,results,identity,root/'wrong-job',age=age)
        except ValueError:pass
        else:raise AssertionError('Cross-job substitution accepted')
        receipts=[item['receipt'] for item in results]
        return {'schema':'cannabis.local-microjob-workload.v1','kind':kind,'classification':'OWNED_LOCAL_FIXTURE',
          'packageSHA256':descriptor['ciphertextSHA256'],'outputDigest':'0x'+digest(json.dumps(receipts,sort_keys=True).encode()),
          'tasksExecuted':len(tasks),'result':values,'requesterAcceptancePassed':accepted,
          'integrityVerified':reconstruction['integrityVerified'],'tamperRejected':True,'crossJobRejected':True,
          'elapsedSeconds':round(time.monotonic()-started,3),'confidentialExecutionEstablished':False,'customerDataUsed':False}

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Usage: exercise-microjob-workload.py matrix|dag|regression')
    print(json.dumps(run(sys.argv[1]),allow_nan=False))
