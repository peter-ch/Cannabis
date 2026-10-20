"""Requester-only reconstruction of active, authenticated private result receipts."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.client import assemble_results,load_identity,MAX_MANIFEST,task_binding_sha256
from compute.job_keys import _unique_json_fields

def main():
    if sys.stdin.isatty() or sys.stdout.isatty():raise ValueError('Private pipes required')
    raw=sys.stdin.buffer.read(16*1024*1024+1)
    if len(raw)>16*1024*1024:raise ValueError('Input bound')
    request=json.loads(raw,object_pairs_hook=_unique_json_fields)
    if set(request)!={'source','packageSHA256','results'}:raise ValueError('Request fields')
    source=request['source']
    if set(source)!={'age','identity','manifest','destination'}:raise ValueError('Source fields')
    if Path(source['manifest']).stat().st_size>MAX_MANIFEST or Path(source['identity']).stat().st_size>65536:raise ValueError('Source bound')
    spec=json.loads(Path(source['manifest']).read_text(encoding='utf-8-sig'),object_pairs_hook=_unique_json_fields)
    tasks={task['id']:index for index,task in enumerate(spec['tasks'])}
    items=[]
    for item in request['results']:
        if set(item)!={'receipt','file','approval'}:raise ValueError('Result fields')
        receipt,approval=item['receipt'],item['approval'];value=approval['value']
        if receipt['taskId'] not in tasks or approval['jobId']!=spec['id'] or value['packageSHA256']!='0x'+request['packageSHA256'] or value['policySHA256']!='0x'+spec['policySHA256']:raise ValueError('Original workload binding')
        task=spec['tasks'][tasks[receipt['taskId']]]
        if value['taskSHA256']!='0x'+task_binding_sha256(request['packageSHA256'],tasks[receipt['taskId']]) or value['runtimeSHA256']!='0x'+task['runtime']['digestSHA256']:raise ValueError('Approved task/runtime binding')
        if any(receipt[k]!=value[k] for k in ['attempt','rank','worldSize']):raise ValueError('Approved attempt binding')
        items.append({'receipt':receipt,'file':item['file']})
    result=assemble_results(spec,request['packageSHA256'],items,load_identity(source['identity']),source['destination'],age=source['age'])
    result.update(approvedAttemptsVerified=True,qualityAccepted=False,paymentAuthorized=False)
    print(json.dumps(result))

if __name__=='__main__':
    try:main()
    except Exception:sys.stderr.write('Requester reconstruction failed\n');sys.exit(1)
