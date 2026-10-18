"""Internal requester-side pipe: recover one approved job key for local wrapping.

Never call this as an interactive export command. The owner identity stays in this
process; only the job key crosses the private pipe to the local JWE encryptor.
"""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.client import load_identity,MAX_MANIFEST
from compute.job_keys import recover_job_key

def main():
    if sys.stdin.isatty() or sys.stdout.isatty():raise ValueError('Anonymous local pipes required')
    raw=sys.stdin.buffer.read(65537)
    if len(raw)>65536:raise ValueError('Pipe request exceeds bound')
    request=json.loads(raw)
    if set(request)!={'protocol','source','expected'} or request['protocol']!='cannabis.local-job-key.v1':raise ValueError('Invalid local pipe protocol')
    source,expected=request['source'],request['expected']
    if set(source)!={'age','identity','capsule','descriptor'}:raise ValueError('Invalid local custody source')
    if set(expected)!={'jobId','packageSHA256','policySHA256','capsuleSHA256','inputRecipient'}:raise ValueError('Invalid approved key binding')
    p=Path(source['descriptor'])
    if p.stat().st_size>MAX_MANIFEST:raise ValueError('Descriptor exceeds bound')
    descriptor=json.loads(p.read_text(encoding='utf-8-sig'))
    if Path(source['identity']).stat().st_size>65536:raise ValueError('Requester identity vault exceeds bound')
    if descriptor.get('id')!=expected['jobId'] or descriptor.get('recipient')!=expected['inputRecipient'] or descriptor.get('keyCustody',{}).get('ciphertextSHA256')!=expected['capsuleSHA256']:raise ValueError('Saved descriptor differs from signed approval')
    recovered=recover_job_key(source['capsule'],load_identity(source['identity']),descriptor,
        expected_package_sha256=expected['packageSHA256'],expected_policy_sha256=expected['policySHA256'],age=source['age'])
    json.dump({'identity':recovered.identity.decode('ascii'),'jobId':recovered.job_id,'packageSHA256':recovered.package_sha256,
        'policySHA256':recovered.policy_sha256,'inputRecipient':recovered.input_recipient,'resultRecipient':recovered.result_recipient},sys.stdout)

if __name__=='__main__':
    try:main()
    except Exception:
        # Never serialize exception objects or key-parser diagnostics over either pipe.
        sys.stderr.write('Local job-key recovery failed\n');sys.exit(1)
