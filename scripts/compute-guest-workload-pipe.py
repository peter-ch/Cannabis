"""Internal protected-guest pipe. No key/contract in arguments, files or logs."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.guest_workload import prepare_guest_workload
from compute.job_keys import RecoveredJobKey


def main():
    if sys.stdin.isatty() or sys.stdout.isatty():raise ValueError('Anonymous guest pipes required')
    raw=sys.stdin.buffer.read(65537)
    if len(raw)>65536:raise ValueError('Guest pipe request exceeds bound')
    request=json.loads(raw)
    if set(request)!={'protocol','source','job','binding','maxBytes'} or request['protocol']!='cannabis.guest-workload.pipe.v1':raise ValueError('Invalid guest pipe protocol')
    source=request['source'];job=request['job']
    if set(source)!={'age','ciphertext','destination'}:raise ValueError('Invalid protected source configuration')
    if set(job)!={'identity','jobId','packageSHA256','policySHA256','inputRecipient','resultRecipient'}:raise ValueError('Invalid guest job key')
    key=RecoveredJobKey(job['identity'].encode('ascii'),job['jobId'],job['packageSHA256'],job['policySHA256'],job['inputRecipient'],job['resultRecipient'])
    prepared=prepare_guest_workload(source['ciphertext'],key,request['binding'],source['destination'],age=source['age'],max_bytes=request['maxBytes'])
    # The private contract crosses only this control-plane pipe; the parent keeps
    # it non-enumerable. It is never printed to a terminal or host-side log.
    json.dump({'report':prepared.report,'workload':prepared.workload},sys.stdout,ensure_ascii=True,allow_nan=False,separators=(',',':'))


if __name__=='__main__':
    try:main()
    except Exception:
        sys.stderr.write('Protected guest workload preparation failed\n');sys.exit(1)
