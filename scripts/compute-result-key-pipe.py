"""Private requester pipe: DPAPI/native owner identity never leaves this process."""
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.client import load_identity,age_binary
from compute.job_keys import _run,_owner_public,_unique_json_fields

def main():
    if sys.stdin.isatty() or sys.stdout.isatty():raise ValueError('Private pipes required')
    raw=sys.stdin.buffer.read(65537)
    if len(raw)>65536:raise ValueError('Oversized request')
    request=json.loads(raw,object_pairs_hook=_unique_json_fields)
    if set(request)!={'protocol','source','expected'} or request['protocol']!='cannabis.local-result-key.v1':raise ValueError('Protocol')
    source,binding=request['source'],request['expected']
    if set(source)!={'age','custody','identity'} or set(binding)!={'releaseId','recipient','resultKeySHA256'}:raise ValueError('Fields')
    for name in ['custody','identity']:
        if Path(source[name]).stat().st_size>65536:raise ValueError('Oversized source')
    record=json.loads(Path(source['custody']).read_text(encoding='utf-8-sig'),object_pairs_hook=_unique_json_fields)
    if set(record)!={'schema','releaseId','recipient','resultKeySHA256','ciphertext','ciphertextSHA256'} or record['schema']!='cannabis.result-key.custody.v1':raise ValueError('Custody')
    if any(record[k]!=v for k,v in binding.items()) or not re.fullmatch(r'[A-Za-z0-9_-]{1,16384}',record['ciphertext']):raise ValueError('Binding')
    ciphertext=base64.urlsafe_b64decode(record['ciphertext']+'='*(-len(record['ciphertext'])%4))
    if base64.urlsafe_b64encode(ciphertext).decode().rstrip('=')!=record['ciphertext'] or hashlib.sha256(ciphertext).hexdigest()!=record['ciphertextSHA256']:raise ValueError('Ciphertext')
    identity=load_identity(source['identity'])
    if _owner_public(identity,source['age'])!=binding['recipient']:raise ValueError('Owner')
    # Only ciphertext is staged. The owner identity is supplied on stdin to age.
    with tempfile.TemporaryDirectory(prefix='cannabis-result-key-') as directory:
        path=Path(directory)/'custody.age';path.write_bytes(ciphertext)
        clear=_run([age_binary(source['age']),'-d','-i','-',str(path)],identity)
    if len(clear)>4096:raise ValueError('Oversized plaintext')
    opened=json.loads(clear,object_pairs_hook=_unique_json_fields)
    if set(opened)!={'schema','releaseId','recipient','resultKeySHA256','key'} or opened['schema']!='cannabis.result-key.v1' or any(opened[k]!=v for k,v in binding.items()):raise ValueError('Protected binding')
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}',opened['key']):raise ValueError('Key encoding')
    key=base64.urlsafe_b64decode(opened['key']+'=')
    if len(key)!=32 or base64.urlsafe_b64encode(key).decode().rstrip('=')!=opened['key'] or '0x'+hashlib.sha256(key).hexdigest()!=binding['resultKeySHA256']:raise ValueError('Key commitment')
    sys.stdout.buffer.write(key)

if __name__=='__main__':
    try:main()
    except Exception:sys.stderr.write('Local result-key recovery failed\n');sys.exit(1)
