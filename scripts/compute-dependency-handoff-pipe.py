"""Requester-only capsule preparation; identity stays in this local process."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.client import load_identity, MAX_MANIFEST
from compute.job_keys import _unique_json_fields
from compute.dependency_bundle import prepare_dependency_bundle


def main():
    if sys.stdin.isatty() or sys.stdout.isatty():
        raise ValueError('Private pipes required')
    raw = sys.stdin.buffer.read(16*1024*1024+1)
    if len(raw) > 16*1024*1024:
        raise ValueError('Input bound')
    request = json.loads(raw, object_pairs_hook=_unique_json_fields)
    if set(request) != {'source', 'context', 'results'}:
        raise ValueError('Request fields')
    source = request['source']
    if set(source) != {'age', 'identity', 'manifest', 'destination'}:
        raise ValueError('Source fields')
    if Path(source['manifest']).stat().st_size > MAX_MANIFEST or Path(source['identity']).stat().st_size > 65536:
        raise ValueError('Source bound')
    spec = json.loads(Path(source['manifest']).read_text(encoding='utf-8-sig'), object_pairs_hook=_unique_json_fields)
    result = prepare_dependency_bundle(spec, request['context'], request['results'], load_identity(source['identity']),
                                       source['destination'], age=source['age'])
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('Requester dependency handoff failed\n')
        sys.exit(1)
