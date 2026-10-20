"""Requester-local re-encryption of explicitly mapped dependency outputs.

Call only after the requester inbox authenticates every receipt and locks the
selected attempts. The low-level opener needs an independently authenticated
descriptor; encryption to a public recipient is not sender authentication.
"""
import os
from pathlib import Path
import shutil
import tempfile

from .client import (validate_workload, task_binding_sha256, open_archive,
                     regular_source, seal_archive, canonical)
from .dependency_inputs import validate_dependency_inputs


def _selection(spec, context):
    validate_workload(spec)
    index = context['task']
    if (type(index) is not int or not 0 <= index < len(spec['tasks'])
            or context['jobId'] != spec['id'] or context['policySHA256'] != spec['policySHA256']
            or context['taskSHA256'] != task_binding_sha256(context['packageSHA256'], index)):
        raise ValueError('Dependency target differs from the private workload')
    task = spec['tasks'][index]
    if (context['runtimeSHA256'] != task['runtime']['digestSHA256']
            or context['worldSize'] != task['resources']['nodes']
            or type(context['rank']) is not int or not 0 <= context['rank'] < context['worldSize']):
        raise ValueError('Dependency target runtime or rank differs')
    mappings = validate_dependency_inputs(spec, task)
    if mappings is None:
        raise ValueError('Dependency task requires explicit input mappings')
    by_id = {t['id']: i for i, t in enumerate(spec['tasks'])}
    needed = {(by_id[m['task']], m['rank']) for m in mappings}
    sources = context['sources']
    if (len(sources) != len(needed) or {(s['task'], s['rank']) for s in sources} != needed
            or any(s['taskSHA256'] != task_binding_sha256(context['packageSHA256'], s['task'])
                   or s['worldSize'] != spec['tasks'][s['task']]['resources']['nodes']
                   or type(s['attempt']) is not int or not 1 <= s['attempt'] <= 1000000 for s in sources)):
        raise ValueError('Dependency provenance differs from the private input mappings')
    return task, mappings


def prepare_dependency_bundle(spec, context, results, identity, destination, *, age=None):
    task, mappings = _selection(spec, context)
    by_id = {t['id']: i for i, t in enumerate(spec['tasks'])}
    needed = {(by_id[m['task']], m['rank']) for m in mappings}
    sources = {(s['task'], s['rank']): s for s in context['sources']}
    if len(sources) != len(context['sources']) or set(sources) != needed or len(results) != len(sources):
        raise ValueError('Dependency results must exactly cover the explicit mappings')
    destination = Path(destination).absolute()
    if os.path.lexists(destination):
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # The requester owns this directory. It is never worker-host staging.
    with tempfile.TemporaryDirectory(prefix='.cannabis-dependencies-', dir=destination.parent) as temp:
        staging = Path(temp)
        os.chmod(staging, 0o700)
        collected = staging / 'collected'
        collected.mkdir(mode=0o700)
        seen, total = set(), 0
        for item in results:
            if set(item) != {'receipt', 'file', 'approval'}:
                raise ValueError('Dependency result fields differ')
            receipt, approval = item['receipt'], item['approval']
            value = approval['value']
            index = by_id.get(receipt['taskId'])
            slot = (index, receipt['rank'])
            source = sources.get(slot)
            if source is None or slot in seen:
                raise ValueError('Unexpected or repeated dependency result')
            original = spec['tasks'][index]
            if (approval['digest'] != source['approvalDigest'] or approval['jobId'] != spec['id']
                    or value['packageSHA256'] != '0x' + context['packageSHA256']
                    or value['policySHA256'] != '0x' + spec['policySHA256']
                    or value['taskSHA256'] != '0x' + task_binding_sha256(context['packageSHA256'], index)
                    or value['runtimeSHA256'] != '0x' + original['runtime']['digestSHA256']
                    or value['reservationId'] != source['reservationId']
                    or receipt['schema'] != 'cannabis.result.v1'
                    or receipt['jobId'] != spec['id'] or receipt['packageSHA256'] != context['packageSHA256']
                    or receipt['recipient'] != spec.get('resultRecipient')
                    or receipt['worldSize'] != original['resources']['nodes']
                    or any(receipt[k] != source[k] for k in ['attempt', 'rank', 'worldSize', 'ciphertextSHA256', 'ciphertextBytes'])
                    or any(value[k] != source[k] for k in ['attempt', 'rank', 'worldSize'])
                    or Path(item['file']).stat().st_size != receipt['ciphertextBytes']):
                raise ValueError('Dependency receipt differs from its approved task')
            root = staging / str(len(seen))
            manifest = open_archive(item['file'], identity, root, receipt['ciphertextSHA256'],
                                    age=age, max_bytes=original.get('outputMaxBytes', 1024**3))
            expected = {k: receipt[k] for k in ['jobId', 'taskId', 'packageSHA256', 'attempt', 'rank', 'worldSize']}
            if (manifest['kind'] != 'result' or manifest['context'] != expected
                    or {f['path'] for f in manifest['files']} != set(original['outputs'])):
                raise ValueError('Dependency archive differs from its output contract')
            for mapping in mappings:
                if (by_id[mapping['task']], mapping['rank']) != slot:
                    continue
                incoming = regular_source(root, mapping['output'])
                size = incoming.stat().st_size
                total += size
                if total > task['dependencyInputMaxBytes']:
                    raise ValueError('Dependency inputs exceed the approved byte budget')
                target = collected / mapping['destination']
                target.parent.mkdir(parents=True, exist_ok=True)
                # Files were authenticated into our exclusive requester directory.
                # Copy data only; do not execute or deserialize customer outputs.
                with incoming.open('rb') as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst, 1024*1024)
                if target.stat().st_size != size:
                    raise ValueError('Dependency artifact changed during collection')
                os.chmod(target, 0o600)
            seen.add(slot)
            shutil.rmtree(root)  # Exact directory created above, inside owned staging.
        if seen != needed:
            raise ValueError('Missing required dependency results')
        sealed = seal_archive(collected, [m['destination'] for m in mappings], context,
                              context['inputRecipient'], destination, kind='dependencies', age=age)
        return {'schema': 'cannabis.dependency-handoff.v1', 'context': context, **sealed}


def open_dependency_bundle(spec, authenticated_handoff, ciphertext, input_identity, destination, *, age=None):
    """Decode only after signature/plan approval, inside protected guest staging.

    This library function supplies neither that staging nor admission. The native
    execution entry point intentionally continues to refuse external dependencies.
    """
    handoff = authenticated_handoff
    task, mappings = _selection(spec, handoff['context'])
    if (handoff['schema'] != 'cannabis.dependency-handoff.v1'
            or handoff['recipient'] != handoff['context']['inputRecipient']
            or handoff['format'] != 'age-v1+ustar'
            or Path(ciphertext).stat().st_size != handoff['ciphertextBytes']):
        raise ValueError('Dependency capsule metadata differs')
    destination = Path(destination).absolute()
    if os.path.lexists(destination):
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.cannabis-dependency-open-', dir=destination.parent) as temp:
        root = Path(temp) / 'verified'
        manifest = open_archive(ciphertext, input_identity, root, handoff['ciphertextSHA256'],
                                age=age, max_bytes=task['dependencyInputMaxBytes'])
        if (manifest['kind'] != 'dependencies' or canonical(manifest['context']) != canonical(handoff['context'])
                or {f['path'] for f in manifest['files']} != {m['destination'] for m in mappings}
                or any(f.get('executable') is not False for f in manifest['files'])):
            raise ValueError('Dependency capsule context or input contract differs')
        destination.mkdir()  # Exclusive reservation; never overwrite existing output.
        try:
            for p in root.iterdir():
                p.rename(destination / p.name)
        except BaseException:
            shutil.rmtree(destination)
            raise
        return {'inputIntegrityVerified': True, 'executionAuthorized': False, 'keyReleaseAuthorized': False}
