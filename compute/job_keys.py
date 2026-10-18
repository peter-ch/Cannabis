"""Per-job input keys, encrypted for requester custody with the established age tool.

Only ciphertext and a public descriptor are written. This module does not release
keys to workers. The requester identity remains in memory and local protected custody.
"""
from __future__ import annotations
import copy
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .client import (HASH, ID, MAX_BYTES, age_binary, canonical, pack_workload,
                     validate_workload)

MAX_CAPSULE = 16384
RECIPIENT = re.compile(r'age1[0-9a-z]{58}')
SECRET = re.compile(rb'AGE-SECRET-KEY-1[A-Z0-9]{58}\n')


def _recipient(value):
    if not isinstance(value, str) or not RECIPIENT.fullmatch(value):
        raise ValueError('Require an age X25519 public recipient')
    return value


def _run(command, data=None):
    try:
        result = subprocess.run(command, input=data, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Local age key operation could not complete') from None
    if result.returncode:
        # Do not include tool stdout/stderr: key-parser diagnostics may contain secrets.
        raise ValueError('Local age key operation failed')
    return result.stdout


def _keygen(age):
    binary = Path(shutil.which(age_binary(age)) or age_binary(age))
    keygen = binary.with_name('age-keygen.exe' if os.name == 'nt' else 'age-keygen')
    if not keygen.is_file():
        raise RuntimeError('Install age-keygen beside the selected age executable')
    return str(keygen)


def _public_identity(identity, age):
    if not isinstance(identity, bytes) or not SECRET.fullmatch(identity):
        raise ValueError('Job key must contain exactly one native X25519 identity')
    try:
        return _recipient(_run([_keygen(age), '-y'], identity).decode('ascii').strip())
    except UnicodeError:
        raise ValueError('Invalid job public identity') from None


def _new_identity(age):
    raw = _run([_keygen(age)])
    lines = [line for line in raw.splitlines() if line and not line.startswith(b'#')]
    if len(lines) != 1:
        raise ValueError('Unexpected age-keygen output')
    identity = lines[0] + b'\n'
    return identity, _public_identity(identity, age)


def _owner_public(identity, age):
    lines = [line for line in identity.splitlines() if line and not line.startswith(b'#')]
    if len(lines) != 1: raise ValueError('Use one requester X25519 identity for job-key custody')
    return _public_identity(lines[0] + b'\n', age)


def _unique_json_fields(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise ValueError('Duplicate encrypted job-key field')
        value[key] = item
    return value


def _write_cipher(path, data):
    with path.open('xb') as f:
        os.chmod(path, 0o600)
        f.write(data); f.flush(); os.fsync(f.fileno())


def _publish(staging, destination):
    # Exclusive directory reservation; descriptor is published last as the ready marker.
    # Hard links cannot overwrite a concurrent caller's files. All files are ciphertext
    # or public metadata. A crash before descriptor publication leaves an incomplete job.
    destination.mkdir(mode=0o700)
    linked = []
    try:
        for name in ['workload.age', 'job-key.age', 'descriptor.json']:
            source, target = staging / name, destination / name
            os.link(source, target); linked.append((source, target))
    except BaseException:
        for source, target in reversed(linked):
            try:
                if os.path.samefile(source, target): target.unlink()
            except FileNotFoundError:
                pass
        try: destination.rmdir()
        except OSError: pass  # Preserve unrelated files if another actor added any.
        raise


def pack_job(spec, root, owner_recipient, destination, age=None):
    """Create workload.age, encrypted job-key.age and descriptor.json exclusively.

    The supplied owner's public key protects the job key and receives returned
    outputs. A fresh, different input identity is generated for every invocation.
    """
    owner_recipient = _recipient(owner_recipient)
    spec = copy.deepcopy(spec)
    if 'resultRecipient' in spec and spec['resultRecipient'] != owner_recipient:
        raise ValueError('Existing result recipient differs from the selected requester key')
    spec['resultRecipient'] = owner_recipient
    validate_workload(spec)
    destination = Path(destination).absolute()
    if os.path.lexists(destination): raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination = destination.parent.resolve(strict=True) / destination.name
    # The temp directory is created by us directly in the verified destination parent.
    with tempfile.TemporaryDirectory(prefix='.cannabis-job-', dir=destination.parent) as tmp:
        staging = Path(tmp)
        os.chmod(staging, 0o700)
        identity, recipient = _new_identity(age)
        if recipient == owner_recipient: raise ValueError('Job input and requester identities must differ')
        descriptor = pack_workload(spec, root, recipient, staging / 'workload.age', age)
        record = {'schema': 'cannabis.job-key.v1', 'jobId': spec['id'],
                  'packageSHA256': descriptor['ciphertextSHA256'], 'packageBytes': descriptor['ciphertextBytes'],
                  'policySHA256': spec['policySHA256'], 'inputRecipient': recipient,
                  'resultRecipient': owner_recipient, 'identity': identity.decode('ascii')}
        ciphertext = _run([age_binary(age), '-r', owner_recipient], canonical(record))
        if not 0 < len(ciphertext) <= MAX_CAPSULE: raise ValueError('Job-key capsule exceeds bound')
        _write_cipher(staging / 'job-key.age', ciphertext)
        descriptor.update(schema='cannabis.package.v2', keyCustody={
            'schema': 'cannabis.job-key.custody.v1', 'format': 'age-v1+json',
            'ciphertextSHA256': hashlib.sha256(ciphertext).hexdigest(), 'ciphertextBytes': len(ciphertext)})
        _write_cipher(staging / 'descriptor.json', canonical(descriptor) + b'\n')
        with (staging / 'workload.age').open('r+b') as f: os.fsync(f.fileno())
        _publish(staging, destination)
    return descriptor


@dataclass(frozen=True)
class RecoveredJobKey:
    # Prevent accidental disclosure through ordinary repr/logging of this object.
    identity: bytes = field(repr=False)
    job_id: str
    package_sha256: str
    policy_sha256: str
    input_recipient: str
    result_recipient: str


def recover_job_key(capsule, owner_identity, descriptor, *, expected_package_sha256,
                    expected_policy_sha256, age=None):
    """Requester-only recovery into memory; never a worker-release authorization.

    Use the requester's saved descriptor and independently approved commitments,
    not a replacement descriptor supplied by a worker or storage operator.
    """
    descriptor = copy.deepcopy(descriptor)
    for digest in [expected_package_sha256, expected_policy_sha256]:
        if not isinstance(digest, str) or not HASH.fullmatch(digest): raise ValueError('Approved package and policy digests required')
    if descriptor.get('schema') != 'cannabis.package.v2' or descriptor.get('ciphertextSHA256') != expected_package_sha256 or descriptor.get('policySHA256') != expected_policy_sha256:
        raise ValueError('Descriptor differs from the approved job')
    if not isinstance(descriptor.get('id'), str) or not ID.fullmatch(descriptor['id']): raise ValueError('Invalid job ID')
    _recipient(descriptor.get('recipient'))
    size = descriptor.get('ciphertextBytes')
    if type(size) is not int or not 0 < size <= MAX_BYTES + MAX_BYTES // 100:
        raise ValueError('Invalid package byte commitment')
    custody = descriptor.get('keyCustody')
    if not isinstance(custody, dict) or set(custody) != {'schema', 'format', 'ciphertextSHA256', 'ciphertextBytes'} or custody['schema'] != 'cannabis.job-key.custody.v1' or custody['format'] != 'age-v1+json':
        raise ValueError('Unknown job-key custody format')
    if type(custody['ciphertextBytes']) is not int or not 0 < custody['ciphertextBytes'] <= MAX_CAPSULE or not isinstance(custody['ciphertextSHA256'], str) or not HASH.fullmatch(custody['ciphertextSHA256']):
        raise ValueError('Invalid capsule commitment')
    with open(capsule, 'rb') as f: ciphertext = f.read(MAX_CAPSULE + 1)
    if len(ciphertext) != custody['ciphertextBytes'] or hashlib.sha256(ciphertext).hexdigest() != custody['ciphertextSHA256']:
        raise ValueError('Job-key capsule commitment mismatch')
    if not isinstance(owner_identity, bytes) or not 0 < len(owner_identity) <= MAX_CAPSULE:
        raise ValueError('Requester identity must come from bounded protected local custody')
    owner_recipient = _owner_public(owner_identity, age)
    # Copy only the already-checked CIPHERTEXT to a private temp directory. The age
    # CLI can then take the identity over stdin without a mutable-source/hash race.
    with tempfile.TemporaryDirectory(prefix='cannabis-key-ciphertext-') as tmp:
        os.chmod(tmp, 0o700)
        source = Path(tmp) / 'key.age'
        _write_cipher(source, ciphertext)
        raw = _run([age_binary(age), '-d', '-i', '-', str(source)], owner_identity)
    if len(raw) > MAX_CAPSULE: raise ValueError('Decrypted job-key capsule exceeds bound')
    try:
        record = json.loads(raw, object_pairs_hook=_unique_json_fields)
    except (ValueError, UnicodeError):
        raise ValueError('Invalid encrypted job-key record') from None
    fields = {'schema', 'jobId', 'packageSHA256', 'packageBytes', 'policySHA256', 'inputRecipient', 'resultRecipient', 'identity'}
    if not isinstance(record, dict) or set(record) != fields or record['schema'] != 'cannabis.job-key.v1':
        raise ValueError('Unknown encrypted job-key record')
    for key, expected in {'jobId': descriptor['id'], 'packageSHA256': expected_package_sha256,
                          'packageBytes': size, 'policySHA256': expected_policy_sha256,
                          'inputRecipient': descriptor['recipient']}.items():
        if record[key] != expected or type(record[key]) is not type(expected):
            raise ValueError('Job-key record binding mismatch')
    _recipient(record['resultRecipient'])
    if record['resultRecipient'] != owner_recipient:
        raise ValueError('Job-key return recipient differs from requester custody')
    if not isinstance(record['identity'], str): raise ValueError('Invalid job identity')
    try: identity = record['identity'].encode('ascii')
    except UnicodeError: raise ValueError('Invalid job identity encoding') from None
    if _public_identity(identity, age) != record['inputRecipient'] or record['resultRecipient'] == record['inputRecipient']:
        raise ValueError('Job-key identity binding mismatch')
    return RecoveredJobKey(identity, record['jobId'], record['packageSHA256'], record['policySHA256'],
                           record['inputRecipient'], record['resultRecipient'])
