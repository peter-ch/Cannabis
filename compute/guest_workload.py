"""Decode approved packages INSIDE protected guest storage. Never launch code."""
from dataclasses import dataclass, field
import copy
import os
from pathlib import Path
import shutil
import tempfile

from .client import HASH, ID, MAX_BYTES, open_archive, task_binding_sha256, validate_workload
from .job_keys import RecoveredJobKey, _public_identity, _recipient


@dataclass(frozen=True)
class PreparedGuestWorkload:
    report: dict
    workload: dict = field(repr=False)
    directory: Path = field(repr=False)


def prepare_guest_workload(source, key, binding, destination, *, age=None, max_bytes=MAX_BYTES):
    """Consume a guest-opened key and its retained approved execution binding.

    The measured control plane owns the caller, executables, input paths and
    protected scratch volume. This decoder does not establish those properties,
    refresh funding, reserve hardware, or authorize a runtime to execute.
    """
    binding=copy.deepcopy(binding)
    fields={'packageSHA256','policySHA256','runtimeSHA256','taskSHA256','attempt','rank','worldSize','acceleratorClass'}
    if not isinstance(binding,dict) or set(binding)!=fields:raise ValueError('Invalid guest workload binding')
    for name in ['packageSHA256','policySHA256','runtimeSHA256','taskSHA256']:
        if not isinstance(binding[name],str) or not HASH.fullmatch(binding[name]):raise ValueError('Invalid guest commitment')
    for name,low,high in [('attempt',1,1000000),('worldSize',1,100000),('rank',0,99999)]:
        if type(binding[name]) is not int or not low<=binding[name]<=high:raise ValueError('Invalid guest rank or attempt')
    if binding['rank']>=binding['worldSize'] or binding['acceleratorClass']!='cpu':
        raise ValueError('Require a valid rank and integrated CPU attestation profile')
    if not isinstance(key,RecoveredJobKey) or not isinstance(key.job_id,str) or not ID.fullmatch(key.job_id):
        raise ValueError('Require the guest-opened per-job key')
    if key.package_sha256!=binding['packageSHA256'] or key.policy_sha256!=binding['policySHA256']:
        raise ValueError('Job key differs from the retained assignment')
    if _public_identity(key.identity,age)!=key.input_recipient or _recipient(key.result_recipient)==key.input_recipient:
        raise ValueError('Guest input and return key binding mismatch')
    destination=Path(destination).absolute()
    if os.path.lexists(destination):raise FileExistsError(destination)
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination=destination.parent.resolve(strict=True)/destination.name
    # No plaintext manifest or content is published at destination until both
    # complete archive authentication and private-assignment checks succeed.
    with tempfile.TemporaryDirectory(prefix='.cannabis-guest-',dir=destination.parent) as temporary:
        staging=Path(temporary);os.chmod(staging,0o700)
        payload=staging/'inputs'
        manifest=open_archive(source,key.identity,payload,key.package_sha256,age=age,max_bytes=max_bytes)
        if manifest.get('kind')!='workload':raise ValueError('Expected an encrypted workload')
        spec=manifest.get('context');validate_workload(spec)
        if spec['id']!=key.job_id or spec['policySHA256']!=key.policy_sha256 or spec.get('resultRecipient')!=key.result_recipient:
            raise ValueError('Private workload differs from approved job or return recipient')
        if {item['path'] for item in manifest['files']}!=set(spec['files']):
            raise ValueError('Private workload inventory differs from declared artifacts')
        indices=[i for i in range(len(spec['tasks'])) if task_binding_sha256(key.package_sha256,i)==binding['taskSHA256']]
        if len(indices)!=1:raise ValueError('Approved task does not belong to this encrypted package')
        index=indices[0];task=spec['tasks'][index]
        if task['runtime']['digestSHA256']!=binding['runtimeSHA256'] or task['resources']['nodes']!=binding['worldSize']:
            raise ValueError('Private runtime or group differs from approved assignment')
        if task['resources'].get('accelerators',0) or task['resources'].get('acceleratorMemoryMiB',0):
            raise ValueError('CPU appraisal cannot prepare an accelerator workload')
        report={'schema':'cannabis.guest-workload.v1','jobId':key.job_id,**binding,'taskIndex':index,
                'inputFiles':len(manifest['files']),'inputBytes':sum(item['bytes'] for item in manifest['files']),
                'packageVerified':True,'assignmentVerified':True,'executionAuthorized':False}
        destination.mkdir(mode=0o700)
        try:
            for item in payload.iterdir():item.rename(destination/item.name)
        except BaseException:
            # Only the directory reserved by this invocation is removed.
            shutil.rmtree(destination);raise
        return PreparedGuestWorkload(report,spec,destination)
