"""Workload-agnostic encrypted packages and requester-side result reconstruction.

No artifact is executed by this module. age supplies authenticated streaming encryption.
Runtime adapters and an attested dispatcher consume the private workload contract.
"""
from __future__ import annotations
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid

MAX_MANIFEST = 4 * 1024 * 1024
MAX_FILES = 100000
MAX_BYTES = 1024 ** 4
ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')
HASH = re.compile(r'^[0-9a-f]{64}$')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def digest_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def task_binding_sha256(package_sha256, task_index):
    """Bind an opaque task index to the already committed encrypted package."""
    if not isinstance(package_sha256,str) or not HASH.fullmatch(package_sha256) or type(task_index) is not int or not 0<=task_index<4096:
        raise ValueError('Task binding requires a package commitment and valid task index')
    return hashlib.sha256(b'cannabis.task.v1\0'+bytes.fromhex(package_sha256)+task_index.to_bytes(4,'big')).hexdigest()


def safe_name(name):
    if not isinstance(name, str) or not name or len(name) > 512 or '\\' in name or ':' in name:
        raise ValueError('Artifact paths must be relative portable POSIX paths')
    p = PurePosixPath(name)
    if p.is_absolute() or p.as_posix() != name or any(x in ('', '.', '..') for x in name.split('/')):
        raise ValueError('Unsafe artifact path')
    for part in p.parts:
        if part.endswith(('.', ' ')) or re.search(r'[\x00-\x1f<>"|?*]', part):
            raise ValueError('Nonportable artifact path')
        if part.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}:
            raise ValueError('Reserved artifact path')
    return name


def regular_source(root, name):
    root = Path(root).resolve(strict=True)
    p = root
    for part in PurePosixPath(safe_name(name)).parts:
        p = p / part
        s = p.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Links and reparse points cannot be packaged')
    if not p.is_file() or not p.resolve().is_relative_to(root):
        raise ValueError('Artifact must be a regular file inside the input directory')
    return p


def validate_workload(spec):
    if len(canonical(spec)) > MAX_MANIFEST or spec.get('schema') != 'cannabis.workload.v1':
        raise ValueError('Expected a bounded cannabis.workload.v1 manifest')
    if not ID.fullmatch(spec.get('id', '')) or not HASH.fullmatch(spec.get('policySHA256', '')):
        raise ValueError('Opaque job ID and confidential policy digest required')
    if 'resultRecipient' in spec and (not isinstance(spec['resultRecipient'],str) or not re.fullmatch(r'age1[0-9a-z]{58}',spec['resultRecipient'])):
        raise ValueError('Result recipient must be an age X25519 public key')
    tasks = spec.get('tasks')
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= 4096:
        raise ValueError('Declare between 1 and 4096 task templates')
    ids = [t.get('id') for t in tasks]
    if any(not isinstance(x,str) or not ID.fullmatch(x) for x in ids) or len(set(ids)) != len(ids):
        raise ValueError('Task IDs must be unique and portable')
    files = spec.get('files')
    if not isinstance(files,list) or len(files) > MAX_FILES:
        raise ValueError('Provide an explicit artifact allowlist')
    if len({safe_name(p).casefold() for p in files}) != len(files):
        raise ValueError('Duplicate or case-colliding artifact names')
    for t in tasks:
        deps = t.get('dependsOn', [])
        if not isinstance(deps,list) or len(set(deps)) != len(deps) or any(d not in ids or d == t['id'] for d in deps):
            raise ValueError('Invalid task dependencies')
        runtime = t.get('runtime', {})
        if set(runtime)-{'adapter','digestSHA256','architecture','os','features','collectiveBackend'}:
            raise ValueError('Private runtime settings belong in launch, not public matching metadata')
        # Adapter IDs are extensible. The client does not restrict executable kinds.
        if not ID.fullmatch(runtime.get('adapter', '')) or not HASH.fullmatch(runtime.get('digestSHA256', '')):
            raise ValueError('Each task needs an adapter ID and pinned runtime digest')
        if any(not isinstance(runtime.get(k),str) or not ID.fullmatch(runtime[k]) for k in ('architecture','os')):
            raise ValueError('Runtime architecture and OS are required')
        if 'collectiveBackend' in runtime and (not isinstance(runtime['collectiveBackend'],str) or not ID.fullmatch(runtime['collectiveBackend'])):
            raise ValueError('Collective backend must be a portable identifier')
        if not isinstance(runtime.get('features',[]),list) or any(not isinstance(f,str) or not ID.fullmatch(f) for f in runtime.get('features',[])):
            raise ValueError('Runtime feature IDs must be portable identifiers')
        if not isinstance(t.get('launch'),dict):
            raise ValueError('Adapter-specific launch contract required')
        resources=t.get('resources',{})
        if set(resources)-{'cpus','memoryMiB','scratchMiB','wallSeconds','nodes','accelerators','acceleratorMemoryMiB'}:
            raise ValueError('Only resource limits belong in public matching metadata')
        for k in ('cpus','memoryMiB','scratchMiB','wallSeconds','nodes'):
            if type(resources.get(k)) is not int or resources[k] < 1:
                raise ValueError('Positive integer resource limits required')
        if resources['nodes'] > 100000 or resources['wallSeconds'] > 2592000:
            raise ValueError('Resource limits exceed client bounds')
        for k in ('accelerators','acceleratorMemoryMiB'):
            if type(resources.get(k,0)) is not int or resources.get(k,0)<0:
                raise ValueError('Invalid accelerator requirement')
        outputs=t.get('outputs',[])
        if t.get('outputScope','leader') not in ('leader','per-rank'):
            raise ValueError('Output scope must be leader or per-rank')
        if type(t.get('outputMaxBytes',1024**3)) is not int or not 0<=t.get('outputMaxBytes',1024**3)<=MAX_BYTES:
            raise ValueError('Invalid per-rank output byte limit')
        if not isinstance(outputs,list) or len({safe_name(x).casefold() for x in outputs}) != len(outputs):
            raise ValueError('Output paths must be unique')
    ordered=[]; pending={t['id']:t for t in tasks}
    from .dependency_inputs import validate_dependency_inputs
    for t in tasks:
        mappings = validate_dependency_inputs(spec, t)
        if t['runtime']['adapter'] == 'native-linux-x86_64-v1' and t['launch'].get('schema') == 'cannabis.native-step-graph.v1':
            from .native_graph import validate_native_graph
            validate_native_graph(t['launch'], files + [m['destination'] for m in mappings or []], t['outputs'])
    while pending:
        ready=[k for k,t in pending.items() if all(d in ordered for d in t.get('dependsOn',[]))]
        if not ready:raise ValueError('Task graph contains a cycle')
        for k in ready:ordered.append(k);del pending[k]
    destinations=set()
    by_id={t['id']:t for t in tasks}
    for item in spec.get('assembly',[]):
        if item.get('task') not in by_id or item.get('output') not in by_id[item['task']].get('outputs',[]):
            raise ValueError('Assembly references an undeclared output')
        task=by_id[item['task']]
        ranks=range(task['resources']['nodes']) if item.get('rank')=='all' else [item.get('rank',0)]
        for rank in ranks:
            if type(rank) is not int or not 0<=rank<task['resources']['nodes'] or (rank and task.get('outputScope','leader')=='leader'):
                raise ValueError('Assembly references an invalid output rank')
            dest=safe_name(item.get('destination','').replace('{rank}',str(rank)))
            if dest.casefold() in destinations:raise ValueError('Assembly destination collision')
            destinations.add(dest.casefold())
    return ordered


def age_binary(value=None):
    found=value or os.environ.get('CANNABIS_AGE') or shutil.which('age')
    if not found:
        raise RuntimeError('Install age, or set CANNABIS_AGE to its executable path')
    return str(found)


def _exclusive_json(path, value):
    with open(path,'x',encoding='utf-8') as f:json.dump(value,f,indent=2)


def _archive_manifest(kind, context, files):
    return {'schema':'cannabis.archive.v1','kind':kind,'context':context,'files':files}


def seal_archive(root, files, context, recipient, destination, *, kind, age=None):
    if not isinstance(recipient,str) or not re.fullmatch(r'age1[0-9a-z]{58}',recipient):
        raise ValueError('Use an age X25519 public recipient')
    destination=Path(destination).resolve()
    if destination.exists():raise FileExistsError(destination)
    destination.parent.mkdir(parents=True,exist_ok=True)
    entries=[];sources=[];seen=set();total=0
    if len(files)>MAX_FILES:raise ValueError('Too many artifacts')
    for name in files:
        safe_name(name)
        if name.casefold() in seen:raise ValueError('Duplicate archive entry')
        seen.add(name.casefold())
        p=regular_source(root,name);size=p.stat().st_size;total+=size
        if total>MAX_BYTES:raise ValueError('Archive exceeds configured client limit')
        entries.append({'path':name,'bytes':size,'sha256':digest_file(p),'executable':bool(p.stat().st_mode & stat.S_IXUSR)})
        sources.append(p)
    manifest=canonical(_archive_manifest(kind,context,entries))
    if len(manifest)>MAX_MANIFEST:raise ValueError('Archive manifest is too large')
    fd,temporary=tempfile.mkstemp(prefix='.cannabis-encrypted-',dir=destination.parent)
    proc=None
    try:
        with os.fdopen(fd,'wb') as out:
            proc=subprocess.Popen([age_binary(age),'-r',recipient],stdin=subprocess.PIPE,stdout=out,stderr=subprocess.PIPE)
            try:
                with tarfile.open(fileobj=proc.stdin,mode='w|',format=tarfile.USTAR_FORMAT) as tar:
                    meta=tarfile.TarInfo('manifest.json');meta.size=len(manifest);meta.mode=0o600
                    tar.addfile(meta,io.BytesIO(manifest))
                    for i,(entry,p) in enumerate(zip(entries,sources)):
                        header=tarfile.TarInfo(f'files/{i:08d}');header.size=entry['bytes'];header.mode=0o600
                        with open(p,'rb') as f:tar.addfile(header,f)
                        if p.stat().st_size!=entry['bytes'] or digest_file(p)!=entry['sha256']:
                            raise ValueError('Input changed while being packaged; create a consistent snapshot first')
                proc.stdin.close()
                error=proc.stderr.read();code=proc.wait()
                if code:raise RuntimeError('age encryption failed: '+error.decode(errors='replace')[:200])
            except BaseException:
                proc.kill();proc.wait();raise
        # Link creates an exclusive destination, preventing overwrite races.
        os.link(temporary,destination)
        return {'ciphertextSHA256':digest_file(destination),'ciphertextBytes':destination.stat().st_size,'format':'age-v1+ustar','recipient':recipient}
    finally:
        if proc:
            for pipe in (proc.stdin,proc.stdout,proc.stderr):
                if pipe and not pipe.closed:pipe.close()
        Path(temporary).unlink(missing_ok=True)


def pack_workload(spec, root, recipient, destination, age=None):
    validate_workload(spec)
    sealed=seal_archive(root,spec['files'],spec,recipient,destination,kind='workload',age=age)
    requirements=[]
    for i,t in enumerate(spec['tasks']):
        requirements.append({'task':i,'taskSHA256':task_binding_sha256(sealed['ciphertextSHA256'],i),'dependsOn':[next(j for j,x in enumerate(spec['tasks']) if x['id']==d) for d in t.get('dependsOn',[])],
          'runtime':t['runtime'],'resources':t['resources']})
    return {'schema':'cannabis.package.v1','id':spec['id'],'policySHA256':spec['policySHA256'],**sealed,
      'requirements':requirements,'executionAuthorized':False,'keyReleaseAuthorized':False}


def open_archive(source, identity, destination, expected_sha256, *, age=None, max_bytes=MAX_BYTES):
    """Expose output only after age verifies EOF and every manifest hash is checked."""
    source=Path(source).absolute();destination=Path(destination).absolute()
    if os.path.lexists(destination):raise FileExistsError(destination)
    if not isinstance(expected_sha256,str) or not HASH.fullmatch(expected_sha256):
        raise ValueError('Invalid ciphertext commitment')
    if type(max_bytes) is not int or not 0<=max_bytes<=MAX_BYTES:raise ValueError('Invalid extraction limit')
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination=destination.parent.resolve(strict=True)/destination.name
    temporary=Path(tempfile.mkdtemp(prefix='.cannabis-unverified-',dir=destination.parent))
    os.chmod(temporary,0o700)
    proc=None
    try:
        # Decrypt only the bytes whose commitment we checked. A storage operator
        # may replace or mutate the original path while this function is running.
        # The snapshot is ciphertext; the private directory must be protected by
        # the requester OS or, for worker inputs, by the confidential guest.
        ciphertext=temporary/'source.age';contents=temporary/'contents'
        source_stat=source.lstat()
        if not stat.S_ISREG(source_stat.st_mode) or getattr(source_stat,'st_file_attributes',0)&0x400:
            raise ValueError('Ciphertext source must be a regular file without links')
        flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
        with os.fdopen(os.open(source,flags),'rb') as incoming:
            opened=os.fstat(incoming.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino)!=(source_stat.st_dev,source_stat.st_ino):
                raise ValueError('Ciphertext source changed before opening')
            # Allow bounded USTAR headers/padding and age framing, while tying
            # ciphertext staging to the approved plaintext extraction budget.
            archive_limit=max_bytes+MAX_MANIFEST+MAX_FILES*1024+32768
            limit=archive_limit+((archive_limit+65535)//65536)*16+65536
            if not 0<opened.st_size<=limit:raise ValueError('Ciphertext source exceeds bound')
            h=hashlib.sha256();total=0
            with ciphertext.open('xb') as saved:
                os.chmod(ciphertext,0o600)
                for chunk in iter(lambda:incoming.read(1024*1024),b''):
                    total+=len(chunk)
                    if total>limit:raise ValueError('Ciphertext source exceeds bound')
                    h.update(chunk);saved.write(chunk)
        if total!=opened.st_size or h.hexdigest()!=expected_sha256:
            raise ValueError('Ciphertext commitment mismatch')
        contents.mkdir(mode=0o700)
        proc=subprocess.Popen([age_binary(age),'-d','-i','-',str(ciphertext)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        proc.stdin.write(identity);proc.stdin.close()
        with tarfile.open(fileobj=proc.stdout,mode='r|') as tar:
            first=tar.next()
            if not first or first.name!='manifest.json' or not first.isfile() or not 0<first.size<=MAX_MANIFEST:
                raise ValueError('Missing bounded package manifest')
            manifest=json.loads(tar.extractfile(first).read())
            if manifest.get('schema')!='cannabis.archive.v1':raise ValueError('Unknown archive schema')
            entries=manifest.get('files')
            if not isinstance(entries,list) or len(entries)>MAX_FILES:raise ValueError('Invalid file inventory')
            total=0;seen=set()
            for i,entry in enumerate(entries):
                name=safe_name(entry['path']);size=entry['bytes'];sha=entry['sha256']
                if name.casefold() in seen or type(size) is not int or size<0 or not HASH.fullmatch(sha):
                    raise ValueError('Invalid file inventory entry')
                seen.add(name.casefold());total+=size
                if total>max_bytes:raise ValueError('Decrypted package exceeds extraction budget')
                member=tar.next()
                if not member or member.name!=f'files/{i:08d}' or not member.isfile() or member.size!=size:
                    raise ValueError('Archive file does not match inventory')
                p=contents.joinpath(*PurePosixPath(name).parts);p.parent.mkdir(parents=True,exist_ok=True)
                h=hashlib.sha256();count=0
                with p.open('xb') as out:
                    src=tar.extractfile(member)
                    for chunk in iter(lambda:src.read(1024*1024),b''):
                        h.update(chunk);count+=len(chunk);out.write(chunk)
                if count!=size or h.hexdigest()!=sha:raise ValueError('Decrypted artifact hash mismatch')
                os.chmod(p,0o700 if entry.get('executable') is True else 0o600)
            if tar.next() is not None:raise ValueError('Undeclared archive member')
            # Drain through tar's reader: it may already have buffered bytes past EOF.
            # Reading only proc.stdout would miss an embedded trailing payload there.
            tail=0
            while chunk:=tar.fileobj.read(65536):
                tail+=len(chunk)
                if tail>32768 or any(chunk):raise ValueError('Unexpected trailing archive data')
        error=proc.stderr.read();code=proc.wait()
        if code:raise ValueError('age authentication/decryption failed')
        destination.mkdir()  # Reserve final destination without overwriting existing paths.
        try:
            for p in contents.iterdir():p.rename(destination/p.name)
        except BaseException:
            shutil.rmtree(destination);raise
        return manifest
    finally:
        if proc and proc.poll() is None:proc.kill();proc.wait()
        if proc:
            for pipe in (proc.stdin,proc.stdout,proc.stderr):
                if pipe and not pipe.closed:pipe.close()
        # This is the exact temporary directory just created by this function.
        shutil.rmtree(temporary)


def seal_result(spec, task_id, package_sha256, root, recipient, destination, *, attempt=1, rank=0, age=None):
    validate_workload(spec)
    if 'resultRecipient' in spec and recipient!=spec['resultRecipient']:
        raise ValueError('Result encryption must use the requester recipient bound inside the workload')
    task=next((t for t in spec['tasks'] if t['id']==task_id),None)
    if task is None or not HASH.fullmatch(package_sha256) or type(attempt) is not int or attempt<1:
        raise ValueError('Result must bind to a declared task, package and attempt')
    if type(rank) is not int or not 0<=rank<task['resources']['nodes'] or (rank and task.get('outputScope','leader')=='leader'):
        raise ValueError('Invalid output rank for this task')
    if sum(regular_source(root,name).stat().st_size for name in task['outputs'])>task.get('outputMaxBytes',1024**3):
        raise ValueError('Result exceeds the agreed output byte limit')
    context={'jobId':spec['id'],'taskId':task_id,'packageSHA256':package_sha256,'attempt':attempt,'rank':rank,'worldSize':task['resources']['nodes']}
    return {'schema':'cannabis.result.v1',**context,**seal_archive(root,task['outputs'],context,recipient,destination,kind='result',age=age),
       'executionAttested':False,'acceptanceRequired':True}


def assemble_results(spec, package_sha256, results, identity, destination, *, age=None):
    validate_workload(spec)
    if not HASH.fullmatch(package_sha256):raise ValueError('Original package digest required')
    destination=Path(destination).resolve()
    if destination.exists():raise FileExistsError(destination)
    destination.parent.mkdir(parents=True,exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix='.cannabis-assembly-',dir=destination.parent))
    by_task={};tasks={t['id']:t for t in spec['tasks']}
    try:
        for i,item in enumerate(results):
            receipt=item['receipt'];task=receipt['taskId'];rank=receipt.get('rank');key=(task,rank)
            if receipt.get('schema')!='cannabis.result.v1' or task not in tasks or key in by_task or receipt['jobId']!=spec['id'] or receipt['packageSHA256']!=package_sha256:
                raise ValueError('Wrong job/task/package or duplicate result receipt')
            if 'resultRecipient' in spec and receipt.get('recipient')!=spec['resultRecipient']:
                raise ValueError('Result recipient differs from the private workload contract')
            if type(receipt.get('attempt')) is not int or receipt['attempt']<1:
                raise ValueError('Result attempt must be a positive integer')
            if type(rank) is not int or not 0<=rank<tasks[task]['resources']['nodes'] or receipt.get('worldSize')!=tasks[task]['resources']['nodes']:
                raise ValueError('Result rank/world size mismatch')
            if rank and tasks[task].get('outputScope','leader')=='leader':raise ValueError('Unexpected nonleader output')
            manifest=open_archive(item['file'],identity,staging/str(i),receipt['ciphertextSHA256'],age=age,max_bytes=tasks[task].get('outputMaxBytes',1024**3))
            expected={k:receipt[k] for k in ('jobId','taskId','packageSHA256','attempt','rank','worldSize')}
            if manifest['kind']!='result' or manifest['context']!=expected or {x['path'] for x in manifest['files']}!=set(tasks[task]['outputs']):
                raise ValueError('Result context/output contract mismatch')
            by_task[key]=staging/str(i)
        expanded=[]
        for item in spec.get('assembly',[]):
            ranks=range(tasks[item['task']]['resources']['nodes']) if item.get('rank')=='all' else [item.get('rank',0)]
            for rank in ranks:expanded.append({**item,'rank':rank,'destination':item['destination'].replace('{rank}',str(rank))})
        required={(item['task'],item['rank']) for item in expanded}
        if not required or not required<=by_task.keys():raise ValueError('Missing required assembly results')
        assembled=staging/'assembled';assembled.mkdir()
        for item in expanded:
            source=by_task[(item['task'],item['rank'])].joinpath(*PurePosixPath(item['output']).parts)
            target=assembled.joinpath(*PurePosixPath(item['destination']).parts)
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        destination.mkdir()
        try:
            for p in assembled.iterdir():p.rename(destination/p.name)
        except BaseException:
            shutil.rmtree(destination);raise
        return {'jobId':spec['id'],'files':[x['destination'] for x in expanded],
          'integrityVerified':True,'acceptanceRequired':True,'paymentAuthorized':False,
          'note':'Authenticated files reconstructed; output quality and worker execution require separate acceptance.'}
    finally:shutil.rmtree(staging)


def dpapi(data, decrypt=False):
    if os.name!='nt':raise RuntimeError('DPAPI vaults require the owning Windows account')
    class Blob(ctypes.Structure):_fields_=[('size',ctypes.c_uint32),('data',ctypes.POINTER(ctypes.c_ubyte))]
    buffer=ctypes.create_string_buffer(data);src=Blob(len(data),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte)));out=Blob()
    crypt=ctypes.windll.crypt32
    ok=crypt.CryptUnprotectData(ctypes.byref(src),None,None,None,None,1,ctypes.byref(out)) if decrypt else crypt.CryptProtectData(ctypes.byref(src),'Cannabis compute identity',None,None,None,1,ctypes.byref(out))
    if not ok:raise OSError('Windows protected-key operation failed')
    try:return ctypes.string_at(out.data,out.size)
    finally:ctypes.windll.kernel32.LocalFree(out.data)


def create_identity(destination, age=None):
    import base64
    if os.name!='nt':raise RuntimeError('Use age-keygen with a protected identity store on this platform')
    binary=Path(age_binary(age));keygen=binary.with_name('age-keygen.exe')
    r=subprocess.run([str(keygen)],capture_output=True,check=True)
    identity=r.stdout
    pub=subprocess.run([str(keygen),'-y'],input=identity,capture_output=True,check=True).stdout.decode().strip()
    sealed=dpapi(identity)
    if dpapi(sealed,True)!=identity:raise RuntimeError('Identity recovery verification failed')
    _exclusive_json(destination,{'schema':'cannabis.compute.identity.dpapi.v1','recipient':pub,'protected':base64.b64encode(sealed).decode()})
    return {'recipient':pub,'protection':'Windows CurrentUser DPAPI','portableBackupRequired':True}


def load_identity(path):
    import base64
    raw=Path(path).read_bytes()
    if raw.startswith(b'{'):
        value=json.loads(raw)
        if value.get('schema')!='cannabis.compute.identity.dpapi.v1':raise ValueError('Unknown identity vault')
        return dpapi(base64.b64decode(value['protected'],validate=True),True)
    return raw
