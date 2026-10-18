"""Owned interoperability fixture; never opens real custody or runs user code."""
import sys, json, io, tarfile, base64, hashlib
context = dict(jobId='owned-browser-fixture', taskId='calculate', packageSHA256='a'*64, attempt=1, rank=0, worldSize=1)
data = b'owned verification result\n'
manifest = dict(schema='cannabis.archive.v1', kind='result', context=context,
    files=[dict(path='answer.txt', bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), executable=False)])
out = io.BytesIO()
with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as tar:
    for name, content in [('manifest.json', json.dumps(manifest).encode()), ('files/00000000', data)]:
        info=tarfile.TarInfo(name); info.size=len(content); tar.addfile(info, io.BytesIO(content))
sys.stdout.write(base64.b64encode(out.getvalue()).decode())
