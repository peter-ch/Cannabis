"""Owned interoperability fixture; never opens real custody or runs user code."""
import sys, json, io, tarfile, base64, hashlib
package_sha256 = sys.argv[3] if len(sys.argv)>3 else 'a'*64
assert len(package_sha256)==64 and all(c in '0123456789abcdef' for c in package_sha256)
context = dict(jobId='owned-browser-fixture', taskId='calculate', packageSHA256=package_sha256, attempt=int(sys.argv[1]) if len(sys.argv)>1 else 1, rank=0, worldSize=1)
repetitions = int(sys.argv[2]) if len(sys.argv)>2 else 1
assert 1 <= repetitions <= 10000
data = b'owned verification result\n' * repetitions
manifest = dict(schema='cannabis.archive.v1', kind='result', context=context,
    files=[dict(path='answer.txt', bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), executable=False)])
out = io.BytesIO()
with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as tar:
    for name, content in [('manifest.json', json.dumps(manifest).encode()), ('files/00000000', data)]:
        info=tarfile.TarInfo(name); info.size=len(content); tar.addfile(info, io.BytesIO(content))
sys.stdout.write(base64.b64encode(out.getvalue()).decode())
