#!/usr/bin/env python3
"""Boot a separate owned network-check image; never admit confidential hardware.

The source operating image is verified and left unchanged. Its retained rootfs is
copied to a private diagnostic image with a different entry and public fixture CA.
The production entry has no diagnostic mode or extra trust-root override.
"""
import argparse
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import ssl
import subprocess
import threading
import time
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[1]


def digest(file):
    with file.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


class Fixture(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_POST(self):
        size=int(self.headers.get('Content-Length','0'))
        if not 0<size<=1024:self.send_error(400);return
        value=json.loads(self.rfile.read(size))
        if value.get('method')!='eth_chainId':self.send_error(400);return
        if self.path=='/redirect':
            self.send_response(302);self.send_header('Location','https://10.0.2.2/elsewhere');self.end_headers();return
        if self.path=='/slow':time.sleep(.5)
        body=json.dumps({'jsonrpc':'2.0','id':value['id'],'result':'0x7a69'}).encode()
        try:
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
            self.end_headers();self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass


def tls_server(out,name):
    cert,key=out/(name+'.crt'),out/(name+'.key')
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Cannabis isolated network fixture',
      '-addext','subjectAltName=IP:10.0.2.2','-addext','basicConstraints=critical,CA:TRUE','-keyout',str(key),'-out',str(cert)],
      stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=30)
    key.chmod(0o600);server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Fixture)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    return server,thread,cert


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();image,out=args.image.resolve(),args.output.resolve()
    if os.geteuid()!=0 or out.exists() or ROOT==out or ROOT in out.parents:raise ValueError('Use root and a new private output directory')
    report=json.loads((image/'build.json').read_text())
    if report['schema']!='cannabis.guest-image-build.v1' or report.get('operatingEntryConfigured') is not True or report['executionAuthorized'] is not False:
        raise ValueError('Require the retained operating image build')
    for name,item in report['outputs'].items():
        if digest(image/name)!=item['sha256']:raise ValueError('Source image changed')
    # Check the source tree against the actual embedded-file manifest before
    # copying. Diagnostic results are tied to these exact measured module bytes.
    source=image/'rootfs';project=Path('opt/cannabis')
    for item in json.loads((source/project/'image-files.json').read_text()):
        if digest(source/item['path'].lstrip('/'))!=item['sha256']:raise ValueError('Retained image rootfs changed')
    out.mkdir(mode=0o700,parents=True);tree=out/'rootfs';shutil.copytree(source,tree,symlinks=True)
    diagnostic_scripts={}
    for name in ['check-guest-network.py','check-guest-network.mjs']:
        target=tree/project/'scripts'/name
        target.write_text((ROOT/'scripts'/name).read_text())
        diagnostic_scripts[name]=digest(target)
    spec=importlib.util.spec_from_file_location('owned_image_writer',ROOT/'scripts/build-guest-image.py');builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    servers=[]
    try:
        trusted=tls_server(out,'trusted');servers.append(trusted)
        untrusted=tls_server(out,'untrusted');servers.append(untrusted)
        (tree/project/'network-check.json').write_text(json.dumps({'tlsPort':trusted[0].server_port,'untrustedPort':untrusted[0].server_port})+'\n')
        shutil.copyfile(trusted[2],tree/project/'network-fixture-ca.pem')
        entry=tree/project/'guest-init'
        entry.write_text('''#!/bin/busybox sh
. /opt/cannabis/prepare-init
/usr/bin/python3 -I -B /opt/cannabis/scripts/check-guest-network.py
code=$?
echo CANNABIS_NETWORK_EXIT $code
/bin/busybox poweroff -f
while :; do /bin/busybox sleep 60; done
''');entry.chmod(0o755)
        artifact=out/'network-check.cpio.gz'
        lock=json.loads((ROOT/'compute/guest-image/inputs.json').read_text())
        builder.write_initramfs(tree,artifact,lock['sourceDateEpoch'])
        ref=report['vmBudget']['profile']['referenceVM'];qemu=shutil.which('qemu-system-x86_64')
        if not qemu:raise ValueError('Require QEMU')
        command=[qemu,'-machine','q35,accel=tcg','-cpu','max','-smp',str(ref['cpus']),'-m',str(ref['memoryMiB']),'-nodefaults',
          '-netdev','user,id=controlnet,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,ipv6=off',
          '-device','virtio-net-pci,netdev=controlnet,mac=52:54:00:ca:42:00','-display','none','-monitor','none','-serial','stdio','-no-reboot',
          '-kernel',str(image/'vmlinuz'),'-initrd',str(artifact),'-append','console=ttyS0 panic=-1 quiet loglevel=3 init=/init']
        with (out/'serial.log').open('xb') as log:
            process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=process.wait(timeout=180)
            finally:
                if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10)
        text=(out/'serial.log').read_text(errors='replace');rows=[line.removeprefix('CANNABIS_NETWORK_RESULT ') for line in text.splitlines() if line.startswith('CANNABIS_NETWORK_RESULT ')]
        if code!=0 or len(rows)!=1 or 'CANNABIS_NETWORK_EXIT 0' not in text or 'Traceback' in text:raise ValueError('Guest network checkpoint failed; inspect the private serial log')
        result=json.loads(rows[0]);expected={'fixedVirtioStaticNetwork','existingConfigurationRefused','changedMTURefused','extraAddressRefused',
          'redirectControlChangeRefused','workloadNetworkStillDenied','workloadTreeCleaned','httpsRPCRead','untrustedCertificateRefused',
          'redirectRefused','deadlineEnforced','wrongTLSNameRefused','dnsResolution'}
        if result['checks']!={name:True for name in expected}:raise ValueError('Incomplete guest network evidence')
        for name,item in report['outputs'].items():
            if digest(image/name)!=item['sha256']:raise ValueError('Source image changed during checkpoint')
        final={'schema':'cannabis.guest-network-verification.v1','checkedAt':datetime.now(timezone.utc).isoformat(),
          'sourceImage':report['outputs'],'diagnosticScriptsSHA256':diagnostic_scripts,'diagnosticInitramfsSHA256':digest(artifact),'productionImageUnchanged':True,
          'diagnosticEntryOnly':True,'fixtureCAOnly':True,'networkAttached':True,'hostTLSFixtureBoundToLoopback':True,
          'externalDNSProbe':'example.com','realChainObserved':False,'hardwareValidated':False,'customerKeysUsed':False,'realPaidJob':False,'result':result}
        (out/'verification.json').write_text(json.dumps(final,indent=2)+'\n');print(json.dumps({'checks':len(expected),'verified':True,'hardwareValidated':False}),flush=True)
    finally:
        for server,thread,_ in servers:server.shutdown();server.server_close();thread.join(timeout=5)


if __name__=='__main__':main()
