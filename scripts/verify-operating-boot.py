#!/usr/bin/env python3
"""Check refusal/shutdown of the exact operating image in isolated ordinary VMs.

Only invalid owned public inputs are sent. This is not a successful hardware
admission, useful workload, customer-key release or real paid acceptance.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from compute.guest_boot import MAGIC,READY,STAGED,encode_public_launch
from compute.guest_vm import VmBudget


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--accelerator',choices=('tcg','kvm'),default='tcg',
                        help='Ordinary VM acceleration for software checks; neither option supplies confidential admission')
    args=parser.parse_args()
    image,out=args.image.resolve(),args.output.resolve()
    if sys.platform!='linux' or out.exists() or out==ROOT or ROOT in out.parents:
        raise ValueError('Require Linux and a new private output directory')
    qemu=shutil.which('qemu-system-x86_64')
    if qemu is None:raise ValueError('Require QEMU')
    if args.accelerator=='kvm' and not os.access('/dev/kvm',os.R_OK|os.W_OK):
        raise ValueError('Selected KVM checks require access to /dev/kvm; no emulation fallback')
    report=json.loads((image/'build.json').read_text())
    if (report['schema']!='cannabis.guest-image-build.v1' or report.get('operatingEntryConfigured') is not True
            or report['executionAuthorized'] is not False or report['hardwareValidated'] is not False):
        raise ValueError('Require the explicit, unadmitted operating image')
    budget=VmBudget(report['vmBudget']['profile']);reference=budget.value['referenceVM']
    for name in ['vmlinuz','initramfs.cpio.gz','cmdline']:
        with (image/name).open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
        if sha!=report['outputs'][name]['sha256'] or (image/name).stat().st_size!=report['outputs'][name]['bytes']:
            raise ValueError('Operating image artifact changed')
    cmdline=(image/'cmdline').read_text().strip()
    if cmdline!='console=null panic=-1 quiet loglevel=0 init=/init':raise ValueError('Require the private operating console policy')
    out.mkdir(parents=True)
    checks={}
    for mode in ['unapproved-launch','malformed-prefix','oversized-prefix','stalled-prefix','missing-port','missing-network','wrong-network']:
        serial=out/(mode+'-serial.log');log=out/(mode+'-qemu.log')
        with tempfile.TemporaryDirectory(prefix='cannabis-boot-') as directory:
            sockpath=Path(directory)/'control.sock'
            qmppath=Path(directory)/'qmp.sock'
            command=[qemu,'-machine','q35,accel='+args.accelerator,'-cpu','max','-smp',str(reference['cpus']),
                '-m',str(reference['memoryMiB']),'-nodefaults','-display','none',
                '-monitor','none','-qmp','unix:'+str(qmppath)+',server=on,wait=off','-serial','file:'+str(serial),'-no-reboot',
                '-kernel',str(image/'vmlinuz'),'-initrd',str(image/'initramfs.cpio.gz'),'-append',cmdline]
            if mode=='missing-network':command+=['-nic','none']
            else:command+=['-netdev','user,id=controlnet,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,ipv6=off,restrict=on',
                '-device','virtio-net-pci,netdev=controlnet,mac='+('52:54:00:ca:42:01' if mode=='wrong-network' else '52:54:00:ca:42:00')]
            if mode!='missing-port':
                command+=['-chardev','socket,id=control,path='+str(sockpath)+',server=on,wait=on',
                    '-device','virtio-serial-pci,id=controlbus','-device','virtserialport,chardev=control,name=org.cannabis.control']
            received=bytearray();peer=None;qmp=None;ready_at=None;started=time.monotonic()
            with log.open('xb') as stream:
                proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
                try:
                    if mode!='missing-port':
                        while not sockpath.exists():
                            if proc.poll() is not None or time.monotonic()-started>10:raise RuntimeError('Control socket did not start')
                            time.sleep(0.02)
                        peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);peer.settimeout(1);peer.connect(str(sockpath))
                    while not qmppath.exists():
                        if proc.poll() is not None or time.monotonic()-started>15:raise RuntimeError('QMP observation did not start')
                        time.sleep(0.02)
                    qmp=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);qmp.settimeout(10);qmp.connect(str(qmppath))
                    qmp_buffer=bytearray();qmp_records=[]
                    def message():
                        while b'\n' not in qmp_buffer:
                            chunk=qmp.recv(4096)
                            if not chunk:raise EOFError('QMP ended during observation setup')
                            qmp_buffer.extend(chunk)
                            if len(qmp_buffer)>65536:raise ValueError('QMP observation bound')
                        line,_,tail=qmp_buffer.partition(b'\n');qmp_buffer[:]=tail
                        return json.loads(line)
                    if 'QMP' not in message():raise ValueError('Unexpected QMP greeting')
                    # Only enable event observation; no VM mutation, memory read,
                    # shutdown command or provider action is requested via QMP.
                    qmp.sendall(b'{"execute":"qmp_capabilities","id":"observe"}\n')
                    while True:
                        row=message();qmp_records.append(row)
                        if row.get('id')=='observe':
                            if row.get('return')!={}:raise ValueError('QMP observation failed')
                            break
                    if mode not in ['missing-port','missing-network','wrong-network']:
                        greeting=bytearray()
                        while len(greeting)<len(READY):
                            if proc.poll() is not None or time.monotonic()-started>90:raise RuntimeError('Operating guest did not become ready')
                            try:chunk=peer.recv(len(READY)-len(greeting))
                            except socket.timeout:continue
                            if not chunk:raise EOFError('Operating guest ended before readiness')
                            greeting.extend(chunk)
                        if bytes(greeting)!=READY:raise ValueError('Unexpected public boot greeting')
                        ready_at=time.monotonic()
                        if mode=='unapproved-launch':payload=encode_public_launch(b'{}',b'{}',b'{}')
                        elif mode=='malformed-prefix':payload=b'X'*len(MAGIC)
                        elif mode=='oversized-prefix':payload=MAGIC+struct.pack('!III',2**32-1,2,2)
                        else:payload=MAGIC[:2]
                        peer.sendall(payload)
                        while proc.poll() is None:
                            if time.monotonic()-started>120:raise TimeoutError('Operating refusal did not retire within its bound')
                            try:chunk=peer.recv(1024)
                            except socket.timeout:continue
                            if not chunk:break
                            received.extend(chunk)
                            if len(received)>len(STAGED):raise ValueError('Unexpected operating response')
                    code=proc.wait(timeout=max(0.01,120-(time.monotonic()-started)))
                    elapsed=time.monotonic()-started
                    if code!=0 or serial.read_bytes():raise ValueError('Operating guest did not retire quietly')
                    qmp.settimeout(2)
                    while True:
                        chunk=qmp.recv(4096)
                        if not chunk:break
                        qmp_buffer.extend(chunk)
                        if len(qmp_buffer)>65536:raise ValueError('QMP observation bound')
                    qmp_records.extend(json.loads(line) for line in qmp_buffer.splitlines() if line.strip())
                    (out/(mode+'-qmp.json')).write_text(json.dumps(qmp_records,indent=2)+'\n')
                    shutdowns=[row.get('data') for row in qmp_records if row.get('event')=='SHUTDOWN']
                    if shutdowns!=[{'guest':True,'reason':'guest-shutdown'}]:
                        raise ValueError('A normal guest power-off was not observed')
                    if bytes(received)!=(STAGED if mode=='unapproved-launch' else b''):
                        raise ValueError('Unexpected staging/refusal boundary')
                    after_ready=None if ready_at is None else time.monotonic()-ready_at
                    if mode=='stalled-prefix' and after_ready<29:raise ValueError('Stalled input did not reach its intake deadline')
                    checks[mode]={'poweredOff':True,'kernelConsoleSilent':True,
                        'shutdownEvent':shutdowns[0],
                        'bootReady':ready_at is not None,'publicPrefixStaged':mode=='unapproved-launch',
                        'elapsedSeconds':round(elapsed,3),'secondsAfterReady':None if after_ready is None else round(after_ready,3)}
                    print(json.dumps({'completed':mode,**checks[mode]}),flush=True)
                finally:
                    if proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
                    if peer is not None:peer.close()
                    if qmp is not None:qmp.close()
    final={'schema':'cannabis.operating-boot-refusal.v1','checkedAt':datetime.now(timezone.utc).isoformat(),
        'image':report['outputs'],'referenceVM':reference,'checks':checks,'networkAttached':True,'externalNetworkEnabled':False,
        'hostFilesystemsAttached':False,'qemuVersion':subprocess.check_output([qemu,'--version'],text=True).splitlines()[0],
        'accelerator':args.accelerator,
        'qmpScope':'Private local event observation only; no VM-control or memory-read command.',
        'hardwareValidated':False,'authorizedJobCompleted':False,'customerKeysUsed':False,'realPaidJob':False}
    (out/'verification.json').write_text(json.dumps(final,indent=2)+'\n')
    print(json.dumps({'operatingRefusals':len(checks),'verified':True,'hardwareValidated':False}))


if __name__=='__main__':main()
