#!/usr/bin/env python3
"""Owned network checks inside a disposable image, never on the provider host."""
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.guest_network import configure_control_network,observe_control_network,_run,_sysctl
from compute.guest_sandbox import NativeSandbox,ScratchLimits,tree_digest
from compute.guest_resources import ResourceLimits


def main():
    if os.geteuid()!=0 or Path('/proc/cmdline').read_text().strip()!='console=ttyS0 panic=-1 quiet loglevel=3 init=/init':
        raise ValueError('Require the dedicated disposable component image')
    checks={};network=configure_control_network();checks['fixedVirtioStaticNetwork']=True
    try:configure_control_network()
    except ValueError:checks['existingConfigurationRefused']=True
    else:raise AssertionError('Configured network was adopted')
    for name,alter,restore in [
        ('changedMTURefused',lambda:_run('link','set','dev','eth0','mtu','1400'),lambda:_run('link','set','dev','eth0','mtu','1500')),
        ('extraAddressRefused',lambda:_run('addr','add','10.0.2.16/24','dev','eth0'),lambda:_run('addr','del','10.0.2.16/24','dev','eth0')),
        ('redirectControlChangeRefused',lambda:_sysctl('net.ipv4.conf.eth0.accept_redirects',1),lambda:_sysctl('net.ipv4.conf.eth0.accept_redirects',0))]:
        alter()
        try:
            try:observe_control_network()
            except ValueError:checks[name]=True
            else:raise AssertionError('Changed network accepted')
        finally:restore()
    observe_control_network()
    # Runtime is the immutable image-built Python tree. This program knows no
    # customer content; the socket probe runs with actual workload restrictions.
    base=Path('/run')/('network-check-'+uuid.uuid4().hex);base.mkdir(mode=0o755)
    inputs=base/'input';inputs.mkdir(mode=0o700)
    parent=Path('/sys/fs/cgroup')/base.name;parent.mkdir(mode=0o700)
    try:
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        root=Path('/opt/cannabis/runtime');digest=tree_digest(root)
        with NativeSandbox(parent,root,inputs,digest,ResourceLimits(1000,256*1024**2,32,30),ScratchLimits(8*1024**2,256)) as sandbox:
            code='''import socket,os,json
for family in [socket.AF_INET,socket.AF_INET6,socket.AF_NETLINK,socket.AF_PACKET,socket.AF_VSOCK]:
 try:socket.socket(family)
 except PermissionError:pass
 else:raise AssertionError('Control network reached by workload')
assert not os.path.exists('/etc/resolv.conf')
a,b=socket.socketpair();a.send(b'owned');assert b.recv(5)==b'owned';a.close();b.close()
open('/output/result','w').write('isolated')
'''
            result=sandbox.run(['/usr/bin/python3','-I','-B','-c',code])
            if not result['success'] or not result['cleanup']['removed'] or result['cleanup']['populated']:
                raise AssertionError('Workload networking refusal or cleanup failed')
            if (sandbox.output_directory/'result').read_text()!='isolated':raise AssertionError('Workload probe did not finish')
            checks['workloadNetworkStillDenied']=True;checks['workloadTreeCleaned']=True
    finally:
        inputs.rmdir();base.rmdir();parent.rmdir()
    rpc=subprocess.run(['/usr/local/bin/node','/opt/cannabis/scripts/check-guest-network.mjs'],capture_output=True,timeout=45,
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','NODE_EXTRA_CA_CERTS':'/opt/cannabis/network-fixture-ca.pem'})
    if rpc.returncode:raise AssertionError('Guest TLS checkpoint failed: '+rpc.stderr.decode(errors='replace')[-3000:])
    value=json.loads(rpc.stdout)
    if not all(value['checks'].values()):raise AssertionError('Guest RPC check incomplete')
    checks.update(value['checks'])
    return {'schema':'cannabis.guest-network-check.v1','network':network,'checks':checks,
      'isolatedRPCFixture':True,'hardwareValidated':False,'customerKeysUsed':False,'realPaidJob':False}


if __name__=='__main__':
    try:print('CANNABIS_NETWORK_RESULT '+json.dumps(main()),flush=True)
    except BaseException:
        import traceback
        traceback.print_exc();raise
