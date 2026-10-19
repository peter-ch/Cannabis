"""Measured control-plane IPv4 setup; never a customer workload network.

The single virtio NIC and static resolver are part of the image profile. No DHCP,
host configuration file, guest command-line override or inherited proxy is used.
TLS, chain/genesis/runtime pins and fresh funding checks remain mandatory. This
does not authenticate the host's DNS/router or supply confidential attestation.
Customer processes keep their separate network namespace and AF_UNIX-only filter.
"""
import os
from pathlib import Path
import socket
import struct
import subprocess

INTERFACE='eth0'
MAC='52:54:00:ca:42:00'
ADDRESS='10.0.2.15'
PREFIX=24
GATEWAY='10.0.2.2'
DNS='10.0.2.3'
RESOLVER=b'nameserver 10.0.2.3\noptions timeout:2 attempts:2\n'
BUSYBOX='/bin/busybox'


def _run(*args):
    result=subprocess.run([BUSYBOX,'ip',*args],stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          env={'PATH':'/bin','LANG':'C'},timeout=3,check=True)
    if len(result.stdout)>16384:raise ValueError('Network observation exceeds its bound')
    return result.stdout.decode('ascii')


def topology():
    """Require the exact kernel NIC before changing addresses or routes."""
    if os.geteuid()!=0:raise ValueError('Require the measured guest control plane')
    root=Path('/sys/class/net')
    if sorted(p.name for p in root.iterdir())!=['eth0','lo']:
        raise ValueError('Require exactly one control-plane interface')
    nic=root/INTERFACE
    if ((nic/'device/driver').resolve(strict=True).name!='virtio_net'
            or (nic/'address').read_text().strip()!=MAC or (nic/'type').read_text().strip()!='1'):
        raise ValueError('Control-plane device differs from the measured profile')
    if (Path('/etc/resolv.conf').is_symlink() or Path('/etc/resolv.conf').read_bytes()!=RESOLVER
            or Path('/etc/nsswitch.conf').read_bytes()!=b'hosts: files dns\n'):
        raise ValueError('Measured resolver configuration differs')


def _sysctl(name,value):
    target=Path('/proc/sys')/name.replace('.','/')
    target.write_text(str(value)+'\n')
    if target.read_text().strip()!=str(value):raise ValueError('Guest network control did not apply')


def observe_control_network():
    topology()
    nic=Path('/sys/class/net')/INTERFACE
    if int((nic/'mtu').read_text())!=1500 or not int((nic/'flags').read_text(),16)&1:
        raise ValueError('Control-plane link is not configured')
    addresses=[]
    for line in _run('-o','-4','addr','show','dev',INTERFACE).splitlines():
        fields=line.split()
        if 'inet' in fields:addresses.append(fields[fields.index('inet')+1])
    if addresses!=[f'{ADDRESS}/{PREFIX}']:raise ValueError('Unexpected guest IPv4 addresses')
    routes=[]
    for line in Path('/proc/net/route').read_text().splitlines()[1:]:
        fields=line.split()
        if len(fields)<11:raise ValueError('Invalid kernel route table')
        iface,destination,gateway,flags,_,_,metric,mask=fields[:8]
        if iface!='eth0':raise ValueError('Unexpected guest route interface')
        addr=lambda value:socket.inet_ntoa(struct.pack('<I',int(value,16)))
        routes.append((addr(destination),addr(gateway),int(flags,16),int(metric),addr(mask)))
    if sorted(routes)!=sorted([('0.0.0.0',GATEWAY,3,0,'0.0.0.0'),('10.0.2.0','0.0.0.0',1,0,'255.255.255.0')]):
        raise ValueError('Guest route differs from the measured profile')
    for name,value in [('net.ipv4.ip_forward',0),('net.ipv4.conf.all.accept_redirects',0),
                       ('net.ipv4.conf.default.accept_redirects',0),('net.ipv4.conf.eth0.accept_redirects',0),
                       ('net.ipv4.conf.all.send_redirects',0),('net.ipv4.conf.eth0.send_redirects',0),
                       ('net.ipv4.conf.all.rp_filter',1),('net.ipv4.conf.eth0.rp_filter',1)]:
        if (Path('/proc/sys')/name.replace('.','/')).read_text().strip()!=str(value):
            raise ValueError('Guest network controls changed')
    v6=Path('/proc/net/if_inet6')
    if v6.exists() and v6.read_text().strip():raise ValueError('IPv6 is outside this measured network profile')
    return {'schema':'cannabis.guest-control-network.v1','interface':INTERFACE,'driver':'virtio_net',
            'mac':MAC,'address':f'{ADDRESS}/{PREFIX}','gateway':GATEWAY,'resolver':DNS,
            'dhcpUsed':False,'hardwareVerified':False,'workloadNetworkingEnabled':False}


def configure_control_network():
    topology()
    # Only the one-use, otherwise empty guest network is configured. This is not
    # a host adapter and must never be called against a provider's own namespace.
    if _run('-o','-4','addr','show','dev',INTERFACE).strip() or len(Path('/proc/net/route').read_text().splitlines())!=1:
        raise ValueError('Refuse an already configured guest network')
    ipv6=Path('/proc/sys/net/ipv6/conf/all/disable_ipv6')
    if ipv6.exists():
        _sysctl('net.ipv6.conf.all.disable_ipv6',1)
        _sysctl('net.ipv6.conf.default.disable_ipv6',1)
    for name,value in [('net.ipv4.ip_forward',0),('net.ipv4.conf.all.accept_redirects',0),
                       ('net.ipv4.conf.default.accept_redirects',0),('net.ipv4.conf.eth0.accept_redirects',0),
                       ('net.ipv4.conf.all.send_redirects',0),('net.ipv4.conf.eth0.send_redirects',0),
                       ('net.ipv4.conf.all.rp_filter',1),('net.ipv4.conf.eth0.rp_filter',1)]:_sysctl(name,value)
    _run('link','set','dev',INTERFACE,'mtu','1500')
    _run('addr','add',f'{ADDRESS}/{PREFIX}','dev',INTERFACE)
    _run('link','set','dev',INTERFACE,'up')
    _run('route','add','default','via',GATEWAY,'dev',INTERFACE)
    return observe_control_network()
