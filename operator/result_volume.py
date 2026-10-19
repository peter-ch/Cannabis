"""Root-managed, bounded ordinary-host ciphertext volume; no execution authority.

Only the selected Linux/ext4 loop path is supported. No sparse or ordinary-folder
fallback. Retain the backing image and manifest; unmount never deletes results.
"""
import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from contextlib import contextmanager

MIB=1024**2
OVERHEAD=12*MIB+256*1024
LOOP_GET_STATUS64=0x4C05
BLKSSZGET=0x1268

def require(ok):
    if not ok: raise ValueError('Bounded result volume unavailable; preserve storage and reconcile')

def limits(max_bytes,max_records):
    require(type(max_bytes) is int and OVERHEAD < max_bytes <= 1024**4)
    require(type(max_records) is int and 1 <= max_records <= 4096)
    database=math.ceil((max_bytes+MIB)/4096)*4096
    journal=2*database+2*MIB
    usable=max_bytes+database+journal+max_records*16384+16*MIB
    inodes=4*max_records+64
    image=math.ceil((usable*5//4+32*MIB)/MIB)*MIB
    return dict(maxBytes=max_bytes,maxRecords=max_records,databaseBytes=database,
                journalBytes=journal,requiredBytes=usable,requiredInodes=inodes,imageBytes=image)

def directory(value):
    p=Path(value)
    require(p.is_absolute() and str(p)==os.path.realpath(p) and len(str(p))<=4096)
    require(not any(ord(c)<32 for c in str(p)))
    s=p.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and not s.st_mode&0o077)
    return p

def regular(p):
    s=p.lstat();require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.geteuid())
    return s

def command(args,timeout=30):
    r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                     env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},timeout=timeout,check=False)
    require(r.returncode==0 and len(r.stdout)<=8192 and len(r.stderr)<=8192)
    return r.stdout.decode('utf-8').strip()

def sync_directory(p):
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def mount_entries():
    def decode(s):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),s)
    result=[]
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        a,b=line.split(' - ',1);a=a.split();b=b.split()
        result.append(dict(id=int(a[0]),device=a[2],root=decode(a[3]),mount=decode(a[4]),
                           flags=set(a[5].split(',')),fs=b[0],source=decode(b[1]),options=set(b[2].split(','))))
    return result

def mount_for(path,exact=False):
    path=str(path);matches=[m for m in mount_entries() if m['mount']==path or not exact and path.startswith(m['mount'].rstrip('/')+'/')]
    require(bool(matches));return max(matches,key=lambda m:len(m['mount']))

def manifest(home):
    require(os.geteuid()==0)
    home=directory(home);p=home/'volume.json';require(regular(p).st_size<=4096)
    v=json.loads(p.read_text())
    require(set(v)=={'schema','limits','imageDevice','imageInode'} and v['schema']=='cannabis.result-volume.v1')
    require(v['limits']==limits(v['limits']['maxBytes'],v['limits']['maxRecords']))
    image=home/'result-volume.ext4';s=regular(image)
    require(s.st_dev==v['imageDevice'] and s.st_ino==v['imageInode'] and s.st_size==v['limits']['imageBytes'])
    require(s.st_blocks*512>=s.st_size and mount_for(image)['fs']=='ext4')
    return home,v,image,s

def loop_binding(device,image_stat):
    require(re.fullmatch(r'/dev/loop[0-9]+',device) is not None)
    fd=os.open(device,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        d=os.fstat(fd);require(stat.S_ISBLK(d.st_mode))
        raw=fcntl.ioctl(fd,LOOP_GET_STATUS64,bytes(232))
        values=struct.unpack_from('=QQQQQIIII',raw)
        require(values[0]==image_stat.st_dev and values[1]==image_stat.st_ino and values[3]==0 and values[4]==0)
        require(values[6]==0 and values[7]==0 and not values[8]&1)
        sector=struct.unpack('=I',fcntl.ioctl(fd,BLKSSZGET,bytes(4)))[0]
        require(sector in (512,4096))
        return fd,d
    except BaseException:
        os.close(fd);raise

@contextmanager
def locked_image(image,expected):
    fd=os.open(image,os.O_RDWR|os.O_NOFOLLOW)
    try:
        held=os.fstat(fd);require(held.st_dev==expected.st_dev and held.st_ino==expected.st_ino)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(fd)

def inspect_volume(home,entries=None):
    home,v,image,s=manifest(home);mount=home/'mount';m=mount_for(mount,exact=True)
    require(m['fs']=='ext4' and m['root']=='/' and {'rw','nosuid','nodev','noexec'}<=m['flags'] and 'discard' not in m['options'])
    fd,dev=loop_binding(m['source'],s)
    try:
        require(m['device']==f'{os.major(dev.st_rdev)}:{os.minor(dev.st_rdev)}')
        root=directory(mount/'spool');r=root.stat();require(r.st_dev==dev.st_rdev)
        require(not any(x['mount'].startswith(str(mount)+'/') for x in mount_entries()))
        f=os.statvfs(root);b=v['limits'];require(not f.f_flag&os.ST_RDONLY and f.f_frsize==4096 and f.f_blocks*4096<=s.st_size)
        require(f.f_blocks*4096>=b['requiredBytes'] and f.f_files>=b['requiredInodes'])
        report={'schema':'cannabis.result-volume-observation.v1','limits':b,'mountId':m['id'],
                'rootDevice':r.st_dev,'rootInode':r.st_ino,'imageDevice':s.st_dev,'imageInode':s.st_ino,
                'backingAllocatedBytes':s.st_blocks*512,'availableBytes':f.f_bavail*4096,'availableInodes':f.f_favail}
        if entries is not None:
            require(type(entries) is list and len(entries)<=b['maxRecords'])
            allowed={}
            for entry in entries:
                require(set(entry)=={'id','maxCiphertextBytes'} and re.fullmatch('[0-9a-f]{64}',entry['id']) is not None)
                require(type(entry['maxCiphertextBytes']) is int and 1<=entry['maxCiphertextBytes']<=64*MIB and entry['id'] not in allowed)
                allowed[entry['id']]=entry['maxCiphertextBytes']
            require(sum(n+OVERHEAD for n in allowed.values())<=b['maxBytes'])
            allocated=r.st_blocks*512;used_inodes=1
            for p in root.iterdir():
                if p.name in ('spool.sqlite','spool.sqlite-journal'):
                    bound=b['databaseBytes'] if p.name=='spool.sqlite' else b['journalBytes']
                    info=regular(p);require(info.st_dev==r.st_dev and info.st_size<=bound)
                    allocated+=info.st_blocks*512;used_inodes+=1
                else:
                    require(p.name in allowed);folder=directory(p);info=folder.stat();require(info.st_dev==r.st_dev)
                    allocated+=info.st_blocks*512;used_inodes+=1
                    for child in folder.iterdir():
                        require(child.name in ('result.age','source.json','source.json.tmp'))
                        info=regular(child);bound=allowed[p.name] if child.name=='result.age' else 6*MIB+8192
                        require(info.st_dev==r.st_dev and info.st_size<=bound)
                        allocated+=info.st_blocks*512;used_inodes+=1
            require(allocated<=b['requiredBytes'] and used_inodes<=b['requiredInodes'])
            require(f.f_bavail*4096+allocated>=b['requiredBytes'] and f.f_favail+used_inodes>=b['requiredInodes'])
            report.update(capacityChecked=True,managedAllocatedBytes=allocated,managedInodes=used_inodes)
        return report
    finally: os.close(fd)

def mount_volume(home):
    home,v,image,s=manifest(home);mount=home/'mount'
    with locked_image(image,s):return _mount_locked(home,mount,image,s)

def _mount_locked(home,mount,image,s):
    require(not any(m['mount']==str(mount) for m in mount_entries()))
    require(directory(mount) and not any(mount.iterdir()))
    # Do not adopt or detach a device already used by another process/namespace.
    # An interrupted setup with an attached device needs explicit reconciliation.
    require(command(['/usr/sbin/losetup','--associated',str(image)])=='')
    device=command(['/usr/sbin/losetup','--find','--show','--nooverlap',str(image)])
    fd,_=loop_binding(device,s);mounted=False
    try:
        command(['/usr/bin/mount','-t','ext4','-o','rw,nosuid,nodev,noexec,nodiscard,noatime',device,str(mount)])
        mounted=True
        root=mount/'spool'
        if not root.exists():root.mkdir(mode=0o700);sync_directory(mount)
        return inspect_volume(home)
    except BaseException:
        if mounted:command(['/usr/bin/umount',str(mount)])
        command(['/usr/sbin/losetup','--detach',device]);raise
    finally:os.close(fd)

def unmount_volume(home):
    home,v,image,s=manifest(home);mount=home/'mount';m=mount_for(mount,exact=True)
    with locked_image(image,s):return _unmount_locked(mount,m,image,s)

def _unmount_locked(mount,m,image,s):
    fd,_=loop_binding(m['source'],s)
    try:
        command(['/usr/bin/umount',str(mount)])
        command(['/usr/sbin/losetup','--detach',m['source']])
        require(not any(x['mount']==str(mount) for x in mount_entries()))
        require(regular(image).st_ino==s.st_ino)
    finally:os.close(fd)

def create_volume(home,max_bytes,max_records):
    require(os.geteuid()==0);home=directory(home);require(not any(home.iterdir()))
    require(mount_for(home)['fs']=='ext4');b=limits(max_bytes,max_records)
    free=os.statvfs(home);require(free.f_bavail*free.f_frsize>=b['imageBytes']+1024*MIB)
    image=home/'result-volume.ext4';fd=os.open(image,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.posix_fallocate(fd,0,b['imageBytes']);os.fsync(fd)
        require(os.fstat(fd).st_blocks*512>=b['imageBytes'])
    finally:os.close(fd)
    command(['/usr/sbin/mkfs.ext4','-q','-F','-b','4096','-m','0','-N',str(max(1024,b['requiredInodes']*2+32)),
             '-E','nodiscard,lazy_itable_init=0,lazy_journal_init=0',str(image)],timeout=120)
    s=regular(image);require(s.st_blocks*512>=s.st_size)
    fd=os.open(image,os.O_RDWR|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    v={'schema':'cannabis.result-volume.v1','limits':b,'imageDevice':s.st_dev,'imageInode':s.st_ino}
    with (home/'volume.json').open('x') as out:os.chmod(out.fileno(),0o600);out.write(json.dumps(v)+'\n');out.flush();os.fsync(out.fileno())
    (home/'mount').mkdir(mode=0o700);sync_directory(home)
    return mount_volume(home)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['create','mount','unmount','inspect']);p.add_argument('directory',type=Path)
    p.add_argument('--max-bytes',type=int,default=256*MIB);p.add_argument('--max-records',type=int,default=16);p.add_argument('--layout',action='store_true')
    args=p.parse_args()
    if args.operation=='create':result=create_volume(args.directory,args.max_bytes,args.max_records)
    elif args.operation=='mount':result=mount_volume(args.directory)
    elif args.operation=='unmount':unmount_volume(args.directory);result={'unmounted':True,'backingPreserved':True}
    else:
        entries=None
        if args.layout:
            raw=bytearray()
            while True:
                part=os.read(0,min(65536,1024**2+1-len(raw)))
                if not part:break
                raw.extend(part);require(len(raw)<=1024**2)
            entries=json.loads(raw)
        result=inspect_volume(args.directory,entries)
    print(json.dumps(result))

if __name__=='__main__':
    try:main()
    except Exception:
        print('Bounded result volume unavailable; preserve storage and reconcile',file=__import__('sys').stderr)
        raise SystemExit(1)
