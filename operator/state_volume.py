"""Preallocated ext4 ceiling for operator metadata, relay SQLite/WAL and temp files.

This ordinary-host filesystem contains no customer content keys. Never reset a
missing manifest or delete retained databases to make room for another session.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import fcntl

from .result_volume import (MIB,require,directory,regular,command,sync_directory,
    mount_entries,mount_for,loop_binding,locked_image)
from .snp_profile import root_directory,unique


def retained(home):
    require(os.geteuid()==0);home=directory(home)
    fd=root_directory(home);os.close(fd)
    record=home/'state-volume.json';s=regular(record);require(s.st_size<=4096 and not s.st_mode&0o077)
    v=json.loads(record.read_text(),object_pairs_hook=unique)
    require(set(v)=={'schema','imageBytes','recoveryBytes','inodes','imageDevice','imageInode'} and v['schema']=='cannabis.operator-state-volume.v1')
    require(type(v['imageBytes']) is int and 64*MIB<=v['imageBytes']<=16*1024*MIB and v['imageBytes']%MIB==0)
    require(type(v['inodes']) is int and 1024<=v['inodes']<=65536)
    require(v['recoveryBytes']==v['imageBytes']//2)
    image=home/'operator-state.ext4';s=regular(image)
    require(not s.st_mode&0o077 and s.st_size==v['imageBytes'] and s.st_blocks*512>=s.st_size and
        (s.st_dev,s.st_ino)==(v['imageDevice'],v['imageInode']) and mount_for(image)['fs']=='ext4')
    return home,v,image,s


def inspect_state(home):
    home,v,image,s=retained(home);mount=home/'mount';m=mount_for(mount,exact=True)
    require(m['fs']=='ext4' and m['root']=='/' and {'rw','nosuid','nodev','noexec'}<=m['flags'] and 'discard' not in m['options'])
    fd,dev=loop_binding(m['source'],s)
    try:
        require(m['device']==f'{os.major(dev.st_rdev)}:{os.minor(dev.st_rdev)}')
        reserve=mount/'recovery.reserve'
        for nested in mount_entries():
            if nested['mount'].startswith(str(mount)+'/'):
                require(nested['mount']==str(reserve) and 'ro' in nested['flags'])
        recovery=regular(reserve);require(recovery.st_dev==dev.st_rdev and recovery.st_size==v['recoveryBytes'] and
            recovery.st_blocks*512>=v['recoveryBytes'] and recovery.st_mode&0o777==0o400)
        state=directory(mount/'state');r=state.stat();require(r.st_dev==dev.st_rdev)
        for name in ['approvals','tmp']:
            require(directory(state/name).stat().st_dev==r.st_dev)
        f=os.statvfs(state);require(not f.f_flag&os.ST_RDONLY and f.f_frsize==4096 and f.f_blocks*4096<=v['imageBytes'] and
            f.f_blocks*4096>=v['imageBytes']*3//4 and v['inodes']<=f.f_files<=v['inodes']+1024)
        return {'schema':'cannabis.operator-state-observation.v1','mountId':m['id'],
            'rootDevice':r.st_dev,'rootInode':r.st_ino,'imageDevice':s.st_dev,'imageInode':s.st_ino,
            'imageBytes':s.st_size,'backingAllocatedBytes':s.st_blocks*512,'availableBytes':f.f_bavail*4096,
            'availableInodes':f.f_favail,'inodeLimit':f.f_files,'loopDevice':m['source'],
            'recoveryBytes':v['recoveryBytes'],'recoveryInode':recovery.st_ino}
    finally:os.close(fd)


def mount_state(home):
    home,v,image,s=retained(home);mount=home/'mount'
    with locked_image(image,s):
        require(not any(m['mount']==str(mount) for m in mount_entries()))
        require(directory(mount) and not any(mount.iterdir()))
        require(command(['/usr/sbin/losetup','--associated',str(image)])=='')
        device=command(['/usr/sbin/losetup','--find','--show','--nooverlap',str(image)])
        fd,_=loop_binding(device,s);mounted=False
        try:
            command(['/usr/bin/mount','-t','ext4','-o','rw,nosuid,nodev,noexec,nodiscard,noatime',device,str(mount)]);mounted=True
            state=mount/'state'
            # Only first creation can introduce layout. A later missing state
            # directory is damaged recovery state, never an empty new database.
            require(state.exists())
            return inspect_state(home)
        except BaseException:
            if mounted:command(['/usr/bin/umount',str(mount)])
            command(['/usr/sbin/losetup','--detach',device]);raise
        finally:os.close(fd)


def unmount_state(home):
    home,v,image,s=retained(home);mount=home/'mount';m=mount_for(mount,exact=True)
    with locked_image(image,s):
        fd,_=loop_binding(m['source'],s)
        try:
            command(['/usr/bin/umount',str(mount)]);command(['/usr/sbin/losetup','--detach',m['source']])
            require(not any(x['mount']==str(mount) for x in mount_entries()))
            require(regular(image).st_ino==s.st_ino)
        finally:os.close(fd)


def create_state(home,image_bytes=1024*MIB,inodes=16384):
    require(os.geteuid()==0);home=directory(home);fd=root_directory(home);os.close(fd)
    require(not any(home.iterdir()) and mount_for(home)['fs']=='ext4')
    require(type(image_bytes) is int and 64*MIB<=image_bytes<=16*1024*MIB and image_bytes%MIB==0)
    require(type(inodes) is int and 1024<=inodes<=65536)
    free=os.statvfs(home);require(free.f_bavail*free.f_frsize>=image_bytes+1024*MIB)
    image=home/'operator-state.ext4';fd=os.open(image,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:os.posix_fallocate(fd,0,image_bytes);os.fsync(fd);require(os.fstat(fd).st_blocks*512>=image_bytes)
    finally:os.close(fd)
    command(['/usr/sbin/mkfs.ext4','-q','-F','-b','4096','-m','0','-N',str(inodes),
        '-E','nodiscard,lazy_itable_init=0,lazy_journal_init=0',str(image)],timeout=120)
    s=regular(image);require(s.st_blocks*512>=s.st_size)
    v={'schema':'cannabis.operator-state-volume.v1','imageBytes':image_bytes,'recoveryBytes':image_bytes//2,
        'inodes':inodes,'imageDevice':s.st_dev,'imageInode':s.st_ino}
    with (home/'state-volume.json').open('x') as out:
        os.chmod(out.fileno(),0o600);out.write(json.dumps(v)+'\n');out.flush();os.fsync(out.fileno())
    mount=home/'mount';mount.mkdir(mode=0o700);sync_directory(home)
    with locked_image(image,s):
        device=command(['/usr/sbin/losetup','--find','--show','--nooverlap',str(image)]);fd,_=loop_binding(device,s);mounted=False
        try:
            command(['/usr/bin/mount','-t','ext4','-o','rw,nosuid,nodev,noexec,nodiscard,noatime',device,str(mount)]);mounted=True
            state=mount/'state';state.mkdir(mode=0o700)
            for name in ['approvals','tmp']:(state/name).mkdir(mode=0o700)
            reserve=os.open(mount/'recovery.reserve',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
            try:os.posix_fallocate(reserve,0,v['recoveryBytes']);os.fsync(reserve)
            finally:os.close(reserve)
            sync_directory(state);sync_directory(mount);return inspect_state(home)
        except BaseException:
            if mounted:command(['/usr/bin/umount',str(mount)])
            command(['/usr/sbin/losetup','--detach',device]);raise
        finally:os.close(fd)


def recovery_reserve(home,profile_file,restore=False):
    """Explicit administrative recovery on the exact stopped unit. No DB edits."""
    from .service_boundary import BoundaryProfile
    profile=BoundaryProfile(str(profile_file));home,v,image,s=retained(home)
    require(profile.value['stateVolume']==str(home))
    unit=profile.value['unit']
    value=command(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID,KillMode'])
    actual=dict(row.split('=',1) for row in value.splitlines())
    require(actual.get('LoadState')=='loaded' and actual.get('MainPID')=='0' and
        actual.get('ActiveState') in ('inactive','failed') and actual.get('KillMode')=='control-group')
    if profile.cgroup.exists():
        from compute.guest_resources import _directory,_values
        group=_directory(profile.cgroup)
        try:require(_values(group,'cgroup.events')['populated']==0)
        finally:os.close(group)
    mount=home/'mount';m=mount_for(mount,exact=True);loop,dev=loop_binding(m['source'],s)
    try:
        require(m['fs']=='ext4' and m['root']=='/' and m['device']==f'{os.major(dev.st_rdev)}:{os.minor(dev.st_rdev)}')
        reserve=mount/'recovery.reserve';info=regular(reserve)
        require(info.st_dev==dev.st_rdev and info.st_mode&0o777==0o400 and info.st_size==(0 if restore else v['recoveryBytes']))
        # Only this preallocated zero-content reserve changes. Databases, WAL,
        # approvals and complete/uncertain customer results remain untouched.
        fd=os.open(reserve,os.O_WRONLY|os.O_NOFOLLOW)
        try:
            # The fixed bootstrap passes a shared lock as fd3 to the Node
            # owner. Exclusive admin access excludes a simultaneous start and
            # remains held through release/restore and fsync.
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            current=command(['/usr/bin/systemctl','show',unit,'--property=ActiveState,MainPID'])
            current=dict(row.split('=',1) for row in current.splitlines())
            require(current.get('MainPID')=='0' and current.get('ActiveState') in ('inactive','failed'))
            require(os.fstat(fd).st_ino==info.st_ino)
            if restore:os.posix_fallocate(fd,0,v['recoveryBytes'])
            else:os.ftruncate(fd,0)
            os.fsync(fd)
        finally:os.close(fd)
        sync_directory(mount)
        if restore:inspect_state(home)
        return {'recoveryReserveRestored':restore,'recoveryReserveReleased':not restore,'databasesModified':False,'unitStopped':True}
    finally:os.close(loop)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['create','mount','inspect','unmount','release-reserve','restore-reserve'])
    parser.add_argument('directory',type=Path);parser.add_argument('--bytes',type=int,default=1024*MIB)
    parser.add_argument('--inodes',type=int,default=16384);parser.add_argument('--profile',type=Path);args=parser.parse_args()
    if args.operation=='create':result=create_state(args.directory,args.bytes,args.inodes)
    elif args.operation=='mount':result=mount_state(args.directory)
    elif args.operation=='inspect':result=inspect_state(args.directory)
    elif args.operation in ('release-reserve','restore-reserve'):
        require(args.profile is not None);result=recovery_reserve(args.directory,args.profile,args.operation=='restore-reserve')
    else:unmount_state(args.directory);result={'unmounted':True,'backingPreserved':True}
    print(json.dumps(result))
