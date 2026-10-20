#!/usr/bin/env python3
"""Fixed systemd main entry. No browser-selected command or unbounded fallback."""
import json
import os
from pathlib import Path
import sys
import types
import fcntl
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
module=types.ModuleType('cannabis_host');module.__path__=[str(ROOT/'operator')];sys.modules['cannabis_host']=module
from cannabis_host.service_boundary import BoundaryProfile
from cannabis_host.snp_profile import root_file,file_digest

def main():
    if len(sys.argv)==4 and sys.argv[1]=='--inspect':
        profile=BoundaryProfile(sys.argv[2]);pid=int(sys.argv[3])
        if pid!=os.getppid():raise ValueError('Require actual operator parent')
        print(json.dumps(profile.observe(pid)));return
    if len(sys.argv)!=2 or os.geteuid()!=0:raise ValueError('Require one retained profile')
    profile=BoundaryProfile(sys.argv[1])
    reserve=Path(profile.value['stateVolume'])/'mount/recovery.reserve'
    lease=os.open(reserve,os.O_RDONLY|os.O_NOFOLLOW)
    fcntl.flock(lease,fcntl.LOCK_SH|fcntl.LOCK_NB)
    if lease!=3:os.dup2(lease,3);os.close(lease)
    os.set_inheritable(3,True)
    profile.configure();profile.observe(os.getpid(),bootstrap=True)
    node=root_file(profile.value['node']['path'],256*1024**2)
    try:
        file_digest(node,profile.value['node'])
        for name in os.listdir('/proc/self/fd'):
            fd=int(name)
            if fd>2 and fd not in (3,node):
                try:os.close(fd)
                except OSError:pass
        args=[profile.value['node']['path'],str(ROOT/'operator/server.mjs'),'--operator-config',profile.value['configuration']['path'],
            '--port',str(profile.value['consolePort'])]
        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1',
            'TMPDIR':str(Path(profile.value['stateVolume'])/'mount/state/tmp'),
            'SQLITE_TMPDIR':str(Path(profile.value['stateVolume'])/'mount/state/tmp')}
        os.execve(node,args,env)
    finally:os.close(node)

if __name__=='__main__':
    try:main()
    except Exception:
        print('Operator resource boundary unavailable; preserve state and inspect the owned unit',file=sys.stderr);sys.exit(1)
