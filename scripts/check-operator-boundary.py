#!/usr/bin/env python3
"""Owned ext4/systemd/cgroup checkpoint. No SNP, real job, custody or spending."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import time
import types
import uuid
import fcntl
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
module=types.ModuleType('cannabis_host');module.__path__=[str(ROOT/'operator')];sys.modules['cannabis_host']=module
from cannabis_host.state_volume import create_state,inspect_state,unmount_state,mount_state,recovery_reserve
from cannabis_host.result_volume import create_volume,unmount_volume
from cannabis_host import service_boundary as boundary

def run(args,timeout=20):
    r=subprocess.run(list(map(str,args)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,text=True)
    if r.returncode:raise RuntimeError(r.stderr[-4000:] or r.stdout[-4000:])
    return r.stdout.strip()

def wait(predicate,timeout=15):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if predicate():return
        time.sleep(.1)
    raise TimeoutError('Owned resource checkpoint expired')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--node',type=Path,required=True)
    parser.add_argument('--kernel-only',action='store_true',help='Scoped follow-up after metadata pressure has passed');args=parser.parse_args()
    assert os.geteuid()==0 and Path('/proc/1/comm').read_text().strip()=='systemd'
    suffix=uuid.uuid4().hex;base=Path('/var/lib')/('cannabis-boundary-check-'+suffix);base.mkdir(mode=0o700)
    state=base/'state-volume';state.mkdir(mode=0o700);result=base/'result-volume';result.mkdir(mode=0o700)
    state_mounted=result_mounted=False;units=[];checks={};handles=[]
    try:
        initial=create_state(state,64*1024**2,2048);state_mounted=True
        create_volume(result,32*1024**2,2);result_mounted=True
        checks['preallocatedStateAndResultVolumes']=initial['backingAllocatedBytes']>=initial['imageBytes']
        if not args.kernel_only:
            pressure=json.loads(run([args.node,ROOT/'test/helpers/operator_metadata_pressure.mjs',state/'mount/state/tmp'],timeout=30))
            checks.update(pressure);del checks['committed']
            pressure_path=state/'mount/state/tmp/owned-pressure.sqlite'
            assert pressure_path.is_file();pressure_path.unlink()
            for extension in ['-wal','-shm']:
                side=Path(str(pressure_path)+extension)
                if side.exists():side.unlink()
            fd=os.open(state/'mount/recovery.reserve',os.O_WRONLY)
            try:os.posix_fallocate(fd,0,initial['recoveryBytes']);os.fsync(fd)
            finally:os.close(fd)
        (state/'mount/state/tmp/sentinel').write_bytes(b'KEEP RECOVERY STATE')
        unmount_state(state);state_mounted=False;mount_state(state);state_mounted=True
        checks['remountPreservesMetadata']=(state/'mount/state/tmp/sentinel').read_bytes()==b'KEEP RECOVERY STATE'

        source=base/'source';source.mkdir(mode=0o700)
        for name in ['operator/service_boundary.py','operator/state_volume.py','operator/result_volume.py','operator/snp_profile.py',
                     'operator/boundary.mjs','compute/guest_resources.py','compute/guest_deadline.py','compute/guest_guardian.py',
                     'scripts/start-operator.py','scripts/compute-guest-guardian.py']:
            target=source/name;target.parent.mkdir(mode=0o700,exist_ok=True);shutil.copyfile(ROOT/name,target);target.chmod(0o600)
        shutil.copyfile(ROOT/'test/helpers/operator_boundary_fixture.mjs',source/'operator/server.mjs')
        # Diagnostics exist only in this copied fixture. Production stderr stays
        # disabled and no customer job or content is loaded by this checkpoint.
        boot=source/'scripts/start-operator.py'
        boot.write_text(boot.read_text().replace('    except Exception:\n',
            '    except Exception:\n        import traceback\n        Path('+repr(str(state/'mount/state/tmp/failure.txt'))+').write_text(traceback.format_exc())\n'))
        app=source/'operator/server.mjs';app.write_text(app.read_text().replace(
            'const boundary=await openOperatorBoundary',
            "process.on('uncaughtException',error=>{fs.writeFileSync(path.join(path.dirname(config.dispatch),'tmp/failure.txt'),String(error.stack));process.exit(1);});\nconst boundary=await openOperatorBoundary"))
        node=base/'node';shutil.copyfile(args.node,node);node.chmod(0o700)
        (source/'operator/fixture-descendant.py').write_text('''import json,os,signal,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.guest_guardian import GuardedResources
from compute.guest_resources import ResourceLimits,join_current_process
limits=ResourceLimits(200,128*1024**2,16,120)
guard=GuardedResources(sys.argv[1],limits)
def enter():join_current_process(guard.path,limits)
child=subprocess.Popen(['/usr/bin/python3','-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(120)'],preexec_fn=enter)
Path(sys.argv[2]+'/tmp/descendant.json').write_text(json.dumps({'supervisor':os.getpid(),'child':child.pid,'group':str(guard.path)}))
while True:time.sleep(1)
''')
        boundary.ROOT=source # Explicit fixture installation only, not a production option.
        def record(file):return {'path':str(file),'bytes':file.stat().st_size,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
        for case in ['owner-death','changed-limit']:
            unit='cannabis-operator-check-'+case+'-'+suffix+'.service';unit_file=Path('/run/systemd/system')/unit
            config=base/(case+'.json');profile=base/(case+'-boundary.json');host=base/(case+'-host.json')
            pool='/sys/fs/cgroup/system.slice/'+unit+'/vm'
            host.write_text(json.dumps({'schema':'cannabis.host-snp-profile.v1','cgroupParent':pool,
                'limits':{'cpu_millis':200,'memory_bytes':128*1024**2,'processes':16,'wall_seconds':120}}));host.chmod(0o600)
            c={'resources':str(profile),'profile':str(host),'spool':str(result/'mount/spool'),'approvals':str(state/'mount/state/approvals'),
                'dispatch':str(state/'mount/state/dispatch.sqlite'),'relay':{'orders':str(state/'mount/state/orders.sqlite'),
                'results':str(state/'mount/state/results.sqlite')},'fixtureOutside':str(base/'unexpected-write'),
                'fixtureDescendant':case=='owner-death','fixturePool':pool}
            config.write_text(json.dumps(c));config.chmod(0o600)
            p={'schema':'cannabis.operator-boundary.v1','unit':unit,'configuration':record(config),'node':record(node),'sourceRoot':str(source),
                'consolePort':4201,'stateVolume':str(state),'control':{'cpu_millis':1000,'memory_bytes':256*1024**2,'processes':64},
                'vm':{'cpu_millis':200,'memory_bytes':128*1024**2,'processes':16}}
            profile.write_text(json.dumps(p));profile.chmod(0o600)
            selected=boundary.BoundaryProfile(str(profile));unit_file.write_text(selected.unit_text());unit_file.chmod(0o600);units.append((unit,unit_file))
            run(['systemctl','daemon-reload']);run(['systemctl','start',unit]);
            ready=state/'mount/state/tmp/ready.json'
            failure=state/'mount/state/tmp/failure.txt'
            wait(lambda:ready.exists() or failure.exists())
            if failure.exists():raise RuntimeError(failure.read_text()[-6000:])
            report=json.loads(ready.read_text());ready.unlink()
            assert all(report['checks'].values());checks.update(report['checks'])
            pid=report['pid'];pidfd=os.pidfd_open(pid);handles.append(pidfd)
            assert run(['systemctl','show',unit,'--property=MainPID','--value'])==str(pid)
            group=Path('/sys/fs/cgroup/system.slice')/unit
            lease=os.open(state/'mount/recovery.reserve',os.O_RDONLY)
            try:
                try:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:checks['actualLeaseBlocksExclusiveRecovery']=True
                else:raise AssertionError('Live owner did not hold its reserve lease')
            finally:os.close(lease)
            try:recovery_reserve(state,profile)
            except (ValueError,OSError):checks['liveReserveReleaseRefused']=True
            else:raise AssertionError('Live reserve release must be refused')
            if case=='owner-death':
                descendant=state/'mount/state/tmp/descendant.json';wait(descendant.exists);d=json.loads(descendant.read_text())
                child=os.pidfd_open(d['child']);handles.append(child)
                assert str(d['child']) in (Path(d['group'])/'cgroup.procs').read_text().split()
                checks['vmDescendantInsideAggregate']=Path(d['group']).is_relative_to(group/'vm')
                os.kill(d['supervisor'],signal.SIGSTOP);os.kill(pid,signal.SIGKILL)
                wait(lambda:bool(select.select([child],[],[],0)[0]),timeout=55)
                checks['ownerDeathKillsStoppedSupervisorAndVm']=True
            else:
                (group/'cpu.max').write_text('max 100000\n')
                wait(lambda:bool(select.select([pidfd],[],[],0)[0]),timeout=20)
                checks['changedKernelLimitStopsOwner']=True
            wait(lambda:not group.exists(),timeout=15)
            checks['aggregateRemovedAfterStop']=True
            released=recovery_reserve(state,profile);assert released['recoveryReserveReleased']
            try:inspect_state(state)
            except ValueError:checks['releasedReserveRefusesIntake']=True
            else:raise AssertionError('Released reserve accepted for operation')
            restored=recovery_reserve(state,profile,restore=True);checks['stoppedReserveRestored']=restored['recoveryReserveRestored']
            assert (state/'mount/state/tmp/sentinel').read_bytes()==b'KEEP RECOVERY STATE'
        print(json.dumps({'schema':'cannabis.operator-boundary-checkpoint.v1','checks':checks,'allChecksPassed':all(checks.values()),
            'actualSystemdCgroupsExt4':True,'sqlitePressureRun':not args.kernel_only,'fixtureApplication':True,'hardwareValidated':False,'paidJob':False}))
    finally:
        for fd in handles:os.close(fd)
        for unit,file in units:
            run(['systemctl','stop',unit],timeout=55)
            subprocess.run(['systemctl','reset-failed',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if file.exists():file.unlink()
        if units:run(['systemctl','daemon-reload'])
        if result_mounted:unmount_volume(result)
        if state_mounted:unmount_state(state)
        assert base.parent==Path('/var/lib') and base.name=='cannabis-boundary-check-'+suffix
        shutil.rmtree(base)

if __name__=='__main__':main()
