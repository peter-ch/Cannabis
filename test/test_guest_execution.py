import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
if sys.platform != 'linux': raise unittest.SkipTest('Native execution admission requires Linux')
from compute.client import canonical
from compute.guest_execution import NativeServiceProfile

MIB=1024**2


def profile():
    limits=lambda cpu,memory,pids,wall:dict(cpu_millis=cpu,memory_bytes=memory*MIB,processes=pids,wall_seconds=wall)
    return {'schema':'cannabis.guest-native-service.v2','units':1,
        'runtime':{'adapter':'native-linux-x86_64-v1','architecture':'x86_64','os':'linux','digestSHA256':'11'*32},
        'resources':{'cpus':1,'memoryMiB':128,'scratchMiB':8,'wallSeconds':60,'nodes':1},
        'total':{**limits(3000,1024,192,120),'children':3},'control':limits(1000,512,64,120),
        'helper':limits(1000,256,64,60),'processLimit':32,'scratchInodes':512,
        'staging':{'bytes':16*MIB,'inodes':1024},'ciphertext':{'bytes':8*MIB,'inodes':64,'inputBytes':4*MIB,'outputBytes':4*MIB}, 'maxInputBytes':MIB,
        'tools':{name+'SHA256':'22'*32 for name in ['python','age','ageKeygen']}}


class NativeServiceTests(unittest.TestCase):
    def test_group_profile_requires_explicit_topology_and_control_capacity(self):
        value=profile();value.update(schema='cannabis.guest-native-service.v4',maxDependencyBytes=MIB)
        value['runtime'].update(adapter='native-group-linux-x86_64-v1',collectiveBackend='attested-tls-ip-v1')
        value['resources']['nodes']=2
        value['ciphertext'].update(bytes=12*MIB,dependencyBytes=4*MIB)
        value['group']={'protocol':'cannabis.group-tls-ip.v1','bindHost':'0.0.0.0','port':29501,
                        'maxBufferedBytes':131072,'maxTrafficBytes':MIB}
        def inspect(p):return NativeServiceProfile(p,'0x'+hashlib.sha256(canonical(p)).hexdigest(),1)
        inspect(value)
        for mutate in [lambda p:p['runtime'].pop('collectiveBackend'),lambda p:p['runtime'].update(architecture='arm64'),
                       lambda p:p['runtime'].update(os='windows'),lambda p:p['runtime'].update(digestSHA256='invalid'),
                       lambda p:p['resources'].update(nodes=1),
                       lambda p:p['resources'].update(accelerators=1,acceleratorMemoryMiB=128),
                       lambda p:p['group'].update(bindHost='example.com'),lambda p:p['group'].update(port=0),
                       lambda p:p['group'].update(maxBufferedBytes=65536),
                       lambda p:(p['resources'].update(nodes=64),p['group'].update(maxBufferedBytes=8*MIB)),
                       lambda p:p.update(schema='cannabis.guest-native-service.v3')]:
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises((ValueError,KeyError)):inspect(changed)

    def test_dependency_capacity_is_explicit_and_page_rounded_in_the_signed_unit(self):
        value=profile();value.update(schema='cannabis.guest-native-service.v3',maxDependencyBytes=MIB)
        value['ciphertext'].update(bytes=12*MIB,dependencyBytes=4*MIB)
        NativeServiceProfile(value,'0x'+hashlib.sha256(canonical(value)).hexdigest(),1)
        for mutate in [lambda p:p['ciphertext'].update(bytes=8*MIB),lambda p:p['ciphertext'].update(dependencyBytes=4*MIB+1),
                       lambda p:p.update(maxDependencyBytes=16*MIB),lambda p:p['ciphertext'].update(dependencyBytes=0),
                       lambda p:p['total'].update(memory_bytes=930*MIB),lambda p:p.update(schema='cannabis.guest-native-service.v2')]:
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):NativeServiceProfile(changed,'0x'+hashlib.sha256(canonical(changed)).hexdigest(),1)

    def test_signed_unit_cannot_be_substituted_or_mutated(self):
        value=profile();digest='0x'+hashlib.sha256(canonical(value)).hexdigest()
        retained=NativeServiceProfile(value,digest,1)
        value['control']['memory_bytes']=16*MIB
        self.assertEqual(retained.control.memory_bytes,512*MIB)
        for altered,sha,units in [(value,digest,1),(profile(),'0x'+'00'*32,1),(profile(),digest,2),(profile(),digest,True)]:
            with self.assertRaises(ValueError): NativeServiceProfile(altered,sha,units)

    def test_underreserved_overlapping_stages_and_storage_are_rejected(self):
        for mutate in [lambda p:p['total'].update(cpu_millis=2000),lambda p:p['total'].update(memory_bytes=900*MIB),
                       lambda p:p['total'].update(processes=159),lambda p:p['total'].update(children=2),
                       lambda p:p['total'].update(wall_seconds=30),lambda p:p.update(maxInputBytes=17*MIB),
                       lambda p:p['staging'].update(bytes=512*MIB),lambda p:p['tools'].update(ageSHA256='bad')]:
            value=profile();mutate(value);digest='0x'+hashlib.sha256(canonical(value)).hexdigest()
            with self.assertRaises(ValueError): NativeServiceProfile(value,digest,1)

    def test_ciphertext_quota_requires_concurrent_page_rounded_capacity(self):
        for mutate in [lambda p:p['total'].update(memory_bytes=927*MIB),
                       lambda p:p['ciphertext'].update(inputBytes=4*MIB+1),
                       lambda p:p['ciphertext'].update(inodes=0),
                       lambda p:p['ciphertext'].update(outputBytes=True),
                       lambda p:p.update(schema='cannabis.guest-native-service.v1')]:
            value=profile();mutate(value);digest='0x'+hashlib.sha256(canonical(value)).hexdigest()
            with self.assertRaises(ValueError): NativeServiceProfile(value,digest,1)


if __name__=='__main__':unittest.main()
