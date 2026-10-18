import copy,hashlib,io,json,os,pathlib,subprocess,sys,tarfile,tempfile,unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from compute.client import pack_workload,open_archive,seal_result,assemble_results,validate_workload,safe_name,age_binary,dpapi,task_binding_sha256,seal_archive
from compute.guest_workload import prepare_guest_workload
from dataclasses import replace
from compute.placement import plan
from compute import job_keys
from compute.job_keys import pack_job,recover_job_key

def fixture():
    return {'schema':'cannabis.workload.v1','id':'opaque-job-1','policySHA256':'a'*64,'files':['program.bin','input.dat'],
      'tasks':[{'id':'work','dependsOn':[],'runtime':{'adapter':'custom-acme-solver','digestSHA256':'b'*64,'architecture':'amd64','os':'linux'},
      'launch':{'arbitraryAdapterContract':{'entrypoint':'program.bin','arguments':['private-customer-label']}},
      'resources':{'cpus':2,'memoryMiB':1024,'scratchMiB':1024,'wallSeconds':600,'nodes':1,'accelerators':0},'outputs':['answer.bin']}],
      'assembly':[{'task':'work','output':'answer.bin','destination':'final/answer.bin'}]}

def worker(id,price=100,seconds=30,group='same'):
    return {'id':id,'adapters':['custom-acme-solver'],'runtimeDigests':['b'*64],'architecture':'amd64','os':'linux',
      'confidentialPolicies':['a'*64],'capacity':{'cpus':4,'memoryMiB':8192,'scratchMiB':8192,'accelerators':0},
      'compatibilityGroup':group,'collectiveBackends':['custom-ring'],'quotes':[{'task':'work','grossBaseUnits':str(price),'runSeconds':seconds,'transferSeconds':2,'feeBasisPoints':100}]}

class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.age=age_binary();keygen=pathlib.Path(cls.age).with_name('age-keygen.exe' if os.name=='nt' else 'age-keygen')
        cls.keygen=str(keygen) if keygen.exists() else 'age-keygen'
        cls.identity=subprocess.run([cls.keygen],capture_output=True,check=True).stdout
        cls.recipient=subprocess.run([cls.keygen,'-y'],input=cls.identity,capture_output=True,check=True).stdout.decode().strip()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
        self.source=self.root/'source';self.source.mkdir();(self.source/'program.bin').write_bytes(b'customer-secret-code')
        (self.source/'input.dat').write_bytes(bytes(range(256))*1024)
        self.spec=fixture()
    def tearDown(self):self.tmp.cleanup()
    def pack(self):
        p=self.root/'job.age';d=pack_workload(self.spec,self.source,self.recipient,p,self.age);return p,d
    def test_arbitrary_adapter_private_streaming_roundtrip(self):
        p,d=self.pack();raw=p.read_bytes()
        self.assertNotIn(b'customer-secret-code',raw);self.assertNotIn('private-customer-label',json.dumps(d));self.assertNotIn('program.bin',json.dumps(d))
        out=self.root/'decoded';m=open_archive(p,self.identity,out,d['ciphertextSHA256'],age=self.age)
        self.assertEqual(m['context'],self.spec);self.assertEqual((out/'input.dat').read_bytes(),(self.source/'input.dat').read_bytes())
        self.assertFalse(d['executionAuthorized']);self.assertFalse(d['keyReleaseAuthorized'])
    def test_large_artifact_crosses_legacy_bundle_limit(self):
        with (self.source/'input.dat').open('wb') as f:
            for _ in range(34):f.write(b'abcdef0123456789'*(1024*1024//16))
        p,d=self.pack();out=self.root/'decoded';open_archive(p,self.identity,out,d['ciphertextSHA256'],age=self.age)
        self.assertEqual(hashlib.sha256((out/'input.dat').read_bytes()).hexdigest(),hashlib.sha256((self.source/'input.dat').read_bytes()).hexdigest())
    def test_wrong_key_and_modified_or_truncated_ciphertext_never_publish_output(self):
        p,d=self.pack();wrong=subprocess.run([self.keygen],capture_output=True,check=True).stdout
        with self.assertRaises(Exception):open_archive(p,wrong,self.root/'wrong',d['ciphertextSHA256'],age=self.age)
        data=p.read_bytes()
        for i,changed in enumerate([data[:-20],data[:-1]+bytes([data[-1]^1])]):
            bad=self.root/f'bad{i}.age';bad.write_bytes(changed);dest=self.root/f'rejected{i}'
            with self.assertRaises(Exception):open_archive(bad,self.identity,dest,hashlib.sha256(changed).hexdigest(),age=self.age)
            self.assertFalse(dest.exists())
        self.assertFalse(list(self.root.glob('.cannabis-unverified-*')))
    def test_storage_path_replacement_cannot_swap_verified_ciphertext(self):
        original,descriptor=self.pack()
        (self.source/'program.bin').write_bytes(b'attacker-replacement-code')
        replacement=self.root/'replacement.age'
        pack_workload(self.spec,self.source,self.recipient,replacement,self.age)
        real_popen=subprocess.Popen;seen=[]
        def replace_after_verification(command,**kwargs):
            seen.append(command[-1])
            # Both archives authenticate to the SAME recipient. Only the hash
            # distinguishes the approved package from an attacker's replacement.
            original.write_bytes(replacement.read_bytes())
            return real_popen(command,**kwargs)
        with patch('compute.client.subprocess.Popen',side_effect=replace_after_verification):
            out=self.root/'snapshot-decoded'
            open_archive(original,self.identity,out,descriptor['ciphertextSHA256'],age=self.age)
        self.assertEqual((out/'program.bin').read_bytes(),b'customer-secret-code')
        self.assertNotEqual(pathlib.Path(seen[0]),original)
        self.assertEqual(sorted(p.name for p in out.iterdir()),['input.dat','program.bin'])
        self.assertFalse(list(self.root.glob('.cannabis-unverified-*')))
    def test_ciphertext_links_and_dangling_destination_links_are_rejected(self):
        original,descriptor=self.pack()
        linked=self.root/'linked.age';destination=self.root/'dangling-output'
        try:linked.symlink_to(original);destination.symlink_to(self.root/'outside',target_is_directory=True)
        except OSError:self.skipTest('Symbolic links unavailable')
        with self.assertRaises(ValueError):open_archive(linked,self.identity,self.root/'linked-output',descriptor['ciphertextSHA256'],age=self.age)
        with self.assertRaises(FileExistsError):open_archive(original,self.identity,destination,descriptor['ciphertextSHA256'],age=self.age)
        self.assertFalse((self.root/'outside').exists())
        self.assertFalse(list(self.root.glob('.cannabis-unverified-*')))
    def test_oversized_ciphertext_is_rejected_before_hashing_or_decryption(self):
        source=self.root/'oversized.age'
        with source.open('wb') as f:f.truncate(200*1024*1024)
        with patch('compute.client.hashlib.sha256',side_effect=AssertionError('Must reject before reading the file')):
            with self.assertRaisesRegex(ValueError,'exceeds bound'):
                open_archive(source,self.identity,self.root/'oversized-output','a'*64,age=self.age,max_bytes=1)
        self.assertFalse((self.root/'oversized-output').exists());self.assertFalse(list(self.root.glob('.cannabis-unverified-*')))
    def test_paths_duplicates_cycles_and_runtime_leaks_rejected(self):
        for name in ['../escape','/absolute','C:/x','a\\b','a/../b','CON.txt','a.','a//b']:
            with self.assertRaises(ValueError):safe_name(name)
        s=copy.deepcopy(self.spec);s['files']=['a','A']
        with self.assertRaises(ValueError):validate_workload(s)
        s=copy.deepcopy(self.spec);s['tasks'][0]['dependsOn']=['work']
        with self.assertRaises(ValueError):validate_workload(s)
        s=copy.deepcopy(self.spec);s['tasks'][0]['runtime']['secretArgument']='private'
        with self.assertRaises(ValueError):validate_workload(s)
        s=copy.deepcopy(self.spec);s['tasks'][0]['runtime']['collectiveBackend']={'arguments':'private'}
        with self.assertRaises(ValueError):validate_workload(s)
    def test_output_limit_and_existing_destination_are_preserved(self):
        p,d=self.pack();dest=self.root/'small'
        with self.assertRaises(ValueError):open_archive(p,self.identity,dest,d['ciphertextSHA256'],age=self.age,max_bytes=1)
        existing=self.root/'existing';existing.mkdir();(existing/'keep').write_text('safe')
        with self.assertRaises(FileExistsError):open_archive(p,self.identity,existing,d['ciphertextSHA256'],age=self.age)
        self.assertEqual((existing/'keep').read_text(),'safe')
    def test_results_bind_to_job_task_attempt_and_reconstruct_on_client(self):
        _,d=self.pack();outputs=self.root/'outputs';outputs.mkdir();(outputs/'answer.bin').write_bytes(b'verified-file-content')
        encrypted=self.root/'result.age';receipt=seal_result(self.spec,'work',d['ciphertextSHA256'],outputs,self.recipient,encrypted,age=self.age)
        items=[{'file':str(encrypted),'receipt':receipt}]
        report=assemble_results(self.spec,d['ciphertextSHA256'],items,self.identity,self.root/'assembled',age=self.age)
        self.assertEqual((self.root/'assembled/final/answer.bin').read_bytes(),b'verified-file-content');self.assertFalse(report['paymentAuthorized'])
        spoof=copy.deepcopy(items);spoof[0]['receipt']['attempt']=2
        with self.assertRaises(ValueError):assemble_results(self.spec,d['ciphertextSHA256'],spoof,self.identity,self.root/'spoof',age=self.age)
        self.assertFalse((self.root/'spoof').exists())
        with self.assertRaises(ValueError):assemble_results(self.spec,d['ciphertextSHA256'],[],self.identity,self.root/'missing',age=self.age)
    def test_attacker_archive_cannot_escape_or_add_undeclared_payload(self):
        buffer=io.BytesIO()
        m={'schema':'cannabis.archive.v1','kind':'result','context':{},'files':[{'path':'../escape','bytes':1,'sha256':hashlib.sha256(b'x').hexdigest()}]}
        with tarfile.open(fileobj=buffer,mode='w') as t:
            data=json.dumps(m).encode();n=tarfile.TarInfo('manifest.json');n.size=len(data);t.addfile(n,io.BytesIO(data))
            n=tarfile.TarInfo('files/00000000');n.size=1;t.addfile(n,io.BytesIO(b'x'))
        data=subprocess.run([self.age,'-r',self.recipient],input=buffer.getvalue(),capture_output=True,check=True).stdout
        p=self.root/'attack.age';p.write_bytes(data)
        with self.assertRaises(ValueError):open_archive(p,self.identity,self.root/'unsafe',hashlib.sha256(data).hexdigest(),age=self.age)
        self.assertFalse((self.root/'escape').exists())
    def test_rank_shards_assemble_on_requester_and_reject_wrong_rank(self):
        self.spec['tasks'][0]['resources']['nodes']=3
        self.spec['tasks'][0]['outputScope']='per-rank'
        self.spec['assembly'][0].update(rank='all',destination='checkpoint/rank-{rank}.bin')
        _,d=self.pack();items=[]
        for rank in range(3):
            outputs=self.root/f'rank-{rank}';outputs.mkdir();(outputs/'answer.bin').write_bytes(bytes([rank])*100)
            encrypted=self.root/f'result-{rank}.age'
            receipt=seal_result(self.spec,'work',d['ciphertextSHA256'],outputs,self.recipient,encrypted,rank=rank,age=self.age)
            items.append({'file':str(encrypted),'receipt':receipt})
        report=assemble_results(self.spec,d['ciphertextSHA256'],items,self.identity,self.root/'shards',age=self.age)
        self.assertEqual(len(report['files']),3)
        for rank in range(3):self.assertEqual((self.root/f'shards/checkpoint/rank-{rank}.bin').read_bytes(),bytes([rank])*100)
        with self.assertRaises(ValueError):assemble_results(self.spec,d['ciphertextSHA256'],items[:2],self.identity,self.root/'incomplete',age=self.age)
        items[0]['receipt']['rank']=2
        with self.assertRaises(ValueError):assemble_results(self.spec,d['ciphertextSHA256'],items,self.identity,self.root/'substitution',age=self.age)
    def test_buffered_payload_after_tar_end_is_rejected(self):
        buffer=io.BytesIO();manifest=json.dumps({'schema':'cannabis.archive.v1','kind':'result','context':{},'files':[]}).encode()
        with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as tar:
            header=tarfile.TarInfo('manifest.json');header.size=len(manifest);tar.addfile(header,io.BytesIO(manifest))
        raw=bytearray(buffer.getvalue());raw[2048:2058]=b'undeclared'
        data=subprocess.run([self.age,'-r',self.recipient],input=raw,capture_output=True,check=True).stdout
        p=self.root/'trailing.age';p.write_bytes(data)
        with self.assertRaises(ValueError):open_archive(p,self.identity,self.root/'trailing',hashlib.sha256(data).hexdigest(),age=self.age)
        self.assertFalse((self.root/'trailing').exists())
    @unittest.skipUnless(os.name=='nt','Windows CurrentUser vault check')
    def test_dpapi_roundtrip(self):
        self.assertEqual(dpapi(dpapi(self.identity),True),self.identity)

    def job(self,name='job'):
        folder=self.root/name
        return folder,pack_job(self.spec,self.source,self.recipient,folder,self.age)
    def recover(self,folder,descriptor,identity=None):
        return recover_job_key(folder/'job-key.age',identity or self.identity,descriptor,
            expected_package_sha256=descriptor['ciphertextSHA256'],expected_policy_sha256=descriptor['policySHA256'],age=self.age)
    def guest_binding(self,descriptor,index=0):
        return {'packageSHA256':descriptor['ciphertextSHA256'],'policySHA256':self.spec['policySHA256'],
                'runtimeSHA256':self.spec['tasks'][index]['runtime']['digestSHA256'],
                'taskSHA256':descriptor['requirements'][index]['taskSHA256'],
                'attempt':1,'rank':0,'worldSize':self.spec['tasks'][index]['resources']['nodes'],'acceleratorClass':'cpu'}
    def test_guest_prepares_bound_arbitrary_workload_without_executing_or_logging_contract(self):
        folder,descriptor=self.job();key=self.recover(folder,descriptor);binding=self.guest_binding(descriptor)
        prepared=prepare_guest_workload(folder/'workload.age',key,binding,self.root/'guest',age=self.age,max_bytes=1024**2)
        self.assertTrue(prepared.report['packageVerified']);self.assertTrue(prepared.report['assignmentVerified'])
        self.assertFalse(prepared.report['executionAuthorized']);self.assertEqual(prepared.report['taskIndex'],0)
        self.assertEqual(prepared.workload['tasks'][0]['launch'],self.spec['tasks'][0]['launch'])
        self.assertEqual((prepared.directory/'program.bin').read_bytes(),b'customer-secret-code')
        self.assertNotIn('private-customer-label',repr(prepared));self.assertNotIn('program.bin',json.dumps(prepared.report))
        self.assertFalse(list(self.root.glob('.cannabis-guest-*')))
    def test_guest_rejects_other_task_runtime_group_and_storage_budget(self):
        folder,descriptor=self.job();key=self.recover(folder,descriptor);binding=self.guest_binding(descriptor)
        changes=[{'taskSHA256':'f'*64},{'runtimeSHA256':'c'*64},{'worldSize':2},{'rank':1},{'attempt':False},{'acceleratorClass':'cuda'}]
        for i,change in enumerate(changes):
            target=self.root/f'reject-binding-{i}'
            with self.assertRaises(ValueError):prepare_guest_workload(folder/'workload.age',key,{**binding,**change},target,age=self.age)
            self.assertFalse(target.exists());self.assertFalse(list(self.root.glob('.cannabis-guest-*')))
        with self.assertRaises(ValueError):prepare_guest_workload(folder/'workload.age',key,binding,self.root/'guest-budget',age=self.age,max_bytes=1)
        self.assertFalse((self.root/'guest-budget').exists());self.assertFalse(list(self.root.glob('.cannabis-guest-*')))
    def test_guest_private_inventory_return_recipient_and_accelerator_requirements_are_checked(self):
        folder,descriptor=self.job();key=self.recover(folder,descriptor)
        for i,mode in enumerate(['inventory','recipient','accelerator','kind']):
            spec=copy.deepcopy(self.spec);spec['resultRecipient']=self.recipient
            if mode=='recipient':spec['resultRecipient']=key.input_recipient
            if mode=='accelerator':spec['tasks'][0]['resources']['accelerators']=1
            source=self.root/f'altered-{i}.age'
            sealed=seal_archive(self.source,['input.dat'] if mode=='inventory' else spec['files'],spec,key.input_recipient,source,kind='result' if mode=='kind' else 'workload',age=self.age)
            modified=replace(key,package_sha256=sealed['ciphertextSHA256'])
            binding={**self.guest_binding(descriptor),'packageSHA256':modified.package_sha256,'taskSHA256':task_binding_sha256(modified.package_sha256,0)}
            with self.assertRaises(ValueError):prepare_guest_workload(source,modified,binding,self.root/f'altered-out-{i}',age=self.age)
            self.assertFalse((self.root/f'altered-out-{i}').exists());self.assertFalse(list(self.root.glob('.cannabis-guest-*')))
    def test_guest_selects_committed_dag_task_and_rank(self):
        task=copy.deepcopy(self.spec['tasks'][0]);task.update(id='reduce',dependsOn=['work'],outputScope='per-rank')
        task['resources']['nodes']=3;self.spec['tasks'].append(task)
        folder,descriptor=self.job();key=self.recover(folder,descriptor);binding=self.guest_binding(descriptor,1);binding['rank']=2
        prepared=prepare_guest_workload(folder/'workload.age',key,binding,self.root/'rank-two',age=self.age)
        self.assertEqual(prepared.report['taskIndex'],1);self.assertEqual(prepared.report['rank'],2)
        self.assertNotEqual(descriptor['requirements'][0]['taskSHA256'],descriptor['requirements'][1]['taskSHA256'])
    def test_fresh_job_keys_keep_other_work_and_returned_results_separate(self):
        original=copy.deepcopy(self.spec);first,a=self.job('first');second,b=self.job('second')
        self.assertEqual(self.spec,original)
        ka=self.recover(first,a);kb=self.recover(second,b)
        self.assertNotEqual(ka.input_recipient,kb.input_recipient);self.assertNotEqual(ka.input_recipient,self.recipient)
        self.assertFalse(b'AGE-SECRET-KEY-' in (first/'job-key.age').read_bytes())
        self.assertFalse('AGE-SECRET-KEY-' in repr(ka));self.assertFalse('identity' in json.dumps(a))
        self.assertNotIn(self.recipient,json.dumps(a));self.assertNotIn('private-customer-label',json.dumps(a))
        self.assertFalse(a['keyReleaseAuthorized']);self.assertFalse(a['executionAuthorized'])
        m=open_archive(first/'workload.age',ka.identity,self.root/'decoded-job',a['ciphertextSHA256'],age=self.age)
        self.assertEqual(m['context']['resultRecipient'],self.recipient)
        with self.assertRaises(Exception):open_archive(second/'workload.age',ka.identity,self.root/'other-job',b['ciphertextSHA256'],age=self.age)
        with self.assertRaises(Exception):open_archive(first/'workload.age',self.identity,self.root/'direct-owner',a['ciphertextSHA256'],age=self.age)
        out=self.root/'result-input';out.mkdir();(out/'answer.bin').write_bytes(b'private-result')
        result=self.root/'return.age'
        receipt=seal_result(m['context'],'work',a['ciphertextSHA256'],out,self.recipient,result,age=self.age)
        with self.assertRaises(Exception):open_archive(result,ka.identity,self.root/'worker-reads-result',receipt['ciphertextSHA256'],age=self.age)
        assembled=assemble_results(m['context'],a['ciphertextSHA256'],[{'file':str(result),'receipt':receipt}],self.identity,self.root/'requester-result',age=self.age)
        self.assertTrue(assembled['integrityVerified']);self.assertEqual((self.root/'requester-result/final/answer.bin').read_bytes(),b'private-result')

    def test_result_recipient_is_bound_in_private_workload(self):
        folder,d=self.job();key=self.recover(folder,d)
        m=open_archive(folder/'workload.age',key.identity,self.root/'decoded',d['ciphertextSHA256'],age=self.age)
        out=self.root/'result';out.mkdir();(out/'answer.bin').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError,'requester recipient'):
            seal_result(m['context'],'work',d['ciphertextSHA256'],out,key.input_recipient,self.root/'wrong-return.age',age=self.age)
        self.assertFalse((self.root/'wrong-return.age').exists())
        receipt=seal_result(m['context'],'work',d['ciphertextSHA256'],out,self.recipient,self.root/'return.age',age=self.age)
        receipt['recipient']=key.input_recipient
        with self.assertRaisesRegex(ValueError,'Result recipient'):
            assemble_results(m['context'],d['ciphertextSHA256'],[{'file':str(self.root/'return.age'),'receipt':receipt}],self.identity,self.root/'rejected-return',age=self.age)
        bad=copy.deepcopy(self.spec);bad['resultRecipient']=key.input_recipient
        with self.assertRaisesRegex(ValueError,'Existing result recipient'):pack_job(bad,self.source,self.recipient,self.root/'mismatch',self.age)

    def test_wrong_owner_and_cross_job_key_capsules_are_rejected(self):
        first,a=self.job('first');second,b=self.job('second')
        wrong=subprocess.run([self.keygen],capture_output=True,check=True).stdout
        with self.assertRaisesRegex(ValueError,'key operation failed'):self.recover(first,a,wrong)
        (first/'job-key.age').write_bytes((second/'job-key.age').read_bytes())
        with self.assertRaisesRegex(ValueError,'commitment mismatch'):self.recover(first,a)
        # Even replacing the outer capsule commitment cannot change its inner job binding.
        altered=copy.deepcopy(a);altered['keyCustody']=b['keyCustody']
        with self.assertRaisesRegex(ValueError,'binding mismatch'):self.recover(first,altered)
        with self.assertRaisesRegex(ValueError,'approved job'):
            recover_job_key(second/'job-key.age',self.identity,b,expected_package_sha256=a['ciphertextSHA256'],expected_policy_sha256=a['policySHA256'],age=self.age)

    def test_capsule_authentication_limits_and_private_key_binding(self):
        folder,d=self.job();source=folder/'job-key.age';original=source.read_bytes()
        for data in [original[:-1],original[:-1]+bytes([original[-1]^1]),b'x'*17000]:
            source.write_bytes(data);bad=copy.deepcopy(d);bad['keyCustody']['ciphertextSHA256']=hashlib.sha256(data).hexdigest();bad['keyCustody']['ciphertextBytes']=len(data)
            with self.assertRaises(ValueError):self.recover(folder,bad)
        source.write_bytes(original)
        raw=subprocess.run([self.age,'-d','-i','-',str(source)],input=self.identity,capture_output=True,check=True).stdout
        record=json.loads(raw)
        other_identity=subprocess.run([self.keygen],capture_output=True,check=True).stdout
        other_recipient=subprocess.run([self.keygen,'-y'],input=other_identity,capture_output=True,check=True).stdout.decode().strip()
        for field,value in [('jobId','another-job'),('packageSHA256','0'*64),('packageBytes',False),('policySHA256','0'*64),('inputRecipient',self.recipient),('identity','not-a-key'),('resultRecipient',other_recipient)]:
            changed=copy.deepcopy(record);changed[field]=value
            cipher=subprocess.run([self.age,'-r',self.recipient],input=json.dumps(changed).encode(),capture_output=True,check=True).stdout
            source.write_bytes(cipher);bad=copy.deepcopy(d);bad['keyCustody'].update(ciphertextSHA256=hashlib.sha256(cipher).hexdigest(),ciphertextBytes=len(cipher))
            with self.assertRaises(ValueError):self.recover(folder,bad)

    def test_job_pack_failure_preserves_existing_files_and_cleans_only_owned_staging(self):
        destination=self.root/'occupied';destination.mkdir();(destination/'keep').write_bytes(b'preserve')
        with self.assertRaises(FileExistsError):pack_job(self.spec,self.source,self.recipient,destination,self.age)
        bad=copy.deepcopy(self.spec);bad['files'].append('missing')
        with self.assertRaises(Exception):pack_job(bad,self.source,self.recipient,self.root/'failed',self.age)
        self.assertFalse((self.root/'failed').exists());self.assertFalse(list(self.root.glob('.cannabis-job-*')))
        real_link=os.link
        def fail_capsule(source,target,*args,**kwargs):
            if pathlib.Path(target)==self.root/'partial/job-key.age':
                (self.root/'partial/foreign').write_bytes(b'keep this')
                raise OSError('injected publishing failure')
            return real_link(source,target,*args,**kwargs)
        with patch.object(job_keys.os,'link',side_effect=fail_capsule):
            with self.assertRaises(OSError):self.job('partial')
        self.assertEqual([x.name for x in (self.root/'partial').iterdir()],['foreign'])
        self.assertEqual((destination/'keep').read_bytes(),b'preserve');self.assertFalse(list(self.root.glob('.cannabis-job-*')))

    def test_concurrent_job_pack_publishes_only_one_coherent_bundle(self):
        barrier=Barrier(2);publish=job_keys._publish
        def concurrent_publish(staging,destination):barrier.wait(timeout=10);return publish(staging,destination)
        with patch.object(job_keys,'_publish',side_effect=concurrent_publish):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(self.job,'race') for _ in range(2)];success=[];errors=[]
                for future in futures:
                    try:success.append(future.result(timeout=15))
                    except FileExistsError as exc:errors.append(exc)
        self.assertEqual(len(success),1);self.assertEqual(len(errors),1)
        folder,d=success[0];key=self.recover(folder,d)
        open_archive(folder/'workload.age',key.identity,self.root/'winner',d['ciphertextSHA256'],age=self.age)
        self.assertEqual(json.loads((folder/'descriptor.json').read_text()),d)
        self.assertFalse(list(self.root.glob('.cannabis-job-*')))

    @unittest.skipUnless(os.name=='nt','Windows owner vault CLI integration')
    def test_job_key_cli_uses_dpapi_owner_custody_without_printing_secret(self):
        from compute.client import create_identity
        vault=self.root/'owner.dpapi.json';owner=create_identity(vault,self.age)
        manifest=self.root/'manifest.json';manifest.write_text(json.dumps(self.spec))
        cli=str(pathlib.Path(__file__).resolve().parents[1]/'scripts/compute-client.py')
        base=[sys.executable,cli,'--age',self.age]
        packed=subprocess.run(base+['pack-job',str(manifest),str(self.source),owner['recipient'],str(self.root/'cli-job')],capture_output=True,check=True)
        d=json.loads(packed.stdout)
        recovered=subprocess.run(base+['verify-job-key',str(self.root/'cli-job/job-key.age'),str(vault),str(self.root/'cli-job/descriptor.json'),'--package-sha256',d['ciphertextSHA256'],'--policy-sha256',d['policySHA256']],capture_output=True,check=True)
        self.assertTrue(json.loads(recovered.stdout)['jobKeyVerified']);self.assertFalse(json.loads(recovered.stdout)['keyReleaseAuthorized'])
        self.assertFalse(b'AGE-SECRET-KEY-' in packed.stdout+packed.stderr+recovered.stdout+recovered.stderr)

class PlacementTests(unittest.TestCase):
    def test_fastest_cheapest_budget_and_fee_conservation(self):
        s=fixture();pool=[worker('fast',200,10),worker('cheap',100,50)]
        a=plan(s,pool,1000);b=plan(s,pool,1000,objective='cheapest');c=plan(s,pool,150)
        self.assertEqual(a['assignments'][0]['workers'],['fast']);self.assertEqual(b['assignments'][0]['workers'],['cheap']);self.assertEqual(c['assignments'][0]['workers'],['cheap'])
        self.assertEqual(int(a['quotedWorkerBaseUnits'])+int(a['quotedFounderBaseUnits']),int(a['quotedGrossBaseUnits']))
        self.assertFalse(a['executionAuthorized']);self.assertFalse(a['keyReleaseAuthorized']);self.assertFalse(a['paymentAuthorized'])
    def test_runtime_confidentiality_capacity_and_deadline_are_mandatory(self):
        s=fixture()
        for field,value in [('architecture','arm64'),('confidentialPolicies',[]),('runtimeDigests',[]),('adapters',[])]:
            w=worker('one');w[field]=value;self.assertFalse(plan(s,[w],1000)['complete'])
        w=worker('one');w['capacity']['memoryMiB']=1;self.assertFalse(plan(s,[w],1000)['complete'])
        self.assertFalse(plan(s,[worker('one')],99)['complete']);self.assertFalse(plan(s,[worker('one')],1000,deadline_seconds=10)['complete'])
    def test_dependencies_and_exclusive_node_leases_prevent_overlap(self):
        s=fixture();second=copy.deepcopy(s['tasks'][0]);second['id']='assemble';second['dependsOn']=['work'];s['tasks'].append(second)
        w=worker('one');q=copy.deepcopy(w['quotes'][0]);q['task']='assemble';w['quotes'].append(q)
        result=plan(s,[w],1000)
        self.assertEqual(result['assignments'][1]['estimatedStartSeconds'],32);self.assertEqual(result['estimatedAssemblyReadySeconds'],64)
    def test_gang_placement_requires_compatible_groups_and_scales(self):
        s=fixture();s['tasks'][0]['resources']['nodes']=2;s['tasks'][0]['runtime']['collectiveBackend']='custom-ring'
        self.assertFalse(plan(s,[worker('a',group='x'),worker('b',group='y')],1000)['complete'])
        self.assertTrue(plan(s,[worker('a'),worker('b')],1000)['complete'])
        s['tasks'][0]['resources']['nodes']=128
        result=plan(s,[worker(f'worker-{i}') for i in range(128)],12800)
        self.assertTrue(result['complete']);self.assertEqual(len(result['assignments'][0]['workers']),128)

if __name__=='__main__':unittest.main()
