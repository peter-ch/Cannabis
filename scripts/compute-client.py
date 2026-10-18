"""Cannabis general-purpose workload client. JSON input/output; never runs bundled code."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compute.client import (pack_workload,seal_result,assemble_results,create_identity,load_identity,validate_workload,MAX_MANIFEST)
from compute.placement import plan
from compute.job_keys import pack_job,recover_job_key

def read(path):
    p=Path(path)
    if p.stat().st_size>MAX_MANIFEST:raise ValueError('JSON input exceeds size limit')
    return json.loads(p.read_text(encoding='utf-8-sig'))

def write(path,data):
    with open(path,'x',encoding='utf-8') as f:json.dump(data,f,indent=2)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--age',help='Path to installed age executable')
    sub=parser.add_subparsers(dest='action',required=True)
    identity=sub.add_parser('init-key');identity.add_argument('vault')
    init=sub.add_parser('init');init.add_argument('destination');init.add_argument('--id',required=True);init.add_argument('--policy-sha256',required=True);init.add_argument('--runtime',required=True);init.add_argument('--launch',required=True);init.add_argument('--file',action='append',default=[]);init.add_argument('--output',action='append',default=[])
    init.add_argument('--cpus',type=int,default=1);init.add_argument('--memory-mib',type=int,default=1024);init.add_argument('--scratch-mib',type=int,default=1024);init.add_argument('--wall-seconds',type=int,default=3600);init.add_argument('--nodes',type=int,default=1);init.add_argument('--accelerators',type=int,default=0);init.add_argument('--accelerator-memory-mib',type=int,default=0);init.add_argument('--per-rank',action='store_true');init.add_argument('--output-max-bytes',type=int,default=1073741824)
    check=sub.add_parser('validate');check.add_argument('manifest')
    pack=sub.add_parser('pack');pack.add_argument('manifest');pack.add_argument('input_directory');pack.add_argument('recipient');pack.add_argument('output');pack.add_argument('--descriptor',required=True)
    job=sub.add_parser('pack-job');job.add_argument('manifest');job.add_argument('input_directory');job.add_argument('requester_recipient');job.add_argument('destination')
    recovery=sub.add_parser('verify-job-key');recovery.add_argument('capsule');recovery.add_argument('identity');recovery.add_argument('descriptor');recovery.add_argument('--package-sha256',required=True);recovery.add_argument('--policy-sha256',required=True)
    placement=sub.add_parser('plan');placement.add_argument('manifest');placement.add_argument('workers');placement.add_argument('--budget-base-units',required=True);placement.add_argument('--objective',choices=['fastest','cheapest'],default='fastest');placement.add_argument('--deadline-seconds',type=int)
    result=sub.add_parser('seal-result');result.add_argument('manifest');result.add_argument('task');result.add_argument('package_sha256');result.add_argument('output_directory');result.add_argument('recipient');result.add_argument('encrypted_output');result.add_argument('--receipt',required=True);result.add_argument('--attempt',type=int,default=1);result.add_argument('--rank',type=int,default=0)
    assemble=sub.add_parser('assemble');assemble.add_argument('manifest');assemble.add_argument('package_sha256');assemble.add_argument('results');assemble.add_argument('identity');assemble.add_argument('destination')
    args=parser.parse_args()
    if args.action=='init-key':value=create_identity(args.vault,args.age)
    elif args.action=='init':
        task={'id':'compute','dependsOn':[],'runtime':read(args.runtime),'launch':read(args.launch),
          'resources':{'cpus':args.cpus,'memoryMiB':args.memory_mib,'scratchMiB':args.scratch_mib,'wallSeconds':args.wall_seconds,'nodes':args.nodes,'accelerators':args.accelerators,'acceleratorMemoryMiB':args.accelerator_memory_mib},
          'outputs':args.output,'outputScope':'per-rank' if args.per_rank else 'leader','outputMaxBytes':args.output_max_bytes}
        spec={'schema':'cannabis.workload.v1','id':args.id,'policySHA256':args.policy_sha256,'files':args.file,'tasks':[task],
          'assembly':[{'task':'compute','output':name,'rank':'all' if args.per_rank else 0,'destination':'rank-{rank}/'+name if args.per_rank else name} for name in args.output]}
        validate_workload(spec);write(args.destination,spec);value={'manifest':args.destination,'valid':True,'tasks':1,'nodes':args.nodes}
    elif args.action=='validate':value={'valid':True,'order':validate_workload(read(args.manifest))}
    elif args.action=='pack':
        if Path(args.descriptor).exists():raise FileExistsError(args.descriptor)
        value=pack_workload(read(args.manifest),args.input_directory,args.recipient,args.output,args.age);write(args.descriptor,value)
    elif args.action=='pack-job':value=pack_job(read(args.manifest),args.input_directory,args.requester_recipient,args.destination,args.age)
    elif args.action=='verify-job-key':
        recovered=recover_job_key(args.capsule,load_identity(args.identity),read(args.descriptor),expected_package_sha256=args.package_sha256,expected_policy_sha256=args.policy_sha256,age=args.age)
        value={'jobKeyVerified':True,'jobId':recovered.job_id,'packageSHA256':recovered.package_sha256,'policySHA256':recovered.policy_sha256,'keyReleaseAuthorized':False}
    elif args.action=='plan':value=plan(read(args.manifest),read(args.workers),args.budget_base_units,objective=args.objective,deadline_seconds=args.deadline_seconds)
    elif args.action=='seal-result':
        if Path(args.receipt).exists():raise FileExistsError(args.receipt)
        value=seal_result(read(args.manifest),args.task,args.package_sha256,args.output_directory,args.recipient,args.encrypted_output,attempt=args.attempt,rank=args.rank,age=args.age);write(args.receipt,value)
    else:
        items=read(args.results)
        value=assemble_results(read(args.manifest),args.package_sha256,items,load_identity(args.identity),args.destination,age=args.age)
    print(json.dumps(value,indent=2))

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'error':type(exc).__name__,'message':str(exc)}),file=sys.stderr);sys.exit(1)
