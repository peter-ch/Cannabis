"""Deterministic, budget-bounded candidate placement for arbitrary runtime adapters.

Quotes/capabilities are advertisements, not attestation or reserved resources.
Each selected task takes an exclusive node lease in the proposed schedule.
"""
from .client import validate_workload


def integer(value, label):
    if isinstance(value,str) and value.isdigit():return int(value)
    if type(value) is int and value>=0:return value
    raise ValueError(label+' must be a nonnegative integer')


def plan(spec, workers, budget_base_units, *, objective='fastest', deadline_seconds=None):
    order=validate_workload(spec);budget=integer(budget_base_units,'budget')
    if objective not in ('fastest','cheapest'):raise ValueError('Choose fastest or cheapest')
    if deadline_seconds is not None:deadline_seconds=integer(deadline_seconds,'deadline')
    if len(workers)>100000:raise ValueError('Worker pool exceeds client bounds')
    ids=[w.get('id') for w in workers]
    if any(not isinstance(x,str) or not x for x in ids) or len(set(ids))!=len(ids):raise ValueError('Unique worker IDs required')
    for w in workers:
        for k in ('cpus','memoryMiB','scratchMiB','accelerators','acceleratorMemoryMiB'):
            integer(w.get('capacity',{}).get(k,0),'capacity')
        integer(w.get('availableInSeconds',0),'availability')
        for q in w.get('quotes',[]):
            if q.get('feeBasisPoints')!=100:raise ValueError('Quotes must include the fixed 1% founder fee')
            integer(q.get('grossBaseUnits'),'gross quote')
            if integer(q.get('runSeconds'),'run time')<1:raise ValueError('Positive run time required')
            integer(q.get('transferSeconds',0),'transfer time')
    by_task={t['id']:t for t in spec['tasks']};finish={};free={};assignments=[];spent=0
    for tid in order:
        task=by_task[tid];runtime=task['runtime'];r=task['resources'];groups={}
        deps=task.get('dependsOn',[])
        if any(d not in finish for d in deps):
            assignments.append({'task':tid,'state':'unassigned','reason':'dependency unassigned'});continue
        ready=max((finish[d] for d in deps),default=0)
        for w in workers:
            if runtime['adapter'] not in w.get('adapters',[]) or runtime['digestSHA256'] not in w.get('runtimeDigests',[]):continue
            if runtime['architecture']!=w.get('architecture') or runtime['os']!=w.get('os'):continue
            if spec['policySHA256'] not in w.get('confidentialPolicies',[]):continue
            if any(integer(w.get('capacity',{}).get(k,0),'capacity')<r.get(k,0) for k in ('cpus','memoryMiB','scratchMiB','accelerators','acceleratorMemoryMiB')):continue
            if not set(runtime.get('features',[]))<=set(w.get('features',[])):continue
            quotes=[q for q in w.get('quotes',[]) if q.get('task')==tid]
            if len(quotes)>1:raise ValueError('Ambiguous duplicate worker quote for task')
            if not quotes:continue
            q=quotes[0]
            if integer(q['runSeconds'],'run time')>r['wallSeconds']:continue
            start=max(ready,integer(w.get('availableInSeconds',0),'availability'),free.get(w['id'],0))
            end=start+integer(q['runSeconds'],'run time')+integer(q.get('transferSeconds',0),'transfer time')
            # Gang workers require a declared shared compatibility group and collective backend.
            group=w.get('compatibilityGroup','') if r['nodes']>1 else 'single'
            if r['nodes']>1 and (not group or runtime.get('collectiveBackend') not in w.get('collectiveBackends',[])):continue
            groups.setdefault(group,[]).append({'worker':w['id'],'start':start,'runSeconds':integer(q['runSeconds'],'run time'),
              'transferSeconds':integer(q.get('transferSeconds',0),'transfer time'),'finish':end,'grossBaseUnits':integer(q['grossBaseUnits'],'gross quote'),
              'waste':sum(integer(w['capacity'].get(k,0),'capacity')-r.get(k,0) for k in ('cpus','memoryMiB','accelerators'))})
        options=[]
        for group,candidates in groups.items():
            # Two deterministic greedy orderings expose useful cost/time tradeoffs.
            for sorter in [lambda c:(c['finish'],c['grossBaseUnits'],c['waste'],c['worker']),lambda c:(c['grossBaseUnits'],c['finish'],c['waste'],c['worker'])]:
                chosen=sorted(candidates,key=sorter)[:r['nodes']]
                if len(chosen)!=r['nodes']:continue
                start=max(c['start'] for c in chosen)
                end=start+max(c['runSeconds']+c['transferSeconds'] for c in chosen)
                cost=sum(c['grossBaseUnits'] for c in chosen)
                if spent+cost>budget or (deadline_seconds is not None and end>deadline_seconds):continue
                options.append((end,cost,sum(c['waste'] for c in chosen),group,chosen,start))
        if not options:
            assignments.append({'task':tid,'state':'unassigned','reason':'no compatible advertised capacity within budget/deadline'});continue
        options.sort(key=lambda o:(o[0],o[1],o[2],o[3]) if objective=='fastest' else (o[1],o[0],o[2],o[3]))
        end,cost,_,group,chosen,start=options[0];finish[tid]=end;spent+=cost
        for c in chosen:free[c['worker']]=end
        assignments.append({'task':tid,'state':'candidate','workers':[c['worker'] for c in chosen],'compatibilityGroup':group,
          'estimatedStartSeconds':start,'estimatedFinishSeconds':end,'grossBaseUnits':str(cost),
          'workerQuotes':[{'worker':c['worker'],'grossBaseUnits':str(c['grossBaseUnits'])} for c in chosen]})
    fee=spent//100
    complete=all(x['state']=='candidate' for x in assignments)
    return {'schema':'cannabis.placement.v1','jobId':spec['id'],'strategy':'greedy-'+objective,'complete':complete,'assignments':assignments,
      'quotedGrossBaseUnits':str(spent),'quotedFounderBaseUnits':str(fee),'quotedWorkerBaseUnits':str(spent-fee),
      'uncommittedBudgetBaseUnits':str(budget-spent),'estimatedAssemblyReadySeconds':max(finish.values(),default=0) if complete else None,
      'executionAuthorized':False,'keyReleaseAuthorized':False,'paymentAuthorized':False,
      'note':'Advertised quotes, exclusive-node schedule and estimates only. Attestation, signed offers, funded escrow and atomic leases are required. A greedy candidate plan is not a global optimum.'}
