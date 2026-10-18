"""Fixed, owner-readable arithmetic fixtures; never accepts arbitrary programs."""
import json
from pathlib import Path

data=json.loads(Path('input.json').read_text(encoding='utf-8'))
if data['operation']=='matrix':
    a,b=data['a'],data['b']
    result=[[sum(x*y for x,y in zip(row,column)) for column in zip(*b)] for row in a]
elif data['operation']=='sum-squares':
    result=sum(x*x for x in range(data['first'],data['last']+1))
elif data['operation']=='fit-line':
    # Ordinary CPU computation, not a mining or issuance race.
    points=data['points'];weight=0.;bias=0.
    for _ in range(2000):
        errors=[weight*x+bias-y for x,y in points]
        weight-=0.03*sum(error*x for error,(x,_) in zip(errors,points))/len(points)
        bias-=0.03*sum(errors)/len(points)
    result={'weight':weight,'bias':bias,'mse':sum((weight*x+bias-y)**2 for x,y in points)/len(points)}
else:
    raise ValueError('Unknown fixed fixture')
Path('answer.json').write_text(json.dumps(result,separators=(',',':')),encoding='utf-8')
