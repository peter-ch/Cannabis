// Offline preparation only. Context/assignment inputs contain public metadata.
import fs from 'node:fs';
import {prepareExecutionPlan,inspectExecutionPlan,executionPlanForOrder} from '../compute/execution_plan.mjs';
import {publicOrderPlan} from '../compute/settlement.mjs';
import {prepareMarketPlan} from '../operator/market-plan.mjs';
const exact=(v,keys)=>{if(!v||Object.keys(v).sort().join()!==keys.sort().join())throw Error('Unexpected preparation fields');};
try {
  const [command,contextFile,inputFile]=process.argv.slice(2);
  if(!['prepare','commit-order','market-plan'].includes(command)||!contextFile||!inputFile||process.argv.length!==5)
    throw Error('Usage: node scripts/compute-execution-plan.mjs prepare|commit-order|market-plan context.json input.json');
  const read=file=>{const bytes=fs.readFileSync(file);if(bytes.length>1024*1024)throw Error('Public input exceeds 1 MiB');return JSON.parse(bytes.toString('utf8'));};
  const context=read(contextFile),input=read(inputFile);let result;
  if(command==='prepare') {
    exact(input,['descriptor','assignments']);result=prepareExecutionPlan(input.descriptor,context,input.assignments);
  } else if(command==='commit-order') {
    exact(input,['job','executionPlan']);
    if(input.job?.schema!=='cannabis.compute.order.v2')throw Error('Start with the agreed unplanned v2 order; existing plan commitments are never overwritten');
    publicOrderPlan(input.job);
    const inspected=inspectExecutionPlan(input.executionPlan);
    const job={...input.job,schema:'cannabis.compute.order.v3',executionPlanSHA256:inspected.digestSHA256};
    executionPlanForOrder(inspected.plan,job,context);publicOrderPlan(job);
    result={job,executionPlan:inspected.plan,executionAuthorized:false,keyReleaseAuthorized:false,paymentAuthorized:false};
  } else {
    exact(input,['asset','job','executionPlan','settlement']);
    const p=inspectExecutionPlan(input.executionPlan).plan;
    result=prepareMarketPlan(context,{schema:'cannabis.market-plan.v1',kind:'order',...input,
      bookings:p.assignments.map(a=>a.booking)}).plan;
  }
  console.log(JSON.stringify(result,null,2));
} catch(error) {console.error(error.message);process.exitCode=1;}
