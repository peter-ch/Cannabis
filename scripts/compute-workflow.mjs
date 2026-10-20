// Complete local workflow entry point. Wallet approvals stay in the browser;
// the terminal accepts no wallet keys, recovery secrets or automatic signatures.
import {RequesterWorkflow,readWorkflow} from '../requester/workflow.mjs';
import {createWorkflowApprovalServer} from '../requester/approval-server.mjs';
const [action,configFile,argument]=process.argv.slice(2);let workflow,approvalServer;
const controller=new AbortController();let stopped;
const stopping=new Promise(resolve=>{stopped=resolve;});
for(const event of ['SIGINT','SIGTERM'])process.once(event,()=>{controller.abort();stopped();});
try {
  if(!['create','status','run','recover','assemble'].includes(action)||!configFile)throw Error();
  workflow=new RequesterWorkflow(readWorkflow(configFile,{verifyInput:['create','run'].includes(action)}),{create:action==='create'});
  if(['create','status'].includes(action))console.log(JSON.stringify(workflow.snapshot(),null,2));
  else if(action==='assemble') {
    const report=await workflow.assemble(argument);
    console.log(JSON.stringify({integrityVerified:report.integrityVerified,approvedAttemptsVerified:report.approvedAttemptsVerified,
      qualityAccepted:false,paymentAuthorized:false}));
  }else {
    let running;
    approvalServer=await createWorkflowApprovalServer({mode:action,snapshot:()=>workflow.snapshot(),start:signApproval=>{
      running=action==='run'?workflow.run({signApproval,signal:controller.signal}):workflow.recover(argument,{signApproval,signal:controller.signal});
      return running;
    }});
    console.log('Open your local wallet review: '+approvalServer.url);
    console.log('Keep the workflow directory for recovery. Press Ctrl+C to stop.');
    await stopping;controller.abort();await approvalServer.close();approvalServer=undefined;
    if(running)await running.catch(()=>{});
  }
}catch{console.error(JSON.stringify({error:'Workflow operation failed. Preserve the workflow directory and review the configuration or retained result.'}));process.exitCode=1;}
finally{controller.abort();if(approvalServer)await approvalServer.close();workflow?.close();}
