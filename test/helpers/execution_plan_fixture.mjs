import {Wallet,ZeroAddress,formatUnits} from 'ethers';
import {inspectExecutionPlan,taskCommitment} from '../../compute/execution_plan.mjs';
import {policy} from '../../compute/settlement.mjs';
const h=n=>'0x'+n.toString(16).padStart(64,'0');
export function executionPlanFixture({group=false}={}) {
  const requester=Wallet.createRandom().address,providers=[Wallet.createRandom().address,Wallet.createRandom().address];
  const context={chainId:31337,genesisHash:h(1),market:Wallet.createRandom().address,escrow:Wallet.createRandom().address,token:ZeroAddress,requester};
  const packageSHA256=h(2).slice(2),policySHA256=h(3).slice(2);
  const runtime={adapter:'custom-cpu-v1',architecture:'x86_64',os:'linux',digestSHA256:h(4).slice(2),...(group?{collectiveBackend:'tcp'}:{})};
  const resources={cpus:1,memoryMiB:128,scratchMiB:8,wallSeconds:60,nodes:group?2:1};
  const requirements=Array.from({length:group?1:2},(_,task)=>({task,taskSHA256:taskCommitment(packageSHA256,task),
    dependsOn:task===1?[0]:[],runtime:structuredClone(runtime),resources:structuredClone(resources)}));
  const assignments=providers.map((provider,i)=>({task:group?0:i,rank:group?i:0,attempt:1,acceleratorClass:'cpu',provider,serviceSHA256:h(10+i),
    booking:{reservationId:h(20+i),offerId:h(30+i),start:String(1000+(group?0:i*100)),end:String(1100+(group?0:i*100)),units:'1',gross:'10000',holdUntil:'900'}}));
  const descriptor={schema:'cannabis.package.v2',id:'owned-plan',ciphertextSHA256:packageSHA256,policySHA256,requirements,
    executionAuthorized:false,keyReleaseAuthorized:false};
  const checked=inspectExecutionPlan({schema:'cannabis.execution-plan.v1',...context,jobId:descriptor.id,packageSHA256,policySHA256,requirements,assignments});
  const job={schema:'cannabis.compute.order.v3',id:descriptor.id,requester,packageSHA256,policySHA256,acceptanceSHA256:h(5).slice(2),
    executionPlanSHA256:checked.digestSHA256,payment:{totalBudget:formatUnits(20000n,18),feeBasisPoints:100,founderRecipient:policy.founderRecipient}};
  const settlement={workers:providers.map(account=>({account,shareBps:5000})),deliveryManager:providers[0],adjudicator:Wallet.createRandom().address,
    acceptBy:'1970-01-01T00:15:00Z',deliverBy:'1970-01-01T00:21:40Z',reviewSeconds:86400,disputeSeconds:86400};
  const configuration={schema:'cannabis.market-console.v1',rpc:'http://127.0.0.1:8545',chainId:'31337',genesisHash:context.genesisHash,
    market:context.market,marketCodeHash:h(40),nativeEscrow:context.escrow,nativeEscrowCodeHash:h(41),
    cannabisEscrow:Wallet.createRandom().address,cannabisEscrowCodeHash:h(42),token:Wallet.createRandom().address,tokenCodeHash:h(43),
    founderRecipient:policy.founderRecipient,maxFinalizedAgeSeconds:1800,maxHeadAgeSeconds:120,
    feeLimits:{gas:'1000000',maxFeePerGas:'100000000000',maxPriorityFeePerGas:'1000000000',maxTotalWei:'100000000000000000'}};
  return {context,descriptor,assignments,checked,job,settlement,configuration};
}
