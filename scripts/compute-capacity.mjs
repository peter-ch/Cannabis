import fs from 'node:fs';
import { CapacityLedger, offerPayload, reservationPayload, verifyOffer } from '../compute/capacity.mjs';
import { inspectLease, leasePayload, promoteLease } from '../compute/leases.mjs';
function read(p){if(fs.statSync(p).size>1024*1024)throw Error('Input too large');return JSON.parse(fs.readFileSync(p,'utf8'));}
const [action,contextFile,inputFile,dbFile]=process.argv.slice(2);
try {
  if(!['offer-payload','reservation-payload','verify','admit-resource','add-offer','reserve','lease-payload','promote-lease','inspect-lease'].includes(action)||!contextFile||!inputFile)throw Error('Usage: node scripts/compute-capacity.mjs ACTION context.json input.json [private-ledger.sqlite]');
  const context=read(contextFile),input=read(inputFile);let result;
  if(action==='offer-payload')result=offerPayload(context,input);
  else if(action==='reservation-payload')result=reservationPayload(context,input);
  else if(action==='verify')result=verifyOffer(context,input);
  else {
    if(!dbFile)throw Error('Private local ledger path required');
    const ledger=new CapacityLedger(dbFile,context);
    try{
      if(action==='lease-payload')result=leasePayload(ledger,input);
      else if(action==='promote-lease')result=await promoteLease(ledger,input.agreement,input.network);
      else if(action==='inspect-lease')result=inspectLease(ledger,input.leaseId);
      else result=action==='admit-resource'?ledger.admitResource(input):action==='add-offer'?ledger.addOffer(input):ledger.reserve(input);
    }finally{ledger.close();}
  }
  console.log(JSON.stringify(result??{recorded:true},null,2));
} catch(error){console.error(JSON.stringify({error:error.message}));process.exitCode=1;}
