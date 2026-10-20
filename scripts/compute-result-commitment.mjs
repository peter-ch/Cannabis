// Assemble public encrypted-result metadata. No RPC, decryption, attestation or
// payment is performed; this is not an output-quality approval.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {marketConfiguration,prepareMarketPlan,exact,check} from '../operator/market-plan.mjs';
import {resultCommitment} from '../compute/result_commitment.mjs';
export function prepareResultCommitment(input) {
  exact(input,['configuration','plan','archives']);const c=marketConfiguration(input.configuration),prepared=prepareMarketPlan(c,input.plan);
  check(prepared.plan.kind==='order');const p=prepared.plan,d=prepared.detail;
  return resultCommitment({chainId:c.chainId,genesisHash:c.genesisHash,escrow:d.asset.escrow,requester:d.requester,orderId:d.orderId,
    termsDigest:d.termsDigest,packageSHA256:p.job.packageSHA256,policySHA256:p.job.policySHA256},input.archives);
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const [source,destination,...extra]=process.argv.slice(2);if(!source||!destination||extra.length)throw Error('Usage: compute-result-commitment.mjs input.json new-result-set.json');
  const stat=fs.statSync(source);check(stat.isFile()&&stat.size>0&&stat.size<=1048576);
  const bytes=fs.readFileSync(source);check(bytes.length<=1048576);const result=prepareResultCommitment(JSON.parse(bytes));
  fs.writeFileSync(destination,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({output:path.resolve(destination),outputDigest:result.outputDigest,archives:result.entries.length,
    resultAuthenticated:false,qualityAccepted:false,sent:false}));
}
