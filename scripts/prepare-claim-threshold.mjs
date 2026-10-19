// Read current policy and export an unsigned increase for the owner's wallet.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Contract,FetchRequest,JsonRpcProvider,getAddress,keccak256,toBeHex} from 'ethers';
import {compile} from './compile.mjs';

export async function prepareClaimThreshold({rpc,chainId,token,codeHash,authority,minimumClaimMembers}) {
  const endpoint=new URL(rpc);
  if(endpoint.username||endpoint.password||(endpoint.protocol!=='https:'&&!(endpoint.protocol==='http:'&&endpoint.hostname==='127.0.0.1')))throw Error('Use HTTPS RPC or loopback verification RPC');
  if(!Number.isSafeInteger(minimumClaimMembers)||minimumClaimMembers<1||minimumClaimMembers>990000)throw Error('Invalid minimum claim members');
  chainId=BigInt(chainId);token=getAddress(token);authority=getAddress(authority);
  if(chainId<=0n||!/^0x[0-9a-fA-F]{64}$/.test(codeHash))throw Error('Expected chain and runtime hash are required');
  const request=new FetchRequest(rpc);request.timeout=15000;
  const provider=new JsonRpcProvider(request,undefined,{cacheTimeout:-1});
  try {
    if((await provider.getNetwork()).chainId!==chainId)throw Error('RPC chain ID does not match');
    const code=await provider.getCode(token);
    if(code==='0x'||keccak256(code).toLowerCase()!==codeHash.toLowerCase())throw Error('Contract code does not match verified release');
    const contract=new Contract(token,compile().Cannabis.abi,provider);
    if(await contract.claimPolicyAuthority()!==authority)throw Error('Wallet is not the claim policy authority');
    const previousMinimum=Number(await contract.minimumClaimMembers());
    await contract.increaseMinimumClaimMembers.staticCall(minimumClaimMembers,{from:authority});
    return {name:'Cannabis',status:'UNSIGNED_VERIFIED_CLAIM_MINIMUM_INCREASE',checkedAt:new Date().toISOString(),
      chainId:chainId.toString(),token,authority,deployedCodeHash:keccak256(code),previousMinimum,minimumClaimMembers,
      transaction:{chainId:toBeHex(chainId),from:authority,to:token,value:'0x0',
        data:contract.interface.encodeFunctionData('increaseMinimumClaimMembers',[minimumClaimMembers])},sent:false,
      review:'Review the current chain, token and new minimum in your wallet. Increases cannot exceed already enrolled membership, cannot be reversed and do not revoke claims or change allocations. Re-simulate before signing. Network fees apply.'};
  } finally {provider.destroy();}
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    const names={rpc:'rpc','chain-id':'chainId',token:'token','code-hash':'codeHash',authority:'authority','minimum-claim-members':'minimumClaimMembers',out:'out'};
    const args=process.argv.slice(2),options={};
    for(let i=0;i<args.length;i+=2) {
      const key=names[args[i]?.slice(2)];
      if(!args[i]?.startsWith('--')||!key||!args[i+1]||Object.hasOwn(options,key))throw Error('Invalid arguments');
      options[key]=args[i+1];
    }
    if(Object.values(names).some(key=>!options[key])||! /^[1-9][0-9]{0,5}$/.test(options.minimumClaimMembers))throw Error('Missing or invalid arguments');
    options.minimumClaimMembers=Number(options.minimumClaimMembers);
    const result=await prepareClaimThreshold(options);
    fs.writeFileSync(options.out,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log(JSON.stringify({output:path.resolve(options.out),status:result.status,sent:false}));
  } catch {
    console.error('Claim minimum preparation failed. Check the reviewed chain/token, authority, current enrollment and unused output path. No transaction was sent.');
    process.exitCode=1;
  }
}
