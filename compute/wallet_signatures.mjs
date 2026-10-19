// Hash-bound EOA/ERC-1271 observation within a canonical escrow snapshot.
// The caller must validate/recheck chain, market, canonicality and anchors too.
// https://eips.ethereum.org/EIPS/eip-1271 and https://eips.ethereum.org/EIPS/eip-1898
import { Interface,getAddress,keccak256,recoverAddress,ZeroAddress } from 'ethers';
const wallet=new Interface(['function isValidSignature(bytes32 digest,bytes signature) view returns(bytes4)']);
const magic='0x1626ba7e'+'0'.repeat(56);
const fields=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join();
const bytes32=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const fail=()=>{throw Error('Booked party signature is not valid at the observed canonical block');};
export function validateWalletApprovals(approvals) {
  approvals=structuredClone(approvals);
  if(!Array.isArray(approvals)||approvals.length!==2)fail();
  const seen=new Set();
  for(const [i,role] of ['requester','provider'].entries()) {
    const a=approvals[i];
    if(!fields(a,['role','signer','digest','signature'])||a.role!==role||getAddress(a.signer)!==a.signer||
      a.signer===ZeroAddress||seen.has(a.signer)||!bytes32(a.digest)||typeof a.signature!=='string'||
      !/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(a.signature))fail();
    seen.add(a.signer);
  }
  return approvals;
}
export async function observeWalletSignatures(send,block,approvals) {
  if(typeof send!=='function'||!bytes32(block?.hash))fail();
  approvals=validateWalletApprovals(approvals);
  const tag={blockHash:block.hash,requireCanonical:true},observed=[];
  for(const a of approvals) {
    const code=await send('eth_getCode',[a.signer,tag]);
    if(typeof code!=='string'||code.length>131074||!/^0x(?:[0-9a-fA-F]{2})*$/.test(code))fail();
    let method,codeHash=null;
    if(code==='0x') {
      if(recoverAddress(a.digest,a.signature)!==a.signer)fail();
      method='ecdsa';
    } else {
      // Match OpenZeppelin SignatureChecker: no ECDSA fallback when code exists.
      // A revert, unsupported hash query or wrong/short return fails closed.
      const returned=await send('eth_call',[{to:a.signer,data:wallet.encodeFunctionData('isValidSignature',[a.digest,a.signature])},tag]);
      if(typeof returned!=='string'||returned.length>8194||!/^0x(?:[0-9a-fA-F]{2}){32,}$/.test(returned)||
        returned.slice(0,66).toLowerCase()!==magic)fail();
      method='erc1271';codeHash=keccak256(code);
    }
    observed.push({role:a.role,signer:a.signer,digest:a.digest,method,codeHash});
  }
  return observed;
}
