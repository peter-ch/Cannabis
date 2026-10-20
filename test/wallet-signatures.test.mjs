// Offline RPC-shape checks, not chain-state or hardware admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Wallet,Interface } from 'ethers';
import { observeWalletSignatures } from '../compute/wallet_signatures.mjs';
const h=n=>'0x'+n.toString(16).padStart(64,'0'),block={hash:h(91)};
const iface=new Interface(['function isValidSignature(bytes32 digest,bytes signature) view returns(bytes4)']);
async function fixture() {
  const wallets=[Wallet.createRandom(),Wallet.createRandom()],approvals=[];
  for(const [i,role] of ['requester','provider'].entries())approvals.push({role,signer:wallets[i].address,digest:h(i+1),signature:wallets[i].signingKey.sign(h(i+1)).serialized});
  return {wallets,approvals};
}
test('EOA checks use the exact canonical block and cannot accept another role digest or signer',async()=>{
  const f=await fixture(),seen=[];
  const send=async(method,params)=>{assert.equal(method,'eth_getCode');assert.deepEqual(params[1],{blockHash:block.hash,requireCanonical:true});seen.push(params[0]);return '0x';};
  const result=await observeWalletSignatures(send,block,f.approvals);
  assert.deepEqual(result.map(r=>r.method),['ecdsa','ecdsa']);assert.deepEqual(seen,f.wallets.map(w=>w.address));
  for(const change of [a=>a[0].digest=h(9),a=>a[1].signer=f.wallets[0].address,a=>a[1].signature=a[0].signature,a=>a.reverse()]) {
    const approvals=structuredClone(f.approvals);change(approvals);await assert.rejects(observeWalletSignatures(send,block,approvals));
  }
});
test('contract signatures require the exact ERC-1271 success word at the same block',async()=>{
  const f=await fixture();f.approvals[1].signature='0x1234';let calls=0;
  const send=async(method,params)=>{
    assert.deepEqual(params[1],{blockHash:block.hash,requireCanonical:true});
    if(method==='eth_getCode')return params[0]===f.wallets[1].address?'0x6000':'0x';
    assert.equal(method,'eth_call');assert.equal(params[0].to,f.wallets[1].address);
    const data=iface.decodeFunctionData('isValidSignature',params[0].data);assert.equal(data[0],h(2));assert.equal(data[1],'0x1234');calls++;
    return iface.encodeFunctionResult('isValidSignature',['0x1626ba7e']);
  };
  const result=await observeWalletSignatures(send,block,f.approvals);assert.equal(calls,1);assert.equal(result[1].method,'erc1271');
  for(const returned of ['0x','0x1626ba7e','0x1626ba7e'+'0'.repeat(55)+'1',iface.encodeFunctionResult('isValidSignature',['0xffffffff']),'0x'+'00'.repeat(4097)])
    await assert.rejects(observeWalletSignatures((m,p)=>m==='eth_call'?returned:send(m,p),block,f.approvals));
});
test('contract-wallet revocation or call failure cannot fall back to a valid EOA signature',async()=>{
  const f=await fixture();let calls=0;
  const send=async(method,params)=>{
    if(method==='eth_getCode')return params[0]===f.wallets[1].address?'0x6000':'0x';
    calls++;throw Error('Owned revocation fixture');
  };
  await assert.rejects(observeWalletSignatures(send,block,f.approvals),/revocation/);assert.equal(calls,1);
});
