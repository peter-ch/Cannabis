import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {TypedDataEncoder} from 'ethers';
import {ProviderWallet,validateProviderReview} from '../operator/provider-wallet.js';
import {launchConsentPayload} from '../compute/guest_consent.mjs';
import {peerChannelPayload} from '../compute/peer_channel.mjs';
import {consentFixture} from './helpers/consent_fixture.mjs';

function fixture(kind='launch') {
  const now=Math.floor(Date.now()/1000),x=consentFixture({start:now-10,end:now+1000});
  return Promise.resolve(x).then(x=>{
    const origin='https://independent.example',binding={origin,channelBinding:'0x'+'12'.repeat(32),
      requesterNonce:'0x'+'13'.repeat(32),providerNonce:'0x'+'14'.repeat(32),validFrom:now,validUntil:now+50};
    const p=kind==='launch'?launchConsentPayload(x.configuration,x.initialization,x.proof,'provider'):
      peerChannelPayload(x.signed,x.initialization,x.proof,binding,'provider',now);
    const review={id:'a'.repeat(64),assignmentId:p.value.assignmentSHA256.slice(2),kind,state:'awaiting-wallet',expiresAt:Date.now()+30000,
      signer:p.signer,genesisHash:x.configuration.network.genesisHash,digest:p.digest,summary:{origin},
      typedData:TypedDataEncoder.getPayload(p.domain,p.types,p.value),executionAuthorized:false,keyReleaseAuthorized:false};
    const provider=new EventEmitter(),calls=[];
    provider.request=async({method,params})=>{
      calls.push({method,params});
      if(['eth_accounts','eth_requestAccounts'].includes(method))return [p.signer];
      if(method==='eth_chainId')return '0x'+BigInt(p.domain.chainId).toString(16);
      if(method==='eth_getBlockByNumber')return {hash:review.genesisHash};
      if(method==='eth_signTypedData_v4')return '0x'+'ab'.repeat(65);
      throw Error('Unexpected wallet operation');
    };
    const wallet=new ProviderWallet();wallet.select(provider);return {x,p,review,provider,calls,wallet};
  });
}

test('wallet signs only the two recognized provider commitments after explicit connection',async()=>{
  for(const kind of ['launch','peer']){
    const {wallet,review,calls}=await fixture(kind);assert.equal(calls.length,0);
    await assert.rejects(wallet.sign(review));await wallet.connect();
    assert.match(await wallet.sign(review),/^0x/);
    assert.deepEqual(calls.map(c=>c.method),['eth_requestAccounts','eth_accounts','eth_accounts','eth_chainId','eth_getBlockByNumber',
      'eth_signTypedData_v4','eth_accounts','eth_chainId','eth_getBlockByNumber']);
    assert.equal(calls[5].params[0],review.signer);assert.deepEqual(JSON.parse(calls[5].params[1]),review.typedData);wallet.clear();
  }
});

test('wallet refuses arbitrary types, requester role, wrong account, chain or genesis before a prompt',async()=>{
  const {wallet,review,provider,calls}=await fixture();await wallet.connect();
  for(const change of [r=>r.typedData.primaryType='Permit',r=>r.typedData.message.role='0',r=>r.typedData.message.spender=r.signer,
    r=>r.typedData.domain.verifyingContract='0x'+'00'.repeat(20),r=>r.assignmentId='b'.repeat(64),r=>r.expiresAt=Date.now()-1,
    r=>r.typedData.types.BookedGuestLaunch[0].type='bytes32']) {
    const changed=structuredClone(review);change(changed);assert.throws(()=>validateProviderReview(changed));await assert.rejects(wallet.sign(changed));
  }
  const original=provider.request;
  for(const [method,result] of [['eth_accounts',[]],['eth_chainId','0x1'],['eth_getBlockByNumber',{hash:'0x'+'ef'.repeat(32)}]]) {
    provider.request=async args=>args.method===method?result:original(args);await assert.rejects(wallet.sign(review));
  }
  assert.ok(!calls.some(c=>c.method==='eth_signTypedData_v4'));wallet.clear();
});

test('wallet rejects late signatures after account, network, disconnection, selection, cancellation or expiry',async()=>{
  for(const change of ['accountsChanged','chainChanged','disconnect','selection','cancel','expiry']){
    const {wallet,review,provider}=await fixture();await wallet.connect();
    let release,entered;const ready=new Promise(r=>entered=r),original=provider.request,controller=new AbortController();
    provider.request=async args=>args.method==='eth_signTypedData_v4'?new Promise(resolve=>{release=resolve;entered();}):original(args);
    if(change==='expiry')review.expiresAt=Date.now()+80;
    const pending=assert.rejects(wallet.sign(review,controller.signal));await ready;
    if(change==='selection')wallet.clear();else if(change==='cancel')controller.abort();
    else if(change==='expiry')await new Promise(r=>setTimeout(r,100));else provider.emit(change,[]);
    release('0x'+'ab'.repeat(65));await pending;wallet.clear();
  }
});

test('wallet rechecks unchanged-provider RPC state after signing and removes old listeners',async()=>{
  const {wallet,review,provider}=await fixture();await wallet.connect();const original=provider.request;let signed=false;
  provider.request=async args=>{if(args.method==='eth_signTypedData_v4')signed=true;
    if(args.method==='eth_chainId'&&signed)return '0x1';return original(args);};
  await assert.rejects(wallet.sign(review));assert.equal(signed,true);wallet.clear();
  for(const event of ['accountsChanged','chainChanged','disconnect'])assert.equal(provider.listenerCount(event),0);
});

test('initial wallet permission may announce its new account without prompting twice',async()=>{
  const {wallet,review,provider,calls}=await fixture(),original=provider.request;
  provider.request=async args=>{if(args.method==='eth_requestAccounts')provider.emit('accountsChanged',[review.signer]);return original(args);};
  assert.deepEqual(await wallet.connect(),[review.signer.toLowerCase()]);await wallet.sign(review);
  assert.equal(calls.filter(c=>c.method==='eth_requestAccounts').length,1);wallet.clear();
});
