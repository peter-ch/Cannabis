import test from 'node:test';
import assert from 'node:assert/strict';
import { Wallet } from 'ethers';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CapacityLedger, offerPayload, reservationPayload, verifyOffer } from '../compute/capacity.mjs';
const h=n=>'0x'+n.toString(16).padStart(64,'0');
const provider=Wallet.createRandom(),requester=Wallet.createRandom(),other=Wallet.createRandom();
const context={chainId:31337,registryId:h(1),token:other.address};
const now=2000000000;
async function offer(changes={}) {
 const value={offerId:h(2),provider:provider.address,resourceId:h(3),serviceSHA256:h(4),policySHA256:h(5),token:context.token,windowStart:now+100,windowEnd:now+10000,expiresAt:now+3000,units:2,grossPerUnitSecond:'10',feeBps:100,termsSHA256:h(6),...changes};
 const p=offerPayload(context,value);return {offer:value,signature:await provider.signTypedData(p.domain,p.types,p.value)};
}
async function reservation(offerDigest,changes={}) {
 const value={reservationId:h(7),offerDigest,requester:requester.address,jobSHA256:h(8),start:now+1000,end:now+1100,units:1,grossBaseUnits:'1000',holdUntil:now+500,...changes};
 const p=reservationPayload(context,value);return {reservation:value,requesterSignature:await requester.signTypedData(p.domain,p.types,p.value),providerSignature:await provider.signTypedData(p.domain,p.types,p.value)};
}
function ledger(){const l=new CapacityLedger(':memory:',context);l.admitResource({provider:provider.address,resourceId:h(3),serviceSHA256:h(4),units:2});return l;}
test('capacity signatures bind price, chain, registry, token and provider; expiry fails closed',async()=>{
 const s=await offer();assert.equal(verifyOffer(context,s,now).value.provider,provider.address);
 for(const change of [{grossPerUnitSecond:'11'},{feeBps:101},{token:requester.address},{provider:requester.address},{serviceSHA256:h(9)}])assert.throws(()=>verifyOffer(context,{...s,offer:{...s.offer,...change}},now));
 assert.throws(()=>verifyOffer({...context,chainId:1},s,now));assert.throws(()=>verifyOffer({...context,registryId:h(9)},s,now));assert.throws(()=>verifyOffer(context,s,now+3000));
});
test('atomic reservations conserve shared capacity across multiple offers and reject replay',async()=>{
 const l=ledger();try{
  const a=l.addOffer(await offer(),now).offerDigest,b=l.addOffer(await offer({offerId:h(9)}),now).offerDigest;
  const r=await reservation(a);assert.equal(l.reserve(r,now).executionAuthorized,false);
  assert.throws(()=>l.reserve(r,now));l.reserve(await reservation(b,{reservationId:h(10)}),now);
  assert.throws(()=>l.reserve({...r,reservation:{...r.reservation,reservationId:h(11)}},now));
  const third=await reservation(b,{reservationId:h(12)});assert.throws(()=>l.reserve(third,now),/already reserved/);
  const later=await reservation(b,{reservationId:h(13),start:now+1100,end:now+1200});assert.equal(l.reserve(later,now).paymentAuthorized,false);
 }finally{l.close();}
});
test('expired holds release capacity; altered prices, unauthorized reservations and excessive holds fail',async()=>{
 const l=ledger();try{
  const digest=l.addOffer(await offer(),now).offerDigest;
  l.reserve(await reservation(digest,{units:2,grossBaseUnits:'2000'}),now);
  l.reserve(await reservation(digest,{reservationId:h(14),units:2,grossBaseUnits:'2000',holdUntil:now+800}),now+501);
  for(const changes of [{reservationId:h(15),grossBaseUnits:'999'},{reservationId:h(16),holdUntil:now+5000},{reservationId:h(17),start:now-1}]){
    const r=await reservation(digest,changes);assert.throws(()=>l.reserve(r,now));
  }
  const r=await reservation(digest,{reservationId:h(18)});r.providerSignature=r.requesterSignature;assert.throws(()=>l.reserve(r,now),/Provider reservation/);
  assert.throws(()=>l.addOffer({offer:{},signature:'0x'},now));
 }finally{l.close();}
});
test('resource admission prevents inflated offers and service-unit substitution',async()=>{
 const l=ledger();try{
  const tooMany=await offer({units:3}),changed=await offer({serviceSHA256:h(40)});
  assert.throws(()=>l.addOffer(tooMany,now));assert.throws(()=>l.addOffer(changed,now));
  assert.throws(()=>l.admitResource({provider:provider.address,resourceId:h(3),serviceSHA256:h(4),units:9}));
 }finally{l.close();}
});
test('independent ledger connections share reservations and reject domain changes',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-capacity-')),file=path.join(dir,'ledger.sqlite');
 const a=new CapacityLedger(file,context),b=new CapacityLedger(file,context);
 try {
  a.admitResource({provider:provider.address,resourceId:h(3),serviceSHA256:h(4),units:2});
  const digest=a.addOffer(await offer(),now).offerDigest;
  a.reserve(await reservation(digest,{units:2,grossBaseUnits:'2000'}),now);
  const duplicate=await reservation(digest,{reservationId:h(55)});assert.throws(()=>b.reserve(duplicate,now),/already reserved/);
  assert.throws(()=>new CapacityLedger(file,{...context,registryId:h(99)}),/domain cannot change/);
 }finally{a.close();b.close();for(const name of fs.readdirSync(dir))fs.unlinkSync(path.join(dir,name));fs.rmdirSync(dir);}
});

test('a narrower offer cannot be oversold even when its underlying resource has spare capacity',async()=>{
 const l=ledger();try{
  const limited=l.addOffer(await offer({units:1}),now).offerDigest;
  l.reserve(await reservation(limited),now);
  const second=await reservation(limited,{reservationId:h(70)});
  assert.throws(()=>l.reserve(second,now),/Offer capacity already reserved/);
  const otherOffer=l.addOffer(await offer({offerId:h(71),units:1}),now).offerDigest;
  l.reserve(await reservation(otherOffer,{reservationId:h(72)}),now);
 }finally{l.close();}
});
