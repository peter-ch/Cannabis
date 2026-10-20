import {getAddress,ZeroAddress,formatUnits} from 'ethers';
import {encodeProviderManifest,inspectProviderManifest} from '../compute/provider_manifest_model.mjs';
import {marketConfiguration,prepareMarketPlan,check,canonical} from '../operator/market-plan.mjs';
import {publicOrderPlan} from '../compute/settlement.mjs';
const $=id=>document.getElementById(id);
const utc=t=>new Date(t*1000).toISOString().replace('.000Z','Z');
const seconds=value=>{check(typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value));
  const t=Date.parse(value)/1000;check(Number.isSafeInteger(t)&&utc(t)===value);return t;};
const nonce=()=>'0x'+Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
let configuration=null,observation=null,manifests=new Map(),onPlan,epoch=0;
const note=(text,error=false)=>{const n=$('direct-order-note');n.textContent=text;n.classList.toggle('market-error',error);};
async function json(file,limit){check(file&&file.size<=limit);return JSON.parse(await file.text());}
function render() {
  const target=$('direct-order-providers'),oldUnits=new Map([...target.children].filter(n=>n.dataset.offer).map(n=>[n.dataset.offer,n.querySelector('[data-units]').value]));target.replaceChildren();
  if(!manifests.size){target.textContent='Search finalized offers, then add provider manifests for the complete job group.';return;}
  for(const [id,m]of manifests){const row=document.createElement('article');row.className='direct-provider';row.dataset.offer=id;
    const title=document.createElement('h4');title.textContent=m.resource.provider;
    const terms=document.createElement('p');terms.textContent=m.terms;
    const detail=document.createElement('p');detail.className='work-note';detail.textContent=`Offer ${id}. Available ${utc(Number(m.offer.start))} to ${utc(Number(m.offer.end))}. Gross rate ${formatUnits(m.offer.grossPerUnitSecond,18)} ${m.offer.escrow===configuration.nativeEscrow?'ETH':'Cannabis'} per unit-second. Policy ${m.offer.policyHash}.`;
    const label=document.createElement('label');label.textContent='Booked units';const units=document.createElement('input');units.type='number';units.min='1';units.max=m.offer.units;units.value=oldUnits.get(id)??'1';units.dataset.units='';label.append(units);
    const remove=document.createElement('button');remove.type='button';remove.textContent='Remove provider offer';remove.onclick=()=>{manifests.delete(id);render();};
    row.append(title,terms,detail,label,remove);target.append(row);
  }
}
export function setOrderMarket(value) {++epoch;configuration=value?marketConfiguration(value):null;observation=null;manifests.clear();
  for(const id of ['direct-order-start','direct-order-end','direct-order-accept','direct-order-deliver','direct-order-hold','direct-order-manager','direct-order-adjudicator','direct-order-job','direct-order-manifests'])$(id).value='';
  $('direct-order-builder').hidden=!configuration;render();note('A plan reserves no capacity and sends no payment.');}
export function retainOfferObservation(value){check(value?.schema==='cannabis.market-snapshot.v1'&&value.finality==='rpc-finalized');
  observation=structuredClone(value);for(const [id,m]of manifests)try{inspectProviderManifest(encodeProviderManifest(m).bytes,observation,id);}catch{manifests.delete(id);}render();}
export function initializeOrderForm(acceptPlan) {
  onPlan=acceptPlan;
  $('direct-order-manifests').addEventListener('change',async()=>{try{
    check(configuration&&observation);const version=epoch,snapshot=observation,files=[...$('direct-order-manifests').files];check(files.length>0&&files.length<=64);
    const added=new Map(manifests);
    for(const file of files) {
      const input=await json(file,131072);check(version===epoch&&snapshot===observation);let manifest=input;
      if(input.schema==='cannabis.market-plan-export.v1') {
        const p=prepareMarketPlan(configuration,input.plan);check(p.plan.kind==='offer'&&canonical(input.deployment)===canonical(p.deployment));manifest=p.plan.manifest;
      } else if(input.schema==='cannabis.market-plan.v1'){const p=prepareMarketPlan(configuration,input);check(p.plan.kind==='offer');manifest=p.plan.manifest;}
      const encoded=encodeProviderManifest(manifest),inspected=inspectProviderManifest(encoded.bytes,observation,manifest.offerId);
      check(inspected.manifest.chainId===configuration.chainId&&inspected.manifest.genesisHash===configuration.genesisHash&&inspected.manifest.market===configuration.market);
      added.set(manifest.offerId,inspected.manifest);check(added.size<=64);
    }
    manifests=added;render();const now=Math.floor(Date.now()/1000),all=[...manifests.values()];
    if(!$('direct-order-start').value){const start=Math.max(now+1800,...all.map(m=>Number(m.offer.start)));
      $('direct-order-start').value=utc(start);$('direct-order-end').value=utc(start+600);$('direct-order-accept').value=utc(start-120);
      $('direct-order-deliver').value=utc(start+1200);$('direct-order-hold').value=utc(Math.min(now+1500,start-60,...all.map(m=>Number(m.offer.expiresAt))));}
    note('Provider declarations match the observed chain. Review capacity, terms and the complete group before preparing.');
  }catch{note('Use manifests matching the current finalized offer search and selected deployment.',true);}});
  $('direct-order-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;
    try {
      check(configuration&&observation&&manifests.size);const version=epoch,snapshot=observation;
      const job=await json($('direct-order-job').files[0],8192);check(version===epoch&&snapshot===observation);const planned=publicOrderPlan(job);
      if(job.schema==='cannabis.compute.order.v3')throw Object.assign(Error('Preassigned bookings required'),
        {userMessage:'This job commits to specific task and worker bookings. Import the complete public market plan prepared by your compute client.'});
      const asset=$('direct-order-asset').value,escrow=asset==='ETH'?configuration.nativeEscrow:configuration.cannabisEscrow;
      const start=seconds($('direct-order-start').value),end=seconds($('direct-order-end').value),holdUntil=seconds($('direct-order-hold').value),now=Math.floor(Date.now()/1000);
      check(end>start&&start>now&&holdUntil>now&&holdUntil<=now+1800&&holdUntil<=start);
      const grossByProvider=new Map(),bookings=[];let total=0n;
      for(const [offerId,m]of manifests) {
        inspectProviderManifest(encodeProviderManifest(m).bytes,observation,offerId,now);
        check(m.offer.escrow===escrow&&m.offer.policyHash==='0x'+job.policySHA256&&start>=Number(m.offer.start)&&end<=Number(m.offer.end)&&holdUntil<=Number(m.offer.expiresAt));
        const row=[...$('direct-order-providers').children].find(n=>n.dataset.offer===offerId),units=row.querySelector('[data-units]').value;
        check(/^[1-9][0-9]{0,9}$/.test(units)&&BigInt(units)<=BigInt(m.offer.units));
        const gross=BigInt(m.offer.grossPerUnitSecond)*BigInt(end-start)*BigInt(units);total+=gross;
        grossByProvider.set(m.resource.provider,(grossByProvider.get(m.resource.provider)??0n)+gross);
        bookings.push({reservationId:nonce(),offerId,start:String(start),end:String(end),units,gross:gross.toString(),holdUntil:String(holdUntil)});
      }
      if(total!==BigInt(planned.payment.totalAtomic))throw Object.assign(Error('Budget differs'),{userMessage:`Provider bookings total ${formatUnits(total,18)} ${asset}; your public job commits to ${job.payment.totalBudget} ${asset}. Agree the terms and update the public job through your compute client before preparing.`});
      const workers=[...grossByProvider].sort(([a],[b])=>BigInt(a)<BigInt(b)?-1:BigInt(a)>BigInt(b)?1:0).map(([account,gross])=>{
        check(gross*10000n%total===0n);return {account,shareBps:Number(gross*10000n/total)};});
      const deliveryManager=getAddress($('direct-order-manager').value),adjudicator=getAddress($('direct-order-adjudicator').value);
      check(deliveryManager!==ZeroAddress&&adjudicator!==ZeroAddress);
      const settlement={workers,deliveryManager,adjudicator,acceptBy:utc(seconds($('direct-order-accept').value)),deliverBy:utc(seconds($('direct-order-deliver').value)),
        reviewSeconds:Number($('direct-order-review-hours').value)*3600,disputeSeconds:Number($('direct-order-dispute-hours').value)*3600};
      const prepared=prepareMarketPlan(configuration,{schema:'cannabis.market-plan.v1',kind:'order',asset,job,settlement,bookings});
      await onPlan(prepared.plan);note('Complete public order plan retained. Review it, share it with the providers for their holds, then review each wallet action separately.');
    }catch(error){note(error.userMessage??'The group, deadlines, agreed roles or exact budget do not match. Check the public job, provider terms and sum of gross bookings; no payment was requested.',true);}
    finally{button.disabled=false;}
  });
}
