import {MarketWallet,validateMarketReview} from './market-wallet.js';
const $=id=>document.getElementById(id),short=s=>typeof s==='string'?s.slice(0,10)+'…'+s.slice(-6):'—';
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const when=s=>{const n=Number(s)*1000;return Number.isFinite(n)&&n>0&&n<8640000000000000?new Date(n).toISOString().replace('.000Z',' UTC'):'Unavailable';};
const amount=v=>{const n=BigInt(v),whole=n/10n**18n,fraction=(n%10n**18n).toString().padStart(18,'0').replace(/0+$/,'');return whole+(fraction?'.'+fraction:'');};
const titles={publishResource:'Publish resource',publishOffer:'Publish offer',withdrawOffer:'Withdraw offer',signBooking:'Sign provider hold',reserveBatch:'Reserve the complete group',
  approveToken:'Approve exact Cannabis allowance',fund:'Fund the job',accept:'Accept as provider',activate:'Activate booked group',cancel:'Cancel unaccepted funding',
  withdrawWorker:'Withdraw earned worker payment',withdrawCredit:'Withdraw available credit'};
let token,configured=false,connected=false,busy=false,refresh,state,plan,review,phase,controller,activeRequest,selectedPlan='',historyKey='',planKey='';
let marketAdapter=null,controlEpoch=0;
const choices=[],seen=new WeakSet();
const wallet=new MarketWallet(()=>{
  if(['sign','send'].includes(phase))controller?.abort();
  $('market-account').replaceChildren(new Option('Connect to select an account',''));
  $('market-wallet-status').textContent='Wallet selection or account changed. Connect and review again.';forgetReview();controls();
});
const message=(text,error=false)=>{const node=$('market-action-status');node.textContent=text;node.classList.toggle('market-error',error);};
function controls() {
  const ready=configured&&connected&&!busy;
  for(const node of $('market-content').querySelectorAll('button,input,select'))node.disabled=!ready;
  $('market-connect').disabled=!ready||!choices.length||$('market-wallet').value==='';
  $('market-account').disabled=!ready||!wallet.accounts.length;
  for(const id of ['market-inspect','market-export'])$(id).disabled=!ready||!plan;
  $('market-confirm').disabled=!ready||!review||Date.now()>=review.expiresAt||!wallet.accounts.includes(review.action.actor)||$('market-account').value!==review.action.actor;
  $('market-cancel-review').disabled=!connected||!review||phase==='send';
  for(const node of $('market-plan-actions').querySelectorAll('button'))node.disabled=!ready||!$('market-account').value;
}
async function api(name,body={}) {
  if(!configured||!connected||!token)throw Error('The selected market is unavailable. Refresh the console.');
  const epoch=controlEpoch;
  if(marketAdapter){const result=await marketAdapter.call(name,body);if(epoch!==controlEpoch)throw Error('Market selection changed. Review again.');return result;}
  const response=await fetch('/api/market/'+name,{method:'POST',headers:{'Content-Type':'application/json','X-Cannabis-Console':token},
    body:JSON.stringify(body),signal:AbortSignal.timeout(5000)});
  if(!response.ok)throw Error('The selected action is unavailable. Check the plan, current state and retained transaction records.');
  const result=await response.json();if(epoch!==controlEpoch)throw Error('Market selection changed. Review again.');return result;
}
async function poll(requestId) {
  activeRequest=requestId;const start=performance.now();
  while(performance.now()-start<65000) {
    if(controller?.signal.aborted)throw Error('Action cancelled. Check retained state before trying again.');
    const value=await api('detail',{requestId});
    if(!['running','rechecking','checking-signature'].includes(value.state)) {
      activeRequest=null;if(['failed','expired','cancelled'].includes(value.state))throw Error(value.error??'The review expired or was cancelled. Refresh current state.');
      return value;
    }
    await new Promise(resolve=>setTimeout(resolve,600));
  }
  throw Error('Observation timed out. Refresh retained state; no new wallet request was made by this timeout.');
}
async function run(action) {
  if(busy)return;busy=true;controller=new AbortController();controls();
  try{await action();}
  catch(error){message(error.message||'The action could not be verified. Preserve recovery state.',true);}
  finally{busy=false;phase=null;controller=null;activeRequest=null;controls();await refresh?.();}
}
function save(name,value) {
  const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'}));
  const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function saveRecovery(actionId,fallback) {
  if(marketAdapter?.recovery)save('cannabis-market-recovery.json',await marketAdapter.recovery());
  else save('cannabis-transaction-recovery-'+actionId+'.json',fallback??await api('action',{actionId}));
}
function forgetReview(){review=undefined;$('market-review').hidden=true;}
function entries(target,items) {
  target.replaceChildren();for(const [label,value] of items){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=String(value);target.append(dt,dd);}
}
function card(title,lines) {
  const node=document.createElement('article');node.className='market-item';const h=document.createElement('h4');h.textContent=title;node.append(h);
  for(const line of lines){const p=document.createElement('p');p.textContent=line;node.append(p);}return node;
}
function button(label,action){const b=document.createElement('button');b.type='button';b.textContent=label;b.addEventListener('click',()=>run(action));return b;}
function showReview(value) {
  review=validateMarketReview(value);const a=review.action,s=a.summary,d=review.deployment;
  $('market-review').hidden=false;$('market-review-title').textContent=titles[a.method];
  const list=[['Account',a.actor],['Chain',d.chainId],['Genesis',d.genesisHash],['Market',d.market],['Review expires',new Date(review.expiresAt).toLocaleTimeString()]];
  if(s.grossBaseUnits)list.push(['Job budget',amount(s.grossBaseUnits)+' '+s.asset],['Workers',amount(s.workerBaseUnits)+' '+s.asset],
    ['Included service fee (1%)',amount(s.serviceFeeBaseUnits)+' '+s.asset],['Escrow',s.escrow],['Order',s.orderId]);
  if(a.kind==='transaction')list.push(['Destination',a.transaction.to],['Maximum network fee',amount(review.quote.maximumGasWei)+' ETH'],
    ['Native value',amount(review.quote.nativeValueWei)+' ETH'],['Maximum total for this action',amount(review.quote.maximumTotalWei)+' ETH'],['Account nonce',BigInt(a.transaction.nonce).toString()]);
  else list.push(['Booking',a.bookingId],['Requester',a.typedData.message.requester],['Hold expires',when(a.typedData.message.holdUntil)]);
  entries($('market-review-summary'),list);
  $('market-review-json').textContent=JSON.stringify(a.kind==='signature'?a.typedData:{transaction:a.transaction,publicTerms:a.summary},null,2);
  $('market-review-note').textContent=a.kind==='signature'?'This signs the selected public hold. It sends no transaction and reserves no capacity by itself.':
    'Only this action is priced. Intermediate steps use the current canonical head and can be reorganized; they may not be finalized. Complete activation before the hold expires. After every provider accepts, immediate cancellation is unavailable. Protected execution still requires finalized activation. A recovery download is requested before the wallet prompt; keep your downloaded copy. Cancellation or a timeout cannot revoke the prompt.';
  $('market-confirm').textContent=a.kind==='signature'?'Review and sign in wallet':'Review and submit in wallet';controls();
}
async function begin(method,bookingId=null) {
  forgetReview();const signer=$('market-account').value;if(!signer||!plan)throw Error('Select a connected account and a retained plan.');
  message('Checking current contracts, booking state and costs…');const request=await api('begin',{planId:plan.id,method,bookingId,signer});
  const result=await poll(request.requestId);if(result.state!=='awaiting-wallet')throw Error('A wallet review was not prepared.');showReview(result.result);
  message('Review the exact parties, terms and maximum cost before opening the wallet.');
}
function renderPlan(value) {
  plan=value;selectedPlan=value.id;$('market-plan').value=value.id;forgetReview();$('market-plan-json').textContent=JSON.stringify(value.plan,null,2);
  const p=value.plan,d=value.detail,target=$('market-plan-detail'),actions=$('market-plan-actions');target.replaceChildren();actions.replaceChildren();
  if(p.kind==='resource') {
    target.append(card('Declared resource',[`Provider: ${p.provider}`,`Resource: ${d.resource}`,`Declared units: ${p.units}`]));
    actions.append(button(titles.publishResource,()=>begin('publishResource')));
  } else if(p.kind==='offer') {
    target.append(card('Public offer plan',[`Provider: ${p.provider}`,`Offer: ${d.offerId}`,`Declared units: ${d.offer.units}`,
      `Gross rate: ${amount(d.offer.grossPerUnitSecond)} ${d.offer.escrow===state.deployment.nativeEscrow?'ETH':'Cannabis'} per unit-second`,
      `${when(d.offer.start)} — ${when(d.offer.end)}`,p.manifest.terms]));
    actions.append(button(titles.publishOffer,()=>begin('publishOffer')),button(titles.withdrawOffer,()=>begin('withdrawOffer')));
  } else {
    target.append(card('Order plan',[`Requester: ${d.requester}`,`Order: ${d.orderId}`,`Budget: ${amount(d.terms.budget)} ${p.asset}; includes exactly 1% service fee.`,
      'Sequence: provider hold signatures → reservation → funding → every provider accepts → group activation. Execution still needs confidential admission.']));
    for(const b of d.bookings){const row=card('Provider hold '+short(b.bookingId),[`Offer: ${b.value.offerId}`,`Gross: ${amount(b.value.gross)} ${p.asset}`,
      `Interval: ${when(b.value.start)} — ${when(b.value.end)}`,value.signatures?.[b.bookingId]?'A signature is retained; it is rechecked when reserving.':'Awaiting the booked provider signature.']);
      row.append(button('Review provider signature',()=>begin('signBooking',b.bookingId)));target.append(row);}
    for(const method of ['reserveBatch',...(p.asset==='Cannabis'?['approveToken']:[]),'fund','accept','activate','cancel','withdrawWorker','withdrawCredit'])
      actions.append(button(titles[method],()=>begin(method)));
  }
  controls();
}
async function inspectSelected() {
  if(!plan)throw Error('Select a retained plan.');const response=await api('inspect',{planId:plan.id}),result=(await poll(response.requestId)).result;
  const target=$('market-plan-detail');const existing=target.querySelector('[data-current-state]');existing?.remove();
  const lines=[`Finalized block: ${result.finalizedBlock.number} (${short(result.finalizedBlock.hash)})`];
  if(result.order){lines.push(`Finalized escrow state: ${result.order.state}`,`Current head state: ${result.headState.order.state} at block ${result.headBlock.number} (may not be finalized)`,
      `Accepted providers at current head: ${result.headState.order.order.acceptedCount} / ${result.headState.order.order.workerCount}`);
    for(const w of result.order.workers)lines.push(`${w.account}: ${w.accepted?'accepted':'not accepted'}; ${amount(w.dueBaseUnits)} ${plan.plan.asset} currently withdrawable${w.withdrawn?' (withdrawal recorded)':''}.`);
    if(result.tokenAllowanceBaseUnits!==null)lines.push('Existing token allowance: '+amount(result.tokenAllowanceBaseUnits)+' Cannabis.');
    lines.push('A cancelled funded order creates a credit; withdrawing that credit is a separate wallet action.');
  } else if(Object.hasOwn(result,'offer'))lines.push(result.offer?result.offer.withdrawn?'Offer withdrawn.':'Offer observed on the selected chain.':'This offer has not been observed on the finalized chain.');
  else lines.push(result.resource.provider==='0x0000000000000000000000000000000000000000'?'Resource has not been published.':'Resource declaration observed.');
  const panel=card('Current chain observation',lines);panel.dataset.currentState='';target.prepend(panel);message('Chain state refreshed. A later wallet action will check it again.');
}
function renderHistory(actions) {
  const key=JSON.stringify(actions.map(a=>[a.id,a.state,a.updatedAt]));if(key===historyKey)return;historyKey=key;
  const target=$('market-history');target.replaceChildren();if(!actions.length){target.append(card('No transaction handoffs retained',[]));return;}
  for(const a of actions){const row=card(titles[a.method]??a.method,[`State: ${a.state}`,`Account: ${a.actor}`,`Recovery record: ${a.id}`,
    a.transactionHash?'Transaction: '+a.transactionHash:'No transaction hash retained. Inspect the selected wallet before trying another transaction.',...(a.walletOutcome?[a.walletOutcome]:[])]);
    if(a.observation?.gasPaidWei)row.append(card('Observed cost',[amount(a.observation.gasPaidWei)+' ETH network fee',`Observed state: ${a.observation.state}`]));
    row.append(button('Save recovery record',()=>saveRecovery(a.id)));
    if(!['confirmed','reverted'].includes(a.state)) {
      if(!a.transactionHash||['hash-reported','not-observed'].includes(a.state)){const label=document.createElement('label');label.textContent='Transaction hash from your wallet';const input=document.createElement('input');input.maxLength=66;input.placeholder='0x…';input.value=a.transactionHash??'';label.append(input);row.append(label);
        row.append(button('Retain this transaction hash',async()=>{await api('report-hash',{actionId:a.id,transactionHash:input.value.trim().toLowerCase()});message('Transaction hash retained. Check its canonical receipt next.');}));}
      if(a.transactionHash)row.append(button('Check canonical receipt',async()=>{const r=await api('observe',{actionId:a.id});await poll(r.requestId);message('Transaction observation updated.');}));
    }
    target.append(row);
  }
}
export function renderMarket(value) {
  state=value;configured=Boolean(value?.schema==='cannabis.market-console-state.v1'&&value.state==='configured');$('market-content').hidden=!configured;
  $('market-status').textContent=configured?`Selected chain ${value.deployment.chainId}. Market ${value.deployment.market}. RPC-reported finality; no confidential admission is inferred.`:
    value?.reason??'No reviewed market is configured.';
  if(!configured){forgetReview();controls();return;}
  const key=JSON.stringify(value.plans);if(key!==planKey){planKey=key;const select=$('market-plan');select.replaceChildren(new Option('Choose a retained plan',''));
    for(const p of value.plans)select.append(new Option(`${p.kind} · ${short(p.id)} · ${short(p.actor)}`,p.id));select.value=selectedPlan;}
  renderHistory(value.actions);controls();
}
export function setMarketConnected(value) {connected=value;if(!value&&['sign','send'].includes(phase))controller?.abort();controls();}
function addWallet(info,provider) {
  if(!provider||!['object','function'].includes(typeof provider)||seen.has(provider)||choices.length>=16||
    typeof provider.request!=='function'||typeof provider.on!=='function'||typeof provider.removeListener!=='function')return;
  seen.add(provider);const name=typeof info?.name==='string'?info.name.slice(0,80):'Injected wallet';choices.push(provider);
  $('market-wallet').append(new Option(name,String(choices.length-1)));controls();
}
export function setMarketControl(c) {
  ++controlEpoch;controller?.abort();
  token=c?.actionToken;configured=Boolean(c?.market);
  if(!configured){wallet.clear();$('market-wallet').value='';plan=null;selectedPlan='';planKey='';historyKey='';forgetReview();}
  controls();
}
export function loadMarketPlan(value){renderPlan(value);}
export async function initializeMarket(refreshStatus,{adapter=null}={}) {
  refresh=refreshStatus;marketAdapter=adapter;
  try{const c=adapter?await adapter.control():await(await fetch('/api/control',{signal:AbortSignal.timeout(5000)})).json();setMarketControl(c);}catch{}
  window.addEventListener('eip6963:announceProvider',event=>addWallet(event.detail?.info,event.detail?.provider));window.dispatchEvent(new Event('eip6963:requestProvider'));
  if(window.ethereum)addWallet({name:'Legacy injected wallet'},window.ethereum);
  $('market-wallet').addEventListener('change',()=>{const selected=choices[Number($('market-wallet').value)];if($('market-wallet').value!==''&&selected)wallet.select(selected);else wallet.clear();controls();});
  $('market-account').addEventListener('change',()=>{forgetReview();controls();});
  $('market-connect').addEventListener('click',()=>run(async()=>{phase='connect';const accounts=await wallet.connect(controller.signal);
    $('market-account').replaceChildren(...accounts.map(a=>new Option(a,a)));$('market-wallet-status').textContent='Connected. Every signature and transaction requires your explicit wallet review.';}));
  $('market-network').addEventListener('click',()=>run(async()=>{const r=await api('network'),v=(await poll(r.requestId)).result;
    $('market-network-status').textContent=`Finalized block ${v.finalizedBlock.number}; head ${v.headBlock.number}. Runtime and fee bindings observed.`;
    $('market-to').value=String(v.finalizedBlock.number);$('market-from').value=String(Math.max(0,v.finalizedBlock.number-255));message('Selected deployment observed.');}));
  $('market-discover').addEventListener('submit',event=>{event.preventDefault();run(async()=>{const r=await api('offers',{fromBlock:Number($('market-from').value),toBlock:Number($('market-to').value)}),v=(await poll(r.requestId)).result;
    const target=$('market-offers');target.replaceChildren();for(const item of v.offers)target.append(card(short(item.offerId),[`Provider: ${item.resource.provider}`,
      `Declared units: ${item.offer.units}; gross rate: ${amount(item.offer.grossPerUnitSecond)} ${item.offer.escrow===state.deployment.nativeEscrow?'ETH':item.offer.escrow===state.deployment.cannabisEscrow?'Cannabis':item.offer.escrow} per unit-second.`,
      `${when(item.offer.start)} — ${when(item.offer.end)}`,item.withdrawn?'Withdrawn':item.expiredAtSnapshot?'Expired at this observation':'Published declaration; hardware and fulfillment remain unverified.']));
    if(!v.offers.length)target.append(card('No offers in this finalized block range',[]));await marketAdapter?.offers?.(v);message('Offer search completed.');});});
  $('market-new-resource-id').addEventListener('click',()=>{$('market-resource-id').value='0x'+Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');});
  $('market-resource').addEventListener('submit',event=>{event.preventDefault();run(async()=>{const provider=$('market-account').value;if(!provider)throw Error('Select your connected provider account.');
    renderPlan(await api('import',{plan:{schema:'cannabis.market-plan.v1',kind:'resource',provider,resourceId:$('market-resource-id').value.trim().toLowerCase(),
      serviceHash:$('market-service-hash').value.trim().toLowerCase(),units:$('market-units').value}}));message('Public resource plan retained. Publishing still requires your wallet approval.');});});
  $('market-import').addEventListener('change',()=>run(async()=>{const file=$('market-import').files?.[0];if(!file||file.size>131072)throw Error('Select a public market plan of at most 128 KiB.');
    const input=JSON.parse(await file.text());let p=input,signatures=[];
    if(input.schema==='cannabis.market-plan-export.v1'){if(canonical(input.deployment)!==canonical(state.deployment))throw Error('The shared plan targets a different reviewed deployment.');p=input.plan;signatures=input.signatures;}
    const retained=await api('import',{plan:p});renderPlan(retained);
    if(!Array.isArray(signatures)||signatures.length>64)throw Error('Invalid shared signature list. The public plan was retained without those signatures.');
    for(const s of signatures){const r=await api('import-signature',{planId:retained.id,bookingId:s.bookingId,signer:s.signer,signature:s.signature});await poll(r.requestId);}
    renderPlan(await api('plan',{planId:retained.id}));message('Public plan retained. Shared signatures were independently checked where supplied.');}));
  $('market-plan').addEventListener('change',()=>run(async()=>{const id=$('market-plan').value;if(!id){plan=null;selectedPlan='';forgetReview();return;}renderPlan(await api('plan',{planId:id}));await inspectSelected();}));
  $('market-inspect').addEventListener('click',()=>run(inspectSelected));
  $('market-export').addEventListener('click',()=>run(async()=>save('cannabis-public-market-plan-'+plan.id+'.json',await api('export',{planId:plan.id}))));
  $('market-cancel-review').addEventListener('click',()=>{const id=review?.id;controller?.abort();forgetReview();if(id)api('cancel',{requestId:id}).catch(()=>{});controls();message('Review discarded. Dismiss any open wallet prompt.');});
  $('market-confirm').addEventListener('click',()=>run(async()=>{const retained=validateMarketReview(review);if($('market-account').value!==retained.action.actor)throw Error('Account changed; review again.');
    if(retained.action.kind==='signature') {phase='sign';const signature=await wallet.sign(retained,controller.signal);phase=null;
      const r=await api('signature',{requestId:retained.id,signature});await poll(r.requestId);renderPlan(await api('plan',{planId:retained.planId}));
      message('Provider signature checked and retained. Save the shareable plan for the requester.');
    } else {
      const r=await api('handoff',{requestId:retained.id}),response=await poll(r.requestId);if(response.state!=='handed-off')throw Error('No wallet handoff was retained.');
      const handoff=response.result;await saveRecovery(handoff.id,handoff);phase='send';
      const outcome=await wallet.send(retained,handoff,controller.signal);phase=null;forgetReview();
      if(outcome.walletRefused){await api('wallet-refused',{actionId:handoff.id});message('Wallet reported rejection. The record is retained; a later attempt needs a new explicit review.');}
      else {await api('report-hash',{actionId:handoff.id,transactionHash:outcome.transactionHash});message('Transaction hash retained. Check its canonical receipt; wallet submission alone is not confirmation.');}
    }
  }));
  setInterval(()=>{if(review&&Date.now()>=review.expiresAt&&!busy){forgetReview();message('Wallet review expired. Request a fresh state and cost review.');}controls();},1000);
  controls();
}
