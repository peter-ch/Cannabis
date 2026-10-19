import {ProviderWallet,validateProviderReview} from './provider-wallet.js';
const $=id=>document.getElementById(id),short=v=>v.slice(0,10)+'…'+v.slice(-6);
let token,configured=false,connected=false,refresh,review,signing=false,phase,controller;
const choices=[],seen=new WeakSet();
const wallet=new ProviderWallet(()=>{
  if(phase==='sign')controller?.abort();$('provider-wallet-status').textContent='Wallet selection or account changed. Connect and review again.';controls();
});
function message(text){$('provider-action-status').textContent=text;}
function controls() {
  $('provider-connect').disabled=!configured||!connected||!choices.length||signing;
  $('provider-wallet').disabled=signing;
  $('provider-sign').disabled=!connected||signing||!review||Date.now()>=review.expiresAt||!wallet.accounts.includes(review.signer.toLowerCase());
  $('provider-decline').disabled=!connected||!review;
}
async function action(name,body) {
  if(!connected||!token)throw Error('Local approval controls are unavailable.');
  const response=await fetch('/api/provider/'+name,{method:'POST',headers:{'Content-Type':'application/json','X-Cannabis-Console':token},
    body:JSON.stringify(body),signal:AbortSignal.timeout(5000)});
  if(!response.ok)throw Error('Approval unavailable. Refresh the assignment and review again.');return response.json();
}
function addWallet(info,provider) {
  if(!provider||!['object','function'].includes(typeof provider)||seen.has(provider)||choices.length>=16||
    typeof provider.request!=='function'||typeof provider.on!=='function'||typeof provider.removeListener!=='function')return;
  seen.add(provider);const name=typeof info?.name==='string'?info.name.slice(0,80):'Injected wallet';
  choices.push({provider,name});const option=document.createElement('option');option.value=String(choices.length-1);option.textContent=name;
  $('provider-wallet').append(option);controls();
}
function forgetReview() {controller?.abort();review=undefined;$('provider-review').hidden=true;controls();}
function showReview(value) {
  forgetReview();review=validateProviderReview(value);$('provider-review').hidden=false;
  $('provider-review-kind').textContent=review.kind==='launch'?'Approve this retained launch assignment':'Approve this live peer connection';
  const m=review.typedData.message,d=review.typedData.domain,s=review.summary;
  const entries=[['Provider',review.signer],['Requester',m.requester],['Chain ID',BigInt(d.chainId).toString()],['Genesis block',review.genesisHash],
    ['Booking market',d.verifyingContract],['Escrow',s.escrow],['Payment asset',s.token==='0x0000000000000000000000000000000000000000'?'ETH (native)':s.token],
    ['Booked gross / worker / service fee (base units)',`${s.grossBaseUnits} / ${s.workerBaseUnits} / ${s.serviceFeeBaseUnits}`],
    ['Service interval',`${new Date(Number(m.validFrom)*1000).toISOString()} → ${new Date(Number(m.validUntil)*1000).toISOString()}`],
    ['Peer origin',s.origin],['Booking',m.bookingId],['Configuration',m.configurationSHA256],['Assignment',m.assignmentSHA256],
    ['Resource / units',`${s.resourceId} / ${s.units}`],['Service commitment',s.serviceSHA256],['Runtime commitment',s.runtimeSHA256],
    ['Task / attempt / rank',`${s.taskSHA256} / ${s.attempt} / ${s.rank} of ${s.worldSize}`],['Approval digest',review.digest],
    ['Review deadline',new Date(review.expiresAt).toLocaleTimeString()]];
  $('provider-review-details').replaceChildren(...entries.flatMap(([title,value])=>{
    const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=title;dd.textContent=value;return [dt,dd];
  }));
  $('provider-typed-data').textContent=JSON.stringify(review.typedData,null,2);controls();
}
export function renderProvider(value) {
  configured=value?.state==='available';$('provider-status').textContent=configured?
    `${value.assignments.length} retained assignment(s). Signatures do not admit execution or release customer keys.`:
    'No retained provider assignments are selected. Wallet controls are unavailable.';
  $('provider-tools').hidden=!configured;
  if(!configured){forgetReview();return;}
  if(review&&!value.requests.some(r=>r.id===review.id&&r.state==='awaiting-wallet'))forgetReview();
  $('provider-assignments').replaceChildren(...value.assignments.map(a=>{
    const row=document.createElement('article'),title=document.createElement('h3'),state=document.createElement('p'),button=document.createElement('button');
    title.textContent=`Booking ${short(a.bookingId)}`;state.textContent=`Provider ${a.provider} · Chain ${a.chainId} · ${a.consentRetained?'Consent retained':'Consent required'}`;
    button.textContent=a.consentRetained?'Consent retained':'Prepare launch approval';
    button.disabled=!connected||a.consentRetained||value.requests.some(r=>r.assignmentId===a.id&&['checking-funding','awaiting-wallet','checking-signature','submitted'].includes(r.state))||a.validUntil*1000<=Date.now();
    button.onclick=async()=>{button.disabled=true;try{await action('begin',{assignmentId:a.id});message('Checking the retained booking and funding before review.');}
      catch{message('Could not prepare this assignment. Keep its retained files and refresh.');}finally{await refresh();}};
    row.append(title,state,button);return row;
  }));
  $('provider-requests').replaceChildren(...value.requests.slice().reverse().map(r=>{
    const row=document.createElement('article'),description=document.createElement('p');
    description.textContent=`${r.kind==='launch'?'Launch consent':'Live peer approval'} · ${r.state.replaceAll('-',' ')} · ${short(r.assignmentId)}`;row.append(description);
    if(r.state==='awaiting-wallet'){
      const button=document.createElement('button');button.textContent='Review approval';button.disabled=!connected||signing;
      button.onclick=async()=>{try{showReview(await action('review',{requestId:r.id}));message('Review the complete commitment before opening your wallet.');}
        catch{forgetReview();message('This request is no longer available for review.');}};row.append(button);
    }return row;
  }));controls();
}
export function setProviderConnected(value){connected=value;if(!value){forgetReview();message('Local monitor disconnected. Pending wallet responses will be discarded.');}controls();}
export async function initializeProvider(onRefresh) {
  refresh=onRefresh;
  window.addEventListener('eip6963:announceProvider',event=>addWallet(event.detail?.info,event.detail?.provider));
  window.dispatchEvent(new Event('eip6963:requestProvider'));
  // Give announcing providers priority; legacy injection remains an explicit choice.
  setTimeout(()=>{if(window.ethereum)addWallet({name:'Injected wallet (legacy)'},window.ethereum);},300);
  $('provider-wallet').onchange=()=>{wallet.clear();forgetReview();};
  $('provider-connect').onclick=async()=>{
    try{const choice=choices[Number($('provider-wallet').value)];if(!choice)throw Error();
      wallet.select(choice.provider);controller=new AbortController();signing=true;phase='connect';controls();
      const accounts=await wallet.connect(controller.signal);$('provider-wallet-status').textContent=`Connected: ${accounts.join(', ')}`;
    }catch{message('Wallet connection unavailable or changed. Select a wallet and try again.');}
    finally{signing=false;phase=undefined;controller=undefined;controls();}
  };
  $('provider-sign').onclick=async()=>{
    if(!review||signing)return;const retained=review;controller=new AbortController();signing=true;phase='sign';controls();
    try{const signature=await wallet.sign(retained,controller.signal);
      if(review?.id!==retained.id||!connected||Date.now()>=retained.expiresAt)throw Error();
      await action('submit',{requestId:retained.id,signature});forgetReview();message('Signature submitted. Wait for independent chain or peer verification.');
    }catch{message('Approval was cancelled, changed or unavailable. Dismiss any stale wallet prompt and review again.');}
    finally{signing=false;phase=undefined;controller=undefined;controls();await refresh();}
  };
  $('provider-decline').onclick=async()=>{
    const selected=review;forgetReview();try{if(selected)await action('decline',{requestId:selected.id});message('Approval declined. Dismiss any open wallet prompt.');}
    catch{message('The request already changed. Any pending wallet response was discarded.');}await refresh();
  };
  try{const response=await fetch('/api/control',{cache:'no-store',signal:AbortSignal.timeout(5000)});if(response.ok){const data=await response.json();
    if(data.schema==='cannabis.console-control.v1'&&data.providerApprovals===true&&/^[0-9a-f]{64}$/.test(data.actionToken))token=data.actionToken;}}
  catch{message('Local controls unavailable. Reload once the console is reachable.');}
  setInterval(()=>{if(review&&Date.now()>=review.expiresAt){forgetReview();message('Review expired. Dismiss any pending wallet prompt.');}controls();},500);
}
