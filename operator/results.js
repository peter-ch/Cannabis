const $=id=>document.getElementById(id),hex=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const labels={reserved:'Reserved · execution not dispatched',dispatched:'Execution outcome uncertain',receiving:'Incomplete encrypted result',
  sealed:'Complete archive · metadata recovery needed',complete:'Complete result · requester storage pending',
  acknowledged:'Requester stored the result',purging:'Retention cleanup in progress'};
const bytes=n=>n<1024?`${n} B`:n<1024**2?`${(n/1024).toFixed(1)} KiB`:`${(n/1024**2).toFixed(1)} MiB`;
let storage,connected=false,actionToken,working=false,refreshHost,selected,review,readSaved=false,page=0,listSignature;
const ready=()=>connected&&storage?.state==='available'&&actionToken&&!working&&storage.operation?.state!=='uploading';
const message=text=>{$('recovery-status').textContent=text;};
const save=(value,name)=>{
  const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
function controls() {
  for(const button of document.querySelectorAll('.result-action'))button.disabled=!ready()||button.dataset.allowed!=='true';
  $('review-delivery').disabled=!ready()||!selected||Boolean(review);
  $('delivery-access').disabled=!ready()||Boolean(review);
  $('confirm-delivery').disabled=!ready()||!review||!readSaved||Date.now()>=review.expiresAt||
    !storage.records.some(r=>r.id===review.id&&r.retryAvailable);
  $('save-read-access').disabled=!connected||!review;
  $('discard-delivery').disabled=working;$('close-delivery').disabled=working;
  $('cancel-upload').disabled=!connected||!actionToken||working||storage?.operation?.state!=='uploading';
}
export function setStorageConnected(value) {
  connected=value;if(!value)$('storage-status').textContent='Storage observation unavailable. Retained readings are stale; recovery controls are disabled.';
  controls();
}
async function control() {
  const response=await fetch('/api/control',{cache:'no-store',signal:AbortSignal.timeout(5000)});
  if(!response.ok)throw Error('Local controls unavailable');const value=await response.json();
  if(value.schema!=='cannabis.console-control.v1'||value.configured&&!hex(value.actionToken))throw Error('Invalid local controls');
  actionToken=value.configured?value.actionToken:null;controls();
}
async function post(route,body) {
  if(!connected||!actionToken||working)throw Error('Refresh the local console before using recovery controls.');
  working=true;controls();
  try {
    const response=await fetch('/api/results/'+route,{method:'POST',cache:'no-store',
      headers:{'Content-Type':'application/json','X-Cannabis-Console':actionToken},body:JSON.stringify(body),signal:AbortSignal.timeout(20000)});
    if(response.status===403){actionToken=null;void control().catch(()=>{});throw Error('The local control session changed. Review the action again.');}
    const value=await response.json();if(!response.ok)throw Error(value.error||'Recovery action unavailable.');return value;
  }catch(error){throw Error(error.name==='AbortError'||error.name==='TimeoutError'||error instanceof TypeError?
    'Action response unavailable. Refresh to see whether an upload started; retained results remain in storage.':error.message);}
  finally{working=false;controls();void refreshHost?.();}
}
function list() {
  const filter=$('result-filter').value,all=storage?.state==='available'?storage.records:[];
  const records=all.filter(r=>filter==='all'||filter==='recoverable'&&r.recoverable||filter==='uncertain'&&['dispatched','receiving'].includes(r.state)||filter==='acknowledged'&&r.state==='acknowledged');
  const pages=Math.max(1,Math.ceil(records.length/20));page=Math.min(page,pages-1);
  const visible=records.slice(page*20,page*20+20),signature=JSON.stringify([storage?.state,all.length,filter,page,visible]);
  if(signature!==listSignature) {
    listSignature=signature;
    const children=visible.map(r=>{
      const article=document.createElement('article');article.className='result-card';
      const title=document.createElement('h3');title.textContent=labels[r.state];
      const id=document.createElement('code');id.textContent=r.id;
      const usage=document.createElement('p');usage.textContent=`${bytes(r.reservedBytes)} reserved · ${bytes(r.receivedBytes)} received`;
      const retention=document.createElement('p');retention.textContent=r.deletionEligibleAt===null?
        r.recoverable?'Retained until the requester acknowledges storage.':'Reserved until the attempt can be safely reconciled.':
        `Retention ends ${new Date(r.deletionEligibleAt).toLocaleString()}. Cleanup is handled separately.`;
      const actions=document.createElement('div');actions.className='actions';
      const recover=document.createElement('button');recover.textContent='Verify and recover';recover.className='result-action';recover.dataset.allowed=String(r.recoverable);
      recover.addEventListener('click',async()=>{
        message('Checking the retained archive and recovery metadata…');
        try{const result=await post('recover',{id:r.id});message(`Recovery ready: ${bytes(result.ciphertextBytes)} verified against ${result.ciphertextSHA256}. The encrypted result remains retained.`);}
        catch(error){message(error.message);}
      });
      const retry=document.createElement('button');retry.textContent='Arrange another delivery';retry.className='result-action secondary';retry.dataset.allowed=String(r.retryAvailable);
      retry.addEventListener('click',async()=>{
        try{if(review)await post('discard-review',{reviewId:review.reviewId});clearReview();selected=r.id;
          $('delivery-panel').hidden=false;$('delivery-result').textContent=`Retained attempt ${r.id}`;
          $('delivery-access').value='';controls();$('delivery-access').focus();}
        catch(error){message(error.message);}
      });
      actions.append(recover,retry);article.append(title,id,usage,retention,actions);return article;
    });
    if(!children.length){const empty=document.createElement('p');empty.className='muted';empty.textContent=storage?.state==='available'?
      all.length?'No attempts match this filter.':'This result store contains no retained attempts.':'Select an existing result volume when starting the console to view its retained attempts.';children.push(empty);}
    $('result-list').replaceChildren(...children);
  }
  $('result-pages').hidden=records.length<=20;$('results-page').textContent=`Page ${page+1} of ${pages}`;
  $('results-previous').disabled=page===0;$('results-next').disabled=page===pages-1;controls();
}
function clearReview(){review=null;readSaved=false;$('delivery-review').hidden=true;controls();}
export function renderStorage(value) {
  if(!value||!['available','unavailable','not-configured'].includes(value.state))throw Error('Unsupported storage observation');
  if(value.state==='available'&&(!Array.isArray(value.records)||value.records.length>4096||
    value.records.some(r=>!hex(r.id)||!Object.hasOwn(labels,r.state))||!value.capacity))throw Error('Unsupported retained records');
  storage=value;$('storage-summary').hidden=$('storage-tools').hidden=value.state!=='available';
  if(value.state==='available') {
    $('storage-status').textContent='Retained result volume connected. Capacity and records come from the local store.';
    $('storage-used').textContent=`${bytes(value.capacity.reservedBytes)} / ${bytes(value.capacity.maxBytes)}`;
    $('storage-records').textContent=`${value.records.length} / ${value.capacity.maxRecords}`;
    $('storage-free').textContent=bytes(value.capacity.availableBytes);
    if(!actionToken)void control().catch(()=>message('Local controls unavailable; refresh to reconnect.'));
  }else $('storage-status').textContent=value.reason;
  const op=value.operation;$('upload-panel').hidden=!op;
  if(op) {
    const descriptions={uploading:'Uploading the retained encrypted result.',uploaded:'The relay reports a complete upload. Requester storage and acceptance remain pending.',
      cancelled:'Upload stopped. The retained result remains available.',failed:'Upload did not complete. The retained result remains available.'};
    $('upload-description').textContent=descriptions[op.state]+' '+op.origin;
    $('upload-progress').value=(op.uploadedBytes+op.reusedBytes)/op.totalBytes*100;
    $('upload-count').textContent=`${bytes(op.uploadedBytes)} sent · ${bytes(op.reusedBytes)} already present · ${bytes(op.totalBytes)} total`;
    $('cancel-upload').hidden=op.state!=='uploading';
  }
  list();controls();
}
export async function initializeStorage(refresh) {
  refreshHost=refresh;await control().catch(()=>{});
  $('result-filter').addEventListener('change',()=>{page=0;list();});
  $('results-previous').addEventListener('click',()=>{page--;list();});
  $('results-next').addEventListener('click',()=>{page++;list();});
  $('review-delivery').addEventListener('click',async()=>{
    try {
      const grants=JSON.parse($('delivery-access').value),value=await post('prepare-retry',{id:selected,grants});
      if(!hex(value.reviewId)||value.id!==selected||!Array.isArray(value.readAccess))throw Error('Invalid delivery review');
      review=value;readSaved=false;$('delivery-review').hidden=false;
      $('review-origin').textContent=value.origin;$('review-bytes').textContent=bytes(value.ciphertextBytes);
      $('review-hash').textContent=value.ciphertextSHA256;$('review-expiry').textContent=new Date(value.expiresAt).toLocaleString();
      message('Review the destination and save requester read access before uploading.');controls();
    }catch(error){message(error instanceof SyntaxError?'Paste the provider delivery access as JSON.':error.message);}
  });
  $('save-read-access').addEventListener('click',()=>{if(!review)return;save(review.readAccess,`cannabis-${review.id.slice(0,12)}-read-access.json`);readSaved=true;controls();});
  $('confirm-delivery').addEventListener('click',async()=>{
    try{if(!review||!readSaved)throw Error('Save requester read access first.');await post('start-retry',{reviewId:review.reviewId});
      clearReview();selected=null;$('delivery-access').value='';$('delivery-panel').hidden=true;message('Upload started. Keep the saved read-access file for the requester.');}
    catch(error){message(error.message);}
  });
  const discard=async close=>{
    try{if(review)await post('discard-review',{reviewId:review.reviewId});clearReview();
      if(close){selected=null;$('delivery-access').value='';$('delivery-panel').hidden=true;}message('Delivery review discarded. No new upload was started.');}
    catch(error){message(error.message);}
  };
  $('discard-delivery').addEventListener('click',()=>discard(false));$('close-delivery').addEventListener('click',()=>discard(true));
  $('cancel-upload').addEventListener('click',async()=>{
    try{await post('cancel-retry',{operationId:storage.operation.id});message('Stopping the upload; retained files will be kept.');}
    catch(error){message(error.message);}
  });
  setInterval(controls,1000);
}
