import {WorkflowWallet} from './workflow-wallet.js';
const $=id=>document.getElementById(id),token=location.hash.slice(1);history.replaceState(null,'',location.pathname);
const message=text=>{$('message').textContent=text;},wallet=new WorkflowWallet(()=>message('Wallet selection changed. Connect the intended account before approving.'));
const rows=new Map();let signing=false,readyShown=false;
async function api(route,body) {
  const response=await fetch('/api/'+route,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+token,...(body?{'Content-Type':'application/json'}:{})},
    body:body?JSON.stringify(body):undefined,cache:'no-store',credentials:'omit',redirect:'error'});
  if(!response.ok)throw Error('The local request was refused. Retain your recovery files.');return response.json();
}
$('connect').onclick=async()=>{try{wallet.select(window.ethereum);const accounts=await wallet.connect();message('Connected '+accounts[0]);}catch{message('Wallet connection unavailable. Open this local page in a browser with your wallet extension.');}};
$('start').onclick=async()=>{try{await api('start',{});$('start').disabled=true;message('Workflow started. Review each request below.');}catch(e){message(e.message);}};
const labels={peer:'Connect to the booked provider',dependency:'Approve the selected dependency input','key-release':'Release the input key to the verified guest',stored:'Acknowledge encrypted result storage'};
function addReview(review) {
  const div=document.createElement('div');div.className='request';
  const title=document.createElement('h3');title.textContent=labels[review.kind];div.append(title);
  const summary=document.createElement('p');summary.textContent='Booking '+review.reservationId+' · Account '+review.requester;div.append(summary);
  const detail=document.createElement('details'),label=document.createElement('summary'),pre=document.createElement('pre');label.textContent='Inspect the exact signature';
  pre.textContent=JSON.stringify(review.typedData,null,2);detail.append(label,pre);div.append(detail);
  const button=document.createElement('button');button.textContent='Review in wallet';button.onclick=async()=>{
    if(signing)return;signing=true;button.disabled=true;
    try {const current=await api('state'),selected=current.requests.find(r=>r.id===review.id);
      if(!selected||JSON.stringify(selected)!==JSON.stringify(review))throw Error('Approval changed or expired.');
      const signature=await wallet.sign(selected);await api('approve',{id:review.id,signature});message('Signature accepted.');
    }catch(e){message(e.message);}finally{signing=false;button.disabled=false;}
  };div.append(button);$('requests').append(div);rows.set(review.id,div);
}
async function refresh() {
  try {const state=await api('state');$('start').disabled=state.state!=='ready';
    $('start').textContent=state.mode==='recover'?'Recover retained result':'Start reviewed workflow';
    if(state.state==='ready'&&!readyShown){readyShown=true;message('Ready. Connect your wallet, then start when you are ready to review approvals.');}
    $('tasks').replaceChildren(...state.workflow.slots.map((slot,i)=>{const row=document.createElement('div');row.className='task';
      const title=document.createElement('strong');title.textContent='Booking '+(i+1)+' · '+({queued:'Waiting for its window and inputs',uncertain:'In progress or awaiting recovery',stored:'Encrypted result retained'}[slot.state]);
      const id=document.createElement('p');id.textContent=slot.reservationId;row.append(title,id);return row;}));
    for(const [id,row] of rows)if(!state.requests.some(r=>r.id===id)){row.remove();rows.delete(id);}
    for(const review of state.requests)if(!rows.has(review.id))addReview(review);
    if(state.state==='finished')message('Workflow run ended. Inspect the retained booking states before reconstruction or payment review.');
    if(state.state==='recovery-required')message('The run needs recovery. Retain the local workflow directory; no booking will be retried automatically.');
  }catch{message('Local workflow unavailable. Keep its directory for recovery.');}
  setTimeout(refresh,1000);
}
if(/^[0-9a-f]{64}$/.test(token))refresh();else{message('Open the private local URL printed by the workflow command.');$('start').disabled=true;}
