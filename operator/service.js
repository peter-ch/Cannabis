const $=id=>document.getElementById(id);
let control,report,connected=false,pending=false,refresh;
const states={stopped:'Stopped',starting:'Checking host and starting',listening:'Booked listener open',stopping:'Stopping sessions',
  failed:'Startup or listener unavailable','reconciliation-required':'Local reconciliation required'};
const phases={'awaiting-requester':'Awaiting requester handoff','starting-vm':'Starting selected VM','staging-guest':'Staging retained guest',
  'relaying-encrypted-session':'Relaying encrypted session','awaiting-vm-stop':'Awaiting VM shutdown','local-session-finished':'Local session finished',
  stopping:'Stopping','failed-local-tree-stopped':'Failed · local tree stopped','failed-cleanup-unknown':'Failed · cleanup unverified'};
function buttons(){const ready=connected&&!pending&&control?.operatorService;
  $('service-start').disabled=!(ready&&report?.canStart);$('service-stop').disabled=!(ready&&report?.canStop);}
export function setServiceConnected(value){connected=value;buttons();
  if(!value&&report?.state!=='not-configured')$('service-connection').textContent='Lifecycle readings are stale. Reconnect to control the service; closing this page does not stop sessions.';
  else $('service-connection').textContent='';}
export function renderService(value){report=value;const configured=value&&value.state!=='not-configured';
  $('service-tools').hidden=!configured;$('service-details').hidden=!configured;
  $('service-state').textContent=configured?(states[value.state]??'Unavailable'):'Service not configured';
  $('service-reason').textContent=value?.reason??'No operator lifecycle report is available.';
  if(configured){$('service-peer').textContent=value.peerOrigin;$('service-relay').textContent=value.relayOrigin;
    $('service-relay-state').textContent=value.relayListening?'Listening for encrypted delivery':'Stopped';
    $('service-channels').textContent=String(value.listener?.authenticatedChannels??0);
    $('service-sessions').replaceChildren(...(value.sessions??[]).map(row=>{const article=document.createElement('article');
      const title=document.createElement('h3'),id=document.createElement('p'),state=document.createElement('p'),cleanup=document.createElement('p');
      title.textContent=phases[row.phase]??'Session state unavailable';id.className='muted service-id';id.textContent=`Assignment ${row.assignmentId}`;
      state.textContent=`${row.active?'Active':'Ended'} · ${new Date(row.startedAt).toLocaleString()}`;
      cleanup.textContent=row.localTreeStopped?'Local process tree stopped. Protected key retirement and paid acceptance are not verified.':
        'Local process cleanup has not been verified. Preserve dispatch and result recovery state.';
      article.append(title,id,state,cleanup);return article;}));
    $('service-empty').hidden=Boolean(value.sessions?.length);
    const rows=value.assignments??[];$('service-assignments').textContent=`${rows.filter(r=>r.consentRetained&&!r.expired&&r.dispatch==='unused').length} retained approved assignments eligible for connection checks · ${rows.length} selected`;
  }buttons();}
async function action(name){if(!connected||pending||!control?.operatorService)return;pending=true;buttons();
  $('service-action').textContent=name==='start'?'Starting checks…':'Requesting stop…';
  try{const response=await fetch('/api/service/'+name,{method:'POST',headers:{'Content-Type':'application/json','x-cannabis-console':control.actionToken},
    body:'{}',signal:AbortSignal.timeout(5000)});if(!response.ok)throw Error();
    $('service-action').textContent=name==='start'?'Start requested. Follow the lifecycle and provider approval panels.':'Stop requested. Await checked cleanup in the lifecycle panel.';
  }catch{$('service-action').textContent='The action could not be confirmed. Refresh lifecycle status before retrying.';}
  finally{pending=false;await refresh();buttons();}}
export async function initializeService(update){refresh=update;
  try{const r=await fetch('/api/control',{cache:'no-store',signal:AbortSignal.timeout(5000)});if(!r.ok)throw Error();
    const value=await r.json();if(value.schema!=='cannabis.console-control.v1')throw Error();control=value;}catch{control=null;}
  $('service-start').addEventListener('click',()=>action('start'));$('service-stop').addEventListener('click',()=>action('stop'));buttons();}
