import {MarketController} from '../operator/market-controller.mjs';
import {marketConfiguration,deployment,sha,check} from '../operator/market-plan.mjs';
import {inspectMarketNetwork} from '../operator/market-chain.mjs';
import {BrowserMarketJournal} from './market-journal.js';
import {initializeMarket,renderMarket,setMarketConnected,setMarketControl,loadMarketPlan} from '../operator/market.js';
import {initializeOrderForm,setOrderMarket,retainOfferObservation} from './market-order-form.js';
const $=id=>document.getElementById(id);
let candidate=null,client=null,journal=null,opening=false,generation=0,selectionGeneration=0,connectionAbort=null;
const say=text=>{$('direct-market-message').textContent=text;};
const control=()=>({market:Boolean(client),actionToken:client?'local-browser-control':null});
function controls(){for(const id of ['direct-market-open','direct-market-new','direct-market-restore'])$(id).disabled=!candidate||opening||Boolean(client);
  $('direct-market-close').disabled=!client&&!opening;$('direct-market-backup').disabled=!client;}
function save(value){const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'}));
  const link=document.createElement('a');link.href=url;link.download='cannabis-market-recovery.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function json(file,limit){check(file&&file.size>0&&file.size<=limit);return JSON.parse(await file.text());}
function refresh() {
  if(!client){renderMarket({state:'not-configured',reason:'No reviewed deployment is selected. Choose it independently before using direct contracts.'});setMarketConnected(false);controls();return;}
  try{journal.assertLive();renderMarket(client.snapshot());setMarketConnected(true);}
  catch{setMarketConnected(false);say('Local market history became unavailable. Preserve recovery files and close this market before restoring.');}
  controls();
}
const routes={network:(c,b)=>c.network(),offers:(c,b)=>c.discover(b),bookings:(c,b)=>c.bookings(b.bookingIds),
  import:(c,b)=>c.importPlan(b.plan),plan:(c,b)=>c.plan(b.planId),export:(c,b)=>c.exportPlan(b.planId),inspect:(c,b)=>c.inspect(b.planId),
  begin:(c,b)=>c.begin(b.planId,{method:b.method,actor:b.signer,bookingId:b.bookingId}),detail:(c,b)=>c.detail(b.requestId),
  handoff:(c,b)=>c.handoff(b.requestId),signature:(c,b)=>c.submitSignature(b.requestId,b.signature),
  'import-signature':(c,b)=>c.importSignature(b.planId,b.bookingId,b.signer,b.signature),
  'report-hash':(c,b)=>c.reportHash(b.actionId,b.transactionHash),action:(c,b)=>c.action(b.actionId),
  observe:(c,b)=>c.observe(b.actionId),'wallet-refused':(c,b)=>c.walletRefused(b.actionId),cancel:(c,b)=>c.cancel(b.requestId)};
async function closeMarket() {
  ++generation;connectionAbort?.abort();setMarketConnected(false);setMarketControl({market:false});
  const previous=client;client=null;const previousJournal=journal;journal=null;
  try{if(previous)await previous.close();else await previousJournal?.close();}finally{opening=false;setOrderMarket(null);refresh();}
}
async function openMarket(mode) {
  if(opening||client)return;const config=marketConfiguration(candidate),version=++generation;
  opening=true;connectionAbort=new AbortController();controls();say('Checking the selected network and contract bindings. No wallet request is being made.');
  let selected;
  try {
    const recovery=mode==='restore'?await json($('direct-market-recovery').files[0],8*1024*1024):null;
    const observed=await inspectMarketNetwork(config,{timeoutMs:60000,signal:connectionAbort.signal});check(generation===version&&!connectionAbort.signal.aborted);
    if(mode==='restore') {
      try{selected=await BrowserMarketJournal.open(config);await selected.restore(recovery);}
      catch(error){if(error.code!=='NO_HISTORY')throw error;selected=await BrowserMarketJournal.open(config,{create:true,recovery});}
    } else selected=await BrowserMarketJournal.open(config,{create:mode==='new'});
    check(generation===version&&!connectionAbort.signal.aborted);
    const ownedJournal=selected;journal=ownedJournal;client=new MarketController(config,ownedJournal,{guard:()=>ownedJournal.assertLive()});selected=null;
    setMarketControl(control());setOrderMarket(config);refresh();
    $('market-to').value=String(observed.finalizedBlock.number);$('market-from').value=String(Math.max(0,observed.finalizedBlock.number-255));
    say('Direct market open in this browser. No account or website order service is required. Keep the latest recovery file; restored transaction claims need fresh receipt checks.');
  }catch(error){await selected?.close();if(generation===version)say(error.message||'The selected network or local recovery could not be verified.');}
  finally{if(generation===version){opening=false;connectionAbort=null;controls();}}
}
export async function initializeWorkMarket() {
  initializeOrderForm(async plan=>{check(client);const owner=client,retained=await owner.importPlan(plan);check(client===owner);refresh();loadMarketPlan(owner.plan(retained.id));
    $('market-plan').focus({preventScroll:true});});
  await initializeMarket(refresh,{adapter:{control,call:async(name,body)=>{check(client&&Object.hasOwn(routes,name));journal.assertLive();return routes[name](client,body);},
    offers:retainOfferObservation,recovery:()=>{check(journal);return journal.exportRecovery();}}});
  $('direct-market-configuration').addEventListener('change',async()=>{
    const version=++selectionGeneration,file=$('direct-market-configuration').files[0];candidate=null;controls();
    $('direct-market-selection').replaceChildren();$('direct-market-pins').textContent='';
    try{await closeMarket();if(version!==selectionGeneration)return;
      const chosen=marketConfiguration(await json(file,16384));if(version!==selectionGeneration)return;candidate=chosen;
      const items=[['Chain',candidate.chainId],['RPC origin',new URL(candidate.rpc).origin],['Genesis',candidate.genesisHash],
        ['Market',candidate.market],['ETH escrow',candidate.nativeEscrow],['Cannabis escrow',candidate.cannabisEscrow],
        ['Cannabis token',candidate.token],['Deployment fingerprint',sha(deployment(candidate))]];
      const list=$('direct-market-selection');list.replaceChildren();for(const [label,value]of items){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;list.append(dt,dd);}
      $('direct-market-pins').textContent=JSON.stringify({deployment:deployment(candidate),feeLimits:candidate.feeLimits,
        maxFinalizedAgeSeconds:candidate.maxFinalizedAgeSeconds,maxHeadAgeSeconds:candidate.maxHeadAgeSeconds},null,2);
      say('Review this deployment against your independently obtained release. Opening it reads its selected RPC; it does not establish hardware admission or request payment.');
    }catch{if(version===selectionGeneration)say('Choose a bounded Cannabis market configuration containing reviewed deployment pins and finite fee limits.');}
    if(version===selectionGeneration)controls();
  });
  for(const [id,mode]of [['direct-market-open','existing'],['direct-market-new','new'],['direct-market-restore','restore']])
    $(id).addEventListener('click',()=>{void openMarket(mode).catch(()=>say('Market setup failed. Preserve recovery state.'));});
  $('direct-market-close').addEventListener('click',()=>{void closeMarket().then(()=>say('Market closed. Pending wallet prompts may still submit; recover their exact transaction hashes before another action.'))
    .catch(()=>say('Closing local history failed. Preserve your latest recovery file and inspect wallet activity before reopening.'));});
  $('direct-market-backup').addEventListener('click',()=>{try{check(journal);save(journal.exportRecovery());say('Recovery download requested. Keep your latest copy; it contains public plans and transaction history, never wallet or workload keys.');}catch{say('Local recovery is unavailable. Do not submit another transaction.');}});
  window.addEventListener('pagehide',()=>{void closeMarket().catch(()=>{});});setInterval(refresh,2000);refresh();
}
