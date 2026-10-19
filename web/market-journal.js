// Public metadata only. A Web Lock owns this deployment's journal for the whole
// client lifetime. IndexedDB commits complete before a wallet handoff is returned.
import {marketConfiguration,deployment,prepareMarketPlan,marketAction,check,canonical,sha,exact} from '../operator/market-plan.mjs';
import {validateRetainedMarketReview} from '../operator/market-wallet-source.js';
const ACTIVE=new Set(['submission-uncertain','hash-reported','pending','included-unfinalized','not-observed']);
const STATES=new Set([...ACTIVE,'confirmed','reverted','wallet-refused']);
const MAX_PLANS=32,MAX_ACTIONS=256,MAX_BYTES=8*1024*1024,MAX_ACTION_BYTES=262144;
const enc=new TextEncoder(),size=v=>enc.encode(canonical(v)).length;
const key=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
const id=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const hash=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const rejection='Wallet reported user rejection. This is not an on-chain failure proof.';
const reviewKeys=['schema','id','planId','expiresAt','deployment','action','actionDigest','feePolicy','quote','chainId','genesisHash','market','hardwareValidated','executionAuthorized','keyReleaseAuthorized'];
const quoteKeys=['estimatedGas','gasLimit','maxFeePerGas','maxPriorityFeePerGas','maximumGasWei','nativeValueWei','maximumTotalWei'];
function retainedReview(input) {
  const r=Object.fromEntries(reviewKeys.map(k=>[k,structuredClone(input[k])]));
  validateRetainedMarketReview(r);return r;
}
const empty=c=>({id:sha(deployment(c)),schema:'cannabis.browser-market-journal.v1',binding:deployment(c),revision:key(),plans:[],signatures:[],actions:[]});
const active=(row,actor)=>row.actions.filter(a=>a.review.action.actor===actor&&ACTIVE.has(a.state));
function plan(c,row,planId) {check(id(planId));const p=row.plans.find(p=>p.id===planId);check(p);const prepared=prepareMarketPlan(c,p.plan);check(prepared.id===planId);return prepared;}
function validate(c,row) {
  exact(row,['id','schema','binding','revision','plans','signatures','actions']);
  check(row?.schema==='cannabis.browser-market-journal.v1'&&row.id===sha(deployment(c))&&canonical(row.binding)===canonical(deployment(c))&&id(row.revision));
  check(Array.isArray(row.plans)&&row.plans.length<=MAX_PLANS&&Array.isArray(row.actions)&&row.actions.length<=MAX_ACTIONS&&
    Array.isArray(row.signatures)&&row.signatures.length<=MAX_PLANS*64&&size(row)<=MAX_BYTES);
  check(new Set(row.plans.map(p=>p.id)).size===row.plans.length&&new Set(row.actions.map(a=>a.id)).size===row.actions.length);
  for(const p of row.plans){exact(p,['id','plan','createdAt']);check(Number.isSafeInteger(p.createdAt)&&p.createdAt>0);plan(c,row,p.id);}
  const signatures=new Set();
  for(const s of row.signatures) {
    exact(s,['planId','bookingId','signer','digest','signature']);const p=plan(c,row,s.planId),b=p.detail.bookings?.find(b=>b.bookingId===s.bookingId);
    check(b&&b.digest===s.digest&&typeof s.signature==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(s.signature));
    marketAction(c,p,{method:'signBooking',actor:s.signer,bookingId:s.bookingId});
    const slot=s.planId+':'+s.bookingId;check(!signatures.has(slot));signatures.add(slot);
  }
  for(const a of row.actions) {
    exact(a,['id','state','review','transactionHash','observation','createdAt','updatedAt','walletOutcome',
      ...['previousReportedHashes','importedAt'].filter(k=>Object.hasOwn(a,k))]);
    check(id(a.id)&&STATES.has(a.state)&&size(a)<=MAX_ACTION_BYTES&&Number.isSafeInteger(a.createdAt)&&a.createdAt>0&&
      Number.isSafeInteger(a.updatedAt)&&a.updatedAt>=a.createdAt&&(a.transactionHash===null||hash(a.transactionHash)));
    check(a.walletOutcome===null||a.walletOutcome===rejection);
    if(a.state==='wallet-refused')check(a.transactionHash===null&&a.walletOutcome===rejection);
    if(['hash-reported','pending','included-unfinalized','not-observed','confirmed','reverted'].includes(a.state))check(hash(a.transactionHash));
    if(Object.hasOwn(a,'importedAt'))check(Number.isSafeInteger(a.importedAt)&&a.importedAt>0);
    if(Object.hasOwn(a,'previousReportedHashes'))check(Array.isArray(a.previousReportedHashes)&&a.previousReportedHashes.length<=8&&a.previousReportedHashes.every(hash));
    exact(a.review,reviewKeys);
    const r=validateRetainedMarketReview(a.review),p=plan(c,row,r.planId);check(r.action.kind==='transaction'&&canonical(r.deployment)===canonical(deployment(c)));
    exact(r.action,['kind','planId','method','actor','bookingId','transaction','summary']);check(r.action.bookingId===null);
    exact(r.quote,[...quoteKeys,'scope']);check(quoteKeys.every(k=>typeof r.quote[k]==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(r.quote[k]))&&
      r.quote.scope==='This transaction only. Later funding, acceptance and activation need their own fresh reviews.');
    const signatures=Object.fromEntries(row.signatures.filter(s=>s.planId===p.id).map(s=>[s.bookingId,s.signature]));
    const derived=marketAction(c,p,{method:r.action.method,actor:r.action.actor,bookingId:null},signatures);
    check(canonical(derived.summary)===canonical(r.action.summary));
    for(const k of ['from','to','data'])check(derived.transaction[k]===r.action.transaction[k]);
    for(const k of ['chainId','value'])check(BigInt(derived.transaction[k])===BigInt(r.action.transaction[k]));
  }
  return row;
}
function restore(c,row,input) {
  exact(input,['schema','deployment','plans','signatures','actions','exportedAt']);
  check(input.schema==='cannabis.browser-market-recovery.v1'&&canonical(input.deployment)===canonical(deployment(c))&&size(input)<=MAX_BYTES&&
    typeof input.exportedAt==='string'&&Number.isFinite(Date.parse(input.exportedAt))&&new Date(input.exportedAt).toISOString()===input.exportedAt);
  // Recovery carries claims, never trusted old RPC responses or arbitrary
  // metadata. Every supplied receipt must be observed again on this device.
  check(Array.isArray(input.actions)&&input.actions.every(a=>a.observation===null));
  const imported=validate(c,{...empty(c),plans:structuredClone(input.plans),signatures:structuredClone(input.signatures),actions:structuredClone(input.actions)});
  for(const p of imported.plans){const old=row.plans.find(v=>v.id===p.id);if(old)check(canonical(old.plan)===canonical(p.plan));else row.plans.push(p);}
  for(const s of imported.signatures){const old=row.signatures.find(v=>v.planId===s.planId&&v.bookingId===s.bookingId);
    if(old)check(canonical(old)===canonical(s));else row.signatures.push(s);}
  for(const a of imported.actions) {
    const old=row.actions.find(v=>v.id===a.id);
    if(old) {
      check(canonical(old.review)===canonical(a.review));
      // Restoring an older file cannot downgrade local uncertainty or overwrite
      // a verified receipt/hash. Add a previously missing hash only as a claim.
      if(!old.transactionHash&&a.transactionHash&&old.state==='submission-uncertain'){old.transactionHash=a.transactionHash;old.state='hash-reported';}
    } else {
      a.observation=null;
      if(a.transactionHash)a.state='hash-reported';
      else if(a.state!=='wallet-refused')a.state='submission-uncertain';
      a.importedAt=Date.now();row.actions.push(a);
    }
  }
  return validate(c,row);
}
function openDB() {
  return new Promise((resolve,reject)=>{
    const request=indexedDB.open('cannabis-direct-market-v1',1);let settled=false;
    const timer=setTimeout(()=>{settled=true;reject(Error('Local market storage did not open in time'));},10000);
    const fail=()=>{clearTimeout(timer);settled=true;reject(Error('Local market storage is unavailable. Preserve recovery files.'));};
    request.onupgradeneeded=()=>request.result.createObjectStore('deployments',{keyPath:'id'});
    request.onerror=request.onblocked=fail;
    request.onsuccess=()=>{clearTimeout(timer);if(settled){request.result.close();return;}settled=true;resolve(request.result);};
  });
}
function transaction(db,id,mode,action) {
  return new Promise((resolve,reject)=>{
    let result,error;const tx=db.transaction('deployments',mode,{durability:'strict'}),store=tx.objectStore('deployments');
    const count=store.count(),request=store.get(id);
    request.onsuccess=()=>{try{result=action(request.result,store,count.result);check(!result?.then);}catch(e){error=e;tx.abort();}};
    tx.oncomplete=()=>resolve(result);tx.onerror=tx.onabort=()=>reject(error??Error('Local journal could not commit. No new wallet handoff is available.'));
  });
}
export class BrowserMarketJournal {
  #c;#db;#row;#release;#closed=false;#queue=Promise.resolve();#closeTask;
  constructor(configuration,db,row,release){this.#c=configuration;this.#db=db;this.#row=row;this.#release=release;
    db.onversionchange=()=>{void this.close();};}
  static async open(configuration,{create=false,recovery=null}={}) {
    const c=marketConfiguration(configuration);check(typeof create==='boolean'&&isSecureContext&&navigator.locks?.request);
    let ready,failed,release;
    const opened=new Promise((resolve,reject)=>{ready=resolve;failed=reject;}),held=new Promise(resolve=>{release=resolve;});
    const ownership=navigator.locks.request('cannabis-direct-market:'+sha(deployment(c)),{mode:'exclusive',ifAvailable:true},async lock=>{
      if(!lock){failed(Error('This market is open in another page. Close it before continuing here.'));return;}
      let db,journal;
      try {
        db=await openDB();
        const row=await transaction(db,sha(deployment(c)),create?'readwrite':'readonly',(old,store,count)=>{
          if(create){if(old)throw Error('Local history already exists. Open or restore it without resetting.');check(count<16);
            const row=recovery?restore(c,empty(c),recovery):empty(c);store.add(row);return row;}
          if(!old)throw Object.assign(Error('No local history for this deployment. Restore your latest backup or explicitly start new history.'),{code:'NO_HISTORY'});
          return validate(c,old);
        });
        journal=new BrowserMarketJournal(c,db,row,async()=>{release();await ownership;});ready(journal);await held;
      }catch(error){failed(error);}finally{db?.close();}
    });ownership.catch(failed);
    return opened;
  }
  assertLive(){check(!this.#closed);}
  #mutate(action) {
    this.assertLive();const run=this.#queue.then(async()=>{
      this.assertLive();const expected=this.#row.revision;
      const next=await transaction(this.#db,this.#row.id,'readwrite',(stored,store)=>{
        check(stored?.revision===expected);const row=structuredClone(this.#row),value=action(row);
        check(!value?.then);row.revision=key();validate(this.#c,row);store.put(row);return {row,value};
      });this.#row=next.row;this.assertLive();return structuredClone(next.value);
    });this.#queue=run.catch(()=>{});return run;
  }
  plan(id){this.assertLive();return plan(this.#c,this.#row,id);}
  addPlan(input){const p=prepareMarketPlan(this.#c,input);return this.#mutate(row=>{
    const old=row.plans.find(x=>x.id===p.id);if(old)check(canonical(old.plan)===canonical(p.plan));
    else{check(row.plans.length<MAX_PLANS);row.plans.push({id:p.id,plan:p.plan,createdAt:Date.now()});}return p;});}
  signatures(planId){this.plan(planId);return Object.fromEntries(this.#row.signatures.filter(s=>s.planId===planId).map(s=>[s.bookingId,s.signature]));}
  signatureRecords(planId){this.plan(planId);return this.#row.signatures.filter(s=>s.planId===planId).map(({planId,...s})=>structuredClone(s));}
  retainSignature(planId,verified){this.plan(planId);return this.#mutate(row=>{
    const value={planId,...Object.fromEntries(['bookingId','signer','digest','signature'].map(k=>[k,verified[k]]))};
    const old=row.signatures.find(s=>s.planId===planId&&s.bookingId===value.bookingId);
    if(old)check(canonical(old)===canonical(value));else row.signatures.push(value);
  });}
  unresolved(actor){this.assertLive();return active(this.#row,actor).map(a=>({id:a.id,state:a.state,nonce:a.review.action.transaction.nonce}));}
  blocking(actor){return this.unresolved(actor).filter(a=>a.state!=='included-unfinalized');}
  handoff(review){check(review.action.kind==='transaction');return this.#mutate(row=>{
    const a=review.action,previous=active(row,a.actor);
    check(Date.now()<review.expiresAt&&row.actions.length<MAX_ACTIONS&&previous.every(p=>p.state==='included-unfinalized'&&BigInt(a.transaction.nonce)>BigInt(p.review.action.transaction.nonce)));
    const value={id:key(),state:'submission-uncertain',review:retainedReview(review),transactionHash:null,observation:null,
      createdAt:Date.now(),updatedAt:Date.now(),walletOutcome:null};row.actions.push(value);return value;
  });}
  action(actionId){this.assertLive();check(id(actionId));const a=this.#row.actions.find(a=>a.id===actionId);check(a);return structuredClone(a);}
  #update(actionId,change){check(id(actionId));return this.#mutate(row=>{const a=row.actions.find(a=>a.id===actionId);check(a);change(a);a.updatedAt=Date.now();return a;});}
  reportHash(actionId,value){check(hash(value));return this.#update(actionId,a=>{
    check(ACTIVE.has(a.state)||a.state==='wallet-refused');
    if(a.transactionHash&&a.transactionHash!==value){check(['hash-reported','not-observed'].includes(a.state)&&(!a.observation||a.observation.state==='not-observed'));
      a.previousReportedHashes??=[];check(a.previousReportedHashes.length<8);a.previousReportedHashes.push(a.transactionHash);}
    a.transactionHash=value;a.state='hash-reported';
  });}
  walletRefused(actionId){return this.#update(actionId,a=>{check(a.state==='submission-uncertain'&&a.transactionHash===null);
    a.state='wallet-refused';a.walletOutcome=rejection;});}
  observe(actionId,observation){return this.#update(actionId,a=>{check(ACTIVE.has(a.state)&&a.transactionHash===observation.transactionHash&&STATES.has(observation.state)&&observation.state!=='wallet-refused');
    a.state=observation.state;a.observation=structuredClone(observation);});}
  exportRecovery(){this.assertLive();return {schema:'cannabis.browser-market-recovery.v1',deployment:deployment(this.#c),
    plans:structuredClone(this.#row.plans),signatures:structuredClone(this.#row.signatures),
    actions:this.#row.actions.map(a=>({...structuredClone(a),observation:null})),exportedAt:new Date().toISOString()};}
  restore(input){return this.#mutate(row=>{restore(this.#c,row,input);return {restored:true};});}
  snapshot(){this.assertLive();return {
    plans:[...this.#row.plans].reverse().map(({id,plan:p,createdAt})=>({id,kind:p.kind,createdAt,actor:p.provider??p.job.requester,asset:p.asset??null})),
    actions:[...this.#row.actions].reverse().map(a=>({id:a.id,planId:a.review.planId,actor:a.review.action.actor,state:a.state,method:a.review.action.method,
      transactionHash:a.transactionHash,createdAt:a.createdAt,updatedAt:a.updatedAt,observation:structuredClone(a.observation),walletOutcome:a.walletOutcome})),
    limits:{plans:MAX_PLANS,actions:MAX_ACTIONS,metadataBytes:MAX_BYTES},physicalCapacityGuaranteed:false};}
  close(){if(this.#closeTask)return this.#closeTask;this.#closed=true;
    return this.#closeTask=(async()=>{await this.#queue;this.#db.close();await this.#release();})();}
}
