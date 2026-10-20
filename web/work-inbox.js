// Requester-local selection history. Only public approvals and encrypted custody/
// receipts persist. There is no network or signing path in this module.
import { validateRecoveryBundle } from './work-approvals.js';
import { sha256 } from './work-results.js';
const enc=new TextEncoder(),tickets=new WeakMap();
const check=(ok,message)=>{if(!ok)throw Error(message);};
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
function immutable(entry) {
  const p=entry.approval,v=p.value;
  return canonical([entry.recipient,p.jobId,v.worldSize,v.runtimeSHA256,v.policySHA256,v.inputRecipient]);
}
export class BrowserResultInbox {
  #db;
  constructor(db){this.#db=db;}
  static open(name='cannabis-requester-results-v1') {
    return new Promise((resolve,reject)=>{
      const request=indexedDB.open(name,1);
      request.onupgradeneeded=()=>request.result.createObjectStore('jobs',{keyPath:'id'});
      request.onerror=()=>reject(Error('Local result storage is unavailable; use the requester desktop client'));
      request.onblocked=()=>reject(Error('Close other Cannabis pages before upgrading local result storage'));
      request.onsuccess=()=>{request.result.onversionchange=()=>request.result.close();resolve(new BrowserResultInbox(request.result));};
    });
  }
  close(){this.#db.close();}
  #transaction(id,mode,fn) {
    return new Promise((resolve,reject)=>{
      let result,error;
      const tx=this.#db.transaction('jobs',mode,{durability:'strict'}),store=tx.objectStore('jobs');
      const count=store.count(),request=store.get(id);
      request.onsuccess=()=>{
        try {result=fn(request.result,store,count.result);check(!result?.then,'Local selection callback must be synchronous');}
        catch(e){error=e;tx.abort();}
      };
      tx.oncomplete=()=>resolve(result);
      tx.onabort=tx.onerror=()=>reject(error??Error('Local result storage failed; no selection was saved'));
    });
  }
  async list() {
    return new Promise((resolve,reject)=>{
      const tx=this.#db.transaction('jobs','readonly'),request=tx.objectStore('jobs').openCursor(),items=[];
      request.onsuccess=()=>{const c=request.result;if(c){items.push({id:c.key,jobId:c.value.jobId,active:c.value.bundle.entries.length});c.continue();}};
      tx.oncomplete=()=>resolve(items);tx.onabort=tx.onerror=()=>reject(Error('Could not read local result selections'));
    });
  }
  async read(id) {
    const state=await this.#transaction(id,'readonly',row=>{check(row,'No saved result selection');return row;});
    check(state.bundle.entries.length>0,'These attempts were retired locally');
    const checked=await validateRecoveryBundle(state.bundle);
    check(checked.id===id&&canonical(checked.slots)===canonical(state.slots),'Saved selection is inconsistent');
    return state;
  }
  async prepare(bundle) {
    const checked=await validateRecoveryBundle(bundle),hashes=[];
    for(const entry of checked.bundle.entries)hashes.push(await sha256(enc.encode(entry.envelope)));
    const revision=await this.#transaction(checked.id,'readonly',row=>row?.revision??null);
    const review={id:checked.id,jobId:checked.jobId,context:checked.bundle.context,count:checked.bundle.entries.length,
      attempts:checked.bundle.entries.map(e=>({attempt:e.approval.value.attempt,rank:e.approval.value.rank,digest:e.approval.digest}))};
    tickets.set(review,{checked,hashes,revision});return review;
  }
  async select(review) {
    const prepared=tickets.get(review);check(prepared,'Review the requester recovery export first');
    const {checked,hashes,revision}=prepared;
    return this.#transaction(checked.id,'readwrite',(old,store,count)=>{
      check((old?.revision??null)===revision,'Selection changed in another page; review the export again');
      check(old||count<16,'Local job capacity reached; use the requester desktop client');
      const state=old?structuredClone(old):{id:checked.id,jobId:checked.jobId,history:{},slots:[],bundle:{...checked.bundle,entries:[]}};
      const entries=new Map(state.slots.map((slot,i)=>[slot,state.bundle.entries[i]]));
      checked.bundle.entries.forEach((entry,i)=>{
        const slot=checked.slots[i],prior=state.history[slot],v=entry.approval.value;
        if(prior) {
          check(prior.immutable===immutable(entry),'Replacement changes the retained workload');
          if(prior.digest===entry.approval.digest) {
            check(prior.active,'A retired approval cannot be reactivated');
            check(!prior.verifiedEnvelope||prior.verifiedEnvelope===hashes[i],'Conflicting receipt for a verified approval');
          } else check(v.attempt>prior.attempt,'This attempt is older than or conflicts with the saved selection');
        }
        state.history[slot]={digest:entry.approval.digest,attempt:v.attempt,active:true,immutable:immutable(entry),
          envelopeSHA256:hashes[i],verifiedEnvelope:prior?.digest===entry.approval.digest?prior.verifiedEnvelope:null};
        entries.set(slot,entry);
      });
      check(Object.keys(state.history).length<=512&&entries.size<=128,'Browser selection capacity reached');
      state.slots=[...entries.keys()];state.bundle.entries=[...entries.values()];
      check(enc.encode(JSON.stringify(state.bundle)).length<=8*1024*1024,'Saved recovery exceeds 8 MiB; use the desktop client');
      if(old&&canonical({...state,revision:null})===canonical({...old,revision:null}))return old;
      state.revision=crypto.randomUUID();store.put(state);return state;
    });
  }
  retire(snapshot) {
    return this.#transaction(snapshot.id,'readwrite',(state,store)=>{
      this.#current(state,snapshot);
      for(const slot of state.slots)state.history[slot].active=false;
      state.slots=[];state.bundle.entries=[];state.revision=crypto.randomUUID();store.put(state);
    });
  }
  #current(state,snapshot) {
    check(state&&state.revision===snapshot.revision&&state.slots.length>0&&
      state.slots.every(slot=>state.history[slot]?.active),'Result selection changed or was retired; reopen the current selection');
  }
  // Retrieval may check an unverified selection, but cannot publish results or
  // mark its receipt verified. Those still require useCurrent after decryption.
  checkCurrent(snapshot) {
    return this.#transaction(snapshot.id,'readonly',state=>{this.#current(state,snapshot);return true;});
  }
  // The synchronous callback runs while a readwrite transaction excludes attempt
  // changes from other tabs. Decryption happens beforehand, never inside IDB.
  useCurrent(snapshot,fn,{verified=false}={}) {
    check(typeof fn==='function'&&Object.prototype.toString.call(fn)!=='[object AsyncFunction]','Require a synchronous local result action');
    return this.#transaction(snapshot.id,'readwrite',(state,store)=>{
      this.#current(state,snapshot);
      if(verified) {
        for(const slot of state.slots)state.history[slot].verifiedEnvelope=state.history[slot].envelopeSHA256;
        store.put(state);
      } else check(state.slots.every(slot=>state.history[slot].verifiedEnvelope===state.history[slot].envelopeSHA256),'Authenticate the selected results first');
      const value=fn();check(!value?.then,'Local result callback must be synchronous');return value;
    });
  }
}
