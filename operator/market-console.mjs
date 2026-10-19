// Independent local market client. The browser selects typed plans and actions;
// network destinations, release pins and journal paths are selected at startup.
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {readMarketOffers,readMarketBookings} from '../compute/market_reader.mjs';
import {MarketJournal} from './market-journal.mjs';
import {marketConfiguration,deployment,readerOptions,prepareMarketPlan,marketAction,check,exact,canonical,sha,hash} from './market-plan.mjs';
import {inspectMarketNetwork,inspectMarketPlan,reviewMarketAction,verifyBookingSignature,observeMarketTransaction} from './market-chain.mjs';

const key=()=>randomBytes(32).toString('hex'),valid=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const pending=new Set(['running','awaiting-wallet','rechecking','checking-signature']);
const maxStateAge=30000;
export function readMarketConfiguration(file) {
  check(typeof file==='string'&&path.isAbsolute(file));const s=fs.lstatSync(file);check(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<=16384);
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW??0));
  try{const actual=fs.fstatSync(fd);check(actual.ino===s.ino&&actual.dev===s.dev&&actual.size<=16384);
    const bytes=Buffer.alloc(16385);let size=0,n;while(size<bytes.length&&(n=fs.readSync(fd,bytes,size,bytes.length-size,null))>0)size+=n;
    check(size<=16384);return marketConfiguration(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,size))));}
  finally{fs.closeSync(fd);}
}
export class MarketConsole {
  #c;#journal;#requests=new Map();#tasks=new Set();#observations=new Map();#closed=false;#closeTask;#guard;
  constructor(configuration,journalFile,{guard=async()=>{}}={}) {
    this.#c=marketConfiguration(configuration);this.#journal=new MarketJournal(journalFile,this.#c);check(typeof guard==='function');this.#guard=guard;
  }
  #live(){check(!this.#closed);}
  #expire(r) {
    if(pending.has(r.state)&&(performance.now()>=r.deadline||Date.now()>=r.expiresAt||Date.now()<r.startedAt))this.#finish(r,'expired');
  }
  #finish(r,state) {r.state=state;clearTimeout(r.timer);r.controller.abort();r.finishedAt=Date.now();}
  #new(kind,{planId=null,actor=null}={}) {
    this.#live();for(const r of this.#requests.values())this.#expire(r);
    const active=[...this.#requests.values()].filter(r=>pending.has(r.state));check(active.length<2);
    if(actor)check(!active.some(r=>r.actor===actor)&&!this.#journal.blocking(actor).length);
    while(this.#requests.size>=24){const old=[...this.#requests.values()].find(r=>!pending.has(r.state));check(old);this.#requests.delete(old.id);}
    const r={id:key(),kind,planId,actor,state:'running',startedAt:Date.now(),expiresAt:Date.now()+60000,
      deadline:performance.now()+60000,controller:new AbortController(),result:null,error:null};
    r.timer=setTimeout(()=>this.#finish(r,'expired'),60000);r.timer.unref();this.#requests.set(r.id,r);return r;
  }
  #request(id,state) {this.#live();check(valid(id));const r=this.#requests.get(id);check(r);this.#expire(r);if(state)check(r.state===state);return r;}
  #runtime(r) {this.#expire(r);check(pending.has(r.state));return {timeoutMs:Math.max(1,Math.floor(r.deadline-performance.now())),signal:r.controller.signal};}
  #track(r,action) {
    const task=Promise.resolve().then(async()=>{await this.#guard();this.#runtime(r);await action();}).catch(()=>{
      if(pending.has(r.state)){r.error='Current chain state, wallet review or local recovery could not be verified. Refresh before a new explicit action.';this.#finish(r,'failed');}
    }).finally(()=>this.#tasks.delete(task));this.#tasks.add(task);
  }
  importPlan(input) {this.#live();return this.#journal.addPlan(input);}
  network() {
    const r=this.#new('network');this.#track(r,async()=>{r.result=await inspectMarketNetwork(this.#c,this.#runtime(r));this.#runtime(r);this.#finish(r,'completed');});
    return {requestId:r.id};
  }
  plan(id) {this.#live();const p=this.#journal.plan(id);return {...p,signatures:this.#journal.signatures(id)};}
  exportPlan(id) {const p=this.plan(id);return {schema:'cannabis.market-plan-export.v1',deployment:deployment(this.#c),plan:p.plan,
    signatures:this.#journal.signatureRecords(id)};}
  discover(range) {
    exact(range,['fromBlock','toBlock']);const selected=structuredClone(range),r=this.#new('offers');
    this.#track(r,async()=>{await inspectMarketNetwork(this.#c,this.#runtime(r));this.#runtime(r);
      const result=await readMarketOffers(readerOptions(this.#c),selected,()=>Math.floor(Date.now()/1000),this.#runtime(r));
      this.#runtime(r);r.result=result;this.#finish(r,'completed');});return {requestId:r.id};
  }
  bookings(ids) {
    const selected=structuredClone(ids),r=this.#new('bookings');this.#track(r,async()=>{
      await inspectMarketNetwork(this.#c,this.#runtime(r));this.#runtime(r);
      const result=await readMarketBookings(readerOptions(this.#c),{bookingIds:selected},()=>Math.floor(Date.now()/1000),this.#runtime(r));
      this.#runtime(r);r.result=result;this.#finish(r,'completed');});return {requestId:r.id};
  }
  inspect(planId) {
    const plan=this.#journal.plan(planId),r=this.#new('inspect',{planId});
    this.#track(r,async()=>{const result=await inspectMarketPlan(this.#c,plan,this.#runtime(r));this.#runtime(r);
      r.result=result;if(this.#observations.size>=8&&!this.#observations.has(planId))this.#observations.delete(this.#observations.keys().next().value);
      this.#observations.set(planId,{observedAt:Date.now(),state:result});this.#finish(r,'completed');});return {requestId:r.id};
  }
  async #preceding(r) {
    // Follow inclusion before finality only after checking the exact receipt
    // again. A nonce floor also prevents reuse after an intervening reorg.
    let minimumNonce=0n;
    for(const previous of this.#journal.unresolved(r.actor)) {
      check(previous.state==='included-unfinalized');const a=this.#journal.action(previous.id);
      const observed=await observeMarketTransaction(this.#c,a.review,a.transactionHash,this.#runtime(r));this.#runtime(r);
      this.#journal.observe(a.id,observed);check(['included-unfinalized','confirmed','reverted'].includes(observed.state));
      const next=BigInt(previous.nonce)+1n;if(next>minimumNonce)minimumNonce=next;
    }
    return minimumNonce;
  }
  begin(planId,selection) {
    const plan=this.#journal.plan(planId),chosen=structuredClone(selection);
    const action=marketAction(this.#c,plan,chosen,this.#journal.signatures(planId));
    const r=this.#new('review',{planId,actor:action.actor});r.selection=chosen;
    this.#track(r,async()=>{
      const minimumNonce=await this.#preceding(r);
      const result=await reviewMarketAction(this.#c,plan,chosen,this.#journal.signatures(planId),this.#runtime(r),{minimumNonce});this.#runtime(r);
      const ttl=Math.min(30000,Math.max(0,(result.headBlock.timestamp+this.#c.maxHeadAgeSeconds)*1000-Date.now()),r.deadline-performance.now());
      check(ttl>=3000);r.deadline=performance.now()+ttl;r.expiresAt=Date.now()+ttl;clearTimeout(r.timer);
      r.timer=setTimeout(()=>this.#finish(r,'expired'),ttl);r.timer.unref();
      const review={schema:'cannabis.market-wallet-review.v1',id:r.id,planId,expiresAt:r.expiresAt,
        deployment:deployment(this.#c),...result,actionDigest:sha(result.action),feePolicy:structuredClone(this.#c.feeLimits)};
      r.result=review;r.state='awaiting-wallet';
    });return {requestId:r.id};
  }
  handoff(requestId) {
    const r=this.#request(requestId,'awaiting-wallet');check(r.result.action.kind==='transaction');r.state='rechecking';
    this.#track(r,async()=>{
      const minimumNonce=await this.#preceding(r);
      const fresh=await reviewMarketAction(this.#c,this.#journal.plan(r.planId),r.selection,this.#journal.signatures(r.planId),this.#runtime(r),
        {retainedTransaction:r.result.action.transaction,minimumNonce});this.#runtime(r);
      check(sha(fresh.action)===r.result.actionDigest&&!this.#journal.blocking(r.actor).length);
      // Persist the complete immutable review BEFORE returning any wallet send
      // capability. A process/browser loss now leaves an uncertain submission.
      const handoff=this.#journal.handoff(r.result);r.result={schema:'cannabis.market-wallet-handoff.v1',id:handoff.id,
        review:r.result,transaction:handoff.review.action.transaction,submissionState:'submission-uncertain'};
      this.#finish(r,'handed-off');
    });return {requestId:r.id};
  }
  submitSignature(requestId,signature) {
    const r=this.#request(requestId,'awaiting-wallet');check(r.result.action.kind==='signature');r.state='checking-signature';
    check(typeof signature==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(signature));
    this.#track(r,async()=>{const result=await verifyBookingSignature(this.#c,this.#journal.plan(r.planId),r.selection,signature,this.#runtime(r));
      this.#runtime(r);this.#journal.retainSignature(r.planId,result);r.result={bookingId:result.bookingId,signer:result.signer,retained:true};
      this.#finish(r,'signature-retained');});return {requestId:r.id};
  }
  importSignature(planId,bookingId,signer,signature) {
    const p=this.#journal.plan(planId),selection={method:'signBooking',actor:signer,bookingId};marketAction(this.#c,p,selection);
    const r=this.#new('signature-import',{planId});
    this.#track(r,async()=>{const result=await verifyBookingSignature(this.#c,p,selection,signature,this.#runtime(r));this.#runtime(r);
      this.#journal.retainSignature(planId,result);r.result={bookingId,signer,retained:true};this.#finish(r,'signature-retained');});return {requestId:r.id};
  }
  reportHash(actionId,transactionHash) {this.#live();return this.#journal.reportHash(actionId,transactionHash);}
  action(actionId) {this.#live();return this.#journal.action(actionId);}
  walletRefused(actionId) {this.#live();return this.#journal.walletRefused(actionId);}
  observe(actionId) {
    const a=this.#journal.action(actionId);check(a.transactionHash);const r=this.#new('transaction-observation',{planId:a.review.action.planId});
    this.#track(r,async()=>{const observation=await observeMarketTransaction(this.#c,a.review,a.transactionHash,this.#runtime(r));this.#runtime(r);
      this.#journal.observe(actionId,observation);r.result=observation;this.#finish(r,'completed');});return {requestId:r.id};
  }
  cancel(requestId) {const r=this.#request(requestId);check(pending.has(r.state));this.#finish(r,'cancelled');return {cancelled:true};}
  detail(requestId) {
    const r=this.#request(requestId);return {id:r.id,kind:r.kind,state:r.state,planId:r.planId,expiresAt:r.expiresAt,
      result:structuredClone(r.result),error:r.error};
  }
  snapshot() {
    this.#live();for(const r of this.#requests.values())this.#expire(r);
    return {schema:'cannabis.market-console-state.v1',state:'configured',deployment:deployment(this.#c),feeLimits:structuredClone(this.#c.feeLimits),
      ...this.#journal.snapshot(),requests:[...this.#requests.values()].map(r=>({id:r.id,kind:r.kind,planId:r.planId,actor:r.actor,state:r.state,
        startedAt:r.startedAt,expiresAt:r.expiresAt,error:r.error})),
      observations:[...this.#observations].map(([planId,value])=>({planId,observedAt:value.observedAt,
        state:value.state.order?.state??(value.state.offer?'offer-observed':'resource-observed'),stale:Date.now()-value.observedAt>maxStateAge})),
      hardwareValidated:false,paidAcceptanceVerified:false,executionAuthorized:false,keyReleaseAuthorized:false,
      finality:'rpc-finalized',note:'RPC-reported canonical state. Declared offers and reservations do not attest physical capacity or completed work.'};
  }
  close() {if(this.#closeTask)return this.#closeTask;this.#closed=true;
    for(const r of this.#requests.values())if(pending.has(r.state))this.#finish(r,'cancelled');
    this.#closeTask=(async()=>{await Promise.allSettled([...this.#tasks]);this.#journal.close();})();return this.#closeTask;}
}
