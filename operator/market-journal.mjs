// Ordinary local public-metadata journal, never wallet/content-key custody.
// Explicit creation only. Preserve uncertain handoffs; no automatic reset,
// pruning, retry, receipt acceptance or physical-capacity claim.
import fs from 'node:fs';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {randomBytes} from 'node:crypto';
import {marketConfiguration,deployment,prepareMarketPlan,check,canonical,sha,hash,exact} from './market-plan.mjs';

const active=new Set(['submission-uncertain','hash-reported','pending','included-unfinalized','not-observed']);
const terminal=new Set(['confirmed','reverted','wallet-refused','wallet-not-requested']);
const id=()=>randomBytes(32).toString('hex'),validID=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const MAX_PLANS=128,MAX_ACTIONS=1024,MAX_JSON=262144,MAX_BYTES=32*1024*1024;
function location(file,create) {
  check(typeof file==='string'&&path.isAbsolute(file)&&path.resolve(file)===file);
  let parent=path.dirname(file);
  while(true){const s=fs.lstatSync(parent);check(s.isDirectory()&&!s.isSymbolicLink());const next=path.dirname(parent);if(parent===next)break;parent=next;}
  if(create){check(!fs.existsSync(file));const fd=fs.openSync(file,'wx',0o600);fs.closeSync(fd);}
  const s=fs.lstatSync(file);check(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=64*1024*1024);
  for(const suffix of ['-wal','-shm'])if(fs.existsSync(file+suffix)){const side=fs.lstatSync(file+suffix);check(side.isFile()&&!side.isSymbolicLink()&&side.nlink===1);}
  return {device:s.dev,inode:s.ino};
}
export class MarketJournal {
  #db;#c;#file;#identity;#closed=false;
  constructor(file,configuration,{create=false}={}) {
    this.#c=marketConfiguration(configuration);this.#file=file;this.#identity=location(file,create);
    try {
      this.#db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
      this.#db.exec('PRAGMA busy_timeout=1000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=256; PRAGMA max_page_count=16384; PRAGMA journal_size_limit=1048576;');
      if(create) {
        this.#db.exec(`BEGIN IMMEDIATE;
          CREATE TABLE settings(id INTEGER PRIMARY KEY CHECK(id=1),schema TEXT NOT NULL,binding TEXT NOT NULL) STRICT;
          CREATE TABLE plans(id TEXT PRIMARY KEY,body TEXT NOT NULL,created INTEGER NOT NULL) STRICT;
          CREATE TABLE signatures(plan_id TEXT NOT NULL REFERENCES plans(id),booking_id TEXT NOT NULL,signer TEXT NOT NULL,body TEXT NOT NULL,
            PRIMARY KEY(plan_id,booking_id)) STRICT;
          CREATE TABLE actions(id TEXT PRIMARY KEY,plan_id TEXT NOT NULL REFERENCES plans(id),actor TEXT NOT NULL,nonce TEXT NOT NULL,
            state TEXT NOT NULL,body TEXT NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL) STRICT;
          PRAGMA user_version=1; COMMIT;`);
        this.#db.prepare('INSERT INTO settings VALUES(1,?,?)').run('cannabis.market-journal.v1',canonical(deployment(this.#c)));
      }
      const setting=this.#db.prepare('SELECT schema,binding FROM settings WHERE id=1').get();
      check(setting?.schema==='cannabis.market-journal.v1'&&setting.binding===canonical(deployment(this.#c))&&
        this.#db.prepare('PRAGMA user_version').get().user_version===1&&this.#db.prepare('PRAGMA quick_check').get().quick_check==='ok');
      // Reopen validates all bounded retained plans/actions, never repairs them.
      check(this.#db.prepare('SELECT count(*) AS n FROM plans').get().n<=MAX_PLANS&&this.#db.prepare('SELECT count(*) AS n FROM actions').get().n<=MAX_ACTIONS);
      for(const row of this.#db.prepare('SELECT id,body FROM plans').all()){const p=prepareMarketPlan(this.#c,JSON.parse(row.body));check(p.id===row.id);}
      for(const row of this.#db.prepare('SELECT id,plan_id,actor,nonce,state,body FROM actions').all()) {
        check(validID(row.id)&&[...active,...terminal].includes(row.state));const body=JSON.parse(row.body);
        check(body.review.action.planId===row.plan_id&&body.review.action.actor===row.actor&&body.review.action.transaction.nonce===row.nonce&&
          body.id===row.id&&body.state===row.state&&Buffer.byteLength(row.body)<=MAX_JSON);
      }
      this.#space(0);
    }catch(error){this.#db?.close();throw error;}
  }
  #live() {check(!this.#closed);const s=fs.lstatSync(this.#file);check(s.isFile()&&!s.isSymbolicLink()&&s.ino===this.#identity.inode&&s.dev===this.#identity.device);}
  #space(extra) {
    const row=this.#db.prepare(`SELECT
      coalesce((SELECT sum(length(CAST(body AS BLOB))) FROM plans),0)+
      coalesce((SELECT sum(length(CAST(body AS BLOB))) FROM actions),0)+
      coalesce((SELECT sum(length(CAST(body AS BLOB))) FROM signatures),0) AS bytes`).get();
    check(row.bytes+extra<=MAX_BYTES);
  }
  #transaction(action) {this.#live();this.#db.exec('BEGIN IMMEDIATE');try{const result=action();this.#db.exec('COMMIT');return result;}
    catch(error){this.#db.exec('ROLLBACK');throw error;}}
  plan(key) {this.#live();check(validID(key));const row=this.#db.prepare('SELECT body FROM plans WHERE id=?').get(key);check(row);return prepareMarketPlan(this.#c,JSON.parse(row.body));}
  addPlan(input) {
    const prepared=prepareMarketPlan(this.#c,input),body=canonical(prepared.plan);check(Buffer.byteLength(body)<=131072);
    return this.#transaction(()=>{
      const old=this.#db.prepare('SELECT body FROM plans WHERE id=?').get(prepared.id);
      if(old){check(old.body===body);return prepared;}
      check(this.#db.prepare('SELECT count(*) AS n FROM plans').get().n<MAX_PLANS);this.#space(Buffer.byteLength(body));
      this.#db.prepare('INSERT INTO plans VALUES(?,?,?)').run(prepared.id,body,Date.now());return prepared;
    });
  }
  signatures(planId) {
    this.plan(planId);return Object.fromEntries(this.#db.prepare('SELECT booking_id,body FROM signatures WHERE plan_id=?').all(planId)
      .map(r=>[r.booking_id,JSON.parse(r.body).signature]));
  }
  signatureRecords(planId) {this.plan(planId);return this.#db.prepare('SELECT body FROM signatures WHERE plan_id=? ORDER BY booking_id').all(planId).map(r=>JSON.parse(r.body));}
  retainSignature(planId,verified) {
    const plan=this.plan(planId);check(plan.plan.kind==='order'&&plan.detail.bookings.some(b=>b.bookingId===verified.bookingId&&b.digest===verified.digest));
    check(typeof verified.signature==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(verified.signature));
    // Verified is produced by the canonical chain reader, not a browser payload.
    const body=canonical({bookingId:verified.bookingId,signer:verified.signer,digest:verified.digest,signature:verified.signature});
    this.#transaction(()=>{const old=this.#db.prepare('SELECT body FROM signatures WHERE plan_id=? AND booking_id=?').get(planId,verified.bookingId);
      if(old){check(old.body===body);return;}this.#space(Buffer.byteLength(body));
      this.#db.prepare('INSERT INTO signatures VALUES(?,?,?,?)').run(planId,verified.bookingId,verified.signer,body);});
  }
  unresolved(actor) {this.#live();return this.#db.prepare('SELECT id,state,nonce FROM actions WHERE actor=? ORDER BY created').all(actor).filter(r=>active.has(r.state));}
  blocking(actor) {return this.unresolved(actor).filter(a=>a.state!=='included-unfinalized');}
  handoff(review) {
    check(review?.action?.kind==='transaction');const a=review.action;this.plan(a.planId);
    check(Buffer.byteLength(canonical(review))<=MAX_JSON-4096&&typeof a.transaction.nonce==='string');
    return this.#transaction(()=>{
      check(!this.blocking(a.actor).length&&this.unresolved(a.actor).every(previous=>BigInt(a.transaction.nonce)>BigInt(previous.nonce))&&
        this.#db.prepare('SELECT count(*) AS n FROM actions').get().n<MAX_ACTIONS);
      const value={id:id(),state:'submission-uncertain',review:structuredClone(review),transactionHash:null,observation:null,
        createdAt:Date.now(),updatedAt:Date.now(),walletOutcome:null},body=canonical(value);this.#space(Buffer.byteLength(body));
      this.#db.prepare('INSERT INTO actions VALUES(?,?,?,?,?,?,?,?)').run(value.id,a.planId,a.actor,a.transaction.nonce,value.state,body,value.createdAt,value.updatedAt);
      return value;
    });
  }
  action(key) {this.#live();check(validID(key));const row=this.#db.prepare('SELECT body FROM actions WHERE id=?').get(key);check(row);return JSON.parse(row.body);}
  #update(key,change) {
    return this.#transaction(()=>{const old=this.action(key),value=change(structuredClone(old));value.updatedAt=Date.now();
      const body=canonical(value);check(Buffer.byteLength(body)<=MAX_JSON);this.#space(Math.max(0,Buffer.byteLength(body)-Buffer.byteLength(canonical(old))));
      this.#db.prepare('UPDATE actions SET state=?,body=?,updated=? WHERE id=?').run(value.state,body,value.updatedAt,key);return value;});
  }
  reportHash(key,value) {
    hash(value);return this.#update(key,a=>{check(active.has(a.state)||['wallet-refused','wallet-not-requested'].includes(a.state));
      if(a.transactionHash!==null&&a.transactionHash!==value) {
        // Correct an unverified pasted hash without forgetting prior candidates.
        // A verified pending/included transaction cannot be replaced here.
        check(['hash-reported','not-observed'].includes(a.state)&&(!a.observation||a.observation.state==='not-observed'));
        a.previousReportedHashes??=[];check(a.previousReportedHashes.length<8);a.previousReportedHashes.push(a.transactionHash);
      }
      a.transactionHash=value;a.state='hash-reported';return a;});
  }
  walletRefused(key) {
    return this.#update(key,a=>{check(a.state==='submission-uncertain'&&a.transactionHash===null);
      a.state='wallet-refused';a.walletOutcome='Wallet reported EIP-1193 user rejection. This is not an on-chain failure proof.';return a;});
  }
  walletNotRequested(key) {
    return this.#update(key,a=>{check(a.state==='submission-uncertain'&&a.transactionHash===null);
      a.state='wallet-not-requested';a.walletOutcome='Local wallet adapter reported no transaction request. This is not an on-chain failure proof.';return a;});
  }
  observe(key,observation) {
    return this.#update(key,a=>{check(active.has(a.state)&&a.transactionHash===observation.transactionHash&&
      [...active,'confirmed','reverted'].includes(observation.state));
      a.state=observation.state;a.observation=structuredClone(observation);return a;});
  }
  snapshot() {
    this.#live();return {plans:this.#db.prepare('SELECT id,body,created FROM plans ORDER BY created DESC').all().map(r=>{
      const p=JSON.parse(r.body);return {id:r.id,kind:p.kind,createdAt:r.created,actor:p.provider??p.job.requester,asset:p.asset??null};}),
      actions:this.#db.prepare('SELECT id,plan_id,actor,state,body,created,updated FROM actions ORDER BY created DESC').all().map(r=>{
        const a=JSON.parse(r.body);return {id:r.id,planId:r.plan_id,actor:r.actor,state:r.state,method:a.review.action.method,
          transactionHash:a.transactionHash,createdAt:r.created,updatedAt:r.updated,observation:a.observation,walletOutcome:a.walletOutcome};}),
      limits:{plans:MAX_PLANS,actions:MAX_ACTIONS,metadataBytes:MAX_BYTES},physicalCapacityGuaranteed:false};
  }
  close() {if(this.#closed)return;this.#closed=true;this.#db.close();}
}
