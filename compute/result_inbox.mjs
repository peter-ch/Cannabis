// Requester-local durable attempt selection and encrypted receipt retrieval.
// Never run this ledger on the untrusted worker/operator or accept its expected
// approvals from a server response. It neither executes work nor approves payment.
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { TypedDataEncoder, getAddress, verifyTypedData, ZeroAddress } from 'ethers';
import { deliveryTypesV2 } from './key_delivery.mjs';
import { openResultDelivery } from './result_delivery.mjs';

const hash=v=>createHash('sha256').update(v).digest('hex');
const bytes32=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const recipient=v=>typeof v==='string'&&/^age1[0-9a-z]{58}$/.test(v);
const fail=message=>{throw Error(message);};
function contextValue(value) {
  if(!value||Object.keys(value).sort().join()!=='chainId,escrow,requester'||!integer(value.chainId,1,Number.MAX_SAFE_INTEGER))fail('Invalid requester inbox context');
  const result={chainId:value.chainId,escrow:getAddress(value.escrow),requester:getAddress(value.requester)};
  if(result.escrow===ZeroAddress||result.requester===ZeroAddress)fail('Invalid requester inbox address');
  return result;
}
function signedApproval(record,context) {
  const p=record?.expectedApproval,d=p?.domain,v=p?.value;
  if(record?.schema!=='cannabis.key-delivery.record.v2'||record.keyWrapped!==true||!d||!v||
    Object.keys(d).sort().join()!=='chainId,name,verifyingContract,version'||
    d.name!=='Cannabis confidential key delivery'||d.version!=='2'||Number(d.chainId)!==context.chainId||
    getAddress(d.verifyingContract)!==context.escrow||getAddress(p.requester)!==context.requester||
    Object.keys(v).sort().join()!==deliveryTypesV2.JobKeyDelivery.map(f=>f.name).sort().join()||
    typeof p.jobId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(p.jobId))fail('Delivery does not belong to this requester inbox');
  for(const {name,type} of deliveryTypesV2.JobKeyDelivery)if(type==='bytes32'&&!bytes32(v[name]))fail('Invalid approval commitment');
  if(!recipient(v.inputRecipient)||!integer(v.attempt,1,1000000)||!integer(v.worldSize,1,100000)||!integer(v.rank,0,v.worldSize-1)||
    !integer(v.notBefore,1,Number.MAX_SAFE_INTEGER)||!integer(v.expiresAt,v.notBefore+1,Number.MAX_SAFE_INTEGER))fail('Invalid approved attempt');
  const digest=TypedDataEncoder.hash(d,deliveryTypesV2,v);
  if(digest!==p.digest||record.approvalDigest!==digest||record.releaseId!==v.releaseId||
    verifyTypedData(d,deliveryTypesV2,v,p.requesterSignature)!==context.requester)fail('Requester approval signature differs');
  // Persist only bounded public approval context, not the guest key envelope,
  // owner identity, result key or decrypted receipt/private output metadata.
  return {domain:{name:d.name,version:d.version,chainId:context.chainId,verifyingContract:context.escrow},
    value:Object.fromEntries(deliveryTypesV2.JobKeyDelivery.map(({name})=>[name,v[name]])),digest,
    requester:context.requester,jobId:p.jobId,requesterSignature:p.requesterSignature};
}
function slotFor(expected) {
  const v=expected.value;
  return hash(JSON.stringify([v.orderId,v.packageSHA256,v.taskSHA256,v.rank]));
}
function publicState(row) {
  return {schema:'cannabis.result-inbox.v1',slotId:row.slot,approvalDigest:row.digest,attempt:row.attempt,
    active:!!row.active,receiptStored:row.envelope_hash!==null,receiptSHA256:row.envelope_hash,
    outputVerified:false,qualityAccepted:false,paymentAuthorized:false};
}

export class ResultInbox {
  #db;#context;#maxReleases;#maxReceiptBytes;
  constructor(file,context,{maxReleases=4096,maxReceiptBytes=64*1024*1024}={}) {
    this.#context=contextValue(context);
    if(!integer(maxReleases,1,100000)||!integer(maxReceiptBytes,1024,1024**3))fail('Invalid requester inbox limits');
    this.#maxReleases=maxReleases;this.#maxReceiptBytes=maxReceiptBytes;
    this.#db=new DatabaseSync(file,{timeout:5000});
    try {
      this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS inbox_context(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS result_releases(digest TEXT PRIMARY KEY,slot TEXT NOT NULL,attempt INTEGER NOT NULL,
          approval TEXT NOT NULL,recipient TEXT NOT NULL,envelope TEXT,envelope_hash TEXT,
          UNIQUE(slot,attempt),CHECK((envelope IS NULL)=(envelope_hash IS NULL))) STRICT;
        CREATE TABLE IF NOT EXISTS result_slots(id TEXT PRIMARY KEY,current_digest TEXT NOT NULL REFERENCES result_releases(digest),
          active INTEGER NOT NULL CHECK(active IN (0,1))) STRICT;`);
      this.#transaction(()=>{
        const body=JSON.stringify(this.#context),saved=this.#db.prepare('SELECT body FROM inbox_context WHERE id=1').get();
        if(saved&&saved.body!==body)fail('Requester inbox context cannot change');
        if(!saved)this.#db.prepare('INSERT INTO inbox_context VALUES(1,?)').run(body);
      });
    }catch(error){this.#db.close();throw error;}
  }
  close(){this.#db.close();}
  #transaction(fn){this.#db.exec('BEGIN IMMEDIATE');try{const result=fn();this.#db.exec('COMMIT');return result;}catch(error){this.#db.exec('ROLLBACK');throw error;}}
  #row(digest,requireActive=true) {
    if(!bytes32(digest))fail('Invalid result approval digest');
    const row=this.#db.prepare(`SELECT r.*,s.current_digest,s.active FROM result_releases r
      JOIN result_slots s ON s.id=r.slot WHERE r.digest=?`).get(digest);
    if(!row)fail('Unknown result approval');
    if(requireActive&&(!row.active||row.current_digest!==digest))fail('Result approval is retired or superseded');
    return {...row,active:row.active&&row.current_digest===digest};
  }
  // Explicit local selection. Never infer a successor from an incoming result.
  activate(record,{resultRecipient,previousApprovalDigest=null}={}) {
    record=structuredClone(record);
    if(!recipient(resultRecipient)||(previousApprovalDigest!==null&&!bytes32(previousApprovalDigest)))fail('Invalid local attempt selection');
    const expected=signedApproval(record,this.#context),body=JSON.stringify(expected),slot=slotFor(expected),v=expected.value;
    if(Buffer.byteLength(body)>16384)fail('Approval exceeds inbox bound');
    return this.#transaction(()=>{
      const current=this.#db.prepare(`SELECT r.*,s.active FROM result_slots s JOIN result_releases r
        ON r.digest=s.current_digest WHERE s.id=?`).get(slot);
      if(current?.digest===expected.digest) {
        if(!current.active||current.approval!==body||current.recipient!==resultRecipient)fail('Cannot reactivate or change an existing approval');
        return {...publicState(current),newSelection:false};
      }
      if((current?.digest??null)!==previousApprovalDigest)fail('Active attempt changed; review the current selection');
      if(current) {
        const prior=JSON.parse(current.approval);
        if(v.attempt<=current.attempt)fail('Replacement attempt must increase');
        if(current.recipient!==resultRecipient||expected.jobId!==prior.jobId||
          ['worldSize','runtimeSHA256','policySHA256','inputRecipient'].some(k=>v[k]!==prior.value[k]))fail('Replacement changes the retained workload');
      }
      if(this.#db.prepare('SELECT count(*) AS n FROM result_releases').get().n>=this.#maxReleases)fail('Requester inbox release capacity reached');
      this.#db.prepare('INSERT INTO result_releases VALUES(?,?,?,?,?,NULL,NULL)').run(expected.digest,slot,v.attempt,body,resultRecipient);
      this.#db.prepare(`INSERT INTO result_slots VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET current_digest=excluded.current_digest,active=1`).run(slot,expected.digest);
      return {...publicState(this.#row(expected.digest)),newSelection:true};
    });
  }
  inspect(digest){return publicState(this.#row(digest,false));}
  retire(digest) {
    return this.#transaction(()=>{
      const row=this.#row(digest);
      this.#db.prepare('UPDATE result_slots SET active=0 WHERE id=? AND current_digest=?').run(row.slot,digest);
      return publicState(this.#row(digest,false));
    });
  }
  async #open(row,envelope,loadResultKey) {
    if(typeof loadResultKey!=='function')fail('Require requester-local result-key recovery');
    const expected=JSON.parse(row.approval),v=expected.value;
    let key;
    try {
      key=await loadResultKey({releaseId:v.releaseId,recipient:row.recipient,resultKeySHA256:v.resultKeySHA256});
      const result=await openResultDelivery(envelope,key,expected);
      if(result.receipt.recipient!==row.recipient)fail('Returned recipient differs from requester custody');
      return result;
    }finally{key?.fill(0);}
  }
  async receive(digest,envelope,loadResultKey) {
    if(typeof envelope!=='string'||!envelope.length||envelope.length>6*1024*1024||
      !/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(envelope))fail('Invalid bounded encrypted receipt');
    const row=this.#row(digest),envelopeHash=hash(envelope);
    if(row.envelope_hash!==null&&row.envelope_hash!==envelopeHash)fail('Conflicting receipt for the approved attempt');
    const result=await this.#open(row,envelope,loadResultKey);
    const report=this.#transaction(()=>{
      const current=this.#row(digest); // Recheck after asynchronous local decryption.
      if(current.envelope_hash!==null) {
        if(current.envelope_hash!==envelopeHash)fail('Conflicting receipt for the approved attempt');
        return {...publicState(current),newDelivery:false};
      }
      const used=this.#db.prepare('SELECT coalesce(sum(length(envelope)),0) AS n FROM result_releases').get().n;
      if(used+envelope.length>this.#maxReceiptBytes)fail('Requester inbox encrypted-receipt capacity reached');
      this.#db.prepare('UPDATE result_releases SET envelope=?,envelope_hash=? WHERE digest=?').run(envelope,envelopeHash,digest);
      return {...publicState(this.#row(digest)),newDelivery:true};
    });
    return Object.defineProperty({...report,receiptAuthenticated:true},'receipt',{value:result.receipt,enumerable:false});
  }
  async recover(digest,loadResultKey) {
    const row=this.#row(digest);
    if(row.envelope===null||hash(row.envelope)!==row.envelope_hash)fail('Saved encrypted receipt is unavailable or changed');
    const result=await this.#open(row,row.envelope,loadResultKey);
    const current=this.#row(digest);
    if(current.envelope_hash!==row.envelope_hash)fail('Saved receipt changed during recovery');
    return Object.defineProperty({...publicState(current),receiptAuthenticated:true,newDelivery:false},'receipt',{value:result.receipt,enumerable:false});
  }
  // A trusted synchronous requester reconstruction step holds the write lock so
  // another local process cannot switch attempts between validation and use.
  // Never pass an async callback, network operation or customer executable here.
  useCurrent(selections,fn) {
    if(!Array.isArray(selections)||!selections.length||selections.length>4096||typeof fn!=='function'||
      Object.prototype.toString.call(fn)==='[object AsyncFunction]'||
      new Set(selections.map(s=>s.approvalDigest)).size!==selections.length)fail('Require unique current result selections');
    return this.#transaction(()=>{
      const approvals=selections.map(selection=>{
        const row=this.#row(selection.approvalDigest);
        if(!row.envelope_hash||row.envelope_hash!==selection.receiptSHA256)fail('Result selection changed before reconstruction');
        return JSON.parse(row.approval);
      });
      const value=fn(approvals);
      if(value&&typeof value.then==='function')fail('Reconstruction callback must be synchronous');
      return value;
    });
  }
}
