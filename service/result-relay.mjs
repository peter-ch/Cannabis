// Bounded opaque result storage on an ordinary host. A slot is provisioned only
// by the local operator; transport success never authenticates work or payment.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { openDurableDatabase } from '../compute/sqlite_runtime.mjs';
import { WorkError, exact, idPattern } from './work-store.mjs';

export const RESULT_CHUNK_BYTES=65536;
export const RESULT_ENVELOPE_BYTES=6*1024*1024;
const MAX_OBJECT_BYTES=64*1024*1024, MAX_TTL_MS=7*86400_000;
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const integer=(n,min,max)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const hex=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s);
const fail=(status,message)=>{throw new WorkError(status,message);};
const missing=()=>fail(404,'Result delivery not found');
const compact=s=>typeof s==='string'&&/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(s);

export class ResultRelay {
  #db;#now;#limits;
  constructor(file,{now=Date.now,maxStorageBytes=128*1024*1024,maxObjects=128,maxEnvelopeBytes=RESULT_ENVELOPE_BYTES}={}) {
    if(!integer(maxStorageBytes,1024,1024**3)||!integer(maxObjects,1,4096)||
      !integer(maxEnvelopeBytes,128,RESULT_ENVELOPE_BYTES)||typeof now!=='function')throw Error('Invalid result relay limits');
    this.#now=now;this.#limits={maxStorageBytes,maxObjects,maxEnvelopeBytes};
    this.#db=openDurableDatabase(file,{timeout:2000});
    try {
      this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS relay_settings(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS relay_objects(id TEXT PRIMARY KEY,approval TEXT NOT NULL,
          upload_hash TEXT NOT NULL,read_hash TEXT NOT NULL,reserved INTEGER NOT NULL,expires INTEGER NOT NULL,
          envelope TEXT,cipher_hash TEXT,cipher_bytes INTEGER,complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1))) STRICT;
        CREATE TABLE IF NOT EXISTS relay_chunks(object_id TEXT NOT NULL REFERENCES relay_objects(id) ON DELETE CASCADE,
          part INTEGER NOT NULL,data BLOB NOT NULL,PRIMARY KEY(object_id,part)) STRICT;
        CREATE INDEX IF NOT EXISTS relay_expiry ON relay_objects(expires);`);
      this.#transaction(()=>{
        const body=JSON.stringify({schema:'cannabis.result-relay-store.v1',chunkBytes:RESULT_CHUNK_BYTES,...this.#limits});
        const old=this.#db.prepare('SELECT body FROM relay_settings WHERE id=1').get();
        if(old&&old.body!==body)throw Error('Result relay limits cannot change without reviewed migration');
        if(!old)this.#db.prepare('INSERT INTO relay_settings VALUES(1,?)').run(body);
      });
      // Logical reservations include the envelope allowance. The database ceiling
      // also leaves room for indexes/pages. WAL/backups still need OS disk limits.
      const pageSize=this.#db.prepare('PRAGMA page_size').get().page_size;
      const pages=Math.ceil((maxStorageBytes*2+8*1024*1024)/pageSize);
      this.#db.exec(`PRAGMA max_page_count=${pages}; PRAGMA journal_size_limit=8388608;`);
    }catch(error){this.#db.close();throw error;}
  }
  close(){this.#db.close();}
  #transaction(fn){this.#db.exec('BEGIN IMMEDIATE');try{const v=fn();this.#db.exec('COMMIT');return v;}catch(e){this.#db.exec('ROLLBACK');throw e;}}
  #time(){const now=this.#now();if(!integer(now,1,Number.MAX_SAFE_INTEGER-MAX_TTL_MS))throw Error('Invalid relay clock');return now;}
  cleanup(){return this.#db.prepare('DELETE FROM relay_objects WHERE expires<=?').run(this.#time()).changes;}
  #row(id,token,role,includeEnvelope=false) {
    if(!idPattern.test(id)||!hex(token)||!['read','upload'].includes(role))return missing();
    const row=this.#db.prepare(`SELECT id,approval,reserved,expires,cipher_hash,cipher_bytes,complete,
      envelope IS NOT NULL AS begun${includeEnvelope?',envelope':''} FROM relay_objects
      WHERE id=? AND ${role}_hash=? AND expires>?`).get(id,hash(token),this.#time());
    if(!row)return missing();return row;
  }
  // Preflight before HTTP body intake. Every mutation rechecks inside its lock.
  authorize(id,token,role){this.#row(id,token,role);}
  reserve({approvalDigest,maxCiphertextBytes,expiresAt,...extra}) {
    if(Object.keys(extra).length||typeof approvalDigest!=='string'||!/^0x[0-9a-f]{64}$/.test(approvalDigest)||
      /^0x0+$/.test(approvalDigest)||!integer(maxCiphertextBytes,1,MAX_OBJECT_BYTES)||
      !integer(expiresAt,this.#time()+1,this.#time()+MAX_TTL_MS))fail(400,'Invalid result reservation');
    return this.#transaction(()=>{
      this.cleanup();
      const used=this.#db.prepare('SELECT count(*) AS n,coalesce(sum(reserved),0) AS bytes FROM relay_objects').get();
      const reserved=maxCiphertextBytes+this.#limits.maxEnvelopeBytes;
      if(used.n>=this.#limits.maxObjects||used.bytes+reserved>this.#limits.maxStorageBytes)fail(503,'Result storage reservation is full');
      const id=randomUUID(),uploadToken=randomBytes(32).toString('hex'),readToken=randomBytes(32).toString('hex');
      this.#db.prepare('INSERT INTO relay_objects(id,approval,upload_hash,read_hash,reserved,expires) VALUES(?,?,?,?,?,?)')
        .run(id,approvalDigest,hash(uploadToken),hash(readToken),reserved,expiresAt);
      return {schema:'cannabis.result-relay-access.v1',id,approvalDigest,expiresAt,chunkBytes:RESULT_CHUNK_BYTES,uploadToken,readToken};
    });
  }
  #status(row) {
    return {schema:'cannabis.result-relay-state.v1',id:row.id,approvalDigest:row.approval,expiresAt:row.expires,
      chunkBytes:RESULT_CHUNK_BYTES,ciphertextSHA256:row.cipher_hash,ciphertextBytes:row.cipher_bytes,
      received:this.#db.prepare('SELECT part FROM relay_chunks WHERE object_id=? ORDER BY part').all(row.id).map(r=>r.part),
      complete:!!row.complete,outputVerified:false,qualityAccepted:false,paymentAuthorized:false};
  }
  status(id,token){return this.#status(this.#row(id,token,'upload'));}
  begin(id,token,manifest) {
    exact(manifest,['resultEnvelope','ciphertextSHA256','ciphertextBytes']);
    const {resultEnvelope,ciphertextSHA256,ciphertextBytes}=manifest;
    if(typeof resultEnvelope!=='string'||resultEnvelope.length>this.#limits.maxEnvelopeBytes||!compact(resultEnvelope)||
      !hex(ciphertextSHA256)||!integer(ciphertextBytes,1,MAX_OBJECT_BYTES))fail(400,'Invalid encrypted result manifest');
    return this.#transaction(()=>{
      const row=this.#row(id,token,'upload',true);
      if(ciphertextBytes>row.reserved-this.#limits.maxEnvelopeBytes)fail(413,'Result exceeds its storage reservation');
      if(row.envelope!==null) {
        if(row.envelope!==resultEnvelope||row.cipher_hash!==ciphertextSHA256||row.cipher_bytes!==ciphertextBytes)fail(409,'Result manifest is already fixed');
      } else this.#db.prepare('UPDATE relay_objects SET envelope=?,cipher_hash=?,cipher_bytes=? WHERE id=?')
        .run(resultEnvelope,ciphertextSHA256,ciphertextBytes,id);
      return this.#status(this.#row(id,token,'upload'));
    });
  }
  put(id,token,index,data) {
    if(!integer(index,0,MAX_OBJECT_BYTES/RESULT_CHUNK_BYTES-1)||!(data instanceof Uint8Array)||
      !integer(data.length,1,RESULT_CHUNK_BYTES))fail(400,'Invalid encrypted result chunk');
    return this.#transaction(()=>{
      const row=this.#row(id,token,'upload');
      if(!row.begun)fail(409,'Set the encrypted manifest first');
      const expected=Math.min(RESULT_CHUNK_BYTES,row.cipher_bytes-index*RESULT_CHUNK_BYTES);
      if(expected<1||data.length!==expected)fail(400,'Chunk does not match the reserved result');
      const old=this.#db.prepare('SELECT data FROM relay_chunks WHERE object_id=? AND part=?').get(id,index);
      if(old){if(!Buffer.from(old.data).equals(data))fail(409,'Stored result chunk cannot change');}
      else {
        if(row.complete)fail(409,'Completed result cannot change');
        this.#db.prepare('INSERT INTO relay_chunks VALUES(?,?,?)').run(id,index,data);
      }
      return {stored:true,index,complete:!!row.complete};
    });
  }
  finish(id,token) {
    return this.#transaction(()=>{
      const row=this.#row(id,token,'upload');
      if(!row.begun)fail(409,'Set the encrypted manifest first');
      if(!row.complete) {
        const digest=createHash('sha256');let index=0,bytes=0;
        for(const part of this.#db.prepare('SELECT part,data FROM relay_chunks WHERE object_id=? ORDER BY part').iterate(id)) {
          if(part.part!==index++||part.data.length!==Math.min(RESULT_CHUNK_BYTES,row.cipher_bytes-bytes))fail(409,'Result chunks are incomplete');
          bytes+=part.data.length;digest.update(part.data);
        }
        if(bytes!==row.cipher_bytes||digest.digest('hex')!==row.cipher_hash)fail(409,'Result bytes do not match the encrypted manifest');
        this.#row(id,token,'upload'); // Expiry during hashing cannot publish.
        this.#db.prepare('UPDATE relay_objects SET complete=1 WHERE id=?').run(id);
      }
      return this.#status(this.#row(id,token,'upload'));
    });
  }
  manifest(id,token) {
    const row=this.#row(id,token,'read',true);if(!row.complete)fail(409,'Encrypted result is not complete');
    return {schema:'cannabis.result-relay-manifest.v1',id:row.id,approvalDigest:row.approval,expiresAt:row.expires,
      chunkBytes:RESULT_CHUNK_BYTES,resultEnvelope:row.envelope,ciphertextSHA256:row.cipher_hash,ciphertextBytes:row.cipher_bytes};
  }
  chunk(id,token,index) {
    const row=this.#row(id,token,'read');if(!row.complete)fail(409,'Encrypted result is not complete');
    if(!integer(index,0,MAX_OBJECT_BYTES/RESULT_CHUNK_BYTES-1))return missing();
    const result=this.#db.prepare('SELECT data FROM relay_chunks WHERE object_id=? AND part=?').get(id,index);
    if(!result)return missing();return result.data;
  }
  remove(id,token){return this.#transaction(()=>{this.#row(id,token,'read');this.#db.prepare('DELETE FROM relay_objects WHERE id=?').run(id);return {deleted:true};});}
}
