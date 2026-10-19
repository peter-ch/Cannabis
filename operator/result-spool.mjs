// Ordinary-host storage accounting. This is neither execution admission nor a
// filesystem quota. Keep the entire directory together across restarts.
import fs from 'node:fs';
import path from 'node:path';
import { createHash,randomBytes } from 'node:crypto';
import { TypedDataEncoder,verifyTypedData } from 'ethers';
import { openDurableDatabase } from '../compute/sqlite_runtime.mjs';
import { deliveryApprovalTypes } from '../compute/key_delivery.mjs';
import { resultStoredPayload } from '../compute/result_transport.mjs';

const DAY=86400000,ENVELOPE=6*1024*1024,stores=new WeakSet(),handles=new WeakMap();
export const RESULT_SPOOL_OVERHEAD=2*ENVELOPE+256*1024;
const check=v=>{if(!v)throw Error('Encrypted result spool unavailable; preserve storage and reconcile before retrying');};
const integer=(n,min,max)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const hash=v=>createHash('sha256').update(v).digest('hex');
const regular=file=>{const s=fs.lstatSync(file);check(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);return s;};
function syncDir(dir) {
  if(process.platform==='win32')return;
  const fd=fs.openSync(dir,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
function approval(value) {
  const expected=structuredClone(value),types=deliveryApprovalTypes(expected?.domain?.version);
  check(expected?.domain?.name==='Cannabis confidential key delivery'&&['2','3'].includes(expected.domain.version)&&
    expected.digest===TypedDataEncoder.hash(expected.domain,types,expected.value)&&
    verifyTypedData(expected.domain,types,expected.value,expected.requesterSignature)===expected.requester&&
    Buffer.byteLength(JSON.stringify(expected))<=128*1024);
  return expected;
}
export function assertResultSpool(spool){check(stores.has(spool));}
export function claimResultReservation(handle,expected,maxCiphertextBytes) {
  const entry=handles.get(handle);check(entry&&stores.has(entry.spool));
  check(entry.digest===expected.digest&&entry.max===maxCiphertextBytes);
  entry.spool.assertDispatched(handle);return entry.spool;
}

export class ResultSpool {
  #db;#root;#now;#settings;
  constructor(directory,{create=false,maxBytes,maxRecords,retentionMs,now=Date.now}={}) {
    check(typeof directory==='string'&&path.isAbsolute(directory)&&directory.length<=4096&&typeof create==='boolean'&&typeof now==='function');
    const root=fs.lstatSync(directory);check(root.isDirectory()&&!root.isSymbolicLink());
    this.#root=fs.realpathSync(directory);this.#now=now;
    const file=path.join(this.#root,'spool.sqlite');
    if(create){check(fs.readdirSync(directory).length===0);const fd=fs.openSync(file,'wx',0o600);fs.closeSync(fd);}
    check(regular(file).size>0||create);
    this.#db=openDurableDatabase(file,{timeout:1000});
    try {
      // A held reader must not grow an unbounded WAL in the result volume.
      // Switching an older store requires exclusive SQLite access; never erase
      // its WAL or recreate the database to get around a failed transition.
      check(this.#db.prepare('PRAGMA journal_mode=DELETE').get().journal_mode==='delete');
      this.#db.exec('PRAGMA synchronous=EXTRA; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;');
      check(this.#db.prepare('PRAGMA synchronous').get().synchronous===3);
      if(create)this.#db.exec(`CREATE TABLE spool_settings(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL,last_time INTEGER NOT NULL) STRICT;
        CREATE TABLE results(id TEXT PRIMARY KEY,digest TEXT UNIQUE NOT NULL,owner TEXT NOT NULL,expected TEXT NOT NULL,
          max_bytes INTEGER NOT NULL,charge INTEGER NOT NULL,service_end INTEGER NOT NULL,retry_end INTEGER NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','receiving','sealed','complete','acknowledged','purging')),
          envelope TEXT,bytes INTEGER,received INTEGER NOT NULL,sha TEXT,ack TEXT,ack_at INTEGER) STRICT;`);
      this.#transaction(()=>{
        if(create){
          this.#settings={schema:'cannabis.result-spool.v1',maxBytes:maxBytes??256*1024*1024,maxRecords:maxRecords??16,retentionMs:retentionMs??7*DAY};
          this.#db.prepare('INSERT INTO spool_settings VALUES(1,?,0)').run(JSON.stringify(this.#settings));
        } else {
          this.#settings=JSON.parse(this.#db.prepare('SELECT body FROM spool_settings WHERE id=1').get().body);
          for(const [key,value] of Object.entries({maxBytes,maxRecords,retentionMs}))if(value!==undefined)check(this.#settings[key]===value);
        }
        const s=this.#settings;check(s.schema==='cannabis.result-spool.v1'&&integer(s.maxBytes,RESULT_SPOOL_OVERHEAD+1,1024**4)&&
          integer(s.maxRecords,1,4096)&&integer(s.retentionMs,DAY,30*DAY));this.#time();
      });
      const pageSize=this.#db.prepare('PRAGMA page_size').get().page_size;
      check(pageSize===4096);
      const pages=Math.ceil((this.#settings.maxBytes+1048576)/pageSize);
      check(this.#db.prepare(`PRAGMA max_page_count=${pages}`).get().max_page_count===pages);
      this.#db.exec('PRAGMA journal_size_limit=0;');
      if(create)syncDir(this.#root);stores.add(this);
    }catch(error){this.#db.close();throw error;}
  }
  #transaction(fn) {
    this.#db.exec('BEGIN IMMEDIATE');
    try{const result=fn();this.#db.exec('COMMIT');return result;}
    catch(error){this.#db.exec('ROLLBACK');throw error;}
  }
  #time() {
    const now=this.#now(),old=this.#db.prepare('SELECT last_time FROM spool_settings WHERE id=1').get();
    check(integer(now,1,Number.MAX_SAFE_INTEGER-400*DAY)&&old&&now>=old.last_time);
    this.#db.prepare('UPDATE spool_settings SET last_time=? WHERE id=1').run(now);return now;
  }
  #row(id) {check(typeof id==='string'&&/^[0-9a-f]{64}$/.test(id));const row=this.#db.prepare('SELECT * FROM results WHERE id=?').get(id);check(row);return row;}
  #owned(handle,state) {
    const owner=handles.get(handle);check(owner?.spool===this);const row=this.#row(owner.id);
    check(row.owner===owner.owner&&row.state===state);return row;
  }
  #directory(row) {
    const directory=path.join(this.#root,row.id);
    if(fs.existsSync(directory)){const s=fs.lstatSync(directory);check(s.isDirectory()&&!s.isSymbolicLink());}
    return directory;
  }
  // Keep the native capacity inspection coherent with file creation, recovery
  // and deletion by other store processes. This callback is local trusted code,
  // synchronous and never a network-selected operation.
  withStorageLayout(inspect) {
    check(typeof inspect==='function');
    return this.#transaction(()=>{
      const rows=this.#db.prepare('SELECT id,max_bytes AS maxCiphertextBytes FROM results ORDER BY id').all();
      const result=inspect(rows);check(!result||typeof result.then!=='function');return result;
    });
  }
  reserve({expected,maxCiphertextBytes,serviceEnd},signal) {
    expected=approval(expected);check(!signal||signal instanceof AbortSignal&&!signal.aborted);
    check(integer(maxCiphertextBytes,1,64*1024*1024));
    const id=randomBytes(32).toString('hex'),owner=hash(randomBytes(32)),charge=maxCiphertextBytes+RESULT_SPOOL_OVERHEAD;
    this.#transaction(()=>{
      const now=this.#time();check(integer(serviceEnd,Math.floor(now/1000)+1,Math.floor(now/1000)+366*86400));
      const used=this.#db.prepare('SELECT count(*) AS n,coalesce(sum(charge),0) AS bytes FROM results').get();
      check(used.n<this.#settings.maxRecords&&used.bytes+charge<=this.#settings.maxBytes);
      this.#db.prepare(`INSERT INTO results(id,digest,owner,expected,max_bytes,charge,service_end,retry_end,state,received)
        VALUES(?,?,?,?,?,?,?,?,'reserved',0)`).run(id,expected.digest,owner,JSON.stringify(expected),maxCiphertextBytes,charge,
        serviceEnd*1000,serviceEnd*1000+this.#settings.retentionMs);
    });
    const handle=Object.freeze({id});handles.set(handle,{spool:this,id,owner,digest:expected.digest,max:maxCiphertextBytes});return handle;
  }
  dispatch(handle) {this.#transaction(()=>{const now=this.#time(),row=this.#owned(handle,'reserved');check(now<row.service_end);
    this.#db.prepare("UPDATE results SET state='dispatched' WHERE id=?").run(row.id);});}
  assertDispatched(handle) {this.#transaction(()=>{this.#time();this.#owned(handle,'dispatched');});}
  cancelUnused(handle) {
    const entry=handles.get(handle);check(entry?.spool===this);
    return this.#transaction(()=>{this.#time();const row=this.#row(entry.id);check(row.owner===entry.owner);
      if(row.state!=='reserved')return false;
      check(!fs.existsSync(this.#directory(row)));this.#db.prepare('DELETE FROM results WHERE id=?').run(row.id);return true;
    });
  }
  begin(handle,{resultEnvelope,ciphertextBytes}) {
    check(typeof resultEnvelope==='string'&&resultEnvelope.length<=ENVELOPE&&
      /^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(resultEnvelope));
    return this.#transaction(()=>{this.#time();const row=this.#owned(handle,'dispatched');check(integer(ciphertextBytes,1,row.max_bytes));
      const directory=this.#directory(row);fs.mkdirSync(directory,{mode:0o700});
      const fd=fs.openSync(path.join(directory,'result.age'),'wx',0o600);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
      syncDir(directory);syncDir(this.#root);
      this.#db.prepare("UPDATE results SET state='receiving',envelope=?,bytes=? WHERE id=?").run(resultEnvelope,ciphertextBytes,row.id);
      return directory;
    });
  }
  append(handle,chunk) {
    check(Buffer.isBuffer(chunk)&&integer(chunk.length,1,65536));
    this.#transaction(()=>{this.#time();const row=this.#owned(handle,'receiving');check(row.received+chunk.length<=row.bytes);
      const file=path.join(this.#directory(row),'result.age');check(regular(file).size===row.received);
      const fd=fs.openSync(file,fs.constants.O_WRONLY|(fs.constants.O_NOFOLLOW??0));
      try{let offset=0;while(offset<chunk.length){const n=fs.writeSync(fd,chunk,offset,chunk.length-offset,row.received+offset);check(n>0);offset+=n;}}
      finally{fs.closeSync(fd);}
      this.#db.prepare('UPDATE results SET received=received+? WHERE id=?').run(chunk.length,row.id);
    });
  }
  seal(handle,ciphertextSHA256) {
    check(typeof ciphertextSHA256==='string'&&/^[0-9a-f]{64}$/.test(ciphertextSHA256));
    const id=this.#transaction(()=>{this.#time();const row=this.#owned(handle,'receiving');check(row.received===row.bytes);
      // Persist the end-frame hash before publishing metadata. A
      // crash after this commit can reconstruct the receipt without a guest/key.
      this.#db.prepare("UPDATE results SET state='sealed',sha=? WHERE id=?").run(ciphertextSHA256,row.id);return row.id;
    });return this.recover(id);
  }
  recover(id) {
    return this.#transaction(()=>{this.#time();const row=this.#row(id);check(['sealed','complete','acknowledged'].includes(row.state));
      const directory=this.#directory(row),ciphertext=path.join(directory,'result.age');check(regular(ciphertext).size===row.bytes);
      // Windows FlushFileBuffers requires a writable descriptor. No bytes are
      // changed here; publication still follows the complete hash check.
      const fd=fs.openSync(ciphertext,fs.constants.O_RDWR|(fs.constants.O_NOFOLLOW??0));
      try{const digest=createHash('sha256'),chunk=Buffer.alloc(65536);let n;
        while((n=fs.readSync(fd,chunk))>0)digest.update(chunk.subarray(0,n));check(digest.digest('hex')===row.sha);fs.fsyncSync(fd);
      }finally{fs.closeSync(fd);}
      const source={approvalDigest:row.digest,resultEnvelope:row.envelope,ciphertextSHA256:row.sha,ciphertextBytes:row.bytes,ciphertext};
      const sourceFile=path.join(directory,'source.json'),text=JSON.stringify(source)+'\n';
      if(fs.existsSync(sourceFile)){check(regular(sourceFile).size===Buffer.byteLength(text));check(fs.readFileSync(sourceFile,'utf8')===text);}
      else {
        // Only a private deterministic staging file may be overwritten after an
        // interrupted metadata write; published metadata is immutable.
        const staging=path.join(directory,'source.json.tmp');if(fs.existsSync(staging))regular(staging);
        const out=fs.openSync(staging,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_TRUNC|(fs.constants.O_NOFOLLOW??0),0o600);
        try{fs.writeFileSync(out,text);fs.fsyncSync(out);}finally{fs.closeSync(out);}
        fs.renameSync(staging,sourceFile);syncDir(directory);
      }
      if(row.state==='sealed')this.#db.prepare("UPDATE results SET state='complete' WHERE id=?").run(id);
      return {source,directory,sourceFile,retryUntil:row.retry_end};
    });
  }
  acknowledge(id,signature) {
    return this.#transaction(()=>{const now=this.#time(),row=this.#row(id);check(['complete','acknowledged'].includes(row.state));
      const expected=JSON.parse(row.expected),payload=resultStoredPayload(expected,{envelopeSHA256:hash(row.envelope),ciphertextSHA256:row.sha,ciphertextBytes:row.bytes});
      check(typeof signature==='string'&&verifyTypedData(payload.domain,payload.types,payload.value,signature)===expected.requester);
      if(row.state==='complete')this.#db.prepare("UPDATE results SET state='acknowledged',ack=?,ack_at=? WHERE id=?").run(signature,now,id);
    });
  }
  status(id) {
    return this.#transaction(()=>{this.#time();const r=this.#row(id);return {id:r.id,approvalDigest:r.digest,state:r.state,
      reservedBytes:r.charge,maxCiphertextBytes:r.max_bytes,receivedBytes:r.received,retryUntil:r.retry_end,
      requesterAcknowledgedStorage:r.ack!==null,qualityAccepted:false,paymentAuthorized:false};});
  }
  list() {return this.#transaction(()=>{this.#time();return this.#db.prepare('SELECT id,digest AS approvalDigest,state,charge AS reservedBytes FROM results ORDER BY id').all();});}
  snapshot() {
    return this.#transaction(()=>{
      const observedAt=this.#time(),records=this.#db.prepare(`SELECT id,digest AS approvalDigest,state,
        charge AS reservedBytes,max_bytes AS maxCiphertextBytes,received AS receivedBytes,
        retry_end AS retryUntil,ack_at AS acknowledgedAt FROM results ORDER BY id`).all();
      return {observedAt,limits:{...this.#settings},reservedBytes:records.reduce((n,r)=>n+r.reservedBytes,0),records};
    });
  }
  usage() {return this.#transaction(()=>{this.#time();const row=this.#db.prepare('SELECT count(*) AS records,coalesce(sum(charge),0) AS reservedBytes FROM results').get();
    return {...row,...this.#settings};});}
  cleanup() {
    // Persist deletion intent before touching any acknowledged files. Complete
    // but unacknowledged results and uncertain executions never expire here.
    const ids=this.#transaction(()=>{const now=this.#time();
      for(const row of this.#db.prepare("SELECT * FROM results WHERE state='reserved' AND service_end<=?").all(now)){
        check(!fs.existsSync(this.#directory(row)));this.#db.prepare('DELETE FROM results WHERE id=?').run(row.id);
      }
      this.#db.prepare("UPDATE results SET state='purging' WHERE state='acknowledged' AND ack_at<=?").run(now-this.#settings.retentionMs);
      return this.#db.prepare("SELECT id FROM results WHERE state='purging'").all();
    });
    for(const {id} of ids)this.#transaction(()=>{this.#time();const row=this.#row(id);check(row.state==='purging'&&row.ack!==null);
      const directory=this.#directory(row);
      if(fs.existsSync(directory)){
        const names=fs.readdirSync(directory);check(names.every(n=>['result.age','source.json','source.json.tmp'].includes(n)));
        for(const name of names){const file=path.join(directory,name);regular(file);fs.unlinkSync(file);}
        fs.rmdirSync(directory);syncDir(this.#root);
      }
      this.#db.prepare('DELETE FROM results WHERE id=?').run(id);
    });return this.usage();
  }
  close(){if(stores.delete(this))this.#db.close();}
}
