// Requester-local recovery only. No booking, payment or execution authority.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {openDurableDatabase} from '../compute/sqlite_runtime.mjs';

export const workflowCheck=v=>{if(!v)throw Error('Requester workflow changed or needs recovery; retain its local files');};
const check=workflowCheck;
export const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?
  '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
export const sha=v=>createHash('sha256').update(v).digest('hex');
export function readWorkflowJSON(file,limit=16*1024*1024) {
  check(typeof file==='string'&&path.isAbsolute(file));
  const prior=fs.lstatSync(file);check(prior.isFile()&&!prior.isSymbolicLink());
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try {const s=fs.fstatSync(fd);check(s.isFile()&&s.ino===prior.ino&&s.dev===prior.dev&&s.size>0&&s.size<=limit);
    const bytes=Buffer.alloc(s.size+1);let count=0,n;
    while(count<bytes.length&&(n=fs.readSync(fd,bytes,count,bytes.length-count,null)))count+=n;
    check(count===s.size);return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,count)));
  }finally{fs.closeSync(fd);}
}
export function privateDirectory(directory) {
  check(typeof directory==='string'&&path.isAbsolute(directory));
  const s=fs.lstatSync(directory),real=fs.realpathSync.native(directory),resolved=path.resolve(directory);
  check(s.isDirectory()&&!s.isSymbolicLink()&&(process.platform==='win32'?real.toLowerCase()===resolved.toLowerCase():real===resolved));
  return real;
}
function syncDirectory(dir) {
  if(process.platform==='win32')return;
  const fd=fs.openSync(dir,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
export function saveWorkflowJSON(file,value) {
  const parent=privateDirectory(path.dirname(file)),bytes=Buffer.from(canonical(value)+'\n');check(bytes.length<=16*1024*1024);
  const temp=path.join(parent,'.pending-'+randomBytes(16).toString('hex'));
  let fd;
  try {fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);
    fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    // Exclusive publication: existing recovery material is never overwritten.
    fs.linkSync(temp,file);fs.unlinkSync(temp);syncDirectory(parent);
  }finally{if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(temp))fs.unlinkSync(temp);}
}

export class WorkflowStore {
  #db;#now;#closed=false;
  constructor(file,manifest,{create=false,clock=()=>Math.floor(Date.now()/1000)}={}) {
    check(path.isAbsolute(file)&&typeof clock==='function');privateDirectory(path.dirname(file));
    const body=canonical(manifest);check(Buffer.byteLength(body)<=16*1024*1024&&manifest.reservations.length>0&&manifest.reservations.length<=64);
    check(new Set(manifest.reservations.map(r=>r.reservationId)).size===manifest.reservations.length);
    this.#now=clock;
    if(create){const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);fs.closeSync(fd);}
    const stat=fs.lstatSync(file);check(stat.isFile()&&!stat.isSymbolicLink()&&stat.nlink===1&&(create||stat.size>0));
    this.#db=openDurableDatabase(file,{timeout:1000});
    try {
      this.#db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;');
      if(create)this.#db.exec(`CREATE TABLE workflow_settings(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL,last_time INTEGER NOT NULL) STRICT;
        CREATE TABLE workflow_slots(id TEXT PRIMARY KEY,state TEXT NOT NULL CHECK(state IN ('queued','uncertain','stored')),
          release_id TEXT,owner_hash TEXT,approval_digest TEXT,receipt_hash TEXT) STRICT;`);
      this.#tx(()=>{
        if(create) {
          this.#db.prepare('INSERT INTO workflow_settings VALUES(1,?,0)').run(body);
          for(const r of manifest.reservations)this.#db.prepare("INSERT INTO workflow_slots VALUES(?,'queued',NULL,NULL,NULL,NULL)").run(r.reservationId);
        }
        check(this.#db.prepare('SELECT body FROM workflow_settings WHERE id=1').get()?.body===body);this.#time();
      });
      this.#db.exec('PRAGMA max_page_count=8192; PRAGMA journal_size_limit=1048576;');
      if(create)syncDirectory(path.dirname(file));
    }catch(e){this.#db.close();throw e;}
  }
  #tx(fn) {check(!this.#closed);this.#db.exec('BEGIN IMMEDIATE');
    try{const v=fn();this.#db.exec('COMMIT');return v;}catch(e){this.#db.exec('ROLLBACK');throw e;}}
  #time() {const now=this.#now(),old=this.#db.prepare('SELECT last_time FROM workflow_settings WHERE id=1').get();
    check(Number.isSafeInteger(now)&&now>0&&old&&now>=old.last_time);this.#db.prepare('UPDATE workflow_settings SET last_time=? WHERE id=1').run(now);return now;}
  snapshot(){return this.#tx(()=>{this.#time();return this.#db.prepare('SELECT id AS reservationId,state,release_id AS releaseId,approval_digest AS approvalDigest,receipt_hash AS receiptSHA256 FROM workflow_slots ORDER BY id').all();});}
  claim(reservationId) {
    const owner=sha(randomBytes(32)),releaseId='0x'+randomBytes(32).toString('hex');
    this.#tx(()=>{this.#time();check(this.#db.prepare("UPDATE workflow_slots SET state='uncertain',release_id=?,owner_hash=? WHERE id=? AND state='queued'").run(releaseId,owner,reservationId).changes===1);});
    // Unknown outcomes remain consumed, including crashes before the first frame.
    return Object.freeze({releaseId,approval:digest=>this.#tx(()=>{this.#time();check(/^0x[0-9a-f]{64}$/.test(digest));
      check(this.#db.prepare("UPDATE workflow_slots SET approval_digest=? WHERE id=? AND owner_hash=? AND state='uncertain' AND approval_digest IS NULL").run(digest,reservationId,owner).changes===1);})});
  }
  stored(reservationId,releaseId,approvalDigest,receiptSHA256) {
    check(/^0x[0-9a-f]{64}$/.test(approvalDigest)&&/^[0-9a-f]{64}$/.test(receiptSHA256));
    return this.#tx(()=>{this.#time();const row=this.#db.prepare('SELECT * FROM workflow_slots WHERE id=?').get(reservationId);
      check(row?.release_id===releaseId&&row.state!=='queued'&&(!row.approval_digest||row.approval_digest===approvalDigest)&&(!row.receipt_hash||row.receipt_hash===receiptSHA256));
      this.#db.prepare("UPDATE workflow_slots SET state='stored',approval_digest=?,receipt_hash=? WHERE id=?").run(approvalDigest,receiptSHA256,reservationId);
    });
  }
  close(){if(!this.#closed){this.#closed=true;this.#db.close();}}
}
