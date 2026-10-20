// Local crash-recovery tombstones, not network booking or execution authority.
// A durable consume precedes callback handoff. Unknown outcomes cannot be retried.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes,createHash } from 'node:crypto';
import { openDurableDatabase } from './sqlite_runtime.mjs';

const journals=new WeakSet(),DAY=86400000;
const integer=(n,min,max)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const check=v=>{if(!v)throw Error('Provider dispatch journal unavailable; retain state and reconcile before retrying');};
const route=v=>check(typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v));
const hash=v=>createHash('sha256').update(v).digest('hex');
export function assertPeerDispatchJournal(value){check(journals.has(value));}

export class PeerDispatchJournal {
  #db;#now;#limits;
  // Creation must be explicit. A missing/deleted journal must not silently reset
  // replay protection. Recovery uses the same intact local database and WAL.
  constructor(file,{create=false,maxRecords=4096,retentionMs=7*DAY,now=Date.now}={}) {
    check(typeof file==='string'&&path.isAbsolute(file)&&typeof create==='boolean'&&
      integer(maxRecords,1,65536)&&integer(retentionMs,DAY,30*DAY)&&typeof now==='function');
    const dir=path.dirname(file),parent=fs.lstatSync(dir);check(parent.isDirectory()&&!parent.isSymbolicLink());
    if(create){const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);fs.closeSync(fd);}
    const stat=fs.lstatSync(file);check(stat.isFile()&&!stat.isSymbolicLink()&&stat.nlink===1&&(create||stat.size>0));
    this.#now=now;this.#limits={maxRecords,retentionMs};
    this.#db=openDurableDatabase(file,{timeout:1000});
    try {
      this.#db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;');
      if(create)this.#db.exec(`
        CREATE TABLE dispatch_settings(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL,last_time INTEGER NOT NULL) STRICT;
        CREATE TABLE dispatch_records(route TEXT PRIMARY KEY,expires INTEGER NOT NULL,consumed_at INTEGER NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('consumed','completed','failed')),owner_hash TEXT NOT NULL) STRICT;
        CREATE INDEX dispatch_expiry ON dispatch_records(expires);`);
      this.#transaction(()=>{
        const body=JSON.stringify({schema:'cannabis.peer-dispatch-store.v1',...this.#limits});
        const old=this.#db.prepare('SELECT body FROM dispatch_settings WHERE id=1').get();
        if(create){check(!old);this.#db.prepare('INSERT INTO dispatch_settings VALUES(1,?,0)').run(body);}
        else check(old?.body===body);
        this.#time();
      });
      // Logical entry limits bound metadata. WAL/filesystem overhead still needs
      // an operator disk quota and cannot stand in for ciphertext reservations.
      const pageSize=this.#db.prepare('PRAGMA page_size').get().page_size;
      this.#db.exec(`PRAGMA max_page_count=${Math.ceil((maxRecords*1024+1048576)/pageSize)}; PRAGMA journal_size_limit=1048576;`);
      if(create&&process.platform!=='win32') {
        const fd=fs.openSync(dir,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);
        try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
      }
      journals.add(this);
    } catch(error){this.#db.close();throw error;}
  }
  #transaction(fn) {
    this.#db.exec('BEGIN IMMEDIATE');
    try{const result=fn();this.#db.exec('COMMIT');return result;}
    catch(error){this.#db.exec('ROLLBACK');throw error;}
  }
  #time() {
    const now=this.#now(),old=this.#db.prepare('SELECT last_time FROM dispatch_settings WHERE id=1').get();
    check(integer(now,1,Number.MAX_SAFE_INTEGER-400*DAY)&&old&&now>=old.last_time);
    this.#db.prepare('UPDATE dispatch_settings SET last_time=? WHERE id=1').run(now);return now;
  }
  status(routeId) {
    route(routeId);return this.#transaction(()=>{this.#time();
      const row=this.#db.prepare('SELECT state,expires,consumed_at FROM dispatch_records WHERE route=?').get(routeId);
      return row?{routeId,state:row.state,expiresAt:row.expires,consumedAt:row.consumed_at,
        recoveryRequired:row.state!=='completed',executionVerified:false}:null;
    });
  }
  consume(routeId,expiresAt) {
    route(routeId);const token=randomBytes(32),owner=hash(token);
    this.#transaction(()=>{
      const now=this.#time();check(integer(expiresAt,now+1,now+366*DAY));
      // Expired consent cannot authenticate again. Tombstones outlive its end;
      // deleting a marker never deletes a result or permits a new service term.
      this.#prune(now);
      check(!this.#db.prepare('SELECT 1 FROM dispatch_records WHERE route=?').get(routeId));
      check(this.#db.prepare('SELECT count(*) AS n FROM dispatch_records').get().n<this.#limits.maxRecords);
      this.#db.prepare('INSERT INTO dispatch_records VALUES(?,?,?,?,?)').run(routeId,expiresAt,now,'consumed',owner);
    });
    // Only this successful caller can record the callback outcome. Neither
    // outcome reopens dispatch, proves protected cleanup, or accepts payment.
    return Object.freeze({finish:state=>{
      check(['completed','failed'].includes(state));
      return this.#transaction(()=>{this.#time();
        check(this.#db.prepare("UPDATE dispatch_records SET state=? WHERE route=? AND owner_hash=? AND state='consumed'")
          .run(state,routeId,owner).changes===1);
      });
    }});
  }
  #prune(now) {return this.#db.prepare('DELETE FROM dispatch_records WHERE expires<=?').run(now-this.#limits.retentionMs).changes;}
  cleanup(){return this.#transaction(()=>this.#prune(this.#time()));}
  close(){if(journals.delete(this))this.#db.close();}
}
