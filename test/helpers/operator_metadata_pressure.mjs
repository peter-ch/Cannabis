// SQLite WAL pressure on a disposable bounded filesystem, never a real store.
import fs from 'node:fs';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
const directory=process.argv[2],file=path.join(directory,'owned-pressure.sqlite');
if(!path.isAbsolute(directory)||fs.existsSync(file))throw Error('Require a fresh owned pressure file');
const writer=new DatabaseSync(file),reader=new DatabaseSync(file);let committed=0,refused=false;
try{
  writer.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=0; CREATE TABLE owned(id INTEGER PRIMARY KEY,body BLOB) STRICT;');
  writer.prepare('INSERT INTO owned VALUES(0,?)').run(Buffer.from('retained sentinel'));
  reader.exec('BEGIN');reader.prepare('SELECT count(*) AS n FROM owned').get();
  const payload=Buffer.alloc(1024*1024,37);
  for(let n=1;n<=128;n++){
    try{writer.prepare('INSERT INTO owned VALUES(?,?)').run(n,payload);committed=n;}
    catch(error){if(!['SQLITE_FULL','SQLITE_IOERR_WRITE','SQLITE_IOERR_FSYNC'].includes(error.errstr)&&
      !/full|disk|I\/O/i.test(error.message))throw error;refused=true;break;}
  }
  if(!refused||committed<1)throw Error('Expected physical metadata ceiling');
  reader.exec('ROLLBACK');reader.close();writer.close();
  // This fixture simulates offline administrative recovery after every DB
  // handle is closed. Production reserve release requires the stopped unit and
  // an exclusive lease; no application action can reclaim that reserved space.
  if(!/^\/var\/lib\/cannabis-(boundary|metadata)-check-[0-9a-f]{32}\//.test(directory))throw Error('Require owned recovery fixture');
  const reserve=path.resolve(directory,'../../recovery.reserve'),info=fs.lstatSync(reserve);
  if(!info.isFile()||info.isSymbolicLink()||info.size<16*1024**2)throw Error('Missing owned reserve');
  fs.truncateSync(reserve,0);
  const reopened=new DatabaseSync(file);
  try{
    if(reopened.prepare('PRAGMA integrity_check').get().integrity_check!=='ok'||
      Buffer.from(reopened.prepare('SELECT body FROM owned WHERE id=0').get().body).toString()!=='retained sentinel'||
      reopened.prepare('SELECT count(*) AS n FROM owned').get().n!==committed+1)throw Error('Committed metadata changed under pressure');
  }finally{reopened.close();}
  console.log(JSON.stringify({physicalCeilingRefused:true,committedRowsPreserved:true,integrityVerified:true,recoveredWithReservedSpace:true,committed}));
}catch(error){try{reader.close();}catch{}try{writer.close();}catch{}throw error;}
