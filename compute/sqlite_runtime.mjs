// Reject runtimes affected by SQLite's documented concurrent WAL-reset bug
// before opening a persistent requester, reservation or service database.
import { DatabaseSync } from 'node:sqlite';

export function hasPatchedSQLiteWAL(version) {
  if(typeof version!=='string'||!/^\d+\.\d+\.\d+$/.test(version))return false;
  const [major,minor,patch]=version.split('.').map(Number);
  if(![major,minor,patch].every(Number.isSafeInteger))return false;
  return major>3||major===3&&(minor>51||minor===51&&patch>=3||minor===50&&patch>=7||minor===44&&patch>=6);
}
export function openDurableDatabase(file,options={}) {
  if(!hasPatchedSQLiteWAL(process.versions.sqlite))throw Error('A patched SQLite runtime is required before opening this database. Use the pinned Cannabis Node tools.');
  return new DatabaseSync(file,options);
}
