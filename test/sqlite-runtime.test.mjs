import test from 'node:test';
import assert from 'node:assert/strict';
import { hasPatchedSQLiteWAL, openDurableDatabase } from '../compute/sqlite_runtime.mjs';

test('WAL runtime gate rejects affected versions and accepts documented fixed branches',()=>{
  for(const version of [undefined,'','3.50.4','3.50.6','3.51.2','3.44.5','3.45.9','3.49.2','3.51.3-custom','3.51','not-a-version'])assert.equal(hasPatchedSQLiteWAL(version),false,String(version));
  for(const version of ['3.51.3','3.50.7','3.44.6','3.52.0','3.53.4'])assert.equal(hasPatchedSQLiteWAL(version),true,version);
});
test('the actual SQLite runtime is patched and the guarded connection uses that library',()=>{
  assert.equal(hasPatchedSQLiteWAL(process.versions.sqlite),true);
  const db=openDurableDatabase(':memory:');
  try{assert.equal(db.prepare('SELECT sqlite_version() AS version').get().version,process.versions.sqlite);}
  finally{db.close();}
});
