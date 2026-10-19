// Disposable Linux filesystem checkpoint. No live custody, hardware or payment.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash,randomBytes } from 'node:crypto';
import { TypedDataEncoder } from 'ethers';
import { PhysicalResultSpool,assertPhysicalResultSpool } from '../../operator/physical-spool.mjs';
import { ResultSpool } from '../../operator/result-spool.mjs';
import { openDurableDatabase } from '../../compute/sqlite_runtime.mjs';
import { deliveryApprovalTypes } from '../../compute/key_delivery.mjs';
import { approvedBrowserFixture } from '../fixtures/approved-browser.mjs';

const [mode,home,recordFile]=process.argv.slice(2),mount=path.join(home,'mount'),directory=path.join(mount,'spool');
const hash=v=>createHash('sha256').update(v).digest('hex');
let spool;
try {
  if(mode==='recover') {
    const record=JSON.parse(fs.readFileSync(recordFile,'utf8'));
    spool=new PhysicalResultSpool(directory);
    assertPhysicalResultSpool(spool);
    const retained=spool.recover(record.id);
    assert.equal(hash(fs.readFileSync(retained.source.ciphertext)),record.ciphertextSHA256);
    assert.equal(hash(fs.readFileSync(retained.sourceFile)),record.metadataSHA256);
    assert.equal(spool.status(record.id).state,'complete');
    assert.equal(spool.checkCapacity().capacityChecked,true);
    process.stdout.write(JSON.stringify({remountedRecovery:true,immutableReceipt:true,unacknowledgedResultRetained:true})+'\n');
  } else {
    assert.equal(mode,'exercise');
    const plain=path.join(path.dirname(home),'plain');fs.mkdirSync(plain,{mode:0o700});
    const logical=new ResultSpool(plain,{create:true});
    try{assert.throws(()=>assertPhysicalResultSpool(logical));assert.throws(()=>new PhysicalResultSpool(plain));}
    finally{logical.close();}
    spool=new PhysicalResultSpool(directory,{create:true});
    const observation=spool.checkCapacity();assert.equal(observation.capacityChecked,true);
    const f=await approvedBrowserFixture(),expected=f.bundle.entries[0].approval,envelope=f.bundle.entries[0].envelope;
    const bytes=Buffer.from(f.encrypted[0]),request={expected,maxCiphertextBytes:1024**2,serviceEnd:Math.floor(Date.now()/1000)+600};
    const r=spool.reserve(request);spool.dispatch(r);spool.begin(r,{resultEnvelope:envelope,ciphertextBytes:bytes.length});
    for(let i=0;i<bytes.length;i+=65536)spool.append(r,bytes.subarray(i,i+65536));
    const retained=spool.seal(r,hash(bytes));
    const metadataSHA256=hash(fs.readFileSync(retained.sourceFile));
    const second=structuredClone(expected),types=deliveryApprovalTypes(second.domain.version);
    second.value.nonce='0x'+randomBytes(32).toString('hex');second.digest=TypedDataEncoder.hash(second.domain,types,second.value);
    second.requesterSignature=await f.owner.signTypedData(second.domain,types,second.value);
    const next={...request,expected:second};

    // A reader pins rollback pages: writes must refuse on timeout, never grow a
    // WAL outside the volume budget or report an uncommitted reservation.
    const reader=openDurableDatabase(path.join(directory,'spool.sqlite'));
    try {
      assert.equal(reader.prepare('PRAGMA journal_mode').get().journal_mode,'delete');
      reader.exec('BEGIN');reader.prepare('SELECT * FROM spool_settings').all();
      assert.throws(()=>spool.reserve(next));
      assert.equal(fs.existsSync(path.join(directory,'spool.sqlite-wal')),false);
      reader.exec('ROLLBACK');
    }finally{reader.close();}
    const reserved=spool.reserve(next);

    const pressure=path.join(mount,'owned-pressure');fs.mkdirSync(pressure,{mode:0o700});
    assert.equal(fs.statSync(pressure).dev,fs.statSync(directory).dev);
    const padding=path.join(pressure,'blocks'),fd=fs.openSync(padding,'wx',0o600);let exhausted=false;
    try {
      const chunk=Buffer.alloc(1024**2,0x57);let total=0;
      try{while(total<=observation.limits.imageBytes){total+=fs.writeSync(fd,chunk);}}
      catch(error){assert.equal(error.code,'ENOSPC');exhausted=true;}
      assert.equal(exhausted,true);fs.fsyncSync(fd);
      assert.throws(()=>spool.dispatch(reserved));
      assert.equal(hash(fs.readFileSync(retained.sourceFile)),metadataSHA256);
      assert.equal(hash(fs.readFileSync(retained.source.ciphertext)),hash(bytes));
    }finally{fs.closeSync(fd);fs.unlinkSync(padding);}
    assert.equal(spool.status(reserved.id).state,'reserved');
    assert.equal(spool.checkCapacity().capacityChecked,true);

    const names=[];exhausted=false;
    try {
      const limit=spool.checkCapacity().availableInodes+1;
      for(let i=0;i<=limit;i++) {
        const name=path.join(pressure,String(i));
        try{const opened=fs.openSync(name,'wx',0o600);fs.closeSync(opened);names.push(name);}
        catch(error){assert.equal(error.code,'ENOSPC');exhausted=true;break;}
      }
      assert.equal(exhausted,true);assert.throws(()=>spool.dispatch(reserved));
    }finally{for(const name of names)fs.unlinkSync(name);fs.rmdirSync(pressure);}
    assert.equal(spool.status(reserved.id).state,'reserved');
    assert.equal(spool.cancelUnused(reserved),true);
    const foreign=path.join(directory,'unregistered');fs.writeFileSync(foreign,'owned fixture',{flag:'wx',mode:0o600});
    try{assert.throws(()=>spool.checkCapacity());}finally{fs.unlinkSync(foreign);}

    // The retained directory descriptor keeps a live store's mount busy.
    const helper=fileURLToPath(new URL('../../operator/result_volume.py',import.meta.url));
    const busy=spawnSync('/usr/bin/python3',['-I','-B',helper,'unmount',home],{encoding:'utf8',timeout:10000,maxBuffer:16384});
    assert.equal(busy.status,1);assert.equal(spool.checkCapacity().capacityChecked,true);
    const recovered=spool.recover(r.id);assert.equal(hash(fs.readFileSync(recovered.sourceFile)),metadataSHA256);
    fs.writeFileSync(recordFile,JSON.stringify({id:r.id,ciphertextSHA256:hash(bytes),metadataSHA256}),{flag:'wx',mode:0o600});
    process.stdout.write(JSON.stringify({physicalReservation:true,plainStoreRefused:true,heldReaderBounded:true,
      diskFullDispatchRefused:true,inodeExhaustionDispatchRefused:true,unknownFileRefused:true,
      liveUnmountRefused:true,completeCopyPreserved:true})+'\n');
  }
}finally{spool?.close();}
