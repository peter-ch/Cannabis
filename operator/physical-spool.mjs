// Selected Linux root-managed result volume. This bounds ordinary-host
// ciphertext storage; it grants no confidential-execution or payment authority.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { ResultSpool } from './result-spool.mjs';

const stores=new WeakSet(),helper=fileURLToPath(new URL('./result_volume.py',import.meta.url));
const check=v=>{if(!v)throw Error('Physical encrypted result storage unavailable; preserve the volume and reconcile');};
function inspect(home,entries) {
  check(process.platform==='linux'&&process.geteuid()===0);
  const args=['-I','-B',helper,'inspect',home];if(entries!==undefined)args.push('--layout');
  const run=spawnSync('/usr/bin/python3',args,{input:entries===undefined?'':JSON.stringify(entries),encoding:'utf8',
    env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin',LANG:'C.UTF-8'},timeout:5000,maxBuffer:16384,windowsHide:true});
  check(!run.error&&run.status===0&&run.stderr==='');
  const value=JSON.parse(run.stdout);check(value.schema==='cannabis.result-volume-observation.v1');
  if(entries!==undefined)check(value.capacityChecked===true);
  return value;
}
const identity=v=>JSON.stringify([v.mountId,v.rootDevice,v.rootInode,v.imageDevice,v.imageInode,v.limits]);
export function assertPhysicalResultSpool(value){check(stores.has(value));}

export class PhysicalResultSpool extends ResultSpool {
  #home;#identity;#directoryFd;
  constructor(directory,{create=false,retentionMs,...unsupported}={}) {
    check(Object.keys(unsupported).length===0&&typeof directory==='string'&&path.isAbsolute(directory));
    check(path.basename(directory)==='spool'&&path.basename(path.dirname(directory))==='mount');
    const home=path.dirname(path.dirname(directory)),before=inspect(home);
    const fd=fs.openSync(directory,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
    try {
      const held=fs.fstatSync(fd);check(held.dev===before.rootDevice&&held.ino===before.rootInode);
      super(directory,{create,maxBytes:before.limits.maxBytes,maxRecords:before.limits.maxRecords,retentionMs});
    }catch(error){fs.closeSync(fd);throw error;}
    this.#home=home;this.#identity=identity(before);this.#directoryFd=fd;
    try{this.checkCapacity();stores.add(this);}catch(error){this.close();throw error;}
  }
  checkCapacity() {
    check(this.#directoryFd!==undefined);
    return this.withStorageLayout(entries=>{
      const value=inspect(this.#home,entries);check(identity(value)===this.#identity);return value;
    });
  }
  reserve(request,signal){this.checkCapacity();return super.reserve(request,signal);}
  dispatch(handle){this.checkCapacity();return super.dispatch(handle);}
  close() {
    stores.delete(this);
    try{super.close();}finally{if(this.#directoryFd!==undefined){fs.closeSync(this.#directoryFd);this.#directoryFd=undefined;}}
  }
}
