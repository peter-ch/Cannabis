// Startup-selected Node journal and configuration. Shared controller logic is
// also used by the independent browser client, without exposing this file API.
import fs from 'node:fs';
import path from 'node:path';
import {marketConfiguration,check} from './market-plan.mjs';
import {MarketJournal} from './market-journal.mjs';
import {MarketController} from './market-controller.mjs';
export function readMarketConfiguration(file) {
  check(typeof file==='string'&&path.isAbsolute(file));const s=fs.lstatSync(file);check(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<=16384);
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW??0));
  try{const actual=fs.fstatSync(fd);check(actual.ino===s.ino&&actual.dev===s.dev&&actual.size<=16384);
    const bytes=Buffer.alloc(16385);let size=0,n;while(size<bytes.length&&(n=fs.readSync(fd,bytes,size,bytes.length-size,null))>0)size+=n;
    check(size<=16384);return marketConfiguration(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,size))));}
  finally{fs.closeSync(fd);}
}
export class MarketConsole extends MarketController {
  constructor(configuration,journalFile,options={}) {
    const journal=new MarketJournal(journalFile,configuration);
    try {super(configuration,journal,options);}catch(error){journal.close();throw error;}
  }
}
