// Explicit fresh journal initialization. Never resets an existing database.
import path from 'node:path';
import {readMarketConfiguration} from '../operator/market-console.mjs';
import {MarketJournal} from '../operator/market-journal.mjs';
const [configuration,journal,...extra]=process.argv.slice(2);
if(extra.length||!configuration||!journal||!path.isAbsolute(configuration)||!path.isAbsolute(journal))
  throw Error('Usage: node scripts/prepare-market-state.mjs ABSOLUTE_CONFIGURATION ABSOLUTE_NEW_JOURNAL');
const store=new MarketJournal(journal,readMarketConfiguration(configuration),{create:true});
try{console.log(JSON.stringify({schema:'cannabis.market-initialization.v1',initialized:true,plans:store.snapshot().plans.length,
  transactionSubmitted:false,hardwareValidated:false}));}finally{store.close();}
