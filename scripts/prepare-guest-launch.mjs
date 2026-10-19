// Local review data only. Never signs, provisions, releases a key or starts work.
import path from 'node:path';
import { readLaunchJSON, validateLaunchAuthorities, encodeLaunchJSON, launchConfigurationPayload, verifyLaunchConfiguration } from '../compute/guest_launch.mjs';
try {
  const [action,authorityFile,configurationFile]=process.argv.slice(2);
  if(!['authorities','prepare','verify'].includes(action)||!authorityFile||process.argv.length>(action==='authorities'?4:5))throw Error('Arguments');
  const authorities=validateLaunchAuthorities(readLaunchJSON(path.resolve(authorityFile),{limit:65536}));
  if(action==='authorities')process.stdout.write(encodeLaunchJSON(authorities));
  else {
    if(!configurationFile)throw Error('Configuration required');
    const input=readLaunchJSON(path.resolve(configurationFile));
    const result=action==='prepare'?launchConfigurationPayload(authorities,input):verifyLaunchConfiguration(authorities,input);
    console.log(JSON.stringify({...result,executionAuthorized:false,hardwareValidated:false},null,2));
  }
}catch{console.error(JSON.stringify({error:'Guest launch preparation failed; review the canonical files, authority signatures and validity window.'}));process.exitCode=1;}
