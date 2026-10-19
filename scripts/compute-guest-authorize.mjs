// Fixed public-only preallocation check. It creates no evidence/session key.
import { readLaunchJSON, readRetainedLaunch, publicLaunchAdmission } from '../compute/guest_launch.mjs';
try {
  if(process.platform!=='linux'||process.getuid()!==0||process.argv.length!==2||process.stdout.isTTY)throw Error('Entry conditions');
  const launch=readRetainedLaunch(readLaunchJSON('/opt/cannabis/launch-authorities.json',{limit:65536,trusted:true}));
  process.stdout.write(JSON.stringify(publicLaunchAdmission(launch))+'\n');
}catch{process.stderr.write('Public guest launch authorization failed\n');process.exitCode=1;}
