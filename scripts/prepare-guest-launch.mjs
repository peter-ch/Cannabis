// Public participant review only. Never signs, provisions or releases a key.
import path from 'node:path';
import { readLaunchJSON } from '../compute/guest_launch.mjs';
import { launchConsentPayload, inspectLaunchConsent, readLaunchConsentState } from '../compute/guest_consent.mjs';
try {
  const [action,...args]=process.argv.slice(2);
  const read=(file,limit)=>readLaunchJSON(path.resolve(file),{limit});
  let result;
  if(action==='prepare'&&args.length===4&&['requester','provider'].includes(args[0])) {
    const [role,configurationFile,initializationFile,proofFile]=args;
    result=launchConsentPayload(read(configurationFile,256*1024),read(initializationFile,65536),read(proofFile,1024*1024),role);
  } else if(['inspect','verify'].includes(action)&&args.length===3) {
    const [signedFile,initializationFile,proofFile]=args;
    const signed=read(signedFile,256*1024),initialization=read(initializationFile,65536),proof=read(proofFile,1024*1024);
    if(action==='verify')result=await readLaunchConsentState(signed,initialization,proof);
    else {
      const c=inspectLaunchConsent(signed,initialization,proof);
      result={configurationSHA256:c.configurationSHA256,assignmentSHA256:c.assignmentSHA256,
        bookingId:c.reservation.reservationId,approvals:c.approvals,chainVerified:false};
    }
  } else throw Error('Arguments');
  console.log(JSON.stringify({...result,executionAuthorized:false,keyReleaseAuthorized:false,hardwareValidated:false},null,2));
}catch{console.error(JSON.stringify({error:'Launch review failed; use prepare ROLE CONFIG INITIALIZATION PROOF, or inspect/verify CONSENT INITIALIZATION PROOF with canonical files.'}));process.exitCode=1;}
