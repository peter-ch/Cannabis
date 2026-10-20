// Owned protocol fixture only: synthetic evidence agent, never a production entry.
// Customer recovery sources and signing keys are absent from this wire contract.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { performance } from 'node:perf_hooks';
import { GuestEvidenceSession } from '../../compute/guest_session.mjs';
import { GuestWire, serveGuestSession } from '../../compute/result_transport.mjs';
import { guestAgentFixture } from './guest_agent_fixture.mjs';
import { readRetainedLaunch } from '../../compute/guest_launch.mjs';
import { inspectNativeGuest } from '../../compute/guest_execution.mjs';
import { receiveEncryptedInput } from '../../compute/input_transport.mjs';

let agent,session,wire;
try {
  const started=performance.now(),wallStart=Date.now(),launch=await readRetainedLaunch();
  const remaining=()=>Math.floor(Math.min(launch.transport.timeoutMs-(performance.now()-started),launch.transport.timeoutMs-(Date.now()-wallStart)));
  wire=new GuestWire(process.stdin,process.stdout,{timeoutMs:remaining()});
  const binding=Object.fromEntries(['packageSHA256','policySHA256','runtimeSHA256','taskSHA256','attempt','rank','worldSize','acceleratorClass']
    .map(k=>[k,launch.initialization.binding[k]]));
  assert.equal(fs.existsSync(launch.execution.source.ciphertext),false);
  await receiveEncryptedInput(wire,{destination:launch.execution.source.ciphertext,
    packageSHA256:binding.packageSHA256,maxCiphertextBytes:launch.execution.profile.ciphertext.inputBytes});
  const preflight=inspectNativeGuest(launch.execution,binding,launch.interval,{timeoutMs:30000});
  assert.equal(preflight.controlContained,true);assert.equal(preflight.executionAuthorized,false);
  agent=await guestAgentFixture();
  const options={...launch,expectedBinding:launch.initialization.binding,
    requester:launch.initialization.requester,jobId:launch.initialization.jobId,agentUrl:agent.url};
  if(launch.execution.profile.schema==='cannabis.guest-native-service.v4') {
    // Disposable negative sessions receive no content envelope or appraisal.
    // Their failures must precede helper startup and any key opening.
    for(const version of ['3','5']) {
      const refused=await GuestEvidenceSession.create(options);
      try {
        await assert.rejects(refused.executeNative('no-content-key',{requester:options.requester,jobId:options.jobId,
          domain:{name:'Cannabis confidential key delivery',version,chainId:launch.initialization.binding.chainId,
            verifyingContract:launch.initialization.binding.escrow},value:{}}),
          version==='3'?/group version/:/protected group start/);
      }finally{await refused.close();}
    }
  }
  session=await GuestEvidenceSession.create(options);
  const result=await serveGuestSession(session,wire,{maxCiphertextBytes:4*1024*1024});
  assert.equal(result.requesterAcknowledgedStorage,true);assert.equal(result.paymentAuthorized,false);
  assert.equal(session.status.state,'consumed');
  await assert.rejects(session.executeNative('replayed-delivery',{}),/closed|expired/);
}catch{process.stderr.write('Owned separated guest fixture failed\n');process.exitCode=1;}
finally{await session?.close();await agent?.close();wire?.fail();wire?.close();}
