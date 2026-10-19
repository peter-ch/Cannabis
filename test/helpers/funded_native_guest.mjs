// Owned protocol fixture only: synthetic evidence agent, never a production entry.
// Customer recovery sources and signing keys are absent from this wire contract.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { GuestEvidenceSession } from '../../compute/guest_session.mjs';
import { GuestWire, serveGuestSession } from '../../compute/result_transport.mjs';
import { guestAgentFixture } from './guest_agent_fixture.mjs';
import { readRetainedLaunch } from '../../compute/guest_launch.mjs';
import { inspectNativeGuest } from '../../compute/guest_execution.mjs';
import { receiveEncryptedInput } from '../../compute/input_transport.mjs';

let agent,session;const wire=new GuestWire(process.stdin,process.stdout,{timeoutMs:110000});
try {
  // Disposable fixture roots only. Production roots have a fixed measured path.
  const launch=readRetainedLaunch(JSON.parse(fs.readFileSync(new URL('./owned-authorities.json',import.meta.url))));
  const binding=Object.fromEntries(['packageSHA256','policySHA256','runtimeSHA256','taskSHA256','attempt','rank','worldSize','acceleratorClass']
    .map(k=>[k,launch.initialization.binding[k]]));
  assert.equal(fs.existsSync(launch.execution.source.ciphertext),false);
  await receiveEncryptedInput(wire,{destination:launch.execution.source.ciphertext,
    packageSHA256:binding.packageSHA256,maxCiphertextBytes:launch.execution.profile.ciphertext.inputBytes});
  const preflight=inspectNativeGuest(launch.execution,binding,launch.interval,{timeoutMs:30000});
  assert.equal(preflight.controlContained,true);assert.equal(preflight.executionAuthorized,false);
  agent=await guestAgentFixture();
  session=await GuestEvidenceSession.create({...launch,expectedBinding:launch.initialization.binding,
    requester:launch.initialization.requester,jobId:launch.initialization.jobId,agentUrl:agent.url});
  const result=await serveGuestSession(session,wire,{maxCiphertextBytes:4*1024*1024});
  assert.equal(result.requesterAcknowledgedStorage,true);assert.equal(result.paymentAuthorized,false);
  assert.equal(session.status.state,'consumed');
  await assert.rejects(session.executeNative('replayed-delivery',{}),/closed|expired/);
}catch{process.stderr.write('Owned separated guest fixture failed\n');process.exitCode=1;}
finally{session?.close();await agent?.close();wire.fail();wire.close();}
