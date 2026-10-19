// Owned protocol fixture only: synthetic evidence agent, never a production entry.
// Customer recovery sources and signing keys are absent from this wire contract.
import assert from 'node:assert/strict';
import { GuestEvidenceSession } from '../../compute/guest_session.mjs';
import { GuestWire, serveGuestSession } from '../../compute/result_transport.mjs';
import { guestAgentFixture } from './guest_agent_fixture.mjs';
import { prepareGuestLaunch } from '../../compute/guest_launch.mjs';
import { inspectNativeGuest } from '../../compute/guest_execution.mjs';

let agent,session;const wire=new GuestWire(process.stdin,process.stdout,{timeoutMs:110000});
try {
  const input=await wire.readJSON(256*1024);
  assert.equal(Object.keys(input).sort().join(),'authorities,initialization,request,signedConfiguration');
  const launch=prepareGuestLaunch(input.authorities,input.signedConfiguration,input.initialization,input.request);
  // Reject host-supplied overrides before using the actual contained runtime.
  assert.throws(()=>prepareGuestLaunch(input.authorities,input.signedConfiguration,input.initialization,
    {...input.request,execution:launch.execution}));
  const binding=Object.fromEntries(['packageSHA256','policySHA256','runtimeSHA256','taskSHA256','attempt','rank','worldSize','acceleratorClass']
    .map(k=>[k,launch.initialization.binding[k]]));
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
