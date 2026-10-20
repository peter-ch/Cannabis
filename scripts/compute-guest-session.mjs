// Fixed measured entry. No universal signer, host-selected service executable,
// configuration override, sample agent or customer-key export option.
import { performance } from 'node:perf_hooks';
import path from 'node:path';
import { readRetainedLaunch } from '../compute/guest_launch.mjs';
import { inspectNativeGuest } from '../compute/guest_execution.mjs';
import { InitializedGuestControlPlane } from '../compute/guest_bootstrap.mjs';
import { GuestWire, serveGuestSession } from '../compute/result_transport.mjs';
import { receiveEncryptedInput } from '../compute/input_transport.mjs';

let control,wire;
try {
  if(process.platform!=='linux'||process.getuid()!==0||process.argv.length!==2||process.stdin.isTTY||process.stdout.isTTY)throw Error('Entry conditions');
  const start=performance.now(),wallStart=Date.now();
  const launch=await readRetainedLaunch();
  const expires=wallStart+launch.transport.timeoutMs;
  const remaining=()=>Math.floor(Math.min(expires-Date.now(),launch.transport.timeoutMs-(performance.now()-start)));
  const binding=Object.fromEntries(['packageSHA256','policySHA256','runtimeSHA256','taskSHA256','attempt','rank','worldSize','acceleratorClass']
    .map(k=>[k,launch.initialization.binding[k]]));
  wire=new GuestWire(process.stdin,process.stdout,{timeoutMs:remaining()});
  await receiveEncryptedInput(wire,{destination:launch.execution.source.ciphertext,
    packageSHA256:binding.packageSHA256,maxCiphertextBytes:launch.execution.profile.ciphertext.inputBytes});
  if(launch.dependency)await receiveEncryptedInput(wire,{destination:path.join(path.dirname(launch.execution.source.ciphertext),'dependency.age'),
    packageSHA256:launch.dependency.signed.handoff.ciphertextSHA256,maxCiphertextBytes:launch.execution.profile.ciphertext.dependencyBytes});
  // No session/channel key exists until actual containment, storage, ciphertext
  // commitment and runtime inspection. Execution repeats admission before keys.
  inspectNativeGuest(launch.execution,binding,launch.interval,{timeoutMs:Math.min(60000,remaining()),dependency:launch.dependency});
  control=await InitializedGuestControlPlane.start({...launch.bootstrap,assignment:launch.initialization},
    {timeoutMs:Math.min(20000,remaining()),signal:wire.signal});
  const session=await control.createSession({policy:launch.policy,challenge:launch.challenge,funding:launch.funding,execution:launch.execution,dependency:launch.dependency});
  await serveGuestSession(session,wire,{maxCiphertextBytes:launch.transport.maxCiphertextBytes});
}catch{process.stderr.write('Configured guest session failed; retire the whole job\n');process.exitCode=1;}
finally{
  try{await control?.close();}catch{process.exitCode=1;}
  wire?.fail();wire?.close();
}
