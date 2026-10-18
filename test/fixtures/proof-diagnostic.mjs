// Disposable test fixture only. Print code locations, never errors containing inputs.
import fs from 'node:fs';
import { generateClaimProof } from '../../claims/identity.mjs';
try {
  const config = JSON.parse(fs.readFileSync(process.argv[2]));
  const membership = JSON.parse(fs.readFileSync(config.membershipFile));
  await generateClaimProof({ ...config, snapshot: membership.snapshot, context: membership.context });
  console.log('Direct fixture proof succeeded');
} catch (error) {
  const frames = String(error.stack).split('\n').slice(1).map(line => line.match(/([a-zA-Z0-9_.-]+\.[cm]?js:\d+:\d+)/)?.[1]).filter(Boolean);
  console.log(JSON.stringify({ failed: true, codeLocations: frames }));
  process.exitCode = 1;
} finally { await globalThis.curve_bn128?.terminate(); }
