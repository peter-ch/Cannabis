import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { compile } from './compile.mjs';
import { startNode, deployLocal, localSources, closeProver, runtime } from './lib.mjs';
import { createServer } from './server.mjs';

async function portFree(port) {
  await new Promise((resolve, reject) => {
    const server = net.createServer(); server.once('error', reject);
    server.listen(port, '127.0.0.1', () => server.close(resolve));
  });
}
await portFree(8545); await portFree(4200);
const artifacts = compile(localSources);
const { child, provider, rpc } = await startNode();
let server;
let stopping = false;
function stop() {
  if (stopping) return; stopping = true;
  server?.close(); provider.destroy(); child.kill();
  closeProver().catch(() => {});
}
process.on('SIGINT', stop); process.on('SIGTERM', stop);
try {
  const { token, start, end, founder, registrar, semaphore, enrollment } = await deployLocal(provider, artifacts);
  const state = { rpc, address: await token.getAddress(), vesting: await token.founderVesting(), start, end, founder, registrar,
    semaphore: await semaphore.getAddress(), enrollment: await enrollment.getAddress(), verification: 'LOCAL_MOCK_ONLY', network: 'local-devnet', chainId: 31337 };
  fs.writeFileSync(path.join(runtime, 'deployment.json'), JSON.stringify(state, null, 2));
  server = createServer({ provider, token, state, vestingAbi: artifacts.FounderVesting.abi });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(4200, '127.0.0.1', resolve); });
  fs.writeFileSync(path.join(runtime, 'processes.json'), JSON.stringify({ supervisor: process.pid, node: child.pid, url: 'http://127.0.0.1:4200' }, null, 2));
  child.once('exit', () => { if (!stopping) { console.error('Local node stopped'); stop(); process.exitCode = 1; } });
  console.log('Cannabis claims development: http://127.0.0.1:4200');
  console.log('Development chain. State resets on restart. Stop with Ctrl+C.');
} catch (error) { stop(); throw error; }
