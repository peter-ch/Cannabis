// Isolated operator workflow exercise. Fixtures never connect to a public chain.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { ContractFactory, keccak256, toUtf8Bytes, parseEther } from 'ethers';
import { generateProof } from '@semaphore-protocol/proof';
import { compile } from './compile.mjs';
import { startNode, deployLocal, localSources, localIdentity, localGroup, closeProver, runtime } from './lib.mjs';

async function provingArtifact(extension, bytes, sha256) {
  const file = path.join(runtime, 'activity-semaphore-7.' + extension);
  let data;
  if (fs.existsSync(file)) {
    if (!fs.lstatSync(file).isFile() || fs.statSync(file).size !== bytes) throw Error('Unexpected cached proving artifact');
    data = fs.readFileSync(file);
  } else {
    const response = await fetch('https://snark-artifacts.pse.dev/semaphore/4.13.0/semaphore-7.' + extension,
      { redirect: 'error', signal: AbortSignal.timeout(30000) });
    if (!response.ok || !response.body) throw Error('Proving artifact unavailable');
    const chunks = []; let size = 0;
    for await (const chunk of response.body) { size += chunk.length; if (size > bytes) throw Error('Oversized proving artifact'); chunks.push(chunk); }
    data = Buffer.concat(chunks);
  }
  if (data.length !== bytes || createHash('sha256').update(data).digest('hex') !== sha256) throw Error('Proving artifact pin mismatch');
  if (!fs.existsSync(file)) fs.writeFileSync(file, data, { flag: 'wx', mode: 0o600 });
  return data;
}

if (process.argv.length !== 2) throw Error('This runner takes no endpoint, key, identity or public-network arguments');
const port = await new Promise(resolve => { const server = net.createServer(); server.listen(0, '127.0.0.1', () => { const p = server.address().port; server.close(() => resolve(p)); }); });
let node;
const hash = text => keccak256(toUtf8Bytes(text));
const runId = new Date().toISOString().replace(/[:.]/g, '-');
try {
  console.log('Cannabis local workflow exercise. All participants and orders below are explicitly synthetic.');
  const artifacts = compile(localSources);
  node = await startNode(port, 'activity-' + runId + '.log');
  const provider = node.provider;
  if ((await provider.getNetwork()).chainId !== 31337n || new URL(node.rpc).hostname !== '127.0.0.1') throw Error('Local chain required');
  const { token, start } = await deployLocal(provider, artifacts, { delay: 1000 });
  const [founder, requester, worker, adjudicator] = await Promise.all([0, 1, 3, 4].map(i => provider.getSigner(i)));
  const requesterAddress = await requester.getAddress(), workerAddress = await worker.getAddress();
  const wasm = await provingArtifact('wasm', 1810182, '3ba75768d5dfbee9d52b732b69eefb1725c8c356a3de9c2f2a71dbc401a0ea61');
  const zkey = await provingArtifact('zkey', 2113447, 'd77851ee4bd496c6b5f70fbfa550f113a89bad972efd4c541267e566163d0600');
  const proof = await generateProof(localIdentity(1), localGroup(128), BigInt(requesterAddress), await token.claimScope(), 7, { wasm, zkey });
  await provider.send('evm_setNextBlockTimestamp', [start + 1]); await provider.send('evm_mine', []);
  const claimReceipt = await (await token.connect(requester).claim(requesterAddress, proof)).wait();
  if (await token.balanceOf(requesterAddress) !== parseEther('420')) throw Error('Local claim failed');
  console.log('Local membership and anonymous claim path passed. Verified real people: 0.');
  const escrow = await new ContractFactory(artifacts.ComputeEscrow.abi, artifacts.ComputeEscrow.bytecode, founder)
    .deploy(await token.getAddress(), await founder.getAddress());
  const escrowReceipt = await escrow.deploymentTransaction().wait();
  const budget = parseEther('100');
  await (await token.connect(requester).approve(await escrow.getAddress(), budget)).wait();
  const now = (await provider.getBlock('latest')).timestamp;
  const terms = { jobHash: hash('Cannabis labeled local arithmetic workflow ' + runId), budget, deliveryManager: workerAddress,
    adjudicator: await adjudicator.getAddress(), acceptBy: now + 300, deliverBy: now + 900, reviewSeconds: 86400, disputeSeconds: 86400 };
  const funded = await (await escrow.connect(requester).fund(terms, [workerAddress], [10000])).wait();
  const order = await escrow.orderId(requesterAddress, terms.jobHash);
  await (await escrow.connect(worker).accept(order)).wait();
  // Tiny deterministic arithmetic fixture; not confidential worker operation or market demand.
  const result = [1, 2, 3, 4].reduce((sum, value, index) => sum + value * [5, 6, 7, 8][index], 0);
  if (result !== 70) throw Error('Arithmetic result mismatch');
  await (await escrow.connect(worker).deliver(order, hash(JSON.stringify({ fixture: true, result })))).wait();
  await (await escrow.connect(requester).approve(order)).wait();
  if (await escrow.workerDue(order, workerAddress) !== parseEther('99') || await escrow.credits(await founder.getAddress()) !== parseEther('1')) throw Error('Fee split mismatch');
  await (await escrow.connect(worker).withdrawWorker(order, workerAddress)).wait();
  await (await escrow.connect(founder).withdrawCredit(await founder.getAddress())).wait();
  if (await escrow.totalLiability() !== 0n || await token.balanceOf(workerAddress) !== parseEther('99') || await token.balanceOf(await founder.getAddress()) !== parseEther('1')) throw Error('Settlement mismatch');
  const report = { schema: 'cannabis.local-workflow-exercise.v1', checkedAt: new Date().toISOString(),
    classification: 'LABELED_LOCAL_FIXTURES_ONLY', chainId: '31337', fixtureCommitments: 128,
    verifiedRealPeople: 0, publicClaims: 0, publicOrders: 0, customerDemand: false, mainnetSpending: false,
    confidentialExecutionEstablished: false, claimPathPassed: true, arithmeticResultMatched: true,
    acceptedJobSettlementPassed: true, founderFeeBasisPoints: 100, liabilitiesCleared: true,
    localGasOnly: { claim: claimReceipt.gasUsed.toString(), escrowCreation: escrowReceipt.gasUsed.toString(), oneWorkerFunding: funded.gasUsed.toString() },
    limitations: 'Fixtures exercise software paths only. They are not verified people, public transactions, customers, revenue, confidential hardware evidence or a network fee quote.' };
  const output = path.join(runtime, 'activity-' + runId + '.json');
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log('Local accepted-job settlement passed: 99% worker share and 1% founder fee, with no remaining liability.');
  console.log('Report saved under .runtime. No public activity or customer demand was generated.');
} catch {
  console.error('Local exercise failed. Inspect the private .runtime log; no public deployment was attempted.');
  process.exitCode = 1;
} finally { node?.provider.destroy(); node?.child.kill(); await closeProver(); }
