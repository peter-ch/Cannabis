// Validate job terms and produce a reviewable plan. Never executes code, signs or pays.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getAddress, parseUnits, formatUnits, keccak256, toUtf8Bytes } from 'ethers';
export const policy = Object.freeze(JSON.parse(fs.readFileSync(new URL('../compute/policy.json', import.meta.url), 'utf8')));
const zero = '0x0000000000000000000000000000000000000000';
function exact(object, keys, label) {
  if (!object || typeof object !== 'object' || Array.isArray(object) ||
      Object.keys(object).some(k => !keys.includes(k)) || keys.some(k => !(k in object))) throw Error('Invalid fields: ' + label);
}
function number(value, min, max, label) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw Error('Invalid ' + label);
}
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
export function quotePayment(totalBudget) {
  if (typeof totalBudget !== 'string' || !/^(0|[1-9]\d*)(\.\d{1,18})?$/.test(totalBudget)) throw Error('Budget must be an exact decimal Cannabis amount');
  const total = parseUnits(totalBudget, 18);
  if (total <= 0n || total > (1n << 256n) - 1n) throw Error('Budget outside token amount range');
  if (total % 100n !== 0n) throw Error('Budget must use multiples of 0.0000000000000001 Cannabis for an exact 1% fee');
  const fee = total * BigInt(policy.feeBasisPoints) / 10000n;
  return { totalAtomic: total.toString(), founderFeeAtomic: fee.toString(), workerPoolAtomic: (total - fee).toString(),
    totalCannabis: formatUnits(total, 18), founderFeeCannabis: formatUnits(fee, 18), workerPoolCannabis: formatUnits(total - fee, 18),
    feeBasisPoints: policy.feeBasisPoints, founderRecipient: getAddress(policy.founderRecipient),
    feeAppliesTo: policy.feeAppliesTo, paymentQuantumAtomic: '100', networkFeesIncluded: false };
}
export function validateJob(job) {
  exact(job, ['schema', 'id', 'requester', 'kind', 'runtime', 'collectiveBackend', 'execution', 'confidentiality', 'resources', 'payment', 'acceptance'], 'job');
  if (job.schema !== 'cannabis.compute.job.v1' || typeof job.id !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(job.id)) throw Error('Invalid job schema or ID');
  if (getAddress(job.requester) === zero) throw Error('Invalid requester');
  if (!['standalone', 'torch-distributed'].includes(job.kind)) throw Error('Unsupported job kind');
  if (typeof job.runtime !== 'string' || !/^(cpu|cuda|rocm|xpu|mps|tpu|custom:[a-z0-9][a-z0-9_.-]{0,63})$/.test(job.runtime)) throw Error('Invalid runtime');
  exact(job.execution, ['image'], 'execution');
  if (typeof job.execution.image !== 'string' || !/^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$/.test(job.execution.image)) throw Error('Execution image must be digest-pinned');
  exact(job.confidentiality, ['required', 'policySHA256', 'encryptedBundleSHA256', 'cipher', 'keyRelease'], 'confidentiality');
  const privacy = job.confidentiality;
  if (privacy.required !== true || privacy.cipher !== 'AES-256-GCM' || privacy.keyRelease !== 'attested-only' ||
      !/^[0-9a-f]{64}$/.test(privacy.policySHA256) || !/^[0-9a-f]{64}$/.test(privacy.encryptedBundleSHA256)) throw Error('Encrypted workload and attested-only key release are mandatory');
  const r = job.resources;
  exact(r, ['nodes', 'processesPerNode', 'cpusPerNode', 'memoryMiBPerNode', 'scratchMiBPerNode', 'acceleratorsPerNode', 'acceleratorMemoryMiB', 'wallSeconds'], 'resources');
  number(r.nodes, 1, 128, 'nodes'); number(r.processesPerNode, 1, 1024, 'processes');
  number(r.cpusPerNode, 1, 4096, 'CPUs'); number(r.memoryMiBPerNode, 64, 16777216, 'RAM');
  number(r.scratchMiBPerNode, 1, 1073741824, 'storage'); number(r.acceleratorsPerNode, 0, 1024, 'accelerators');
  number(r.acceleratorMemoryMiB, 0, 16777216, 'device memory'); number(r.wallSeconds, 1, 604800, 'wall time');
  if (job.runtime === 'cpu' ? r.acceleratorsPerNode !== 0 || r.acceleratorMemoryMiB !== 0 : r.acceleratorsPerNode < 1 || r.acceleratorMemoryMiB < 1) throw Error('Runtime/device requirements disagree');
  if (job.kind === 'standalone') {
    if (r.nodes !== 1 || r.processesPerNode !== 1 || job.collectiveBackend !== null) throw Error('Standalone job must use one node and no collective backend');
  } else {
    if (typeof job.collectiveBackend !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/.test(job.collectiveBackend)) throw Error('Distributed job requires a collective backend');
    const known = { cpu: 'gloo', cuda: 'nccl', rocm: 'nccl', xpu: 'xccl' };
    if (known[job.runtime] && known[job.runtime] !== job.collectiveBackend) throw Error('Collective backend does not match runtime');
    if (job.runtime === 'cpu' ? r.processesPerNode > r.cpusPerNode : r.processesPerNode > r.acceleratorsPerNode) throw Error('Not enough devices/CPUs for exclusive ranks');
  }
  exact(job.payment, ['totalBudget', 'feeBasisPoints', 'founderRecipient'], 'payment');
  if (job.payment.feeBasisPoints !== policy.feeBasisPoints || getAddress(job.payment.founderRecipient) !== getAddress(policy.founderRecipient)) throw Error('Job must include the published founder fee and recipient');
  quotePayment(job.payment.totalBudget);
  exact(job.acceptance, ['encryptedTermsSHA256'], 'acceptance');
  if (!/^[0-9a-f]{64}$/.test(job.acceptance.encryptedTermsSHA256)) throw Error('Encrypted acceptance terms digest is required');
  return structuredClone(job);
}
export function planJob(input, workers = []) {
  const job = validateJob(input), r = job.resources;
  if (!Array.isArray(workers)) throw Error('Workers must be an array');
  const ids = new Set();
  for (const worker of workers) {
    if (!worker || typeof worker.id !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(worker.id) || ids.has(worker.id)) throw Error('Invalid or duplicate worker ID');
    ids.add(worker.id);
  }
  const eligible = workers.filter(w => {
    const c = w.capacity;
    return w.runtime === job.runtime && w.os === 'linux' && Array.isArray(w.imageDigests) && w.imageDigests.includes(job.execution.image) &&
      w.isolation === 'confidential-vm' && w.confidentialCapabilities?.cpu === true &&
      (job.runtime === 'cpu' || w.confidentialCapabilities?.accelerators === true) &&
      (job.kind === 'standalone' || Array.isArray(w.collectiveBackends) && w.collectiveBackends.includes(job.collectiveBackend)) &&
      c && Object.values(c).every(v => Number.isSafeInteger(v) && v >= 0) &&
      c.cpus >= r.cpusPerNode && c.memoryMiB >= r.memoryMiBPerNode && c.scratchMiB >= r.scratchMiBPerNode &&
      c.accelerators >= r.acceleratorsPerNode && c.acceleratorMemoryMiB >= r.acceleratorMemoryMiB;
  }).sort((a, b) => a.id.localeCompare(b.id)).slice(0, r.nodes);
  const assignments = Array.from({ length: r.nodes }, (_, rank) => ({
    rank, workerId: eligible[rank]?.id ?? null, processes: r.processesPerNode,
    workloadSource: 'encrypted-bundle; decode only inside attested execution', attestationVerified: false
  }));
  return { schema: 'cannabis.compute.plan.v1', jobHash: keccak256(toUtf8Bytes(canonical(job))),
    job, payment: quotePayment(job.payment.totalBudget),
    assignment: { requiredNodes: r.nodes, matchingNodes: eligible.length, capacityMatched: eligible.length === r.nodes, workers: assignments },
    executionAuthorized: false, keyReleaseAuthorized: false, fundsMoved: false,
    requirements: ['Verify fresh vendor-rooted CPU and accelerator attestations, patch state, measurements and debug-disabled policy; advertisements are not attestations',
      'Bind the key-release channel to job, policy, lease, nonce and an ephemeral key held inside the verified environment',
      'Keep code, inputs, outputs, checkpoints, logs, swap and distributed traffic encrypted outside attested execution',
      'Reserve all ranks atomically under one expiring lease', 'Verify signed job terms and funded payment agreement',
      'Enforce quotas and cancellation inside the sandbox', 'Establish private authenticated job networking',
      'Verify input/output licenses, artifact access and acceptance terms', 'Independently review escrow, refunds and dispute handling'] };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length < 1 || args.length > 2) throw Error('Usage: compute-plan.mjs job.json [workers.json]');
  for (const file of args) if (fs.statSync(file).size > 1048576) throw Error('Manifest exceeds 1 MiB');
  const job = JSON.parse(fs.readFileSync(args[0], 'utf8'));
  const workers = args[1] ? JSON.parse(fs.readFileSync(args[1], 'utf8')) : [];
  console.log(JSON.stringify(planJob(job, workers), null, 2));
}
