import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planJob, quotePayment, policy, validateJob } from '../scripts/compute-plan.mjs';
const image = 'registry.example/fixture@sha256:' + 'a'.repeat(64);
function job(runtime = 'cpu', kind = 'torch-distributed') {
  const device = runtime !== 'cpu';
  return { schema: 'cannabis.compute.job.v1', id: 'verification-job', requester: '0x1111111111111111111111111111111111111111',
    kind, runtime, collectiveBackend: kind === 'standalone' ? null : ({ cpu: 'gloo', cuda: 'nccl', rocm: 'nccl', xpu: 'xccl' }[runtime] ?? 'vendor_backend'),
    execution: { image },
    confidentiality: { required: true, policySHA256: 'c'.repeat(64), encryptedBundleSHA256: 'd'.repeat(64), cipher: 'AES-256-GCM', keyRelease: 'attested-only' },
    resources: { nodes: kind === 'standalone' ? 1 : 2, processesPerNode: 1, cpusPerNode: 2,
      memoryMiBPerNode: 1024, scratchMiBPerNode: 512, acceleratorsPerNode: device ? 1 : 0, acceleratorMemoryMiB: device ? 2048 : 0, wallSeconds: 600 },
    payment: { totalBudget: '100', feeBasisPoints: 100, founderRecipient: policy.founderRecipient },
    acceptance: { encryptedTermsSHA256: 'b'.repeat(64) } };
}
function worker(id, runtime = 'cpu') {
  return { id, runtime, os: 'linux', imageDigests: [image], isolation: 'confidential-vm', confidentialCapabilities: { cpu: true, accelerators: runtime !== 'cpu' },
    collectiveBackends: ['gloo', 'nccl', 'xccl', 'vendor_backend'],
    capacity: { cpus: 8, memoryMiB: 8192, scratchMiB: 4096, accelerators: runtime === 'cpu' ? 0 : 2, acceleratorMemoryMiB: runtime === 'cpu' ? 0 : 4096 } };
}
test('1% founder fee uses integer arithmetic and preserves the exact total', () => {
  const quote = quotePayment('100'); assert.equal(quote.founderFeeCannabis, '1.0'); assert.equal(quote.workerPoolCannabis, '99.0');
  for (const amount of ['0.0000000000000001', '0.0000000000000002', '123456789123456789.1234567891234567']) {
    const q = quotePayment(amount), total = BigInt(q.totalAtomic), fee = BigInt(q.founderFeeAtomic);
    assert.equal(fee + BigInt(q.workerPoolAtomic), total); assert.equal(fee, total / 100n);
  }
  for (const value of ['0', '-1', '1e20', '0.000000000000000001', '0.000000000000000199', '1.0000000000000000001', '9'.repeat(90), 1]) assert.throws(() => quotePayment(value));
});
test('job cannot silently remove the founder fee, change its recipient or use mutable code', () => {
  for (const alter of [
    j => { j.payment.feeBasisPoints = 0; }, j => { j.payment.founderRecipient = j.requester; },
    j => { j.execution.image = 'registry.example/job:latest'; }, j => { j.confidentiality.required = false; },
    j => { j.confidentiality.keyRelease = 'host'; }, j => { j.execution.args = ['plaintext-secret']; },
    j => { j.resources.wallSeconds = 0; }, j => { j.id = null; }
  ]) { const value = job(); alter(value); assert.throws(() => validateJob(value)); }
});
test('plans CPU, CUDA, ROCm, XPU and custom adapters without executing jobs', () => {
  for (const runtime of ['cpu', 'cuda', 'rocm', 'xpu', 'custom:vendor-v1']) {
    const value = job(runtime), plan = planJob(value, [worker('b', runtime), worker('a', runtime)]);
    assert.equal(plan.assignment.capacityMatched, true); assert.equal(plan.executionAuthorized, false); assert.equal(plan.fundsMoved, false);
    assert.deepEqual(plan.assignment.workers.map(c => c.workerId), ['a', 'b']);
    assert.equal(plan.assignment.workers[1].rank, 1);
    assert.equal(plan.keyReleaseAuthorized, false);
    assert.equal(plan.assignment.workers[0].attestationVerified, false);
  }
  const standalone = planJob(job('cpu', 'standalone'), [worker('a')]);
  assert.equal(standalone.assignment.workers.length, 1);
  assert.equal(standalone.keyReleaseAuthorized, false);
});
test('matching rejects incompatible hardware, capacity, image, backend and unisolated workers', () => {
  const good = worker('good');
  const wrong = [
    { ...good, id: 'runtime', runtime: 'cuda' }, { ...good, id: 'image', imageDigests: [] },
    { ...good, id: 'backend', collectiveBackends: [] }, { ...good, id: 'isolation', isolation: 'host-subprocess' },
    { ...good, id: 'no-tee', confidentialCapabilities: { cpu: false } },
    { ...good, id: 'ram', capacity: { ...good.capacity, memoryMiB: 64 } }, { ...good, id: 'os', os: 'windows' }
  ];
  const plan = planJob(job(), [good, ...wrong]); assert.equal(plan.assignment.matchingNodes, 1); assert.equal(plan.assignment.capacityMatched, false);
  assert.throws(() => planJob(job(), [good, good]), /duplicate/);
  const invalid = job('rocm'); invalid.collectiveBackend = 'xccl'; assert.throws(() => validateJob(invalid), /backend/);
});
test('job hash ignores object-key ordering but commits to encrypted workload and payment terms', () => {
  const original = job(), reversed = Object.fromEntries(Object.entries(original).reverse());
  const first = planJob(original).jobHash; assert.equal(planJob(reversed).jobHash, first);
  reversed.confidentiality.encryptedBundleSHA256 = 'e'.repeat(64); assert.notEqual(planJob(reversed).jobHash, first);
  assert.equal(planJob(original).assignment.capacityMatched, false);
});
