import { test } from 'node:test';
import assert from 'node:assert/strict';
import { newContentKey, sealBundle, openBundle, envelopeDigest } from '../scripts/compute-crypto.mjs';
const context = { jobId: 'opaque-job-123', policySHA256: 'a'.repeat(64) };
test('encrypted bundles round-trip without exposing custom code or internal arguments', () => {
  const key = newContentKey(), source = Buffer.from(JSON.stringify({ program: 'private-training.py', args: ['private-dataset-name'], secret: 'private-model-weights' }));
  const envelope = sealBundle(source, key, context);
  assert.deepEqual(openBundle(envelope, key, context), source);
  const wire = JSON.stringify(envelope);
  for (const text of ['private-training.py', 'private-dataset-name', 'private-model-weights']) assert.equal(wire.includes(text), false);
  assert.match(envelopeDigest(envelope), /^[0-9a-f]{64}$/);
  assert.notEqual(sealBundle(source, key, context).iv, envelope.iv);
  key.fill(0);
});
test('wrong keys, changed ciphertext, authentication tags and policy/job substitution fail closed', () => {
  const key = newContentKey(), envelope = sealBundle(Buffer.from('private payload'), key, context);
  assert.throws(() => openBundle(envelope, newContentKey(), context));
  assert.throws(() => openBundle(envelope, key, { ...context, jobId: 'another-job' }));
  assert.throws(() => openBundle(envelope, key, { ...context, policySHA256: 'b'.repeat(64) }));
  for (const field of ['ciphertext', 'tag', 'iv']) {
    const bytes = Buffer.from(envelope[field], 'base64'); bytes[0] ^= 1;
    assert.throws(() => openBundle({ ...envelope, [field]: bytes.toString('base64') }, key, context));
  }
  assert.throws(() => openBundle({ ...envelope, plaintext: 'secret' }, key, context));
  assert.throws(() => openBundle({ ...envelope, tag: '' }, key, context));
  assert.throws(() => sealBundle(Buffer.from('x'), Buffer.alloc(16), context));
  key.fill(0);
});
