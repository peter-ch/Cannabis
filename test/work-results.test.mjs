import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { Encrypter, generateIdentity, identityToRecipient } from 'age-encryption';
import { openResults, readResultArchive, sha256 } from '../web/work-results.js';
const archive = new Uint8Array(Buffer.from(execFileSync('python', ['test/fixtures/browser-result.py'], { encoding: 'utf8' }), 'base64'));
async function fixture() {
  const identity = await generateIdentity(), recipient = await identityToRecipient(identity), e = new Encrypter(); e.addRecipient(recipient);
  const bytes = await e.encrypt(archive);
  const receipt = { schema: 'cannabis.result.v1', jobId: 'owned-browser-fixture', taskId: 'calculate', packageSHA256: 'a'.repeat(64), attempt: 1, rank: 0, worldSize: 1,
    recipient, ciphertextSHA256: await sha256(bytes), ciphertextBytes: bytes.length };
  const spec = { schema: 'cannabis.workload.v1', id: receipt.jobId, resultRecipient: recipient,
    tasks: [{ id: 'calculate', resources: { nodes: 1 }, outputs: ['answer.txt'] }], assembly: [{ task: 'calculate', output: 'answer.txt', destination: 'finished/answer.txt' }] };
  return { identity, spec, packageSHA256: receipt.packageSHA256, results: [{ receipt, bytes }] };
}
test('browser decrypts the Python USTAR format and reconstructs only agreed outputs', async () => {
  const value = await fixture(), files = await openResults(value);
  assert.deepEqual([...files.keys()], ['finished/answer.txt']); assert.equal(new TextDecoder().decode(files.get('finished/answer.txt')), 'owned verification result\n');
});
test('browser rejects ciphertext substitution, wrong identities and cross-job receipts', async () => {
  const value = await fixture();
  await assert.rejects(openResults({ ...value, identity: await generateIdentity() }), /identity does not match/);
  for (const changed of [{ jobId: 'substituted' }, { rank: 1 }, { recipient: 'wrong' }, { attempt: 0 }, { ciphertextSHA256: 'b'.repeat(64) }]) {
    await assert.rejects(openResults({ ...value, results: [{ ...value.results[0], receipt: { ...value.results[0].receipt, ...changed } }] }));
  }
  const damaged = value.results[0].bytes.slice(); damaged[damaged.length - 1] ^= 1;
  await assert.rejects(openResults({ ...value, results: [{ bytes: damaged, receipt: { ...value.results[0].receipt, ciphertextSHA256: await sha256(damaged) } }] }));
});
test('result viewer rejects unsafe destinations, missing results, trailing members and bad tar checksums', async () => {
  const value = await fixture();
  for (const destination of ['../escape', '/absolute', 'C:/path', 'CON', 'dir\\file', 'dir/..', 'file.']) {
    const spec = structuredClone(value.spec); spec.assembly[0].destination = destination;
    await assert.rejects(openResults({ ...value, spec }), /Unsafe/);
  }
  const duplicate = structuredClone(value.spec); duplicate.assembly.push({ ...duplicate.assembly[0], destination: 'finished/answer.txt/nested' });
  await assert.rejects(openResults({ ...value, spec: duplicate }), /Overlapping/);
  await assert.rejects(openResults({ ...value, results: [] }), /result count/);
  const extra = archive.slice(); extra[extra.length - 1] = 1; await assert.rejects(readResultArchive(extra), /trailing/);
  const bad = archive.slice(); bad[0] ^= 1; await assert.rejects(readResultArchive(bad), /checksum/);
});
