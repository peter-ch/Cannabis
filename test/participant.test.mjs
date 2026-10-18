import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createParticipant, checkParticipant, prepareEnrollmentRequest } from '../participant/windows-custody.mjs';

test('Windows participant custody encrypts identity and owner key, rejects replacement and requires portable recovery before a request', { skip: process.platform !== 'win32' }, async () => {
  const age = process.env.CANNABIS_AGE;
  assert.ok(age && path.isAbsolute(age));
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-participant-test-'));
  const options = { directory, age, ageKeygen: path.join(path.dirname(age), 'age-keygen.exe') };
  try {
    const created = await createParticipant(options);
    assert.equal(created.enrolled, false); assert.equal(created.portableRecoveryVerified, false);
    assert.match(created.commitment, /^[1-9][0-9]+$/);
    assert.equal((await checkParticipant(options)).commitment, created.commitment);
    const file = path.join(directory, 'participant.json'), bytes = fs.readFileSync(file), record = JSON.parse(bytes);
    assert.equal(bytes.includes(Buffer.from('AGE-SECRET-KEY')), false);
    assert.ok(Buffer.from(record.vault, 'base64').toString('ascii').startsWith('age-encryption.org/v1'));
    await assert.rejects(createParticipant(options)); assert.deepEqual(fs.readFileSync(file), bytes);
    const output = path.join(directory, 'request.json');
    await assert.rejects(prepareEnrollmentRequest({ ...options, output })); assert.equal(fs.existsSync(output), false);
    fs.writeFileSync(file, JSON.stringify({ ...record, ownerDPAPI: Buffer.alloc(32, 1).toString('base64') }));
    await assert.rejects(checkParticipant(options));
    fs.writeFileSync(file, JSON.stringify({ ...record, vaultSHA256: '0'.repeat(64) }));
    await assert.rejects(checkParticipant(options));
  } finally {
    const target = fs.realpathSync(directory);
    if (path.dirname(target) !== fs.realpathSync(os.tmpdir()) || !path.basename(target).startsWith('cannabis-participant-test-')) throw Error('Unexpected cleanup target');
    fs.rmSync(target, { recursive: true });
  }
});
