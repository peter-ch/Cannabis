import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { Group } from '@semaphore-protocol/group';
import { verifyProof } from '@semaphore-protocol/proof';
import { maybeGetSnarkArtifacts, Project } from '@zk-kit/artifacts';
import { createEncryptedIdentity, inspectEncryptedIdentity, generateClaimProof, validateMembershipSnapshot, claimScope } from '../claims/identity.mjs';

let directory, age, identityFile, vault, backup, context, snapshot, artifacts;
const recipient = '0x' + '12'.repeat(20), token = '0x' + '13'.repeat(20);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function config() { return { age, identityFile, vault, commitment: backup.commitment, context, snapshot, artifacts, recipient }; }
before(async () => {
  const binary = process.platform === 'win32' ? 'age.exe' : 'age';
  age = process.env.CANNABIS_AGE || process.env.PATH.split(path.delimiter).map(dir => path.resolve(dir, binary)).find(file => fs.existsSync(file));
  assert.ok(age, 'Install age 1.3.2 with age-keygen or set CANNABIS_AGE');
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-identity-check-'));
  identityFile = path.join(directory, 'owner.key'); vault = path.join(directory, 'participant.age');
  const keygen = path.join(path.dirname(age), process.platform === 'win32' ? 'age-keygen.exe' : 'age-keygen');
  const result = spawnSync(keygen, ['-o', identityFile], { encoding: 'utf8', windowsHide: true });
  assert.equal(result.status, 0);
  const pub = spawnSync(keygen, ['-y', identityFile], { encoding: 'utf8', windowsHide: true });
  assert.equal(pub.status, 0);
  backup = createEncryptedIdentity({ age, recipient: pub.stdout.trim(), vault });
  const commitments = [backup.commitment, ...Array.from({ length: 127 }, (_, i) => String(i + 1))];
  context = { chainId: '31337', token, root: new Group(commitments).root.toString(), memberCount: commitments.length };
  snapshot = { schema: 'cannabis.membership-snapshot.v1', chainId: context.chainId, token, root: context.root, commitments };
  // Download only in fixture setup. The participant API must use explicitly supplied pinned bytes.
  const paths = await maybeGetSnarkArtifacts(Project.SEMAPHORE, { parameters: [7], version: '4.13.0' });
  const artifact = file => { const data = fs.readFileSync(file); return { path: file, bytes: data.length, sha256: digest(data) }; };
  artifacts = { depth: 7, wasm: artifact(paths.wasm), zkey: artifact(paths.zkey) };
});
after(async () => {
  await globalThis.curve_bn128?.terminate();
  if (directory) {
    // Remove only explicitly created fixture files from the verified owned directory.
    for (const name of ['owner.key', 'participant.age', 'corrupt.age', 'other.key', 'other.age', 'bad.key', 'config.json', 'result.json', 'membership.json', 'proof.json', 'bad-proof.json']) fs.rmSync(path.join(directory, name), { force: true });
    fs.rmdirSync(directory);
  }
});
test('encrypted backup recovers the same commitment without exporting a secret', async () => {
  assert.deepEqual(await inspectEncryptedIdentity(config()), { commitment: backup.commitment, recoveryVerified: true, enrolled: false });
  const raw = fs.readFileSync(vault);
  assert.equal(raw.includes(Buffer.from(backup.commitment)), false);
  assert.equal(raw.includes(Buffer.from('cannabis.claim-identity.v1')), false);
  assert.equal(digest(raw), backup.ciphertextSHA256);
  assert.equal(Object.hasOwn(backup, 'identity'), false);
  assert.throws(() => createEncryptedIdentity({ age, recipient: 'age1' + 'x'.repeat(58), vault }), /already exists/);
  assert.equal(digest(fs.readFileSync(vault)), backup.ciphertextSHA256);
});
test('wrong expected identity, wrong owner key and modified ciphertext fail recovery', async () => {
  await assert.rejects(inspectEncryptedIdentity({ ...config(), commitment: '1' }), /does not match/);
  const data = fs.readFileSync(vault); data[data.length - 1] ^= 1;
  const corrupt = path.join(directory, 'corrupt.age'); fs.writeFileSync(corrupt, data);
  await assert.rejects(inspectEncryptedIdentity({ ...config(), vault: corrupt }), /operation failed/);
  const other = path.join(directory, 'other.key');
  const keygen = path.join(path.dirname(age), process.platform === 'win32' ? 'age-keygen.exe' : 'age-keygen');
  assert.equal(spawnSync(keygen, ['-o', other], { windowsHide: true }).status, 0);
  await assert.rejects(inspectEncryptedIdentity({ ...config(), identityFile: other }), /operation failed/);
  const bad = path.join(directory, 'bad.key'); fs.writeFileSync(bad, 'AGE-PLUGIN-SHOULD-NOT-EXECUTE\n');
  await assert.rejects(inspectEncryptedIdentity({ ...config(), identityFile: bad }), /native age/);
});
test('complete membership, canonical integers and deployment context are enforced', () => {
  assert.equal(validateMembershipSnapshot(snapshot, context).size, 128);
  assert.throws(() => validateMembershipSnapshot({ ...snapshot, chainId: '1' }, context), /context mismatch/);
  assert.throws(() => validateMembershipSnapshot({ ...snapshot, token: recipient }, context), /context mismatch/);
  assert.throws(() => validateMembershipSnapshot({ ...snapshot, commitments: snapshot.commitments.slice(1) }, context), /complete membership/);
  assert.throws(() => validateMembershipSnapshot(snapshot, { ...context, memberCount: 127 }), /complete membership/);
  assert.throws(() => validateMembershipSnapshot({ ...snapshot, commitments: Array(128).fill('1') }, context), /Duplicate/);
  const modified = structuredClone(snapshot); modified.commitments[1] = '1000';
  assert.throws(() => validateMembershipSnapshot(modified, context), /root mismatch/);
  modified.commitments[1] = '01'; assert.throws(() => validateMembershipSnapshot(modified, context), /canonical/);
  assert.throws(() => claimScope('031337', token), /canonical/);
});
test('incorrect artifact pins and depth fail before opening participant custody', async () => {
  for (const field of ['wasm', 'zkey']) {
    const changed = structuredClone(artifacts); changed[field].sha256 = '00'.repeat(32);
    await assert.rejects(generateClaimProof({ ...config(), vault: path.join(directory, 'missing.age'), artifacts: changed }), /artifact does not match/);
  }
  await assert.rejects(generateClaimProof({ ...config(), artifacts: { ...artifacts, depth: 8 } }), /group depth/);
});
test('actual offline proof binds the recipient and scope and reveals no member identifier', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw Error('Network forbidden during participant proving'); };
  try {
    const proof = await generateClaimProof(config());
    assert.equal(await verifyProof(proof), true);
    assert.equal(proof.message, BigInt(recipient).toString());
    assert.equal(proof.scope, claimScope(context.chainId, token));
    assert.equal(proof.merkleTreeRoot, context.root);
    assert.deepEqual(Object.keys(proof).sort(), ['merkleTreeDepth', 'merkleTreeRoot', 'nullifier', 'message', 'scope', 'points'].sort());
    assert.equal(JSON.stringify(proof).includes(backup.commitment), false);
    assert.equal(await verifyProof({ ...proof, message: BigInt(token).toString() }), false);
    assert.equal(await verifyProof({ ...proof, scope: claimScope('1', token) }), false);
  } finally { globalThis.fetch = originalFetch; }
});
test('CLI writes only the requested public recovery report and never echoes private diagnostics', () => {
  const input = path.join(directory, 'config.json'), output = path.join(directory, 'result.json');
  fs.writeFileSync(input, JSON.stringify(config()));
  const run = spawnSync(process.execPath, ['scripts/claim-identity.mjs', 'inspect', '--config', input, '--out', output], { encoding: 'utf8', windowsHide: true });
  assert.equal(run.status, 0); assert.equal(JSON.parse(run.stdout).sent, false);
  assert.equal(JSON.parse(fs.readFileSync(output)).recoveryVerified, true);
  const again = spawnSync(process.execPath, ['scripts/claim-identity.mjs', 'inspect', '--config', input, '--out', output], { encoding: 'utf8', windowsHide: true });
  assert.equal(again.status, 1); assert.equal(again.stdout, '');
  assert.equal(again.stderr.includes(identityFile), false); assert.equal(again.stderr.includes(backup.commitment), false);
});
test('proof CLI consumes a complete downloaded membership bundle and rejects mixed sources', async () => {
  const membershipFile = path.join(directory, 'membership.json'), input = path.join(directory, 'config.json'), output = path.join(directory, 'proof.json');
  fs.writeFileSync(membershipFile, JSON.stringify({ schema: 'cannabis.membership-download.v1', snapshot, context }));
  const { snapshot: _snapshot, context: _context, ...base } = config();
  fs.writeFileSync(input, JSON.stringify({ ...base, membershipFile }));
  const args = ['scripts/claim-identity.mjs', 'prove', '--config', input, '--out', output];
  const result = spawnSync(process.execPath, args, { encoding: 'utf8', windowsHide: true });
  if (result.status !== 0) {
    const diagnostic = spawnSync(process.execPath, ['test/fixtures/proof-diagnostic.mjs', input], { encoding: 'utf8', windowsHide: true });
    assert.fail('Fixture proof failed: ' + diagnostic.stdout);
  }
  assert.equal(result.status, 0); assert.equal(JSON.parse(result.stdout).sent, false);
  assert.equal(await verifyProof(JSON.parse(fs.readFileSync(output))), true);
  fs.writeFileSync(input, JSON.stringify({ ...base, membershipFile, context }));
  args[args.length - 1] = path.join(directory, 'bad-proof.json');
  const mixed = spawnSync(process.execPath, args, { encoding: 'utf8', windowsHide: true });
  assert.equal(mixed.status, 1); assert.equal(fs.existsSync(args.at(-1)), false);
});
