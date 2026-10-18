// Local Windows participant custody. No network, provider registration or wallet operations.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { createEncryptedIdentity, inspectEncryptedIdentity, readBounded } from '../claims/identity.mjs';

const digest = value => createHash('sha256').update(value).digest('hex');
const expected = (value, fields) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length || fields.some(k => !Object.hasOwn(value, k))) throw Error('Unexpected participant record');
};
const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
function run(exe, args, input, maxBuffer = 65536) {
  const r = spawnSync(exe, args, { input, windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'ignore'], timeout: 30000, maxBuffer });
  if (r.error || r.status !== 0 || !r.stdout?.length || r.stdout.length > maxBuffer) { r.stdout?.fill(0); throw Error('Local custody operation failed'); }
  return r.stdout;
}
function protect(mode, input) {
  if (process.platform !== 'win32' || !['Protect', 'Unprotect'].includes(mode) || input.length > 16384) throw Error('Windows custody is required');
  const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; $m=[IO.MemoryStream]::new(); [Console]::OpenStandardInput().CopyTo($m); $b=$m.ToArray(); try { if($b.Length -gt 16384){throw 'Input bound'}; $v=[Security.Cryptography.ProtectedData]::${mode}($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::OpenStandardOutput().Write($v,0,$v.Length) } finally { [Array]::Clear($b,0,$b.Length); if($null -ne $v){[Array]::Clear($v,0,$v.Length)}; $m.Dispose() }`;
  return run(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], input, 16384);
}
function secureDirectory(directory) {
  if (!path.isAbsolute(directory) || directory.includes('\0')) throw Error('Use an absolute private directory');
  fs.mkdirSync(directory, { recursive: true });
  if (fs.lstatSync(directory).isSymbolicLink() || !fs.statSync(directory).isDirectory()) throw Error('Use a regular private directory');
  const script = `$ErrorActionPreference='Stop'; $p=[Console]::In.ReadToEnd(); $s=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; & icacls.exe $p '/inheritance:r' '/grant:r' ('*'+$s+':(OI)(CI)(F)') '*S-1-5-18:(OI)(CI)(F)' | Out-Null; if($LASTEXITCODE -ne 0){throw 'Permissions failed'}; [Console]::Write('ok')`;
  run(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], directory);
}
function decode(text, maximum) {
  if (typeof text !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) throw Error('Invalid custody encoding');
  const bytes = Buffer.from(text, 'base64');
  if (!bytes.length || bytes.length > maximum || bytes.toString('base64') !== text) throw Error('Invalid custody size');
  return bytes;
}
function ownerRecipient(ageKeygen, ownerKey) {
  if (!Buffer.isBuffer(ownerKey) || ownerKey.length > 4096) throw Error('Invalid owner key');
  const lines = ownerKey.toString('ascii').split(/\r?\n/).filter(x => x && !x.startsWith('#'));
  if (lines.length !== 1 || !/^AGE-SECRET-KEY-1[0-9A-Z]{58}$/.test(lines[0])) throw Error('Require one native owner key');
  const recipient = run(ageKeygen, ['-y'], ownerKey, 256).toString('ascii').trim();
  if (!/^age1[0-9a-z]{58}$/.test(recipient)) throw Error('Invalid owner recipient');
  return recipient;
}
function record(file) {
  const value = JSON.parse(readBounded(file, 65536).toString('utf8'));
  expected(value, ['schema', 'createdAt', 'commitment', 'recipient', 'vault', 'vaultSHA256', 'ownerDPAPI']);
  if (value.schema !== 'cannabis.windows-participant.v1' || !/^[1-9][0-9]{0,77}$/.test(value.commitment) || !/^age1[0-9a-z]{58}$/.test(value.recipient)) throw Error('Invalid participant record');
  const cipher = decode(value.vault, 16384); decode(value.ownerDPAPI, 16384);
  if (digest(cipher) !== value.vaultSHA256) throw Error('Participant vault changed');
  return value;
}
async function inspect({ age, ageKeygen, value, key }) {
  if (ownerRecipient(ageKeygen, key) !== value.recipient) throw Error('Owner recipient does not match');
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-participant-'));
  const vault = path.join(stage, 'identity.age');
  try {
    fs.writeFileSync(vault, decode(value.vault, 16384), { flag: 'wx', mode: 0o600 });
    return await inspectEncryptedIdentity({ age, vault, identityKey: key, commitment: value.commitment });
  } finally { fs.rmSync(vault, { force: true }); fs.rmdirSync(stage); }
}
export async function createParticipant({ directory, age, ageKeygen }) {
  if (process.platform !== 'win32') throw Error('Use Windows');
  secureDirectory(directory);
  const file = path.join(directory, 'participant.json');
  if (fs.existsSync(file)) throw Error('An identity already exists; use recovery instead of creating another');
  const key = run(ageKeygen, [], undefined, 4096);
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-participant-'));
  const vault = path.join(stage, 'identity.age');
  try {
    const recipient = ownerRecipient(ageKeygen, key);
    const result = createEncryptedIdentity({ age, recipient, vault });
    const value = { schema: 'cannabis.windows-participant.v1', createdAt: new Date().toISOString(),
      commitment: result.commitment, recipient, vault: fs.readFileSync(vault).toString('base64'),
      vaultSHA256: result.ciphertextSHA256, ownerDPAPI: protect('Protect', key).toString('base64') };
    await inspect({ age, ageKeygen, value, key });
    fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    return { commitment: value.commitment, recoveryVerified: true, portableRecoveryVerified: false, enrolled: false };
  } finally { key.fill(0); fs.rmSync(vault, { force: true }); fs.rmdirSync(stage); }
}
export async function checkParticipant({ directory, age, ageKeygen }) {
  const value = record(path.join(directory, 'participant.json'));
  const key = protect('Unprotect', decode(value.ownerDPAPI, 16384));
  try { return await inspect({ age, ageKeygen, value, key }); }
  finally { key.fill(0); }
}
// age reads its passphrase from the owner's console. It never goes through this API.
function interactiveAge(age, args, input, limit = 65536) {
  if (!process.stdin.isTTY || !process.stderr.isTTY) throw Error('Open the guided setup in an interactive terminal');
  return new Promise((resolve, reject) => {
    const child = spawn(age, args, { shell: false, windowsHide: false, stdio: ['pipe', 'pipe', 'inherit'] });
    const chunks = []; let size = 0, done = false;
    const timer = setTimeout(() => child.kill(), 600000);
    const fail = () => { if (done) return; done = true; clearTimeout(timer); chunks.forEach(x => x.fill(0)); reject(Error('Backup operation did not complete')); };
    child.stdout.on('data', chunk => { size += chunk.length; if (size > limit) { child.kill(); fail(); } else chunks.push(chunk); });
    child.on('error', fail); child.stdin.on('error', () => {});
    child.on('close', code => {
      if (code !== 0 || !size || done) { fail(); return; }
      done = true; clearTimeout(timer); const bytes = Buffer.concat(chunks); chunks.forEach(x => x.fill(0)); resolve(bytes);
    });
    child.stdin.end(input);
  });
}
export async function exportParticipant({ directory, age, ageKeygen, output }) {
  if (!path.isAbsolute(output) || fs.existsSync(output)) throw Error('Choose a new absolute backup filename');
  const value = record(path.join(directory, 'participant.json'));
  const key = protect('Unprotect', decode(value.ownerDPAPI, 16384));
  let plain;
  try {
    await inspect({ age, ageKeygen, value, key });
    plain = Buffer.from(JSON.stringify({ schema: 'cannabis.participant-recovery.v1', commitment: value.commitment,
      recipient: value.recipient, vault: value.vault, vaultSHA256: value.vaultSHA256, ownerKey: key.toString('base64') }));
    const encrypted = await interactiveAge(age, ['--encrypt', '--passphrase'], plain);
    fs.writeFileSync(output, encrypted, { flag: 'wx', mode: 0o600 });
    return { commitment: value.commitment, backupSHA256: digest(encrypted), portableRecoveryVerified: false, enrolled: false };
  } finally { key.fill(0); plain?.fill(0); }
}
export async function restoreParticipant({ directory, age, ageKeygen, backup }) {
  const bytes = readBounded(backup, 65536);
  const plaintext = await interactiveAge(age, ['--decrypt'], bytes);
  let key;
  try {
    const restored = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    expected(restored, ['schema', 'commitment', 'recipient', 'vault', 'vaultSHA256', 'ownerKey']);
    if (restored.schema !== 'cannabis.participant-recovery.v1' || digest(decode(restored.vault, 16384)) !== restored.vaultSHA256) throw Error('Invalid portable backup');
    key = decode(restored.ownerKey, 4096);
    await inspect({ age, ageKeygen, value: restored, key });
    secureDirectory(directory);
    const file = path.join(directory, 'participant.json');
    if (fs.existsSync(file)) {
      const existing = record(file);
      if (existing.commitment !== restored.commitment || existing.vaultSHA256 !== restored.vaultSHA256) throw Error('A different identity already exists here');
      // Rewrap for this Windows account, including a migrated copy with old DPAPI keys.
      const replacement = path.join(directory, 'participant-restored-' + Date.now() + '.json');
      fs.writeFileSync(replacement, JSON.stringify({ ...existing, ownerDPAPI: protect('Protect', key).toString('base64') }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      fs.renameSync(replacement, file);
    } else {
      const value = { schema: 'cannabis.windows-participant.v1', createdAt: new Date().toISOString(), commitment: restored.commitment,
        recipient: restored.recipient, vault: restored.vault, vaultSHA256: restored.vaultSHA256, ownerDPAPI: protect('Protect', key).toString('base64') };
      fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    }
    const evidence = { schema: 'cannabis.participant-recovery-check.v1', checkedAt: new Date().toISOString(), commitment: restored.commitment,
      vaultSHA256: restored.vaultSHA256, backupSHA256: digest(bytes), portableRecoveryVerified: true, enrolled: false };
    fs.writeFileSync(path.join(directory, 'recovery-check.json'), JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
    return evidence;
  } finally { key?.fill(0); plaintext.fill(0); }
}
export async function prepareEnrollmentRequest({ directory, age, ageKeygen, output }) {
  if (!path.isAbsolute(output) || fs.existsSync(output)) throw Error('Choose a new absolute request filename');
  const value = record(path.join(directory, 'participant.json'));
  await checkParticipant({ directory, age, ageKeygen });
  const recovery = JSON.parse(readBounded(path.join(directory, 'recovery-check.json'), 8192).toString('utf8'));
  if (recovery.portableRecoveryVerified !== true || recovery.commitment !== value.commitment || recovery.vaultSHA256 !== value.vaultSHA256) throw Error('Verify the portable backup before preparing enrollment');
  const result = { schema: 'cannabis.participant-enrollment-request.v1', commitment: value.commitment,
    status: 'AWAITING_REVIEWED_PROVIDER', enrolled: false,
    instructions: 'Share this commitment only through the official reviewed person-verification flow when it opens. This file is not proof of personhood, an enrollment receipt or a token balance. Do not publish it alongside a receiving wallet.' };
  fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return result;
}
