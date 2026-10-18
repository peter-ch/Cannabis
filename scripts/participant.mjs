import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { createParticipant, checkParticipant, exportParticipant, restoreParticipant, prepareEnrollmentRequest } from '../participant/windows-custody.mjs';

if (process.platform !== 'win32' || !stdin.isTTY || !stdout.isTTY) {
  console.error('Open Start-Cannabis.cmd in an interactive Windows terminal.'); process.exit(1);
}
const age = process.env.CANNABIS_AGE, ageKeygen = age && path.join(path.dirname(age), 'age-keygen.exe');
if (!age || !path.isAbsolute(age) || !fs.existsSync(ageKeygen)) {
  console.error('Start-Cannabis.cmd installs the required private encryption tools.'); process.exit(1);
}
const directory = path.join(process.env.LOCALAPPDATA, 'CannabisParticipant', 'identity');
const options = { directory, age, ageKeygen };
// Release readline before age opens the console for its own masked password prompt.
async function ask(message) {
  const prompt = readline.createInterface({ input: stdin, output: stdout });
  try { return (await prompt.question(message)).trim(); }
  finally { prompt.close(); }
}
function filePath(answer) {
  const value = answer.replace(/^"(.*)"$/, '$1');
  if (!path.isAbsolute(value)) throw Error('Use a full path, such as E:\\Cannabis-backup.age');
  return value;
}
console.log('\nCANNABIS\nYour identity. Your recovery. Your participation.\n');
console.log('This guide prepares your own encrypted participant identity on this PC.');
console.log('Community enrollment opens after the Cannabis ceremony and mainnet release are ready.');
console.log('It does not ask for a wallet seed, move money or register you automatically.');
console.log('If you already have a Cannabis participant backup, choose Restore. Keep the same identity.\n');
for (;;) {
  const exists = fs.existsSync(path.join(directory, 'participant.json'));
  console.log('\n' + (exists ? 'Local identity: saved' : 'Local identity: not created'));
  console.log('1  Create my identity\n2  Save a password-encrypted backup\n3  Restore or verify a backup\n4  Prepare my enrollment request\n5  Check this PC can open my identity\n0  Close');
  try {
    const selected = await ask('\nChoose a step: ');
    if (selected === '0') break;
    if (selected === '1') {
      if (exists) { console.log('Your identity is already saved. Choose backup or recovery.'); continue; }
      if ((await ask('Create your first participant identity on this device? Type CREATE: ')) !== 'CREATE') continue;
      await createParticipant(options);
      console.log('Identity created and locally checked. Next choose 2 to save a portable backup.');
    } else if (selected === '2') {
      const output = filePath(await ask('New backup file path (for example E:\\Cannabis-backup.age): '));
      console.log('The encryption tool will ask for a backup passphrase. Use a long unique passphrase and keep it separately.');
      await exportParticipant({ ...options, output });
      console.log('Encrypted backup saved. Choose 3 and reopen it to verify recovery.');
    } else if (selected === '3') {
      const backup = filePath(await ask('Full path to your existing Cannabis .age backup: '));
      console.log('Enter the existing backup passphrase in the encryption tool prompt.');
      await restoreParticipant({ ...options, backup });
      console.log('Portable recovery verified. Your same identity is available on this PC.');
    } else if (selected === '4') {
      const output = filePath(await ask('New enrollment request file path (for example E:\\Cannabis-request.json): '));
      await prepareEnrollmentRequest({ ...options, output });
      console.log('Request prepared. It contains your commitment only, with no secret or wallet address.');
      console.log('Keep it private until the official verification flow opens. You are not enrolled yet.');
    } else if (selected === '5') {
      await checkParticipant(options); console.log('This Windows account opened the saved identity successfully.');
    } else console.log('Choose one of the listed steps.');
  } catch {
    console.log('That step did not finish. Check the selected path and password, and avoid overwriting existing files.');
    console.log('Enrollment-request preparation also requires a successful portable backup check. Your saved identity is retained.');
  }
}
console.log('Your encrypted identity stays on this device. Keep your portable backup and passphrase safe.');
