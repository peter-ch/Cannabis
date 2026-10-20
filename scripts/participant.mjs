import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { getAddress } from 'ethers';
import { createParticipant, checkParticipant, exportParticipant, restoreParticipant, prepareEnrollmentRequest } from '../participant/windows-custody.mjs';
import { selectParticipantClaimConfiguration, reviewParticipantClaim, prepareParticipantClaim } from '../participant/claim-flow.mjs';

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
async function guidedClaim() {
  const config = filePath(await ask('Full path to the reviewed claim configuration: '));
  const selection = selectParticipantClaimConfiguration(config);
  console.log('\nCompare these values with the canonical reviewed Cannabis release before continuing.');
  console.log('A configuration file alone does not authenticate a release. Cannabis is Preparing mainnet launch.');
  console.log('Chain ID: ' + selection.chainId + '\nCannabis contract: ' + selection.token);
  console.log('Contract code hash: ' + selection.tokenCodeHash);
  console.log('Enrollment: ' + selection.enrollment + '\nEnrollment code hash: ' + selection.enrollmentCodeHash);
  console.log('Semaphore: ' + selection.semaphore + '\nSemaphore code hash: ' + selection.semaphoreCodeHash);
  console.log('Deployment start block: ' + selection.fromBlock + '\nRPC origin: ' + selection.rpcOrigin);
  console.log('Release and proving-pin digest (SHA-256): ' + selection.releaseDigest);
  console.log('Proving depth: ' + selection.artifacts.depth);
  for (const name of ['wasm', 'zkey']) console.log(name + ': ' + selection.artifacts[name].sha256 + ' (' + selection.artifacts[name].bytes + ' bytes)');
  console.log('The selected RPC supplies the chain view. The guide does not independently verify Ethereum consensus.');
  const confirmedToken = await ask('To read membership from this RPC, enter the reviewed Cannabis contract address (blank cancels): ');
  if (!confirmedToken) return;
  if (getAddress(confirmedToken) !== selection.token) throw Error('Contract selection changed');
  const recipient = getAddress(await ask('Your receiving wallet address (never a seed or private key): '));
  console.log('Downloading the full finalized membership group and checking deployment pins...');
  const review = await reviewParticipantClaim(selection, recipient, options);
  console.log('\nClaim: ' + review.claimAmount + ' Cannabis\nReceiving wallet: ' + review.recipient);
  console.log('Chain ID: ' + review.chainId + '\nContract: ' + review.token);
  console.log('Common opening: ' + new Date(review.claimsStartAt*1000).toISOString());
  console.log('Finalized members: ' + review.memberCount + '\nCurrent claim minimum: ' + review.minimumClaimMembers);
  console.log(review.singletonPrivacy ? 'Only one member is enrolled. This claim has no membership anonymity.' : 'Small groups limit membership privacy. You may wait for more real members.');
  if (!review.open) { console.log('Claims are not open yet. Return after the common opening.'); return; }
  console.log('No identity secret or member index is sent to the RPC. After your approval, simulation sends the public proof and recipient.');
  console.log('This prepares an unsigned transaction. Your wallet must review fees and sign separately.');
  const output = filePath(await ask('New unsigned-claim output file (full path): '));
  const confirmedRecipient = await ask('Enter the receiving wallet address again to approve proving and simulation (blank cancels): ');
  if (!confirmedRecipient) return;
  try {
    const result = await prepareParticipantClaim(review, { reviewId: review.reviewId,
      releaseDigest: review.releaseDigest, token: review.token, recipient: getAddress(confirmedRecipient) }, output);
    console.log('Unsigned claim saved. No transaction was signed or sent.');
    console.log('Review the chain, contract, recipient and network fee in your wallet, and re-simulate immediately before signing.');
    console.log('Saved to: ' + result.output);
  } finally {
    const curve = globalThis.curve_bn128;
    await curve?.terminate();
    if (globalThis.curve_bn128 === curve) delete globalThis.curve_bn128;
  }
}
console.log('\nCANNABIS\nYour identity. Your recovery. Your participation.\n');
console.log('This guide prepares your own encrypted participant identity on this PC.');
console.log('Community enrollment opens after the Cannabis ceremony and mainnet release are ready.');
console.log('It does not ask for a wallet seed, move money or register you automatically.');
console.log('If you already have a Cannabis participant backup, choose Restore. Keep the same identity.\n');
for (;;) {
  const exists = fs.existsSync(path.join(directory, 'participant.json'));
  console.log('\n' + (exists ? 'Local identity: saved' : 'Local identity: not created'));
  console.log('1  Create my identity\n2  Save a password-encrypted backup\n3  Restore or verify a backup\n4  Prepare my enrollment request\n5  Check this PC can open my identity\n6  Review and prepare an unsigned community claim\n0  Close');
  let selected;
  try {
    selected = await ask('\nChoose a step: ');
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
    } else if (selected === '6') {
      await guidedClaim();
    } else console.log('Choose one of the listed steps.');
  } catch {
    if (selected === '6') {
      console.log('Claim preparation did not finish. No transaction was signed or sent.');
      console.log('Check the reviewed release, recovered same identity, opening, current membership, recipient, proving-file pins and new output path.');
      console.log('Changed or expired inputs require a fresh review. Your saved identity is retained.');
      continue;
    }
    console.log('That step did not finish. Check the selected path and password, and avoid overwriting existing files.');
    console.log('Enrollment-request preparation also requires a successful portable backup check. Your saved identity is retained.');
  }
}
console.log('Your encrypted identity stays on this device. Keep your portable backup and passphrase safe.');
