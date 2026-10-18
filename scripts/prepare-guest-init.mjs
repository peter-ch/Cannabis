// Prepare a public assignment commitment. Never reads keys or launches services.
import fs from 'node:fs';
import { guestInitialization } from '../compute/guest_initialization.mjs';

try {
  const [inputFlag, input, outputFlag, output, ...rest] = process.argv.slice(2);
  if (inputFlag !== '--input' || outputFlag !== '--out' || !input || !output || rest.length) throw Error('Expected --input assignment.json --out initialization.json');
  const source = fs.openSync(input, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  let data;
  try {
    const stat = fs.fstatSync(source);
    if (!stat.isFile() || stat.size < 1 || stat.size > 65536) throw Error('Require a bounded regular assignment file');
    const buffer = Buffer.alloc(65537);
    let size = 0;
    while (size < buffer.length) { const count = fs.readSync(source, buffer, size, buffer.length - size, null); if (!count) break; size += count; }
    if (size !== stat.size) throw Error('Assignment changed during read');
    data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size)));
  } finally { fs.closeSync(source); }
  const initialized = guestInitialization(data);
  fs.writeFileSync(output, initialized.canonical + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ schema: 'cannabis.guest-initialization-preparation.v1', tee: initialized.assignment.tee,
    initData: initialized.digest, initDataBase64: initialized.digestBase64, output, hardwareValidated: false, executionAuthorized: false }));
} catch (error) { console.error(error.message); process.exitCode = 1; }
