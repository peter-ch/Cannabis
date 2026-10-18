// All configuration fields are public values or local paths; never put secret keys in JSON.
import fs from 'node:fs';
import path from 'node:path';
import { createEncryptedIdentity, inspectEncryptedIdentity, generateClaimProof, readBounded } from '../claims/identity.mjs';

try {
  const [command, configFlag, configPath, outFlag, outPath, ...extra] = process.argv.slice(2);
  if (!['create', 'inspect', 'prove'].includes(command) || configFlag !== '--config' || outFlag !== '--out' || !configPath || !outPath || extra.length) throw Error('Use create|inspect|prove --config local-config.json --out output.json');
  if (fs.existsSync(outPath)) throw Error('Output already exists');
  const config = JSON.parse(readBounded(path.resolve(configPath), 128 * 1024 * 1024).toString('utf8'));
  if (command === 'prove' && config.membershipFile) {
    if (Object.hasOwn(config, 'snapshot') || Object.hasOwn(config, 'context')) throw Error('Choose one membership input');
    const membership = JSON.parse(readBounded(config.membershipFile, 128 * 1024 * 1024).toString('utf8'));
    if (membership.schema !== 'cannabis.membership-download.v1') throw Error('Invalid membership download format');
    config.snapshot = membership.snapshot; config.context = membership.context;
  }
  const result = command === 'create' ? createEncryptedIdentity(config) : command === 'inspect' ? await inspectEncryptedIdentity(config) : await generateClaimProof(config);
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ output: path.resolve(outPath), operation: command, sent: false }));
} catch {
  // Library and tool diagnostics may contain private inputs. Never print them.
  console.error('Local claim operation failed. Check the documented configuration, custody files, membership and artifact pins.');
  process.exitCode = 1;
} finally { await globalThis.curve_bn128?.terminate(); }
