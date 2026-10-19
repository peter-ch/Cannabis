// Local operator provisioning only. No network, content keys, signing or payment.
import fs from 'node:fs';
import path from 'node:path';
import { ResultRelay } from '../service/result-relay.mjs';
import { exact } from '../service/work-store.mjs';
const [configFile, requestFile, destination] = process.argv.slice(2);
let relay, access, created = false;
function read(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try { const s = fs.fstatSync(fd); if (!s.isFile() || s.size > 8192) throw Error(); return JSON.parse(fs.readFileSync(fd, 'utf8')); }
  finally { fs.closeSync(fd); }
}
try {
  if (!configFile || !requestFile || !destination || process.argv.length !== 5 || !path.isAbsolute(destination)) throw Error();
  const config = read(configFile), request = read(requestFile);
  exact(config, ['database', 'origin']); exact(request, ['approvalDigest', 'maxCiphertextBytes', 'expiresAt']);
  if (!path.isAbsolute(config.database)) throw Error();
  const url = new URL(config.origin);
  if (url.origin !== config.origin || url.username || url.password || url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === '127.0.0.1')) throw Error();
  // Existing directories/files are never overwritten. Use protected local storage.
  fs.mkdirSync(destination, { mode: 0o700 }); created = true;
  relay = new ResultRelay(config.database); access = relay.reserve(request);
  for (const role of ['upload', 'read']) {
    const { uploadToken, readToken, ...context } = access;
    const value = { ...context, origin: config.origin, role, token: role === 'upload' ? uploadToken : readToken };
    fs.writeFileSync(path.join(destination, role + '.json'), JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  }
  console.log(JSON.stringify({ reserved: true, files: ['upload.json', 'read.json'], executionAuthorized: false, paymentAuthorized: false }));
} catch {
  if (access) { try { relay.remove(access.id, access.readToken); } catch {} }
  // Retain partial files for diagnosis. Revocation was attempted; a storage
  // failure can leave the reserved slot until expiry, never paid admission.
  console.error(JSON.stringify({ error: 'Storage reservation failed; retain existing files and review private configuration.', directoryCreated: created }));
  process.exitCode = 1;
} finally { relay?.close(); }
