import { Decrypter, identityToRecipient } from 'age-encryption';

export const MAX_RESULT_BYTES = 64 * 1024 * 1024;
const utf8 = new TextDecoder('utf-8', { fatal: true });
export const sha256 = async bytes => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
const check = (condition, message) => { if (!condition) throw Error(message); };
const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value) && !/^0+$/.test(value);
function safePath(name) {
  check(typeof name === 'string' && name.length > 0 && name.length <= 512 && !/[\\:\x00-\x1f\x7f]/.test(name), 'Unsafe result path');
  check(name.split('/').every(p => p && p !== '.' && p !== '..' && !/[. ]$/.test(p) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p)), 'Unsafe result path');
  return name;
}
function field(bytes) { return utf8.decode(bytes).split('\0')[0]; }
function octal(bytes) {
  const text = field(bytes).trim(); check(/^[0-7]+$/.test(text), 'Invalid archive integer');
  const n = Number.parseInt(text, 8); check(Number.isSafeInteger(n) && n >= 0, 'Archive integer overflow'); return n;
}
export async function readResultArchive(bytes) {
  check(bytes instanceof Uint8Array && bytes.length <= MAX_RESULT_BYTES && bytes.length % 512 === 0, 'Result archive exceeds browser limits or is truncated');
  let offset = 0;
  function member() {
    check(offset + 512 <= bytes.length, 'Truncated archive');
    const h = bytes.subarray(offset, offset + 512); offset += 512;
    check(h.some(b => b !== 0), 'Missing archive member');
    const checksum = h.reduce((sum, b, i) => sum + (i >= 148 && i < 156 ? 32 : b), 0);
    check(checksum === octal(h.subarray(148, 156)), 'Invalid archive checksum');
    check(field(h.subarray(257, 263)) === 'ustar' && [0, 48].includes(h[156]) && !field(h.subarray(157, 257)) && !field(h.subarray(345, 500)), 'Only regular USTAR result files are supported');
    const name = field(h.subarray(0, 100)), size = octal(h.subarray(124, 136)), end = offset + size;
    check(end <= bytes.length && size <= MAX_RESULT_BYTES, 'Truncated archive member');
    const data = bytes.subarray(offset, end); offset += Math.ceil(size / 512) * 512;
    check(offset <= bytes.length && !bytes.subarray(end, offset).some(b => b !== 0), 'Invalid archive padding');
    return { name, data };
  }
  const first = member(); check(first.name === 'manifest.json' && first.data.length <= 1024 * 1024, 'Missing bounded result manifest');
  const manifest = JSON.parse(utf8.decode(first.data));
  check(manifest.schema === 'cannabis.archive.v1' && manifest.kind === 'result' && Array.isArray(manifest.files) && manifest.files.length <= 4096, 'Invalid result manifest');
  const files = new Map(), seen = new Set();
  for (const [i, entry] of manifest.files.entries()) {
    const name = safePath(entry.path), folded = name.toLowerCase();
    check(!seen.has(folded) && Number.isSafeInteger(entry.bytes) && entry.bytes >= 0 && hash(entry.sha256), 'Invalid result inventory'); seen.add(folded);
    const item = member();
    check(item.name === 'files/' + String(i).padStart(8, '0') && item.data.length === entry.bytes && await sha256(item.data) === entry.sha256, 'Result file differs from its authenticated inventory');
    files.set(name, item.data);
  }
  const tail = bytes.subarray(offset);
  check(tail.length >= 1024 && tail.length <= 32768 && !tail.some(b => b !== 0), 'Unexpected archive members or trailing data');
  return { manifest, files };
}

// Inputs are requester-held workload terms and receipt commitments. Successful
// authentication is not a claim of correct computation or payment approval.
export async function openResults({ spec, packageSHA256, identity, results }) {
  check(spec?.schema === 'cannabis.workload.v1' && typeof spec.id === 'string' && Array.isArray(spec.tasks) && spec.tasks.length > 0 && spec.tasks.length <= 4096 && Array.isArray(spec.assembly) && spec.assembly.length > 0 && spec.assembly.length <= 4096 && hash(packageSHA256), 'Load the original private workload and encrypted package digest');
  const identities = identity.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
  check(identities.length === 1 && /^AGE-SECRET-KEY-1[0-9A-Z]+$/.test(identities[0]), 'Use one requester result identity, never a wallet seed');
  const recipient = await identityToRecipient(identities[0]);
  check(spec.resultRecipient === recipient, 'Result identity does not match the original workload recipient');
  const tasks = new Map(spec.tasks.map(t => [t.id, t]));
  check(tasks.size === spec.tasks.length && results.length > 0 && results.length <= 128, 'Invalid task or result count');
  check(results.reduce((n, r) => n + r.bytes.length, 0) <= MAX_RESULT_BYTES, 'Use the streaming client for result sets above 64 MiB');
  const opened = new Map();
  for (const { receipt, bytes } of results) {
    const task = tasks.get(receipt.taskId), key = `${receipt.taskId}\0${receipt.rank}`;
    check(receipt.schema === 'cannabis.result.v1' && receipt.jobId === spec.id && receipt.packageSHA256 === packageSHA256 && receipt.recipient === recipient && task && !opened.has(key), 'Wrong job, recipient, task, package or duplicate result');
    check(Number.isSafeInteger(receipt.attempt) && receipt.attempt > 0 && Number.isSafeInteger(receipt.rank) && receipt.rank >= 0 && Number.isSafeInteger(task.resources?.nodes) && task.resources.nodes > 0 && task.resources.nodes <= 4096 && receipt.rank < task.resources.nodes && receipt.worldSize === task.resources.nodes && (!receipt.rank || task.outputScope === 'per-rank'), 'Invalid result rank or attempt');
    check(hash(receipt.ciphertextSHA256) && await sha256(bytes) === receipt.ciphertextSHA256 && bytes.length === receipt.ciphertextBytes, 'Encrypted result digest or size mismatch');
    const d = new Decrypter(); d.addIdentity(identities[0]);
    const plaintext = await d.decrypt(bytes);
    const { manifest, files } = await readResultArchive(plaintext);
    const expected = ['jobId', 'taskId', 'packageSHA256', 'attempt', 'rank', 'worldSize'];
    check(manifest.context && Object.keys(manifest.context).sort().join() === [...expected].sort().join() && expected.every(k => manifest.context[k] === receipt[k]), 'Authenticated result context differs from receipt');
    check(Array.isArray(task.outputs) && task.outputs.length === files.size && new Set(task.outputs).size === task.outputs.length && task.outputs.every(name => files.has(name)), 'Result does not match agreed outputs');
    const outputLimit = task.outputMaxBytes ?? 1024 ** 3;
    check(Number.isSafeInteger(outputLimit) && outputLimit >= 0 && [...files.values()].reduce((n, b) => n + b.length, 0) <= outputLimit, 'Output exceeds the agreed limit');
    opened.set(key, files);
  }
  const assembled = new Map(), destinations = new Set();
  for (const item of spec.assembly) {
    const task = tasks.get(item.task); check(task, 'Unknown assembly task');
    const ranks = item.rank === 'all' ? Array.from({ length: task.resources.nodes }, (_, i) => i) : [item.rank ?? 0];
    for (const rank of ranks) {
      check(Number.isSafeInteger(rank) && rank >= 0 && rank < task.resources.nodes, 'Invalid assembly rank');
      const output = opened.get(`${item.task}\0${rank}`)?.get(item.output);
      check(output && typeof item.destination === 'string', 'Missing required result');
      const name = safePath(item.destination.replaceAll('{rank}', String(rank))), folded = name.toLowerCase();
      check(![...destinations].some(d => d === folded || d.startsWith(folded + '/') || folded.startsWith(d + '/')), 'Overlapping assembly destinations');
      destinations.add(folded); assembled.set(name, output);
      check(assembled.size <= 4096, 'Too many assembled files');
    }
  }
  return assembled;
}
