// Public assignment commitment consumed inside the measured guest control plane.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { getAddress, ZeroAddress } from 'ethers';
import { validateAttestationBinding } from './attestation.mjs';

const fields = ['schema', 'tee', 'requester', 'jobId', 'binding'];
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}

export function guestInitialization(initialization) {
  const value = structuredClone(initialization);
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length || fields.some(k => !Object.hasOwn(value, k)) ||
      !['cannabis.guest-initialization.v1','cannabis.guest-initialization.v2'].includes(value.schema) || !['snp', 'tdx'].includes(value.tee) ||
      typeof value.jobId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value.jobId)) throw Error('Invalid guest initialization assignment');
  if (typeof value.requester !== 'string' || getAddress(value.requester) === ZeroAddress) throw Error('Invalid initialization requester');
  // Canonical addresses make equivalent input encodings produce one commitment.
  value.requester = getAddress(value.requester);
  validateAttestationBinding(value.binding);
  if((value.schema==='cannabis.guest-initialization.v2')!==Object.hasOwn(value.binding,'configurationSHA256'))
    throw Error('Initialization version differs from its configuration commitment');
  value.binding.escrow = getAddress(value.binding.escrow);
  const bytes = Buffer.from(canonical(value));
  const digest = createHash(value.tee === 'snp' ? 'sha256' : 'sha384').update(bytes).digest();
  return { assignment: value, canonical: bytes.toString(), digest: digest.toString('hex'), digestBase64: digest.toString('base64') };
}

export function readGuestInitialization(file) {
  // Bound reads and reject FIFOs/devices before reading. On Linux, also reject
  // symlinks at open, so a replaced pathname cannot redirect the file descriptor.
  const handle = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const stat = fs.fstatSync(handle);
    if (!stat.isFile() || stat.size < 1 || stat.size > 65536) throw Error('Require a bounded regular initialization file');
    const bytes = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = fs.readSync(handle, bytes, length, bytes.length - length, null);
      if (!read) break;
      length += read;
    }
    if (length !== stat.size) throw Error('Initialization file changed during read');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length));
    const result = guestInitialization(JSON.parse(text));
    // Prevent duplicate-key/whitespace encodings from acquiring a different
    // meaning in another parser. The preparation command writes this form.
    if (text !== result.canonical + '\n') throw Error('Require canonical guest initialization bytes');
    return result;
  } finally { fs.closeSync(handle); }
}

export function matchGuestInitialization(initialization, { policy, expectedBinding, requester, jobId }) {
  const result = guestInitialization(initialization);
  const assignment = result.assignment;
  if (policy?.tee !== assignment.tee || policy?.measurements?.initData !== result.digest ||
      getAddress(requester) !== assignment.requester || jobId !== assignment.jobId || canonical(expectedBinding) !== canonical(assignment.binding)) {
    throw Error('Guest initialization differs from the approved guest assignment or hardware initialization digest');
  }
  return result;
}
