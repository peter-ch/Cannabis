// Small authenticated envelopes for private job instructions and metadata.
// Keys stay with the caller. This is not a TEE, attestation verifier or key-release service.
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
const maxBytes = 32 * 1024 * 1024;
function context(key, value) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw Error('Use a 32-byte content key');
  if (!value || typeof value.jobId !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(value.jobId) ||
      typeof value.policySHA256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.policySHA256)) throw Error('Invalid encryption context');
  return { schema: 'cannabis.compute.envelope.v1', cipher: 'AES-256-GCM', jobId: value.jobId, policySHA256: value.policySHA256 };
}
function decode(value, limit) {
  if (typeof value !== 'string' || value.length > Math.ceil(limit / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw Error('Invalid envelope encoding');
  const data = Buffer.from(value, 'base64');
  if (data.length > limit || data.toString('base64') !== value) throw Error('Invalid envelope size');
  return data;
}
export function newContentKey() { return randomBytes(32); }
export function sealBundle(plaintext, key, expected) {
  const header = context(key, expected);
  if (!Buffer.isBuffer(plaintext) || plaintext.length > maxBytes) throw Error('Bundle exceeds 32 MiB; use a reviewed chunked storage layer for datasets');
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify(header)));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ...header, iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}
export function openBundle(envelope, key, expected) {
  const header = context(key, expected), fields = [...Object.keys(header), 'iv', 'ciphertext', 'tag'];
  if (!envelope || Object.keys(envelope).length !== fields.length || fields.some(k => !(k in envelope)) ||
      Object.entries(header).some(([k, v]) => envelope[k] !== v)) throw Error('Envelope context mismatch');
  const iv = decode(envelope.iv, 12), tag = decode(envelope.tag, 16), ciphertext = decode(envelope.ciphertext, maxBytes);
  if (iv.length !== 12 || tag.length !== 16) throw Error('Invalid nonce or authentication tag');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(JSON.stringify(header))); decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
export function envelopeDigest(envelope) {
  return createHash('sha256').update(JSON.stringify(envelope)).digest('hex');
}
