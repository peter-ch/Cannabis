// Portable signed agreements. No saved database flag is funding evidence.
import { AbiCoder, TypedDataEncoder, getAddress, keccak256, verifyTypedData, ZeroAddress } from 'ethers';
import { domain, offerPayload, reservationPayload } from './capacity.mjs';
import { leaseTypes, inspectLease } from './leases.mjs';
import { settlementTerms, termsDigest } from '../scripts/compute-escrow.mjs';
import { policy } from '../scripts/compute-plan.mjs';

const coder = AbiCoder.defaultAbiCoder();
const hash = v => typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v) && !/^0x0+$/.test(v);
function exact(v, keys) {
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).sort().join() !== [...keys].sort().join()) throw Error('Unexpected lease proof fields');
}
function signature(payload, value, signer) {
  if (verifyTypedData(payload.domain, payload.types, payload.value, value) !== getAddress(signer)) throw Error('Lease proof signature mismatch');
}

export function exportLeaseProof(ledger, leaseId) {
  return ledger.transaction(() => {
    const record = inspectLease(ledger, leaseId);
    const reservations = record.agreement.request.reservationIds.map(id => {
      const row = ledger.db.prepare('SELECT body FROM reservations WHERE id=?').get(id);
      if (!row) throw Error('Missing retained reservation');
      return JSON.parse(row.body);
    });
    const offers = [...new Set(reservations.map(s => s.reservation.offerDigest))].map(digest => {
      const row = ledger.db.prepare('SELECT body FROM offers WHERE digest=?').get(digest);
      if (!row) throw Error('Missing retained offer');
      return JSON.parse(row.body);
    });
    const proof = { schema: 'cannabis.lease-proof.v1', agreement: record.agreement, reservations, offers,
      fundedAnchor: record.finalityEvidence.finalizedBlock };
    const verified = verifyLeaseProof(proof, ledger.context);
    if (verified.digest !== record.digest || verified.orderId !== record.orderId) throw Error('Retained lease differs from signed agreement');
    return proof;
  });
}

export function verifyLeaseProof(input, context) {
  // The transport must apply this byte bound before JSON parsing, too.
  if (Buffer.byteLength(JSON.stringify(input)) > 16 * 1024 * 1024) throw Error('Lease proof exceeds bound');
  const proof = structuredClone(input), d = domain(context);
  exact(proof, ['schema', 'agreement', 'reservations', 'offers', 'fundedAnchor']);
  if (proof.schema !== 'cannabis.lease-proof.v1') throw Error('Unknown lease proof');
  const signed = proof.agreement;
  exact(signed, ['request', 'requesterSignature', 'providerSignatures']);
  const r = signed.request;
  exact(r, ['leaseId', 'reservationIds', 'job', 'settlement', 'escrow', 'expiresAt']);
  if (!hash(r.leaseId) || !Array.isArray(r.reservationIds) || r.reservationIds.length < 1 || r.reservationIds.length > 4096 ||
      r.reservationIds.some(id => !hash(id)) || new Set(r.reservationIds).size !== r.reservationIds.length ||
      !Number.isSafeInteger(r.expiresAt) || r.expiresAt < 1 || r.job?.schema !== 'cannabis.compute.order.v2') throw Error('Invalid lease agreement');
  exact(r.settlement, ['workers', 'deliveryManager', 'adjudicator', 'acceptBy', 'deliverBy', 'reviewSeconds', 'disputeSeconds']);
  if (Array.isArray(r.settlement.workers)) for (const worker of r.settlement.workers) exact(worker, ['account', 'shareBps']);
  const terms = settlementTerms(r.job, r.settlement), escrow = getAddress(r.escrow);
  if (escrow === ZeroAddress) throw Error('Invalid lease escrow');
  if (!Array.isArray(proof.reservations) || proof.reservations.length !== r.reservationIds.length ||
      !Array.isArray(proof.offers) || proof.offers.length < 1 || proof.offers.length > proof.reservations.length) throw Error('Incomplete reservation proof');
  const offers = new Map(), reservations = new Map(), usedOffers = new Set();
  for (const signedOffer of proof.offers) {
    exact(signedOffer, ['offer', 'signature']);
    const p = offerPayload(context, signedOffer.offer);
    signature(p, signedOffer.signature, signedOffer.offer.provider);
    if (offers.has(p.digest)) throw Error('Duplicate offer proof');
    offers.set(p.digest, signedOffer.offer);
  }
  const prices = new Map(); let total = 0n;
  for (const signedReservation of proof.reservations) {
    exact(signedReservation, ['reservation', 'requesterSignature', 'providerSignature']);
    const reservation = signedReservation.reservation, p = reservationPayload(context, reservation);
    const offer = offers.get(reservation.offerDigest);
    if (!offer || reservations.has(reservation.reservationId) || !r.reservationIds.includes(reservation.reservationId)) throw Error('Unknown or duplicate reservation proof');
    const provider = getAddress(offer.provider);
    signature(p, signedReservation.requesterSignature, terms.requester);
    signature(p, signedReservation.providerSignature, provider);
    if (getAddress(reservation.requester) !== terms.requester || reservation.jobSHA256 !== '0x' + r.job.packageSHA256 ||
        offer.policySHA256 !== '0x' + r.job.policySHA256) throw Error('Lease proof workload mismatch');
    if (reservation.start < offer.windowStart || reservation.end > offer.windowEnd || reservation.units > offer.units ||
        reservation.holdUntil > reservation.start || reservation.holdUntil > offer.expiresAt || r.expiresAt > reservation.holdUntil ||
        terms.terms.acceptBy > reservation.start || terms.terms.deliverBy < reservation.end) throw Error('Lease proof interval mismatch');
    const gross = BigInt(reservation.grossBaseUnits);
    if (gross !== BigInt(offer.grossPerUnitSecond) * BigInt(reservation.end - reservation.start) * BigInt(reservation.units)) throw Error('Lease proof quote mismatch');
    prices.set(provider, (prices.get(provider) ?? 0n) + gross); total += gross;
    reservations.set(reservation.reservationId, { ...reservation, provider, resourceId: offer.resourceId, serviceSHA256: offer.serviceSHA256, digest: p.digest });
    usedOffers.add(reservation.offerDigest);
  }
  if (usedOffers.size !== offers.size || total !== BigInt(terms.terms.budget) || prices.size !== terms.accounts.length ||
      terms.accounts.some((a, i) => !prices.has(a) || total * BigInt(terms.shares[i]) !== prices.get(a) * 10000n)) throw Error('Lease proof budget or worker shares mismatch');
  const binding = { chainId: context.chainId, escrow, token: getAddress(context.token), founderRecipient: getAddress(policy.founderRecipient), ...terms };
  const orderId = keccak256(coder.encode(['string', 'uint256', 'address', 'address', 'bytes32'],
    ['Cannabis compute order v1', context.chainId, escrow, terms.requester, terms.terms.jobHash]));
  const value = { leaseId: r.leaseId, reservationDigests: [...r.reservationIds].sort().map(id => reservations.get(id).digest),
    escrow, orderId, termsDigest: termsDigest(binding), expiresAt: r.expiresAt };
  const payload = { domain: d, types: leaseTypes, value };
  signature(payload, signed.requesterSignature, terms.requester);
  if (!Array.isArray(signed.providerSignatures) || signed.providerSignatures.length !== terms.accounts.length) throw Error('Missing lease proof provider signatures');
  const seen = new Set();
  for (const item of signed.providerSignatures) {
    exact(item, ['provider', 'signature']); const provider = getAddress(item.provider);
    if (seen.has(provider) || !terms.accounts.includes(provider)) throw Error('Unexpected lease proof provider');
    signature(payload, item.signature, provider); seen.add(provider);
  }
  const anchor = proof.fundedAnchor;
  exact(anchor, ['number', 'hash', 'timestamp']);
  if (!Number.isSafeInteger(anchor.number) || anchor.number < 0 || !hash(anchor.hash) ||
      !Number.isSafeInteger(anchor.timestamp) || anchor.timestamp < 1 || anchor.timestamp > r.expiresAt) throw Error('Funding anchor is outside the signing window');
  return { digest: TypedDataEncoder.hash(d, leaseTypes, value), orderId, termsDigest: value.termsDigest,
    requester: terms.requester, job: r.job, escrow, signingExpiresAt: r.expiresAt,
    providers: terms.accounts, reservations: [...reservations.values()], fundedAnchor: anchor };
}
