// Portable market commitments and independent chain observations. No local
// reservation database, coordinator signature, wallet signing or key custody.
import { AbiCoder, getAddress, keccak256, ZeroAddress } from 'ethers';
import { bookingPayload } from './market.mjs';
import { readMarketBookings, readMarketBookingsAtAnchor, readCurrentMarketBookings } from './market_reader.mjs';
import { readFundedEscrowAtAnchor, readCurrentEscrow } from './finality.mjs';
import { settlementTerms, termsDigest } from '../scripts/compute-escrow.mjs';
import { policy } from '../scripts/compute-plan.mjs';
import { validateWalletApprovals } from './wallet_signatures.mjs';

const coder = AbiCoder.defaultAbiCoder();
const seconds = () => Math.floor(Date.now() / 1000);
const hash = v => typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v) && !/^0x0+$/.test(v);
const integer = n => Number.isSafeInteger(n) && n >= 0;
const plain = v => JSON.parse(JSON.stringify(v, (_, x) => typeof x === 'bigint' ? x.toString() : x));
const canonical = v => Array.isArray(v) ? '[' + v.map(canonical).join(',') + ']' :
  v && typeof v === 'object' ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}' : JSON.stringify(v);
function exact(v, keys) {
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).sort().join() !== [...keys].sort().join())
    throw Error('Unexpected market lease fields');
}
function uint(value, maximum = Number.MAX_SAFE_INTEGER) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > BigInt(maximum)) throw Error('Invalid market lease integer');
  return Number(value);
}
function address(value) {
  const a = getAddress(value); if (a === ZeroAddress || a !== value) throw Error('Require canonical market lease address'); return a;
}
function retainedRecord(r) { return plain({ bookingId: r.bookingId, booking: r.booking, offer: r.offer, resource: r.resource }); }

// This verifies commitments, not whether any booking actually exists. Both the
// requester and protected guest must independently call readMarketLeaseState.
export function verifyMarketLeaseProof(input, context) {
  if (Buffer.byteLength(JSON.stringify(input)) > 1024 * 1024) throw Error('Market lease proof exceeds bound');
  const p = structuredClone(input);
  exact(p, ['schema', 'chainId', 'market', 'token', 'escrow', 'job', 'settlement', 'bookings', 'fundedAnchor']);
  if (p.schema !== 'cannabis.market-lease.v1' || !integer(p.chainId) || p.chainId < 1 || p.chainId !== context.chainId ||
      address(p.market) !== getAddress(context.market) || getAddress(p.token) !== getAddress(context.token) ||
      p.job?.schema !== 'cannabis.compute.order.v2') throw Error('Market lease domain differs');
  address(p.escrow);
  exact(p.settlement, ['workers', 'deliveryManager', 'adjudicator', 'acceptBy', 'deliverBy', 'reviewSeconds', 'disputeSeconds']);
  if (Array.isArray(p.settlement.workers)) for (const w of p.settlement.workers) exact(w, ['account', 'shareBps']);
  const terms = settlementTerms(p.job, p.settlement);
  const digest = termsDigest({ chainId: p.chainId, escrow: p.escrow, token: p.token, founderRecipient: policy.founderRecipient, ...terms });
  const orderId = keccak256(coder.encode(['string', 'uint256', 'address', 'address', 'bytes32'],
    ['Cannabis compute order v1', p.chainId, p.escrow, terms.requester, terms.terms.jobHash]));
  if (!Array.isArray(p.bookings) || p.bookings.length < 1 || p.bookings.length > 64) throw Error('Require 1..64 market bookings');
  const prices = new Map(), reservations = []; let previous = '', total = 0n;
  for (const r of p.bookings) {
    exact(r, ['bookingId', 'booking', 'offer', 'resource']);
    if (!hash(r.bookingId) || r.bookingId <= previous) throw Error('Require sorted unique booking digests'); previous = r.bookingId;
    const b = r.booking, o = r.offer, resource = r.resource;
    exact(o, ['resource', 'escrow', 'policyHash', 'manifestHash', 'start', 'end', 'expiresAt', 'units', 'grossPerUnitSecond']);
    exact(resource, ['provider', 'serviceHash', 'units']);
    if (bookingPayload(context, b).digest !== r.bookingId || address(b.requester) !== terms.requester ||
        b.orderId !== orderId || b.termsDigest !== digest || address(o.escrow) !== p.escrow ||
        o.policyHash !== '0x' + p.job.policySHA256 || !hash(o.resource) || !hash(o.manifestHash) || !hash(resource.serviceHash))
      throw Error('Market booking differs from workload or settlement commitments');
    const provider = address(resource.provider), start = uint(b.start), end = uint(b.end), units = uint(b.units, 2 ** 32 - 1);
    const hold = uint(b.holdUntil), offerStart = uint(o.start), offerEnd = uint(o.end), expires = uint(o.expiresAt);
    if (start < offerStart || end > offerEnd || hold > expires || hold > start || hold < 1 || start < 1 || end <= start ||
        units < 1 || units > uint(o.units, 2 ** 32 - 1) || uint(o.units, 2 ** 32 - 1) > uint(resource.units, 2 ** 32 - 1) ||
        terms.terms.acceptBy > start || terms.terms.deliverBy < end) throw Error('Market booking interval or units differ');
    if (!/^[1-9][0-9]*$/.test(b.gross) || !/^[1-9][0-9]*$/.test(o.grossPerUnitSecond)) throw Error('Invalid market booking price');
    const gross = BigInt(b.gross), rate = BigInt(o.grossPerUnitSecond);
    if (rate % 100n || gross % 100n || gross !== rate * BigInt(end - start) * BigInt(units)) throw Error('Market booking price differs');
    prices.set(provider, (prices.get(provider) ?? 0n) + gross); total += gross;
    reservations.push({ reservationId: r.bookingId, provider, resourceId: o.resource, serviceSHA256: resource.serviceHash,
      start, end, units, grossBaseUnits: b.gross, holdUntil: hold });
  }
  if (total !== BigInt(terms.terms.budget) || prices.size !== terms.accounts.length ||
      terms.accounts.some((a, i) => !prices.has(a) || total * BigInt(terms.shares[i]) !== prices.get(a) * 10000n))
    throw Error('Incomplete market booking group or incorrect worker prices');
  exact(p.fundedAnchor, ['number', 'hash', 'timestamp']);
  if (!integer(p.fundedAnchor.number) || !hash(p.fundedAnchor.hash) || !integer(p.fundedAnchor.timestamp) || p.fundedAnchor.timestamp < 1)
    throw Error('Invalid market funding anchor');
  // The legacy field name leaseDigest now commits a distinct versioned domain,
  // market contract and full sorted booking group, not a local ledger identifier.
  const leaseDigest = keccak256(coder.encode(['string', 'uint256', 'address', 'address', 'bytes32', 'bytes32', 'bytes32[]'],
    ['Cannabis on-chain booking group v1', p.chainId, p.market, p.escrow, orderId, digest, p.bookings.map(r => r.bookingId)]));
  return { schema: p.schema, digest: leaseDigest, orderId, termsDigest: digest, market: p.market, escrow: p.escrow,
    requester: terms.requester, job: p.job, providers: terms.accounts, shares: terms.shares, reservations,
    fundedAnchor: p.fundedAnchor, proof: p, executionAuthorized: false, keyReleaseAuthorized: false };
}

function checkMarket(snapshot, lease) {
  if (snapshot.market !== lease.market || canonical(snapshot.bookings.map(retainedRecord)) !== canonical(lease.proof.bookings) ||
      snapshot.bookings.some(r => !r.activated || !r.orderActivated)) throw Error('Canonical activated bookings differ from the retained market lease');
}
function checkEscrow(snapshot, lease) {
  if (snapshot.orderId !== lease.orderId || snapshot.termsDigest !== lease.termsDigest || snapshot.requester !== lease.requester ||
      snapshot.escrow !== lease.escrow || getAddress(snapshot.token) !== getAddress(lease.proof.token) || snapshot.state !== 2 ||
      canonical(snapshot.accounts) !== canonical(lease.providers) || canonical(snapshot.shares) !== canonical(lease.shares) ||
      snapshot.acceptedCount !== lease.providers.length || BigInt(snapshot.acceptedBitmap) !== (1n << BigInt(lease.providers.length)) - 1n)
    throw Error('Market funding must remain a matching fully accepted active order');
}
function configuration(proof, network) {
  const lease = verifyMarketLeaseProof(proof, { chainId: network.chainId, market: network.market, token: network.token });
  if (lease.escrow !== getAddress(network.escrow)) throw Error('Market lease escrow differs from approved network');
  return lease;
}

export async function createMarketLeaseProof(network, { job, settlement, bookingIds }, clock = seconds) {
  const market = await readMarketBookings(network, { bookingIds: [...bookingIds].sort() }, clock);
  const proof = { schema: 'cannabis.market-lease.v1', chainId: network.chainId, market: getAddress(network.market),
    token: getAddress(network.token), escrow: getAddress(network.escrow), job: structuredClone(job), settlement: structuredClone(settlement),
    bookings: market.bookings.map(retainedRecord), fundedAnchor: market.finalizedBlock };
  const lease = configuration(proof, network); checkMarket(market, lease);
  const escrow = await readFundedEscrowAtAnchor({ ...network, orderId: lease.orderId, fundedAnchor: proof.fundedAnchor }, clock);
  checkEscrow(escrow, lease);
  if (canonical(escrow.finalizedBlock) !== canonical(proof.fundedAnchor)) throw Error('Booking and funding anchors differ');
  return proof;
}

// Original activation/funding, fresh finalized state and current canonical state
// are read independently. Historical JSON and optional indexers have no authority.
export async function readMarketLeaseState(proof, network, clock = seconds, options = {}, runtime) {
  network = structuredClone(network);
  exact(options,['launchApprovals','channelApprovals'].filter(k=>Object.hasOwn(options,k)));
  if(Object.hasOwn(options,'channelApprovals')&&!Object.hasOwn(options,'launchApprovals'))throw Error('Channel authentication requires launch consent');
  if(['launchApprovals','channelApprovals'].some(k=>Object.hasOwn(network,k)))throw Error('Launch consent belongs to the assignment, not network configuration');
  const launchApprovals=Object.hasOwn(options,'launchApprovals')?validateWalletApprovals(options.launchApprovals):undefined;
  const channelApprovals=Object.hasOwn(options,'channelApprovals')?validateWalletApprovals(options.channelApprovals):undefined;
  const lease = configuration(proof, network), query = { bookingIds: lease.proof.bookings.map(r => r.bookingId) };
  // Callers derive these digests from inspectLaunchConsent for the exact chosen
  // booking. This low-level reader verifies state, not an arbitrary assignment.
  if(launchApprovals && (launchApprovals[0].signer!==lease.requester || !lease.providers.includes(launchApprovals[1].signer)))
    throw Error('Launch approval parties differ from the funded market group');
  if(channelApprovals && channelApprovals.some((a,i)=>a.signer!==launchApprovals[i].signer))
    throw Error('Channel approval parties differ from launch consent');
  const consent={...(launchApprovals?{launchApprovals}:{}),...(channelApprovals?{channelApprovals}:{})};
  const n = { ...network, orderId: lease.orderId }, fundedAnchor = lease.fundedAnchor;
  const [originalMarket, originalEscrow] = await Promise.all([
    readMarketBookingsAtAnchor({ ...n, fundedAnchor }, query, clock, runtime), readFundedEscrowAtAnchor({ ...n, fundedAnchor }, clock, runtime)
  ]);
  checkMarket(originalMarket, lease); checkEscrow(originalEscrow, lease);
  if (canonical(originalEscrow.finalizedBlock) !== canonical(fundedAnchor)) throw Error('Original funding anchor timestamp differs');
  const finalized = await readMarketBookings(n, query, clock, runtime); checkMarket(finalized, lease);
  if (finalized.finalizedBlock.number < fundedAnchor.number) throw Error('Market finality regressed');
  // Consent may be created after original funding. It must be valid at both
  // fresh observations, not retroactively at the historical funding anchor.
  const funded = await readFundedEscrowAtAnchor({ ...n, ...consent, fundedAnchor: finalized.finalizedBlock }, clock, runtime); checkEscrow(funded, lease);
  if (canonical(funded.finalizedBlock) !== canonical(finalized.finalizedBlock)) throw Error('Finalized booking and funding anchors differ');
  const currentMarket = await readCurrentMarketBookings({ ...n, finalizedAnchor: finalized.finalizedBlock, fundingAnchor: fundedAnchor }, query, clock, runtime);
  checkMarket(currentMarket, lease);
  const current = await readCurrentEscrow({ ...n, ...consent, finalizedAnchor: finalized.finalizedBlock, fundingAnchor: fundedAnchor }, clock, runtime);
  checkEscrow(current, lease);
  if (current.headBlock.number < currentMarket.headBlock.number) throw Error('Latest market/funding view regressed');
  return { schema: 'cannabis.market-lease-state.v1', leaseDigest: lease.digest, market: lease.market, orderId: lease.orderId,
    fundedAnchor, finalizedBlock: finalized.finalizedBlock, headBlock: current.headBlock, observedAt: current.observedAt,
    ...(launchApprovals?{launchSignatures:{finalized:funded.launchSignatures,head:current.launchSignatures}}:{}),
    ...(channelApprovals?{channelSignatures:{finalized:funded.channelSignatures,head:current.channelSignatures}}:{}),
    executionAuthorized: false, keyReleaseAuthorized: false, hardwareVerified: false };
}
