// Direct wallet preparation. No founder server, private key, RPC or signing here.
import { Interface, TypedDataEncoder, getAddress, ZeroAddress } from 'ethers';
import marketABI from './market-abi.json' with { type: 'json' };

const abi = new Interface(marketABI);
export const bookingTypes = { Booking: [
  ['reservationId', 'bytes32'], ['offerId', 'bytes32'], ['requester', 'address'],
  ['orderId', 'bytes32'], ['termsDigest', 'bytes32'], ['start', 'uint64'], ['end', 'uint64'],
  ['units', 'uint32'], ['gross', 'uint256'], ['holdUntil', 'uint64']
].map(([name, type]) => ({ name, type })) };

export function marketDomain({ chainId, market }) {
  const id = BigInt(chainId), target = getAddress(market);
  if (id <= 0n || id >= 2n ** 256n || target === ZeroAddress) throw Error('Require a chain and market contract');
  return { name: 'Cannabis compute market', version: '1', chainId: id.toString(), verifyingContract: target };
}

export function bookingPayload(context, booking) {
  if (!booking || Object.keys(booking).sort().join() !== bookingTypes.Booking.map(x => x.name).sort().join())
    throw Error('Unexpected booking fields');
  const value = structuredClone(booking), domain = marketDomain(context);
  for (const key of ['reservationId', 'offerId', 'orderId', 'termsDigest'])
    if (!/^0x[0-9a-fA-F]{64}$/.test(value[key]) || /^0x0+$/.test(value[key])) throw Error('Require nonzero booking commitments');
  if (getAddress(value.requester) === ZeroAddress || BigInt(value.units) < 1n || BigInt(value.gross) < 100n ||
      BigInt(value.gross) % 100n || BigInt(value.start) < 1n || BigInt(value.end) <= BigInt(value.start) ||
      BigInt(value.holdUntil) < 1n || BigInt(value.holdUntil) > BigInt(value.start)) throw Error('Invalid booking interval or amount');
  return { domain, types: bookingTypes, value, digest: TypedDataEncoder.hash(domain, bookingTypes, value) };
}

const commands = new Set(['publishResource', 'publishOffer', 'withdrawOffer', 'reserveBatch', 'activate']);
export function prepareMarketTransaction(context, { from, method, args }) {
  const domain = marketDomain(context), sender = getAddress(from);
  if (sender === ZeroAddress || !commands.has(method) || !Array.isArray(args)) throw Error('Unsupported market operation');
  if (method === 'reserveBatch') {
    if (!Array.isArray(args[0]) || args[0].length < 1 || args[0].length > 64 || !Array.isArray(args[1]) || args[0].length !== args[1].length)
      throw Error('Require 1..64 bookings and provider signatures');
    for (const b of args[0]) {
      bookingPayload(context, b);
      if (getAddress(b.requester) !== sender) throw Error('Only the requester can submit its booking');
    }
  }
  if (method === 'activate' && (!Array.isArray(args[0]) || args[0].length < 1 || args[0].length > 64 ||
      args[0].some((id, i) => !/^0x[0-9a-fA-F]{64}$/.test(id) || i > 0 && BigInt(id) <= BigInt(args[0][i - 1]))))
    throw Error('Require sorted unique booking digests');
  return {
    schema: 'cannabis.market-transaction.v1',
    transaction: { chainId: domain.chainId, from: sender, to: domain.verifyingContract, value: '0', data: abi.encodeFunctionData(method, args) },
    method, transactionSubmitted: false, runtimeVerified: false, simulated: false,
    executionAuthorized: false, keyReleaseAuthorized: false,
    note: 'Review the deployed runtime and current chain state, simulate and price gas before wallet signing. This offline payload is not deployment, booking or execution evidence.'
  };
}
