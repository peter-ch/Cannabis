// Direct RPC discovery/inspection. Optional indexers cannot authorize bookings.
import { FetchRequest, Interface, JsonRpcProvider, getAddress, keccak256 } from 'ethers';
import abi from './market-abi.json' with { type: 'json' };

const market = new Interface(abi);
const hash = value => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value) && !/^0x0+$/.test(value);
const integer = n => Number.isSafeInteger(n) && n >= 0;
const plain = value => JSON.parse(JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v));
const object = tuple => tuple.toObject(true);

async function snapshot(options, inspect, clock) {
  const endpoint = new URL(options.rpc);
  if (endpoint.username || endpoint.password || !(endpoint.protocol === 'https:' || endpoint.protocol === 'http:' && endpoint.hostname === '127.0.0.1'))
    throw Error('Require HTTPS RPC or loopback verification RPC');
  if (options.finality !== 'rpc-finalized' || !Number.isSafeInteger(options.maxFinalizedAgeSeconds) ||
      options.maxFinalizedAgeSeconds < 1 || options.maxFinalizedAgeSeconds > 7200 ||
      !hash(options.genesisHash) || !hash(options.marketCodeHash) || BigInt(options.chainId) <= 0n)
    throw Error('Pin the chain, genesis, market runtime and bounded finalized policy');
  const address = getAddress(options.market), request = new FetchRequest(endpoint.href);
  request.timeout = 15000;
  const provider = new JsonRpcProvider(request, undefined, { cacheTimeout: -1 });
  const send = (method, params) => provider.send(method, params);
  try {
    const [network, genesis, block] = await Promise.all([
      provider.getNetwork(), send('eth_getBlockByNumber', ['0x0', false]), send('eth_getBlockByNumber', ['finalized', false])
    ]);
    const checkAge = () => {
      const age = clock() - Number(BigInt(block.timestamp));
      if (!Number.isSafeInteger(age) || age < -30 || age > options.maxFinalizedAgeSeconds) throw Error('Finalized market block is stale or in the future');
    };
    if (network.chainId !== BigInt(options.chainId) || genesis?.hash?.toLowerCase() !== options.genesisHash.toLowerCase() ||
        !hash(block?.hash) || !integer(Number(BigInt(block.number)))) throw Error('Market chain or genesis differs');
    checkAge();
    const tag = { blockHash: block.hash, requireCanonical: true };
    const code = await send('eth_getCode', [address, tag]);
    if (code === '0x' || keccak256(code).toLowerCase() !== options.marketCodeHash.toLowerCase()) throw Error('Market runtime differs from the reviewed release');
    const call = async (name, args = []) => market.decodeFunctionResult(name,
      await send('eth_call', [{ to: address, data: market.encodeFunctionData(name, args) }, tag]));
    const value = await inspect({ call, send, address, block });
    const [canonical, watermark] = await Promise.all([
      send('eth_getBlockByNumber', [block.number, false]), send('eth_getBlockByNumber', ['finalized', false])
    ]);
    if (canonical?.hash !== block.hash || !watermark || BigInt(watermark.number) < BigInt(block.number))
      throw Error('Finalized market state changed during inspection');
    checkAge();
    return plain({ schema: 'cannabis.market-snapshot.v1', chainId: network.chainId, market: address,
      marketCodeHash: options.marketCodeHash, genesisHash: options.genesisHash,
      finalizedBlock: { number: Number(BigInt(block.number)), hash: block.hash, timestamp: Number(BigInt(block.timestamp)) },
      ...value, executionAuthorized: false, keyReleaseAuthorized: false,
      note: 'RPC-reported finalized state, not a local consensus proof or physical capacity attestation.' });
  } finally { provider.destroy(); }
}

async function readOffer(call, id) {
  const [offer, withdrawn] = await Promise.all([call('offers', [id]), call('withdrawnOffers', [id])]);
  if (!hash(offer.resource)) throw Error('Unknown market offer');
  const resource = await call('resources', [offer.resource]);
  return { offerId: id, offer: object(offer), resource: object(resource), withdrawn: withdrawn[0] };
}

export async function readMarketOffers(options, { fromBlock, toBlock }, clock = () => Math.floor(Date.now() / 1000)) {
  if (!integer(fromBlock) || !integer(toBlock) || toBlock < fromBlock || toBlock - fromBlock >= 256)
    throw Error('Scan an explicit range of at most 256 blocks');
  return snapshot(options, async ({ call, send, address, block }) => {
    if (toBlock > Number(BigInt(block.number))) throw Error('Offer discovery cannot scan unfinalized blocks');
    const logs = await send('eth_getLogs', [{ address, fromBlock: '0x' + fromBlock.toString(16), toBlock: '0x' + toBlock.toString(16),
      topics: [market.getEvent('OfferPublished').topicHash] }]);
    if (!Array.isArray(logs) || logs.length > 128) throw Error('Too many offers; scan a smaller block range');
    const offers = [], seen = new Set();
    for (const log of logs) {
      const height = Number(BigInt(log.blockNumber));
      if (log.removed || getAddress(log.address) !== address || height < fromBlock || height > toBlock || !hash(log.blockHash))
        throw Error('Invalid offer discovery log');
      const event = market.parseLog(log);
      if (event?.name !== 'OfferPublished' || seen.has(event.args.offerId)) throw Error('Invalid or duplicate offer event');
      seen.add(event.args.offerId);
      const current = await readOffer(call, event.args.offerId);
      if (JSON.stringify(plain(current.offer)) !== JSON.stringify(plain(object(event.args.offer))))
        throw Error('Offer event differs from finalized contract state');
      offers.push({ ...current, publishedBlock: height,
        expiredAtSnapshot: BigInt(current.offer.expiresAt) <= BigInt(block.timestamp) });
    }
    return { fromBlock, toBlock, offers };
  }, clock);
}

export async function readMarketBookings(options, { bookingIds }, clock = () => Math.floor(Date.now() / 1000)) {
  if (!Array.isArray(bookingIds) || bookingIds.length < 1 || bookingIds.length > 64 ||
      bookingIds.some(id => !hash(id)) || new Set(bookingIds.map(id => id.toLowerCase())).size !== bookingIds.length)
    throw Error('Require 1..64 unique booking digests');
  return snapshot(options, async ({ call, block }) => {
    const bookings = [];
    for (const id of bookingIds) {
      const record = await call('bookings', [id]);
      if (!hash(record.booking.offerId)) throw Error('Unknown market booking');
      const current = await readOffer(call, record.booking.offerId);
      const active = (await call('activatedOrders', [current.offer.escrow, record.booking.orderId]))[0];
      if (record.activated && !active) throw Error('Booking and order activation disagree');
      bookings.push({ bookingId: id, booking: object(record.booking), activated: record.activated, orderActivated: active, ...current,
        consumesCapacityAtSnapshot: BigInt(record.booking.end) > BigInt(block.timestamp) &&
          (record.activated || BigInt(record.booking.holdUntil) > BigInt(block.timestamp)) });
    }
    return { bookings };
  }, clock);
}
