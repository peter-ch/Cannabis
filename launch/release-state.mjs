// Observe release address/nonce prerequisites through a selected read-only RPC.
import { toQuantity } from 'ethers';
import { validateRelease } from './release.mjs';

function quantity(value) {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value) ||
      BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Invalid release RPC quantity');
  return Number(BigInt(value));
}
export async function observeReleaseState(input, options, dependencyObservation) {
  const plan = validateRelease(input, options?.dependencies);
  if (dependencyObservation?.schema !== 'cannabis.dependency-observation.v1' ||
      !dependencyObservation.runtimeAndLinksMatched || dependencyObservation.sent !== false ||
      JSON.stringify(dependencyObservation.dependencies) !== JSON.stringify(plan.dependencies))
    throw Error('Matching dependency observation required');
  const url = new URL(options.rpc);
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' &&
      !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)))) throw Error('Invalid release RPC endpoint');
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 60000);
  let id = 0;
  async function call(method, params = []) {
    if (!['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_getTransactionCount'].includes(method))
      throw Error('Read-only release method required');
    const requestId = ++id;
    try {
      const response = await fetch(url, { method: 'POST', redirect: 'error', credentials: 'omit',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }),
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]) });
      if (!response.ok || !response.body) throw Error('Release RPC transport failure');
      let size = 0; const chunks = [];
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 256 * 1024) { controller.abort(); throw Error('Release RPC response exceeds bound'); }
        chunks.push(chunk);
      }
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      if (data.jsonrpc !== '2.0' || data.id !== requestId || Object.hasOwn(data, 'error') || !Object.hasOwn(data, 'result'))
        throw Error('Invalid release RPC envelope');
      return data.result;
    } catch { throw Error('Read-only release RPC failed'); }
  }
  const firstNonce = BigInt(plan.configuration.firstNonce), deployer = plan.configuration.deployer;
  const chain = async () => { if (quantity(await call('eth_chainId')) !== 1) throw Error('Wrong release network'); };
  const canonical = async anchor => {
    if (!anchor || !Number.isSafeInteger(anchor.number) || anchor.number < 0 ||
        !Number.isSafeInteger(anchor.timestamp) || !/^0x[0-9a-f]{64}$/.test(anchor.hash)) throw Error('Invalid release anchor');
    const block = await call('eth_getBlockByNumber', [toQuantity(anchor.number), false]);
    if (block?.hash?.toLowerCase() !== anchor.hash || quantity(block.number) !== anchor.number ||
        quantity(block.timestamp) !== anchor.timestamp) throw Error('Release canonical block changed');
  };
  async function inspect(anchor) {
    const at = { blockHash: anchor.hash, requireCanonical: true };
    const [code, nonce] = await Promise.all([call('eth_getCode', [deployer, at]), call('eth_getTransactionCount', [deployer, at])]);
    if (code !== '0x' || BigInt(quantity(nonce)) !== firstNonce) throw Error('Require an undelegated EOA with the exact reviewed nonce');
    await Promise.all(Object.values(plan.addresses).map(async address => {
      const [targetCode, targetNonce] = await Promise.all([call('eth_getCode', [address, at]), call('eth_getTransactionCount', [address, at])]);
      if (targetCode !== '0x' || quantity(targetNonce) !== 0) throw Error('A predicted release address is occupied');
    }));
  }
  try {
    await chain();
    const { anchor, checkedHead } = dependencyObservation;
    const now = Math.floor(Date.now() / 1000);
    if (checkedHead?.timestamp < now - 300 || checkedHead?.timestamp > now + 60 ||
        anchor?.timestamp < now - 7200 || checkedHead?.number < anchor?.number) throw Error('Stale release dependency observation');
    for (const block of [anchor, checkedHead]) { await canonical(block); await inspect(block); await canonical(block); }
    if (BigInt(quantity(await call('eth_getTransactionCount', [deployer, 'pending']))) !== firstNonce)
      throw Error('Pending transactions invalidate the release nonce');
    const latest = await call('eth_getBlockByNumber', ['latest', false]);
    if (latest?.hash?.toLowerCase() !== checkedHead.hash || quantity(latest.number) !== checkedHead.number)
      throw Error('Release head advanced; prepare again against fresh dependencies');
    await canonical(checkedHead); await chain();
    return { schema: 'cannabis.release-state-observation.v1', checkedAt: new Date().toISOString(),
      anchor, checkedHead, deployer, firstNonce: firstNonce.toString(), predictedAddresses: plan.addresses,
      undelegatedSender: true, targetsUnoccupied: true, pendingNonceMatched: true,
      scope: 'Selected RPC view at the recorded anchors; no reservation, signing approval or independent consensus.', sent: false };
  } finally { clearTimeout(timer); controller.abort(); }
}
