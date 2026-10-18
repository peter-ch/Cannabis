// Read-only, single-transaction deployment fees. No custody, signing or broadcast.
import { getAddress, Interface, keccak256, Transaction, toQuantity, formatEther } from 'ethers';

const ORACLE = '0x420000000000000000000000000000000000000F';
const ORACLE_ABI = new Interface(['function getL1Fee(bytes) view returns (uint256)',
  'function getL1FeeUpperBound(uint256) view returns (uint256)', 'function getOperatorFee(uint256) view returns (uint256)',
  'function version() view returns (string)', 'function isFjord() view returns (bool)', 'function isIsthmus() view returns (bool)', 'function isJovian() view returns (bool)']);
const MODELS = { '1': 'ethereum-eip1559', '8453': 'base-oracle', '42161': 'arbitrum-inclusive-estimate' };
const UINT256 = 1n << 256n;
const exact = (v, keys) => {
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== keys.length || keys.some(k => !Object.hasOwn(v, k))) throw Error('Unexpected fee input fields');
};
function quantity(v) {
  if (typeof v !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(v) || v.length > 66) throw Error('Invalid RPC quantity');
  return BigInt(v);
}
function hash(v) { if (typeof v !== 'string' || !/^0x[0-9a-f]{64}$/i.test(v) || /^0x0+$/.test(v)) throw Error('Invalid fee anchor or data hash'); return v.toLowerCase(); }
function anchor(v) {
  if (!v || typeof v !== 'object') throw Error('Missing fee anchor');
  const number = quantity(v.number), timestamp = quantity(v.timestamp), baseFee = quantity(v.baseFeePerGas), gasLimit = quantity(v.gasLimit);
  if (number > BigInt(Number.MAX_SAFE_INTEGER) || timestamp > BigInt(Number.MAX_SAFE_INTEGER) || gasLimit < 21000n) throw Error('Invalid fee anchor');
  return { number: Number(number), hash: hash(v.hash), timestamp: Number(timestamp), baseFee, gasLimit };
}
function fresh(block) {
  const now = Math.floor(Date.now() / 1000);
  if (block.timestamp < now - 120 || block.timestamp > now + 30) throw Error('Fee head is stale or in the future');
}

export async function quoteDeploymentFee(options) {
  if (!options || Object.keys(options).some(k => !['rpc', 'transaction', 'expectedDataHash', 'gasBufferBps'].includes(k))) throw Error('Unexpected fee options');
  const tx = structuredClone(options.transaction);
  exact(tx, ['chainId', 'from', 'data', 'value']);
  const chainId = quantity(tx.chainId).toString(), model = MODELS[chainId];
  if (!model || tx.value !== '0x0') throw Error('Require a supported zero-value contract deployment');
  tx.from = getAddress(tx.from);
  if (BigInt(tx.from) === 0n || typeof tx.data !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(tx.data) || tx.data.length > 2 + 49152 * 2) throw Error('Invalid deployment data');
  const dataHash = hash(options.expectedDataHash);
  if (keccak256(tx.data) !== dataHash) throw Error('Deployment data does not match the independently reviewed hash');
  const bufferBps = options.gasBufferBps ?? 2000;
  if (!Number.isSafeInteger(bufferBps) || bufferBps < 0 || bufferBps > 10000) throw Error('Gas buffer must be 0 through 10000 basis points');
  const url = new URL(options.rpc);
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)))) throw Error('Require HTTPS or literal loopback RPC');
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 60000), started = Date.now();
  let sequence = 0;
  async function rpc(method, params = []) {
    if (!['eth_chainId', 'eth_getBlockByNumber', 'eth_estimateGas', 'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_getBalance', 'eth_getTransactionCount', 'eth_getCode', 'eth_call'].includes(method)) throw Error('Read-only fee method required');
    const id = ++sequence; let response;
    try {
      response = await fetch(url, { method: 'POST', redirect: 'error', credentials: 'omit',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]) });
      if (!response.ok || !response.body) throw Error('HTTP failure');
      const chunks = []; let size = 0;
      for await (const chunk of response.body) { size += chunk.length; if (size > 256 * 1024) throw Error('Response bound exceeded'); chunks.push(chunk); }
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      if (data.jsonrpc !== '2.0' || data.id !== id || Object.hasOwn(data, 'error') || !Object.hasOwn(data, 'result')) throw Error('Invalid RPC envelope');
      return data.result;
    } catch { throw Error('Fee-estimation RPC failed; no incomplete fee total is returned'); }
    finally { if (response?.body && !response.bodyUsed) await response.body.cancel().catch(() => {}); }
  }
  try {
    if (quantity(await rpc('eth_chainId')) !== BigInt(chainId)) throw Error('Wrong fee network');
    const block = anchor(await rpc('eth_getBlockByNumber', ['latest', false])); fresh(block);
    const at = { blockHash: block.hash, requireCanonical: true };
    const [gasResult, priceResult, tipResult, balanceResult, nonceResult] = await Promise.all([
      rpc('eth_estimateGas', [tx, toQuantity(block.number)]), rpc('eth_gasPrice'), rpc('eth_maxPriorityFeePerGas'),
      rpc('eth_getBalance', [tx.from, at]), rpc('eth_getTransactionCount', [tx.from, at])
    ]);
    const gas = quantity(gasResult), gasPrice = quantity(priceResult), priority = quantity(tipResult), balance = quantity(balanceResult), nonce = quantity(nonceResult);
    const initCode = Buffer.from(tx.data.slice(2), 'hex');
    const intrinsic = 53000n + initCode.reduce((sum, byte) => sum + (byte === 0 ? 4n : 16n), 0n) + 2n * BigInt(Math.ceil(initCode.length / 32));
    if (gas < intrinsic || gasPrice < block.baseFee || gasPrice === 0n || nonce > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Inconsistent fee estimate');
    const gasLimit = (gas * BigInt(10000 + bufferBps) + 9999n) / 10000n;
    if (gasLimit > block.gasLimit || gasLimit > 16777216n) throw Error('Buffered deployment exceeds the supported transaction gas limit');
    const maxFee = [2n * block.baseFee + priority, gasPrice, priority].reduce((a, b) => a > b ? a : b);
    if (maxFee >= UINT256) throw Error('Invalid fee parameters');
    const unsigned = Transaction.from({ type: 2, chainId: BigInt(chainId), nonce: Number(nonce), gasLimit,
      maxFeePerGas: maxFee, maxPriorityFeePerGas: priority, data: tx.data, value: 0n }).unsignedSerialized;
    let l1Fee = 0n, l1SizeBound = 0n, operatorFee = 0n, bufferedOperatorFee = 0n, oracle = null;
    if (chainId === '8453') {
      const code = await rpc('eth_getCode', [ORACLE, at]);
      if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(code)) throw Error('Missing Base fee oracle');
      const call = async (method, args = []) => {
        const data = ORACLE_ABI.encodeFunctionData(method, args);
        return ORACLE_ABI.decodeFunctionResult(method, await rpc('eth_call', [{ to: ORACLE, data }, at]))[0];
      };
      const [version, fjord, isthmus, jovian] = await Promise.all([call('version'), call('isFjord'), call('isIsthmus'), call('isJovian')]);
      if (version !== '1.6.0' || !fjord || !isthmus || !jovian) throw Error('Unreviewed Base fee-oracle profile');
      [l1Fee, l1SizeBound, operatorFee, bufferedOperatorFee] = await Promise.all([
        call('getL1Fee', [unsigned]), call('getL1FeeUpperBound', [(unsigned.length - 2) / 2]), call('getOperatorFee', [gas]), call('getOperatorFee', [gasLimit])
      ]);
      if (l1SizeBound < l1Fee || bufferedOperatorFee < operatorFee) throw Error('Inconsistent Base fee bounds');
      oracle = { address: ORACLE, proxyCodeHash: keccak256(code), version, isFjord: fjord, isIsthmus: isthmus, isJovian: jovian };
    }
    const feePrice = gasPrice > block.baseFee + priority ? gasPrice : block.baseFee + priority;
    const estimatedFee = gas * feePrice + l1Fee + operatorFee;
    const planningBudget = gasLimit * maxFee + 2n * l1SizeBound + bufferedOperatorFee;
    if (planningBudget < estimatedFee) throw Error('Fee budget is inconsistent with estimate');
    const canonical = anchor(await rpc('eth_getBlockByNumber', [toQuantity(block.number), false]));
    if (canonical.hash !== block.hash || canonical.number !== block.number || canonical.timestamp !== block.timestamp || canonical.baseFee !== block.baseFee || canonical.gasLimit !== block.gasLimit) throw Error('Fee anchor changed');
    if (quantity(await rpc('eth_chainId')) !== BigInt(chainId)) throw Error('Fee network changed');
    fresh(block);
    if (Date.now() < started || Date.now() - started >= 60000) throw Error('Fee observation exceeded its time bound');
    return { schema: 'cannabis.deployment-fee.v1', checkedAt: new Date().toISOString(), chainId, model,
      anchor: { number: block.number, hash: block.hash, timestamp: block.timestamp }, deploymentDataKeccak256: dataHash,
      from: tx.from, nonce: nonce.toString(), initCodeBytes: (tx.data.length - 2) / 2,
      estimatedGas: gas.toString(), gasBufferBps: bufferBps, gasLimit: gasLimit.toString(),
      baseFeePerGasWei: block.baseFee.toString(), observedGasPriceWei: gasPrice.toString(),
      feePriceForEstimateWei: feePrice.toString(),
      proposedMaxPriorityFeePerGasWei: priority.toString(), proposedMaxFeePerGasWei: maxFee.toString(),
      l1FeeIncludedInGasEstimate: chainId === '42161', l1DataFeeWei: chainId === '42161' ? null : l1Fee.toString(),
      l1DataSizeBoundWei: chainId === '42161' ? null : l1SizeBound.toString(), operatorFeeWei: operatorFee.toString(), bufferedOperatorFeeWei: bufferedOperatorFee.toString(),
      estimatedNetworkFeeWei: estimatedFee.toString(), estimatedNetworkFeeETH: formatEther(estimatedFee),
      planningBudgetWei: planningBudget.toString(), planningBudgetETH: formatEther(planningBudget),
      nativeBalanceWei: balance.toString(), planningShortfallWei: (balance >= planningBudget ? 0n : planningBudget - balance).toString(), oracle,
      scope: 'One zero-value creation transaction in the selected RPC view. Arbitrum gas already includes L1 cost; Base adds oracle L1 and operator fees. No bridge, escrow, enrollment or running-service expenses included.',
      limits: 'Time-sensitive estimate, not a spending cap, transaction approval or source audit. Base L1 size bound is an oracle estimate; prices and state can change. Recheck before owner signing.',
      spendAuthorized: false, sent: false };
  } finally { clearTimeout(timer); controller.abort(); }
}
