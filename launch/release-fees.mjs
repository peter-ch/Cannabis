// Sequential read-only simulation; no state overrides, custody or transaction send.
import { createHash } from 'node:crypto';
import { formatEther, getAddress, keccak256, toQuantity } from 'ethers';
import { readReleasePackage } from './release-package.mjs';
import { releaseGetters } from './release-getters.mjs';
import { verifyLaunchDependencies } from './dependencies.mjs';

const TX_CAP = 16777216n, DURATION = 60000;
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function quantity(value) {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value) || value.length > 66)
    throw Error('Invalid release fee quantity');
  return BigInt(value);
}
function hash(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value) || /^0x0+$/.test(value))
    throw Error('Invalid release fee block hash');
  return value.toLowerCase();
}
function block(value) {
  if (!value) throw Error('Missing fee anchor');
  return { number: quantity(value.number), hash: hash(value.hash), timestamp: quantity(value.timestamp),
    baseFee: quantity(value.baseFeePerGas), gasLimit: quantity(value.gasLimit) };
}
function fresh(head) {
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (head.timestamp < now - 120n || head.timestamp > now + 30n) throw Error('Stale release fee anchor');
}
function intrinsic(data) {
  const bytes = Buffer.from(data.slice(2), 'hex');
  return 53000n + bytes.reduce((sum, byte) => sum + (byte === 0 ? 4n : 16n), 0n) +
    2n * BigInt(Math.ceil(bytes.length / 32));
}
function sameTransaction(actual, expected) {
  if (!actual || getAddress(actual.from) !== expected.from ||
      (actual.to ? getAddress(actual.to) : null) !== (expected.to ?? null) ||
      actual.input?.toLowerCase() !== expected.data.toLowerCase() || !Array.isArray(actual.accessList) ||
      actual.accessList.length || actual.authorizationList?.length || actual.blobVersionedHashes?.length)
    throw Error('Simulation transaction changed');
  for (const key of ['chainId', 'nonce', 'value', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'type'])
    if (quantity(actual[key]) !== quantity(expected[key])) throw Error('Simulation transaction fields changed');
}
function checkSimulation(result, requests, anchor, validation) {
  if (!Array.isArray(result) || result.length !== requests.length) throw Error('Incomplete simulated sequence');
  let parent = anchor.hash;
  return result.map((value, index) => {
    const current = block(value), calls = requests[index].calls;
    if (current.number !== anchor.number + BigInt(index + 1) ||
        current.timestamp !== anchor.timestamp + BigInt(12 * (index + 1)) ||
        hash(value.parentHash) !== parent || current.gasLimit !== anchor.gasLimit ||
        (!validation && current.baseFee !== 0n) ||
        !Array.isArray(value.calls) || value.calls.length !== calls.length ||
        !Array.isArray(value.transactions) || value.transactions.length !== calls.length)
      throw Error('Simulation block or result count changed');
    parent = current.hash;
    let sum = 0n;
    const outputs = value.calls.map((output, i) => {
      const call = calls[i]; sameTransaction(value.transactions[i], call);
      if (output?.status !== '0x1' || Object.hasOwn(output, 'error') ||
          typeof output.returnData !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(output.returnData) ||
          output.returnData.length > 2 + 24576 * 2 || !Array.isArray(output.logs))
        throw Error('A simulated call failed or returned invalid data');
      const gas = quantity(output.gasUsed), maximum = quantity(output.maxUsedGas), limit = quantity(call.gas);
      if (gas < (call.to ? 21000n : intrinsic(call.data)) || maximum < gas || maximum > limit ||
          limit > TX_CAP || limit > current.gasLimit ||
          (validation && current.baseFee + quantity(call.maxPriorityFeePerGas) > quantity(call.maxFeePerGas)))
        throw Error('Inconsistent simulated gas or fee limits');
      sum += gas;
      return { gas, maximum, returnData: output.returnData.toLowerCase() };
    });
    if (sum !== quantity(value.gasUsed) || sum > current.gasLimit) throw Error('Simulation block gas changed');
    return outputs;
  });
}
export async function quoteNetworkRelease(options) {
  if (!options || Object.keys(options).some(key => !['rpc', 'manifestFile', 'expectedPackageSHA256', 'gasBufferBps'].includes(key)))
    throw Error('Unexpected complete release fee options');
  const { rpc: endpoint, manifestFile, expectedPackageSHA256 } = options;
  const buffer = options.gasBufferBps ?? 2000;
  if (!Number.isSafeInteger(buffer) || buffer < 0 || buffer > 10000) throw Error('Invalid release gas buffer');
  const url = new URL(endpoint);
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' &&
      !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)))) throw Error('Invalid fee RPC');
  const { plan, packageSHA256 } = await readReleasePackage(manifestFile, expectedPackageSHA256);
  const dependencyObservation = await verifyLaunchDependencies({ rpc: url.toString(), dependencies: plan.dependencies });
  const cancel = new AbortController(), timer = setTimeout(() => cancel.abort(), DURATION), started = Date.now();
  let sequence = 0;
  async function rpc(method, params = []) {
    if (!['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_getTransactionCount', 'eth_getBalance',
      'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_simulateV1'].includes(method)) throw Error('Read-only fee method required');
    const id = ++sequence; let response;
    try {
      response = await fetch(url, { method: 'POST', redirect: 'error', credentials: 'omit',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: AbortSignal.any([cancel.signal, AbortSignal.timeout(20000)]) });
      if (!response.ok || !response.body) throw Error('Fee HTTP failure');
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length; if (size > 2 * 1024 * 1024) throw Error('Fee response exceeds bound');
        chunks.push(chunk);
      }
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      if (data.jsonrpc !== '2.0' || data.id !== id || Object.hasOwn(data, 'error') || !Object.hasOwn(data, 'result'))
        throw Error('Invalid fee RPC envelope');
      return data.result;
    } catch { throw Error('Complete release fee RPC failed; no partial quote returned'); }
    finally { if (response?.body && !response.bodyUsed) await response.body.cancel().catch(() => {}); }
  }
  try {
    const head = block(await rpc('eth_getBlockByNumber', [toQuantity(dependencyObservation.checkedHead.number), false]));
    if (head.hash !== dependencyObservation.checkedHead.hash) throw Error('Dependency anchor changed');
    fresh(head);
    const c = plan.configuration, at = { blockHash: head.hash, requireCanonical: true };
    async function inspect(tag) {
      if (quantity(await rpc('eth_chainId')) !== 1n) throw Error('Wrong fee chain');
      const [code, nonce, balance, pending] = await Promise.all([rpc('eth_getCode', [c.deployer, tag]),
        rpc('eth_getTransactionCount', [c.deployer, tag]), rpc('eth_getBalance', [c.deployer, tag]),
        rpc('eth_getTransactionCount', [c.deployer, 'pending'])]);
      if (code !== '0x' || quantity(nonce) !== BigInt(c.firstNonce) || quantity(pending) !== BigInt(c.firstNonce))
        throw Error('Release sender, nonce or pending transactions changed');
      await Promise.all(Object.values(plan.addresses).map(async address => {
        const [code, nonce] = await Promise.all([rpc('eth_getCode', [address, tag]), rpc('eth_getTransactionCount', [address, tag])]);
        if (code !== '0x' || quantity(nonce) !== 0n) throw Error('A release target is occupied');
      }));
      return quantity(balance);
    }
    const balance = await inspect(at);
    const [gasPrice, priority] = await Promise.all([rpc('eth_gasPrice').then(quantity), rpc('eth_maxPriorityFeePerGas').then(quantity)]);
    if (gasPrice === 0n || gasPrice < head.baseFee) throw Error('Invalid current fee prices');
    const maxFee = [2n * head.baseFee + priority, gasPrice, priority].reduce((a, b) => a > b ? a : b);
    if (maxFee >= 2n ** 256n) throw Error('Fee exceeds uint256');
    const cap = head.gasLimit < TX_CAP ? head.gasLimit : TX_CAP;
    const make = (tx, gas, validated) => ({ ...tx, type: '0x2', gas: toQuantity(gas),
      maxFeePerGas: toQuantity(validated ? maxFee : 0), maxPriorityFeePerGas: toQuantity(validated ? priority : 0) });
    const getters = releaseGetters(plan);
    const first = plan.transactions.map(entry => ({ calls: [make(entry.transaction, cap, false)] }));
    first.push({ calls: getters.map((getter, i) => make({ chainId: '0x1', from: c.deployer, to: getter.to,
      nonce: toQuantity(BigInt(c.firstNonce) + 5n + BigInt(i)), data: getter.data, value: '0x0' }, 100000n, false)) });
    async function simulate(blockStateCalls, validation) {
      return rpc('eth_simulateV1', [{ blockStateCalls, validation, traceTransfers: false, returnFullTransactions: true }, head.hash]);
    }
    const firstResult = await simulate(first, false);
    const observations = checkSimulation(firstResult, first, head, false);
    const relations = new Map();
    for (let i = 0; i < getters.length; ++i) {
      const getter = getters[i], returned = observations[5][i].returnData;
      if (getter.relation) {
        if (!/^0x[0-9a-f]{64}$/.test(returned) ||
            (relations.has(getter.relation) && relations.get(getter.relation) !== returned))
          throw Error('Simulated enrollment group mismatch');
        relations.set(getter.relation, returned);
      } else if (returned !== getter.expected.toLowerCase()) throw Error('Simulated release link or allocation mismatch');
    }
    const limits = observations.slice(0, 5).map(([result]) => (result.maximum * BigInt(10000 + buffer) + 9999n) / 10000n);
    if (limits.some(limit => limit > cap)) throw Error('Buffered creation exceeds gas limits');
    const planningBudget = limits.reduce((sum, limit) => sum + limit * maxFee, 0n);
    if (balance < planningBudget) {
      const error = Error('Native balance does not cover the complete buffered release budget');
      error.funding = { status: 'UNVALIDATED_FUNDING_SHORTFALL', packageSHA256, anchorHash: head.hash,
        planningBudgetWei: planningBudget.toString(), nativeBalanceWei: balance.toString(),
        shortfallWei: (planningBudget - balance).toString(), simulationValidationPassed: false,
        scope: 'Initial zero-fee simulation only; fee validation and final freshness checks have not run.',
        spendAuthorized: false, sent: false };
      throw error;
    }
    const second = plan.transactions.map((entry, i) => ({ calls: [make(entry.transaction, limits[i], true)] }));
    const secondResult = await simulate(second, true);
    const validated = checkSimulation(secondResult, second, head, true);
    for (let i = 0; i < 5; ++i)
      if (!validated[i][0].returnData.length || validated[i][0].returnData === '0x' ||
          validated[i][0].returnData !== observations[i][0].returnData ||
          validated[i][0].gas !== observations[i][0].gas || validated[i][0].maximum !== observations[i][0].maximum)
        throw Error('Validated creation differs from the postcondition simulation');
    const canonical = block(await rpc('eth_getBlockByNumber', [toQuantity(head.number), false]));
    if (Object.keys(head).some(key => head[key] !== canonical[key])) throw Error('Canonical fee anchor changed');
    const latest = block(await rpc('eth_getBlockByNumber', ['latest', false])); fresh(latest);
    if (latest.number < head.number || latest.timestamp < head.timestamp) throw Error('Fee head regressed');
    const currentBalance = await inspect({ blockHash: latest.hash, requireCanonical: true });
    const latestAgain = block(await rpc('eth_getBlockByNumber', [toQuantity(latest.number), false]));
    if (Object.keys(latest).some(key => latest[key] !== latestAgain[key]) || currentBalance < planningBudget)
      throw Error('Current sender state or balance changed');
    fresh(head);
    if (Date.now() < started || Date.now() - started >= DURATION) throw Error('Fee observation exceeded its time bound');
    const feePrice = gasPrice > head.baseFee + priority ? gasPrice : head.baseFee + priority;
    const transactions = plan.transactions.map((entry, i) => ({
      role: entry.role, expectedAddress: entry.expectedAddress, nonce: entry.transaction.nonce,
      deploymentDataKeccak256: entry.deploymentDataKeccak256,
      simulatedGasUsed: validated[i][0].gas.toString(), maximumGasBeforeRefunds: validated[i][0].maximum.toString(),
      gasLimit: limits[i].toString(), simulatedRuntimeKeccak256: keccak256(validated[i][0].returnData),
      estimatedNetworkFeeWei: (validated[i][0].gas * feePrice).toString(), planningBudgetWei: (limits[i] * maxFee).toString()
    }));
    const estimated = transactions.reduce((sum, tx) => sum + BigInt(tx.estimatedNetworkFeeWei), 0n);
    if (estimated > planningBudget) throw Error('Inconsistent aggregate deployment fee');
    const publicBlock = b => ({ number: toQuantity(b.number), hash: b.hash, timestamp: toQuantity(b.timestamp) });
    return { schema: 'cannabis.network-release-fee.v1', checkedAt: new Date().toISOString(), chainId: '1', packageSHA256,
      anchor: publicBlock(head), checkedHead: publicBlock(latest), from: c.deployer, firstNonce: c.firstNonce,
      gasBufferBps: buffer, transactions, postconditionsChecked: getters.length,
      dependencyObservation, simulationSHA256: { postconditions: sha(firstResult), feeValidation: sha(secondResult) },
      simulationValidationPassed: true, stateOverridesUsed: false, blockOverridesUsed: false,
      baseFeePerGasWei: head.baseFee.toString(), observedGasPriceWei: gasPrice.toString(),
      feePriceForEstimateWei: feePrice.toString(), proposedMaxPriorityFeePerGasWei: priority.toString(),
      proposedMaxFeePerGasWei: maxFee.toString(), estimatedNetworkFeeWei: estimated.toString(),
      estimatedNetworkFeeETH: formatEther(estimated), planningBudgetWei: planningBudget.toString(),
      planningBudgetETH: formatEther(planningBudget), nativeBalanceWei: balance.toString(),
      checkedHeadNativeBalanceWei: currentBalance.toString(), planningShortfallWei: '0',
      scope: 'Five sequential zero-value Ethereum creations, one per simulated block. Diagnostic view calls are excluded from deployment costs.',
      limits: [
        'Selected RPC simulation, not independently proven consensus, deployment receipts or a source audit.',
        'Postconditions use a zero-fee simulation; the separate validation-enabled pass checks the same five creations with explicit buffered gas and fee limits.',
        'Validation does not check signatures. The sender is separately checked for empty code, exact nonce, pending nonce and actual balance. No state or balance overrides are used.',
        'The estimate uses current fee observations. Simulated future blocks are not inclusion promises; costs and state can change. Refresh before every owner-controlled signature.',
        'Only the five creations are included. Ceremony transactions, claims, compute jobs, independent review and ongoing services remain separate.'
      ], spendAuthorized: false, sent: false };
  } finally { clearTimeout(timer); cancel.abort(); }
}
