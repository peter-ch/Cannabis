// Pure read-only inspection, shared with actual isolated-chain execution checks.
// Production entry points obtain the plan only from the strict Ethereum package.
import { getAddress, Interface, ZeroAddress, parseEther, toQuantity } from 'ethers';
import { releaseGetters } from './release-getters.mjs';
import { matchReleaseRuntime } from './release-runtime.mjs';

export function rpcQuantity(value) {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value) || value.length > 66)
    throw Error('Invalid deployment RPC quantity');
  return BigInt(value);
}
export function rpcHash(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value) || /^0x0+$/.test(value))
    throw Error('Invalid deployment hash');
  return value.toLowerCase();
}
export function deploymentBlock(value) {
  if (!value) throw Error('Missing canonical deployment block');
  return { number: rpcQuantity(value.number), hash: rpcHash(value.hash), timestamp: rpcQuantity(value.timestamp),
    gasLimit: rpcQuantity(value.gasLimit), gasUsed: rpcQuantity(value.gasUsed), baseFee: rpcQuantity(value.baseFeePerGas) };
}
export function checkFinalityProgress(anchor, finalized, head, now = BigInt(Math.floor(Date.now() / 1000))) {
  const sameHeightChanged = (a, b) => a.number === b.number && Object.keys(a).some(key => a[key] !== b[key]);
  if (sameHeightChanged(anchor, finalized) || sameHeightChanged(finalized, head) ||
      finalized.number < anchor.number || finalized.timestamp < anchor.timestamp ||
      head.number < finalized.number || head.timestamp < finalized.timestamp ||
      head.timestamp < now - 120n || head.timestamp > now + 30n ||
      finalized.timestamp < now - 7200n || finalized.timestamp > now + 30n)
    throw Error('Canonical finality changed or verification state is stale');
}
const roles = { registrar: 'CommunityRegistrar', token: 'Cannabis', enrollment: 'CannabisEnrollment',
  founderVesting: 'FounderVesting', nativeEscrow: 'ComputeEscrow', cannabisEscrow: 'ComputeEscrow', market: 'ComputeMarket' };
const mutable = new Set(['totalSupply', 'balanceOf', 'communityIssued', 'minimumClaimMembers',
  'enrolledCount', 'roundCount', 'released', 'totalLiability']);

export async function inspectDeployedRelease({ plan, runtimes, transactionHashes, anchor, rpc }) {
  plan = structuredClone(plan); runtimes = structuredClone(runtimes); anchor = structuredClone(anchor);
  if (!Array.isArray(transactionHashes) || transactionHashes.length !== 5 ||
      new Set(transactionHashes.map(rpcHash)).size !== 5) throw Error('Require five distinct ordered creation hashes');
  transactionHashes = transactionHashes.map(rpcHash);
  const blockCache = new Map(), receipts = [], c = plan.configuration, at = { blockHash: anchor.hash, requireCanonical: true };
  const getBlock = number => {
    const key = toQuantity(number);
    if (!blockCache.has(key)) blockCache.set(key, rpc('eth_getBlockByNumber', [key, false]));
    return blockCache.get(key);
  };
  let previous = null;
  for (let i = 0; i < 5; ++i) {
    const txHash = rpcHash(transactionHashes[i]), expected = plan.transactions[i];
    const [tx, receipt] = await Promise.all([rpc('eth_getTransactionByHash', [txHash]), rpc('eth_getTransactionReceipt', [txHash])]);
    if (!tx || !receipt || receipt.status !== '0x1' || rpcHash(tx.hash) !== txHash || rpcHash(receipt.transactionHash) !== txHash ||
        tx.to !== null || receipt.to !== null || getAddress(tx.from) !== c.deployer || getAddress(receipt.from) !== c.deployer ||
        getAddress(receipt.contractAddress) !== expected.expectedAddress || tx.input?.toLowerCase() !== expected.transaction.data.toLowerCase() ||
        rpcQuantity(tx.chainId) !== BigInt(c.chainId) || rpcQuantity(tx.nonce) !== BigInt(c.firstNonce) + BigInt(i) ||
        rpcQuantity(tx.value) !== 0n || rpcQuantity(tx.type) !== 2n || rpcQuantity(receipt.type) !== 2n ||
        !Array.isArray(tx.accessList) || tx.accessList.length || tx.authorizationList?.length || tx.blobVersionedHashes?.length)
      throw Error('Creation transaction or successful receipt does not match the package');
    const number = rpcQuantity(receipt.blockNumber), index = rpcQuantity(receipt.transactionIndex);
    const blockHash = rpcHash(receipt.blockHash);
    if (number > anchor.number || rpcQuantity(tx.blockNumber) !== number || rpcQuantity(tx.transactionIndex) !== index ||
        rpcHash(tx.blockHash) !== blockHash || (previous && (number < previous.number || (number === previous.number && index <= previous.index))))
      throw Error('Creation is unfinalized, reordered or inconsistently included');
    const rawBlock = await getBlock(number), block = deploymentBlock(rawBlock);
    if (block.number !== number || block.hash !== blockHash || block.timestamp > anchor.timestamp ||
        block.timestamp >= BigInt(Date.parse(plan.claimsOpen) / 1000) ||
        !Array.isArray(rawBlock.transactions) || index >= BigInt(rawBlock.transactions.length) ||
        rpcHash(rawBlock.transactions[Number(index)]) !== txHash)
      throw Error('Creation is absent from the canonical block or past opening');
    const gas = rpcQuantity(receipt.gasUsed), limit = rpcQuantity(tx.gas), cumulative = rpcQuantity(receipt.cumulativeGasUsed);
    const effective = rpcQuantity(receipt.effectiveGasPrice), maximum = rpcQuantity(tx.maxFeePerGas), priority = rpcQuantity(tx.maxPriorityFeePerGas);
    const price = maximum < block.baseFee + priority ? maximum : block.baseFee + priority;
    const initcode = Buffer.from(tx.input.slice(2), 'hex');
    const intrinsic = 53000n + initcode.reduce((sum, byte) => sum + (byte === 0 ? 4n : 16n), 0n) +
      2n * BigInt(Math.ceil(initcode.length / 32));
    if (gas < intrinsic || gas > limit || limit > 16777216n || limit > block.gasLimit || cumulative < gas ||
        cumulative > block.gasUsed || block.gasUsed > block.gasLimit || priority > maximum || maximum < block.baseFee ||
        effective !== price) throw Error('Creation gas or paid fee is inconsistent');
    receipts.push({ role: expected.role, transactionHash: txHash, blockNumber: toQuantity(number), blockHash,
      transactionIndex: toQuantity(index), address: expected.expectedAddress,
      gasUsed: gas.toString(), effectiveGasPriceWei: effective.toString(), networkFeeWei: (gas * effective).toString() });
    previous = { number, index };
    if (expected.role === 'token') {
      const event = new Interface(['event Transfer(address indexed from, address indexed to, uint256 value)']);
      if (!Array.isArray(receipt.logs)) throw Error('Missing founder mint logs');
      const mints = receipt.logs.filter(log => getAddress(log.address) === plan.addresses.token).map(log => {
        if (log.removed || rpcHash(log.transactionHash) !== txHash || rpcHash(log.blockHash) !== blockHash) throw Error('Changed founder mint inclusion');
        return event.parseLog(log);
      }).filter(log => log?.name === 'Transfer' && log.args.from === ZeroAddress);
      if (mints.length !== 1 || mints[0].args.to !== plan.addresses.founderVesting || mints[0].args.value !== parseEther('4200000'))
        throw Error('Founder allocation was not minted to the fixed vesting contract');
    }
  }
  const code = {};
  await Promise.all(Object.entries(roles).map(async ([role, name]) => {
    code[role] = { address: plan.addresses[role], ...matchReleaseRuntime(await rpc('eth_getCode', [plan.addresses[role], at]), runtimes[name]) };
  }));
  const getters = releaseGetters(plan).filter(getter => !mutable.has(getter.method)), relations = new Map();
  const states = await Promise.all(getters.map(async getter => ({
    getter, result: await rpc('eth_call', [{ to: getter.to, data: getter.data }, at])
  })));
  for (const { getter, result } of states) {
    if (typeof result !== 'string' || !/^0x[0-9a-f]{64}$/i.test(result)) throw Error('Malformed deployed getter result');
    const value = result.toLowerCase();
    if (getter.relation) {
      if (relations.has(getter.relation) && relations.get(getter.relation) !== value) throw Error('Deployed token and enrollment groups differ');
      relations.set(getter.relation, value);
    } else if (value !== getter.expected.toLowerCase()) throw Error('Deployed immutable link, allocation or fee differs');
  }
  // Membership group control must belong to the append-only enrollment contract.
  const group = BigInt(relations.get('sameSemaphoreGroup'));
  const semaphore = new Interface(['function getGroupAdmin(uint256) view returns (address)']);
  const admin = await rpc('eth_call', [{ to: plan.dependencies.semaphore.address,
    data: semaphore.encodeFunctionData('getGroupAdmin', [group]) }, at]);
  if (admin.toLowerCase() !== semaphore.encodeFunctionResult('getGroupAdmin', [plan.addresses.enrollment]).toLowerCase())
    throw Error('Semaphore group has a different administrator');
  // Recheck every receipt block after the complete state observation.
  for (const [number, promise] of blockCache) {
    const before = deploymentBlock(await promise), after = deploymentBlock(await rpc('eth_getBlockByNumber', [number, false]));
    if (Object.keys(before).some(key => before[key] !== after[key])) throw Error('Canonical creation block changed');
  }
  return { receipts, code, immutableChecks: getters.length + 1, groupId: group.toString(),
    founderMintToVestingVerified: true,
    totalDeploymentNetworkFeeWei: receipts.reduce((sum, receipt) => sum + BigInt(receipt.networkFeeWei), 0n).toString() };
}
