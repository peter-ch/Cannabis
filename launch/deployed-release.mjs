// Verify the complete selected release through read-only finalized Ethereum RPC.
import { toQuantity } from 'ethers';
import { readReleasePackage } from './release-package.mjs';
import { compileReleaseRuntime } from './release-runtime.mjs';
import { verifyLaunchDependencies } from './dependencies.mjs';
import { checkFinalityProgress, deploymentBlock, inspectDeployedRelease, rpcHash, rpcQuantity } from './release-inspection.mjs';

export async function verifyDeployedRelease(options) {
  if (!options || Object.keys(options).sort().join(',') !== 'expectedPackageSHA256,manifestFile,rpc,transactionHashes')
    throw Error('Require the exact deployment verification options');
  const { rpc: endpoint, manifestFile, expectedPackageSHA256 } = options;
  if (!Array.isArray(options.transactionHashes) || options.transactionHashes.length !== 5)
    throw Error('Require the five ordered transaction hashes');
  const hashes = options.transactionHashes.map(rpcHash);
  if (new Set(hashes).size !== 5) throw Error('Duplicate deployment transaction hash');
  const url = new URL(endpoint);
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' &&
      !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)))) throw Error('Invalid verification RPC');
  const release = await readReleasePackage(manifestFile, expectedPackageSHA256, { deployed: true });
  const runtimes = compileReleaseRuntime(release);
  const dependencyObservation = await verifyLaunchDependencies({ rpc: url.toString(), dependencies: release.plan.dependencies, maxHeadAgeSeconds: 120 });
  const cancel = new AbortController(), started = Date.now(), timer = setTimeout(() => cancel.abort(), 60000);
  let sequence = 0;
  async function rpc(method, params = []) {
    if (!['eth_chainId', 'eth_getBlockByNumber', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getCode', 'eth_call'].includes(method))
      throw Error('Read-only deployment verification required');
    const id = ++sequence; let response;
    try {
      response = await fetch(url, { method: 'POST', redirect: 'error', credentials: 'omit',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: AbortSignal.any([cancel.signal, AbortSignal.timeout(15000)]) });
      if (!response.ok || !response.body) throw Error('Verification HTTP failure');
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length; if (size > 1024 * 1024) throw Error('Verification response exceeds bound');
        chunks.push(chunk);
      }
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      if (data.jsonrpc !== '2.0' || data.id !== id || Object.hasOwn(data, 'error') || !Object.hasOwn(data, 'result'))
        throw Error('Invalid verification RPC response');
      return data.result;
    } catch { throw Error('Deployment verification RPC failed; no complete verification returned'); }
    finally { if (response?.body && !response.bodyUsed) await response.body.cancel().catch(() => {}); }
  }
  try {
    const chain = async () => { if (rpcQuantity(await rpc('eth_chainId')) !== 1n) throw Error('Require Ethereum mainnet verification'); };
    await chain();
    const anchor = deploymentBlock(await rpc('eth_getBlockByNumber', [toQuantity(dependencyObservation.anchor.number), false]));
    if (anchor.hash !== dependencyObservation.anchor.hash || anchor.timestamp !== BigInt(dependencyObservation.anchor.timestamp))
      throw Error('Finalized dependency anchor changed');
    const inspection = await inspectDeployedRelease({ plan: release.plan, runtimes, transactionHashes: hashes, anchor, rpc });
    const canonical = deploymentBlock(await rpc('eth_getBlockByNumber', [toQuantity(anchor.number), false]));
    const finalized = deploymentBlock(await rpc('eth_getBlockByNumber', ['finalized', false]));
    const head = deploymentBlock(await rpc('eth_getBlockByNumber', ['latest', false]));
    if (Object.keys(anchor).some(key => anchor[key] !== canonical[key])) throw Error('Canonical finalized anchor changed');
    checkFinalityProgress(anchor, finalized, head);
    for (const observed of [finalized, head]) {
      const current = deploymentBlock(await rpc('eth_getBlockByNumber', [toQuantity(observed.number), false]));
      if (Object.keys(observed).some(key => observed[key] !== current[key])) throw Error('Finality or head tag is not canonical');
    }
    await chain();
    if (Date.now() < started || Date.now() - started >= 60000) throw Error('Deployment verification exceeded deadline');
    const publicBlock = value => ({ number: toQuantity(value.number), hash: value.hash, timestamp: toQuantity(value.timestamp) });
    return { schema: 'cannabis.deployed-network-verification.v1', checkedAt: new Date().toISOString(),
      status: 'DEPLOYMENT_MATCHES_SELECTED_RPC', chainId: '1', packageSHA256: release.packageSHA256,
      founder: release.plan.configuration.founder, addresses: release.plan.addresses,
      claimsOpen: release.plan.claimsOpen, founderVestingEnds: release.plan.founderVestingEnds,
      configuredInitialMinimum: release.plan.configuration.minimumClaimMembers,
      finalizedAnchor: publicBlock(anchor), checkedFinalized: publicBlock(finalized), checkedHead: publicBlock(head),
      dependencyObservation, ...inspection, creationAndRuntimeRecompiled: true,
      scope: 'Five canonical finalized creations and seven matching runtimes with immutable link/state checks in the selected RPC view.',
      limits: [
        'RPC observations do not independently prove Ethereum consensus or provide a security/privacy audit.',
        'Runtime templates match outside compiler-declared immutable slots; repeated immutable values and explicit immutable links are checked. Exact creation data and successful canonical receipts bind their origin.',
        'Mutable enrollment, balances, claim totals and escrow liabilities may legitimately change. This checks release provenance, not a current paid service or claim eligibility.',
        'Historical package reconstruction does not prove that seven-day opening notice was published.',
        'Independent review, ceremony legitimacy, actual confidential execution, real paid acceptance and public launch arrangements remain separate.'
      ], liveStatusAuthorized: false, independentReview: false, realPaidJobEstablished: false, sent: false };
  } finally { clearTimeout(timer); cancel.abort(); }
}
