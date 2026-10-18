// Compare reviewed dependency pins with canonical RPC state. No signing or broadcast.
import { Interface, getAddress, keccak256, toQuantity } from 'ethers';

const names = ['semaphore', 'verifier', 'poseidon'];
const ABI = new Interface(['function verifier() view returns (address)']);
const isHash = value => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value) && !/^0x0+$/.test(value);
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw Error('Unexpected dependency fields');
}
function bounded(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw Error('Dependency-check bound is invalid');
  return value;
}
function quantity(value) {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value) || BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Invalid RPC quantity');
  return Number(BigInt(value));
}
function block(value) {
  if (!value || !isHash(value.hash)) throw Error('Missing canonical block');
  return { number: quantity(value.number), hash: value.hash.toLowerCase(), timestamp: quantity(value.timestamp) };
}
export function validateDependencies(input) {
  exact(input, ['schema', 'chainId', ...names, 'poseidonLinkOffsets']);
  if (input.schema !== 'cannabis.semaphore-dependencies.v1' || typeof input.chainId !== 'string' || !/^[1-9][0-9]{0,77}$/.test(input.chainId) || BigInt(input.chainId) >= 2n ** 256n) throw Error('Invalid dependency schema or chain');
  const result = structuredClone(input);
  for (const name of names) {
    exact(result[name], ['address', 'codeHash']);
    result[name].address = getAddress(result[name].address);
    if (BigInt(result[name].address) === 0n || !isHash(result[name].codeHash)) throw Error('Pin nonzero dependency addresses and code hashes');
    result[name].codeHash = result[name].codeHash.toLowerCase();
  }
  if (new Set(names.map(name => result[name].address)).size !== names.length) throw Error('Dependency addresses must be distinct');
  const offsets = result.poseidonLinkOffsets;
  if (!Array.isArray(offsets) || offsets.length < 1 || offsets.length > 32) throw Error('Require compiler-derived Poseidon link offsets');
  for (let i = 0; i < offsets.length; i++) {
    bounded(offsets[i], 1, 24576 - 20);
    if (i && offsets[i] < offsets[i - 1] + 20) throw Error('Library links must be ordered and nonoverlapping');
  }
  return result;
}
function reader(url, duration) {
  const cancel = new AbortController(), timer = setTimeout(() => cancel.abort(), duration);
  let id = 0;
  return { close() { clearTimeout(timer); cancel.abort(); }, async call(method, params) {
    if (!['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call'].includes(method)) throw Error('Read-only dependency method required');
    const requestId = ++id;
    let response;
    try {
      response = await fetch(url, { method: 'POST', redirect: 'error', credentials: 'omit',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }),
        signal: AbortSignal.any([cancel.signal, AbortSignal.timeout(15000)]) });
      if (!response.ok || !response.body) throw Error('RPC HTTP failure');
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 256 * 1024) throw Error('RPC response exceeds bound');
        chunks.push(chunk);
      }
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      if (data.jsonrpc !== '2.0' || data.id !== requestId || Object.hasOwn(data, 'error') || !Object.hasOwn(data, 'result')) throw Error('Invalid RPC response');
      return data.result;
    } catch { throw Error('Dependency RPC read failed; finalized state and EIP-1898 support are required'); }
    finally { if (response?.body && !response.bodyUsed) await response.body.cancel().catch(() => {}); }
  } };
}
export async function verifyLaunchDependencies(options) {
  if (!options || Object.keys(options).some(key => !['rpc', 'dependencies', 'maxDurationMs', 'maxHeadAgeSeconds', 'maxFinalizedAgeSeconds'].includes(key))) throw Error('Unexpected dependency-check options');
  const dependencies = validateDependencies(options.dependencies);
  const url = new URL(options.rpc);
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)))) throw Error('Use HTTPS RPC or literal loopback HTTP without userinfo or fragments');
  const duration = bounded(options.maxDurationMs ?? 60000, 1000, 300000);
  const headAge = bounded(options.maxHeadAgeSeconds ?? 300, 30, 3600);
  const finalAge = bounded(options.maxFinalizedAgeSeconds ?? 7200, 300, 86400);
  const rpc = reader(url.toString(), duration), started = Date.now();
  const at = anchor => ({ blockHash: anchor.hash, requireCanonical: true });
  const checkChain = async () => {
    const value = await rpc.call('eth_chainId', []);
    if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value) || BigInt(value).toString() !== dependencies.chainId) throw Error('RPC chain does not match dependency pins');
  };
  const canonical = async anchor => {
    const current = block(await rpc.call('eth_getBlockByNumber', [toQuantity(anchor.number), false]));
    if (current.number !== anchor.number || current.hash !== anchor.hash || current.timestamp !== anchor.timestamp) throw Error('Canonical dependency block changed');
  };
  async function inspect(anchor) {
    const codes = await Promise.all(names.map(async name => {
      const code = await rpc.call('eth_getCode', [dependencies[name].address, at(anchor)]);
      if (typeof code !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(code) || code.length > 2 + 24576 * 2 || keccak256(code).toLowerCase() !== dependencies[name].codeHash) throw Error('Dependency runtime-code mismatch: ' + name);
      return code.toLowerCase();
    }));
    const semaphore = codes[0].slice(2), library = dependencies.poseidon.address.slice(2).toLowerCase();
    for (const offset of dependencies.poseidonLinkOffsets) {
      if (semaphore.slice(offset * 2 - 2, offset * 2) !== '73' || semaphore.slice(offset * 2, (offset + 20) * 2) !== library) throw Error('Semaphore library link does not match reviewed Poseidon');
    }
    const raw = await rpc.call('eth_call', [{ to: dependencies.semaphore.address, data: ABI.encodeFunctionData('verifier') }, at(anchor)]);
    if (typeof raw !== 'string' || !/^0x0{24}[0-9a-fA-F]{40}$/.test(raw) || ABI.decodeFunctionResult('verifier', raw)[0] !== dependencies.verifier.address) throw Error('Semaphore verifier does not match reviewed dependency');
  }
  try {
    await checkChain();
    const anchor = block(await rpc.call('eth_getBlockByNumber', ['finalized', false]));
    let now = Math.floor(Date.now() / 1000);
    if (anchor.timestamp < now - finalAge || anchor.timestamp > now + 60) throw Error('Finalized dependency state is stale or future-dated');
    await inspect(anchor); await canonical(anchor);
    const head = block(await rpc.call('eth_getBlockByNumber', ['latest', false]));
    now = Math.floor(Date.now() / 1000);
    if (head.number < anchor.number || head.timestamp < anchor.timestamp || head.timestamp < now - headAge || head.timestamp > now + 60) throw Error('Current dependency head is stale or inconsistent');
    await inspect(head); await canonical(head); await checkChain();
    if (Date.now() - started >= duration) throw Error('Dependency-check deadline exceeded');
    return { schema: 'cannabis.dependency-observation.v1', dependencies, anchor: { ...anchor, tag: 'finalized' }, checkedHead: head,
      checkedAt: new Date().toISOString(), runtimeAndLinksMatched: true, sent: false,
      scope: 'Compared caller-reviewed source pins with the selected RPC view; no independent consensus, source audit, funding or launch approval.' };
  } finally { rpc.close(); }
}
