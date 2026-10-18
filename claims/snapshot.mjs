// Whole-group download. Trusts a selected RPC's chain view; does not implement a light client.
import { Interface, getAddress, keccak256, toBeHex, toQuantity } from 'ethers';
import { Group } from '@semaphore-protocol/group';
import { claimScope } from './identity.mjs';

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ABI = new Interface([
  'function enrollment() view returns (address)', 'function semaphore() view returns (address)',
  'function groupId() view returns (uint256)', 'function claimScope() view returns (uint256)',
  'function enrolledCount() view returns (uint256)',
  'function getGroupAdmin(uint256) view returns (address)',
  'function getMerkleTreeRoot(uint256) view returns (uint256)',
  'function getMerkleTreeSize(uint256) view returns (uint256)',
  'event MemberAdded(uint256 indexed groupId,uint256 index,uint256 identityCommitment,uint256 merkleTreeRoot)',
  'event MembersAdded(uint256 indexed groupId,uint256 startIndex,uint256[] identityCommitments,uint256 merkleTreeRoot)',
  'event MemberUpdated(uint256 indexed groupId,uint256 index,uint256 identityCommitment,uint256 newIdentityCommitment,uint256 merkleTreeRoot)',
  'event MemberRemoved(uint256 indexed groupId,uint256 index,uint256 identityCommitment,uint256 merkleTreeRoot)'
]);
const TOPICS = ['MemberAdded', 'MembersAdded', 'MemberUpdated', 'MemberRemoved'].map(name => ABI.getEvent(name).topicHash);
const hash = value => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value) && !/^0x0+$/.test(value);
function quantity(value) {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value) || BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Invalid bounded RPC quantity');
  return Number(BigInt(value));
}
function integer(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw Error('Invalid ' + label);
  return value;
}
function nonzeroAddress(value) {
  const result = getAddress(value);
  if (BigInt(result) === 0n) throw Error('Expected a nonzero deployment address');
  return result;
}
function block(value) {
  if (!value || !hash(value.hash)) throw Error('Missing canonical block');
  return { number: quantity(value.number), hash: value.hash.toLowerCase(), timestamp: quantity(value.timestamp) };
}
function sourceConfig(options) {
  const config = structuredClone(options), release = config.release;
  if (!release || Object.keys(release).sort().join(',') !== ['chainId','token','tokenCodeHash','enrollment','enrollmentCodeHash','semaphore','semaphoreCodeHash','fromBlock'].sort().join(',')) throw Error('Require exact reviewed deployment fields');
  claimScope(release.chainId, release.token);
  for (const name of ['token', 'enrollment', 'semaphore']) {
    release[name] = nonzeroAddress(release[name]);
    if (!hash(release[name + 'CodeHash'])) throw Error('Pin all three reviewed runtime-code hashes');
    release[name + 'CodeHash'] = release[name + 'CodeHash'].toLowerCase();
  }
  if (new Set([release.token, release.enrollment, release.semaphore]).size !== 3) throw Error('Deployment addresses must be distinct');
  integer(release.fromBlock, 0, Number.MAX_SAFE_INTEGER, 'deployment start block');
  const url = new URL(config.rpc);
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)))) throw Error('Use HTTPS RPC or literal loopback HTTP without userinfo or fragments');
  return { ...config, release, rpc: url.toString(),
    pageSize: integer(config.pageSize ?? 2000, 1, 10000, 'block page size'),
    maxPages: integer(config.maxPages ?? 10000, 1, 10000, 'page budget'),
    maxDurationMs: integer(config.maxDurationMs ?? 300000, 1000, 3600000, 'download deadline'),
    maxHeadAgeSeconds: integer(config.maxHeadAgeSeconds ?? 300, 30, 3600, 'head freshness bound') };
}

function rpcReader(url, deadline) {
  let id = 0; const cancel = new AbortController();
  const timer = setTimeout(() => cancel.abort(), deadline);
  const allowed = new Set(['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call', 'eth_getLogs']);
  return { close() { clearTimeout(timer); cancel.abort(); }, async call(method, params) {
    if (!allowed.has(method)) throw Error('Only snapshot read methods are allowed');
    const requestId = ++id;
    let response;
    try {
      response = await fetch(url, { method: 'POST', redirect: 'error', credentials: 'omit',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }),
        signal: AbortSignal.any([cancel.signal, AbortSignal.timeout(15000)]) });
      if (!response.ok || !response.body) throw Error('RPC HTTP failure');
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length; if (size > 8 * 1024 * 1024) throw Error('RPC response exceeds bound');
        chunks.push(chunk);
      }
      const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      if (payload.jsonrpc !== '2.0' || payload.id !== requestId || Object.hasOwn(payload, 'error') || !Object.hasOwn(payload, 'result')) throw Error('Invalid RPC result');
      return payload.result;
    } catch { throw Error('Snapshot RPC read failed; finalized and EIP-1898 support are required'); }
    finally { if (response?.body && !response.bodyUsed) await response.body.cancel().catch(() => {}); }
  } };
}

export async function downloadMembershipSnapshot(options) {
  const config = sourceConfig(options), { release } = config;
  const rpc = rpcReader(config.rpc, config.maxDurationMs), started = Date.now();
  const withinDeadline = () => { if (Date.now() - started >= config.maxDurationMs) throw Error('Membership download deadline exceeded'); };
  const at = anchor => ({ blockHash: anchor.hash, requireCanonical: true });
  const call = async (target, name, args, anchor) => {
    const raw = await rpc.call('eth_call', [{ to: target, data: ABI.encodeFunctionData(name, args) }, at(anchor)]);
    return ABI.decodeFunctionResult(name, raw)[0];
  };
  async function checkCode(anchor) {
    await Promise.all(['token', 'enrollment', 'semaphore'].map(async name => {
      const code = await rpc.call('eth_getCode', [release[name], at(anchor)]);
      if (typeof code !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(code) || code.length > 256 * 1024 || keccak256(code).toLowerCase() !== release[name + 'CodeHash']) throw Error('Runtime-code hash does not match reviewed ' + name);
    }));
  }
  try {
    const checkChain = async () => {
      const actual = await rpc.call('eth_chainId', []);
      if (typeof actual !== 'string' || !/^0x[0-9a-f]+$/i.test(actual) || BigInt(actual).toString() !== release.chainId) throw Error('RPC chain does not match release');
    };
    await checkChain();
    const anchor = block(await rpc.call('eth_getBlockByNumber', ['finalized', false]));
    if (release.fromBlock > anchor.number || anchor.timestamp > Math.floor(Date.now()/1000) + 60) throw Error('Invalid finalized anchor or deployment range');
    const pages = Math.ceil((anchor.number - release.fromBlock + 1) / config.pageSize);
    if (pages > config.maxPages) throw Error('Membership range exceeds page budget');
    await checkCode(anchor);
    const [enrollmentAddress, semaphoreAddress, groupId, scope, enrolledCount, enrollmentSemaphore, enrollmentGroup] = await Promise.all([
      call(release.token, 'enrollment', [], anchor), call(release.token, 'semaphore', [], anchor),
      call(release.token, 'groupId', [], anchor), call(release.token, 'claimScope', [], anchor),
      call(release.enrollment, 'enrolledCount', [], anchor), call(release.enrollment, 'semaphore', [], anchor),
      call(release.enrollment, 'groupId', [], anchor)
    ]);
    if (enrollmentAddress !== release.enrollment || semaphoreAddress !== release.semaphore || enrollmentSemaphore !== release.semaphore || enrollmentGroup !== groupId || scope.toString() !== claimScope(release.chainId, release.token)) throw Error('Deployment relationships or claim scope do not match');
    if (enrolledCount < 128n || enrolledCount > 990000n) throw Error('Finalized group must contain 128 to 990000 commitments');
    const [root, size, admin] = await Promise.all([
      call(release.semaphore, 'getMerkleTreeRoot', [groupId], anchor),
      call(release.semaphore, 'getMerkleTreeSize', [groupId], anchor), call(release.semaphore, 'getGroupAdmin', [groupId], anchor)
    ]);
    if (size !== enrolledCount || admin !== release.enrollment || root <= 0n || root >= FIELD) throw Error('Finalized group state does not match enrollment');
    const group = new Group(), commitments = [], unique = new Set();
    const topicGroup = toBeHex(groupId, 32).toLowerCase(); let eventCount = 0;
    for (let from = release.fromBlock; from <= anchor.number; from += config.pageSize) {
      withinDeadline(); const to = Math.min(anchor.number, from + config.pageSize - 1);
      const logs = await rpc.call('eth_getLogs', [{ address: release.semaphore, fromBlock: toQuantity(from), toBlock: toQuantity(to), topics: [TOPICS, topicGroup] }]);
      if (!Array.isArray(logs) || logs.length > 8192) throw Error('Event page exceeds bound; reduce page size');
      const ordered = logs.map(log => {
        if (!log || log.removed !== false || getAddress(log.address) !== release.semaphore || !hash(log.blockHash) || !hash(log.transactionHash) || !Array.isArray(log.topics) || log.topics.length !== 2 || log.topics[1].toLowerCase() !== topicGroup || !TOPICS.includes(log.topics[0])) throw Error('Unexpected membership event envelope');
        const number = quantity(log.blockNumber), transaction = quantity(log.transactionIndex), index = quantity(log.logIndex);
        if (number < from || number > to || (number === anchor.number && log.blockHash.toLowerCase() !== anchor.hash)) throw Error('Event outside the requested canonical range');
        if (typeof log.data !== 'string' || log.data.length > 17000 || !/^0x(?:[0-9a-fA-F]{2})*$/.test(log.data)) throw Error('Membership event data exceeds bound');
        return { log, number, transaction, index };
      }).sort((a,b) => a.number-b.number || a.transaction-b.transaction || a.index-b.index);
      const seenPositions = new Set();
      for (const { log, number, index } of ordered) {
        const position = number + ':' + index;
        if (seenPositions.has(position)) throw Error('Repeated membership event');
        seenPositions.add(position);
        const event = ABI.parseLog(log);
        if (!event || !['MemberAdded','MembersAdded'].includes(event.name)) throw Error('Non-append membership event is forbidden');
        const startIndex = event.args[1], members = event.name === 'MemberAdded' ? [event.args[2]] : Array.from(event.args[2]);
        if (event.args[0] !== groupId || startIndex !== BigInt(commitments.length) || members.length < 1 || members.length > 256 || commitments.length + members.length > Number(enrolledCount)) throw Error('Missing, repeated or excessive membership additions');
        for (const member of members) {
          if (member <= 0n || member >= FIELD || unique.has(member.toString())) throw Error('Invalid or duplicate commitment');
          unique.add(member.toString()); commitments.push(member.toString());
        }
        group.addMembers(members);
        if (group.root !== event.args[3]) throw Error('Reconstructed event root does not match');
        eventCount++; withinDeadline();
      }
    }
    if (commitments.length !== Number(enrolledCount) || group.root !== root) throw Error('Membership event history is incomplete');
    // Recheck the anchor, then ensure no newer membership has made this root stale.
    const canonical = block(await rpc.call('eth_getBlockByNumber', [toQuantity(anchor.number), false]));
    if (canonical.number !== anchor.number || canonical.hash !== anchor.hash) throw Error('Finalized anchor changed during download');
    const head = block(await rpc.call('eth_getBlockByNumber', ['latest', false]));
    const now = Math.floor(Date.now()/1000);
    if (head.number < anchor.number || head.timestamp < now-config.maxHeadAgeSeconds || head.timestamp > now+60) throw Error('Current head is stale or inconsistent');
    await checkCode(head);
    const [currentRoot, currentCount, currentSize, currentAdmin] = await Promise.all([
      call(release.semaphore, 'getMerkleTreeRoot', [groupId], head), call(release.enrollment, 'enrolledCount', [], head),
      call(release.semaphore, 'getMerkleTreeSize', [groupId], head), call(release.semaphore, 'getGroupAdmin', [groupId], head)
    ]);
    if (currentRoot !== root || currentCount !== enrolledCount || currentSize !== size || currentAdmin !== admin) throw Error('Membership changed; wait for enrollment finality and download again');
    const currentHead = block(await rpc.call('eth_getBlockByNumber', [toQuantity(head.number), false]));
    if (currentHead.number !== head.number || currentHead.hash !== head.hash) throw Error('Head changed during verification');
    await checkChain(); withinDeadline();
    return { schema: 'cannabis.membership-download.v1',
      snapshot: { schema: 'cannabis.membership-snapshot.v1', chainId: release.chainId, token: release.token, root: root.toString(), commitments },
      context: { chainId: release.chainId, token: release.token, root: root.toString(), memberCount: commitments.length },
      evidence: { release, anchor: { ...anchor, tag: 'finalized' }, checkedHead: head, groupId: groupId.toString(), pages, eventCount,
        checkedAt: new Date().toISOString(), rpcTrust: 'Selected RPC chain view; no independent consensus or state-proof verification', consistencyChecked: true }, sent: false };
  } finally { rpc.close(); }
}
