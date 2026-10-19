import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { AbiCoder, ContractFactory, formatUnits, keccak256, ZeroAddress } from 'ethers';
import { compile } from '../scripts/compile.mjs';
import { startNode } from '../scripts/lib.mjs';
import { policy } from '../scripts/compute-plan.mjs';
import { settlementTerms, termsDigest } from '../scripts/compute-escrow.mjs';
import { bookingPayload } from '../compute/market.mjs';
import { createMarketLeaseProof, verifyMarketLeaseProof, readMarketLeaseState } from '../compute/market_lease.mjs';
import { marketAttestationBinding, configuredMarketAttestationBinding, AttestationLedger, trusteeRuntimeData } from '../compute/attestation.mjs';
import { validateGuestConfiguration } from '../compute/guest_configuration.mjs';
import { prepareGuestLaunch, publicLaunchAdmission } from '../compute/guest_launch.mjs';
import { nativeServiceCommitment } from '../compute/guest_execution.mjs';
import { launchFixture } from './helpers/launch_fixture.mjs';
import { GuestFunding } from '../compute/guest_funding.mjs';
import { guestInitialization } from '../compute/guest_initialization.mjs';
import { keyDeliveryPayload, sealJobKeyDelivery, openJobKeyDelivery, inspectKeyDelivery } from '../compute/key_delivery.mjs';
import { sealResultDelivery, openResultDelivery } from '../compute/result_delivery.mjs';
import { resultKeyCommitment } from '../compute/result_keys.mjs';
import { launchConsentPayload, inspectLaunchConsent, readLaunchConsentState } from '../compute/guest_consent.mjs';

const h = n => '0x' + n.toString(16).padStart(64, '0');
const utc = n => new Date(n * 1000).toISOString().replace('.000Z', 'Z');
const coder = AbiCoder.defaultAbiCoder();
function syntheticEAR(key, policy, challenge, channel, now) {
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])) : value;
  const runtime = trusteeRuntimeData(challenge, channel), m = policy.measurements;
  const claims = { iss: policy.issuer, iat: now, exp: now + 120, eat_profile: 'tag:github.com,2024:confidential-containers/Trustee',
    'ear.verifier-id': { developer: 'https://confidentialcontainers.org', build: policy.verifierBuild }, submods: { cpu0: {
      'ear.status': 'affirming', 'ear.appraisal-policy-id': policy.appraisalPolicyId,
      'ear.trustworthiness-vector': { 'instance-identity': 0, configuration: 2, executables: 3, 'file-system': 0, hardware: 2, 'runtime-opaque': 0, 'storage-opaque': 0, 'sourced-data': 0 },
      'ear.veraison.annotated-evidence': { snp: { measurement: m.launch, policy_debug_allowed: false, policy_migrate_ma: false,
        reported_tcb_bootloader: 1, reported_tcb_tee: 1, reported_tcb_snp: 1, reported_tcb_microcode: 1 }, init_data: m.initData,
        init_data_claims: null, runtime_data_claims: runtime,
        report_data: createHash('sha384').update(JSON.stringify(canonical(runtime))).digest('hex') + '00'.repeat(16) } } } };
  const body = [{ alg: 'ES256', typ: 'JWT', jwk: key.publicKey.export({ format: 'jwk' }) }, claims].map(v => Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
  return body + '.' + sign('sha256', Buffer.from(body), { key: key.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
}
let node, provider, owner, workers, judge, native, tokenEscrow, market, asset, contractWorker, initial;
const port = () => new Promise(resolve => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
before(async () => {
  const artifacts = compile({ 'MarketLeaseAsset.sol': { content: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
contract MarketLeaseAsset is ERC20 { constructor() ERC20("Isolated verification", "FIX") { _mint(msg.sender, 1000000 ether); } }
contract MarketConsentWallet {
  address public immutable owner;
  mapping(bytes32 => bool) public approved;
  constructor(address owner_) { owner = owner_; }
  function approveDigest(bytes32 digest, bool value) external { require(msg.sender == owner); approved[digest] = value; }
  function invoke(address target, bytes calldata data) external {
    require(msg.sender == owner); (bool ok,) = target.call(data); require(ok);
  }
  function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4) {
    return approved[digest] && ECDSA.recover(digest, signature) == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
  }
}
` } });
  node = await startNode(await port(), 'market-lease-test-node.log'); provider = node.provider;
  const accounts = await Promise.all([0, 1, 2, 3].map(i => provider.getSigner(i))); [owner, ...workers] = accounts; judge = workers.pop();
  const deploy = async (name, args = []) => { const a = artifacts[name], c = await new ContractFactory(a.abi, a.bytecode, owner).deploy(...args); await c.waitForDeployment(); return c; };
  asset = await deploy('MarketLeaseAsset'); native = await deploy('ComputeEscrow', [ZeroAddress, policy.founderRecipient]);
  tokenEscrow = await deploy('ComputeEscrow', [await asset.getAddress(), policy.founderRecipient]);
  market = await deploy('ComputeMarket', [await native.getAddress(), await tokenEscrow.getAddress()]);
  contractWorker = await deploy('MarketConsentWallet', [await workers[0].getAddress()]);
  await (await asset.approve(await tokenEscrow.getAddress(), 100000000n)).wait();
  initial = await provider.send('evm_snapshot', []);
});
after(() => { provider?.destroy(); node?.child.kill(); });

async function setup({ token = false, activate = true, execution, contractProvider = false } = {}) {
  await provider.send('evm_revert', [initial]); initial = await provider.send('evm_snapshot', []);
  let time = (await provider.getBlock('latest')).timestamp;
  await provider.send('evm_setNextBlockTimestamp', [time + 1]); await provider.send('evm_mine', []); ++time;
  const clock = () => time, start = time + 1000, end = start + 100, escrow = token ? tokenEscrow : native;
  const account = await owner.getAddress(), addresses = await Promise.all(workers.map(w => w.getAddress()));
  if(contractProvider)addresses[0]=await contractWorker.getAddress();
  const workerCall=async(i,target,name,args)=>{
    const tx=contractProvider&&i===0
      ? await contractWorker.connect(workers[i]).invoke(await target.getAddress(),target.interface.encodeFunctionData(name,args))
      : await target.connect(workers[i])[name](...args);
    return tx.wait();
  };
  const network = { rpc: node.rpc, chainId: 31337, market: await market.getAddress(), marketCodeHash: keccak256(await provider.getCode(await market.getAddress())),
    token: token ? await asset.getAddress() : ZeroAddress, escrow: await escrow.getAddress(), genesisHash: (await provider.getBlock(0)).hash,
    escrowCodeHash: keccak256(await provider.getCode(await escrow.getAddress())), tokenCodeHash: token ? keccak256(await provider.getCode(await asset.getAddress())) : null,
    finality: 'rpc-finalized', maxFinalizedAgeSeconds: 1800, maxHeadAgeSeconds: 120 };
  const context = { chainId: 31337, market: network.market, token: network.token };
  const job = { schema: 'cannabis.compute.order.v2', id: 'market-private-job', requester: account, packageSHA256: h(70).slice(2),
    policySHA256: h(71).slice(2), acceptanceSHA256: h(72).slice(2),
    payment: { totalBudget: formatUnits(20000n, 18), feeBasisPoints: 100, founderRecipient: policy.founderRecipient } };
  const settlement = { workers: addresses.map(account => ({ account, shareBps: 5000 })), deliveryManager: addresses[0],
    adjudicator: await judge.getAddress(), acceptBy: utc(time + 800), deliverBy: utc(end + 60), reviewSeconds: 86400, disputeSeconds: 86400 };
  const terms = settlementTerms(job, settlement), orderId = await escrow.orderId(account, terms.terms.jobHash);
  const digest = termsDigest({ chainId: 31337, escrow: network.escrow, token: network.token, founderRecipient: policy.founderRecipient, ...terms });
  const bookings = [], signatures = [], ids = [];
  for (let i = 0; i < 2; ++i) {
    await workerCall(i,market,'publishResource',[h(10 + i),execution?nativeServiceCommitment(execution).serviceSHA256:h(20 + i),1]);
    const resource = await market.resourceKey(addresses[i], h(10 + i));
    const offer = { resource, escrow: network.escrow, policyHash: '0x' + job.policySHA256, manifestHash: h(30 + i), start, end,
      expiresAt: time + 900, units: 1, grossPerUnitSecond: 100 };
    await workerCall(i,market,'publishOffer',[h(40 + i),offer]);
    const offerId = keccak256(coder.encode(['address', 'bytes32'], [addresses[i], h(40 + i)]));
    const booking = { reservationId: h(50 + i), offerId, requester: account, orderId, termsDigest: digest, start, end, units: 1, gross: '10000', holdUntil: time + 600 };
    const p = bookingPayload(context, booking); bookings.push(booking); ids.push(p.digest);
    if(contractProvider&&i===0)await (await contractWorker.connect(workers[0]).approveDigest(p.digest,true)).wait();
    signatures.push(await workers[i].signTypedData(p.domain, p.types, p.value));
  }
  await (await market.reserveBatch(bookings, signatures)).wait();
  await (await escrow.fund(terms.terms, terms.accounts, terms.shares, { value: token ? 0 : 20000 })).wait();
  for (let i=0;i<workers.length;++i) await workerCall(i,escrow,'accept',[orderId]);
  if (activate) await (await market.activate(ids.sort())).wait();
  time = (await provider.getBlock('latest')).timestamp;
  const input = { job, settlement, bookingIds: ids };
  const proof = activate ? await createMarketLeaseProof(network, input, clock) : null;
  const run = { runtimeSHA256: execution?.profile.runtime.digestSHA256??h(73).slice(2), taskSHA256: h(74).slice(2), attempt: 1, rank: 0, worldSize: 1, acceleratorClass: 'cpu' };
  const setTime = async value => { time = value; await provider.send('evm_setNextBlockTimestamp', [time]); await provider.send('evm_mine', []); };
  return { network, context, input, proof, clock, setTime, start, end, escrow, orderId, ids, run, addresses, workerCall };
}

function guest(d, proof = d.proof, changes = {}) {
  const lease = verifyMarketLeaseProof(proof, d.context), r = lease.reservations[0];
  const binding = marketAttestationBinding(proof, d.context, r.reservationId, d.run, d.clock());
  const initialization = { schema: 'cannabis.guest-initialization.v1', tee: 'snp', requester: lease.requester, jobId: lease.job.id, binding };
  const options = { proof, context: d.context, network: d.network, provider: r.provider, resourceId: r.resourceId, serviceSHA256: r.serviceSHA256, ...changes };
  return { lease, r, initialization, funding: new GuestFunding(options, initialization, { clock: d.clock }) };
}

test('a complete ETH or token market group independently funds the retained guest without a capacity database', async () => {
  for (const token of [false, true]) {
    const d = await setup({ token }); await d.setTime(d.start + 1);
    const g = guest(d);
    try {
      assert.equal(g.lease.providers.length, 2); g.funding.assertService({ serviceSHA256: g.r.serviceSHA256, units: 1 });
      const state = await g.funding.refresh();
      assert.equal(state.schema, 'cannabis.guest-funding.v2'); assert.equal(state.leaseDigest, g.lease.digest);
      assert.equal(state.executionAuthorized, false); assert.equal(state.hardwareVerified, false);
      assert.equal(state.reservationId, d.ids[0]); assert.ok(state.headBlock.number >= state.finalizedBlock.number);
    } finally { g.funding.close(); }
  }
});

test('unactivated and incomplete groups cannot become requester proofs', async () => {
  const held = await setup({ activate: false });
  await assert.rejects(createMarketLeaseProof(held.network, held.input, held.clock), /activated bookings/);
  const d = await setup();
  await assert.rejects(createMarketLeaseProof(d.network, { ...d.input, bookingIds: [d.ids[0]] }, d.clock), /Incomplete/);
});

test('proof commitments reject workload, price, shares, group, network and byte-format substitution', async () => {
  const d = await setup();
  for (const mutate of [p => p.job.packageSHA256 = h(90).slice(2), p => p.job.policySHA256 = h(90).slice(2),
    p => p.job.acceptanceSHA256 = h(90).slice(2), p => p.bookings.reverse(), p => p.bookings.pop(),
    p => p.bookings[0].booking.gross = '9999', p => p.bookings[0].offer.policyHash = h(99),
    p => p.bookings[0].booking.start = '0' + p.bookings[0].booking.start, p => p.bookings[0].resource.units = '0',
    p => p.settlement.workers[0].shareBps = 4999, p => p.chainId = 1, p => p.market = '0x' + '12'.repeat(20),
    p => p.token = d.network.escrow, p => p.fundedAnchor.timestamp = -1, p => p.bookings[0].secret = 'not-a-field']) {
    const p = structuredClone(d.proof); mutate(p); assert.throws(() => verifyMarketLeaseProof(p, d.context));
  }
});

test('locally consistent invented service/resource/provider data is refused by fresh chain reads', async () => {
  const d = await setup(); await d.setTime(d.start + 1);
  for (const mutate of [p => p.bookings[0].resource.serviceHash = h(91), p => p.bookings[0].offer.resource = h(92),
    p => p.bookings[0].offer.manifestHash = h(93), p => p.bookings.forEach(r => r.resource.units = '2')]) {
    const p = structuredClone(d.proof); mutate(p);
    verifyMarketLeaseProof(p, d.context); // Structural consistency is deliberately insufficient.
    await assert.rejects(readMarketLeaseState(p, d.network, d.clock), /activated bookings differ/);
  }
});

test('withdrawn offers preserve admitted bookings, but a delivered order immediately closes the guest', async () => {
  const d = await setup(); await d.setTime(d.start + 1);
  const g = guest(d), record = d.proof.bookings[0];
  const worker = workers.find(w => w.address === record.resource.provider);
  await (await market.connect(worker).withdrawOffer(record.booking.offerId)).wait();
  await g.funding.refresh();
  await (await d.escrow.connect(workers[0]).deliver(d.orderId, h(95))).wait();
  await assert.rejects(g.funding.refresh(), /fully accepted active/);
  assert.throws(() => g.funding.assertWindow(), /closed/);
});

test('guest assignment, approved resource, interval, and deployment pins cannot be replaced', async () => {
  const d = await setup();
  for (const changes of [{ provider: await judge.getAddress() }, { resourceId: h(99) }, { serviceSHA256: h(99).slice(2) },
    { network: { ...d.network, market: d.network.escrow } }]) assert.throws(() => guest(d, d.proof, changes));
  await assert.rejects(guest(d).funding.refresh(), /not started/);
  await d.setTime(d.start + 1);
  for (const changes of [{ marketCodeHash: h(99) }, { escrowCodeHash: h(99) }, { genesisHash: h(99) }, { chainId: 1 }])
    await assert.rejects(readMarketLeaseState(d.proof, { ...d.network, ...changes }, d.clock));
  const g = guest(d); await d.setTime(d.end); await assert.rejects(g.funding.refresh(), /expired/);
});

async function proxy(transform) {
  const server = http.createServer(async (req, res) => {
    try {
      const parts = []; for await (const p of req) parts.push(p); const input = JSON.parse(Buffer.concat(parts));
      const one = async m => transform(m, await (await fetch(node.rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(m) })).json());
      const result = Array.isArray(input) ? await Promise.all(input.map(one)) : await one(input);
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(result));
    } catch { res.writeHead(500); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { rpc: 'http://127.0.0.1:' + server.address().port, close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}

test('original activation block substitution, timestamp forgery and unsupported hash reads fail closed', async () => {
  const d = await setup(); await d.setTime(d.start + 1);
  for (const mutate of [p => p.fundedAnchor.hash = h(90), p => p.fundedAnchor.timestamp--, p => p.fundedAnchor.number--]) {
    const p = structuredClone(d.proof); mutate(p); await assert.rejects(readMarketLeaseState(p, d.network, d.clock));
  }
  let reads = 0;
  const p = await proxy((m, r) => {
    if (['eth_getCode', 'eth_call'].includes(m.method)) {
      assert.equal(m.params[1].requireCanonical, true); ++reads;
      return { id: m.id, jsonrpc: '2.0', error: { code: -32602, message: 'Canonical hash reads unavailable' } };
    } return r;
  });
  try { await assert.rejects(readMarketLeaseState(d.proof, { ...d.network, rpc: p.rpc }, d.clock)); assert.ok(reads > 0); }
  finally { await p.close(); }
});

test('freshness and latest inactive funding cannot be hidden behind a valid original proof', async () => {
  const d = await setup(); await d.setTime(d.start + 1);
  await assert.rejects(readMarketLeaseState(d.proof, d.network, () => d.clock() + 1801), /stale/);
  const abi = d.escrow.interface;
  const p = await proxy((m, r) => {
    if (m.method === 'eth_call' && m.params[0].to.toLowerCase() === d.network.escrow.toLowerCase() &&
        m.params[0].data.startsWith(abi.getFunction('orders').selector) && m.params[1].blockHash !== d.proof.fundedAnchor.hash) {
      const decoded = [...abi.decodeFunctionResult('orders', r.result)]; decoded[2] = 3n;
      return { ...r, result: abi.encodeFunctionResult('orders', decoded) };
    } return r;
  });
  try { await assert.rejects(readMarketLeaseState(d.proof, { ...d.network, rpc: p.rpc }, d.clock), /fully accepted active/); }
  finally { await p.close(); }
});

test('requester approval and encrypted result recovery retain the market group without a capacity journal', async () => {
  const d = await setup(); await d.setTime(d.start + 1);
  const g = guest(d), key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const p = { schema: 'cannabis.attestation.trustee-policy.v1', issuer: 'Fixture only', signingJwk: key.publicKey.export({ format: 'jwk' }),
    verifierBuild: 'synthetic fixture', appraisalPolicyId: 'fixture', maxTokenAgeSeconds: 90, maxTokenLifetimeSeconds: 120, challengeTTLSeconds: 90,
    tee: 'snp', measurements: { launch: '11'.repeat(48), initData: guestInitialization(g.initialization).digest, minimumTCB: { bootloader: 1, tee: 1, snp: 1, microcode: 1 } } };
  const attestations = new AttestationLedger(':memory:', p, d.clock);
  try {
    const challenge = attestations.challenge(g.initialization.binding), resultKey = Buffer.alloc(32, 7);
    const source = { schema: 'cannabis.market-requester.v1', context: d.context, proof: d.proof };
    const descriptor = { schema: 'cannabis.package.v2', id: g.lease.job.id, ciphertextSHA256: g.lease.job.packageSHA256,
      policySHA256: g.lease.job.policySHA256, recipient: 'age1' + 'a'.repeat(58),
      keyCustody: { schema: 'cannabis.job-key.custody.v1', format: 'age-v1+json', ciphertextSHA256: h(96).slice(2), ciphertextBytes: 100 } };
    const request = { releaseId: h(97), leaseId: g.lease.digest, nonce: challenge.nonce, channelJwk: key.publicKey.export({ format: 'jwk' }),
      descriptor, notBefore: d.clock(), expiresAt: d.clock() + 60, resultKeySHA256: resultKeyCommitment(resultKey) };
    const payload = keyDeliveryPayload(source, attestations, request, d.clock());
    assert.equal(payload.value.leaseDigest, g.lease.digest); assert.equal(payload.value.reservationId, g.r.reservationId);
    assert.equal(payload.keyReleaseAuthorized, false);
    assert.throws(() => keyDeliveryPayload(source, attestations, { ...request, leaseId: h(99) }, d.clock()), /group differs/);
    const receipt = { schema: 'cannabis.result.v1', jobId: g.lease.job.id, packageSHA256: g.lease.job.packageSHA256,
      attempt: 1, rank: 0, worldSize: 1, taskId: 'work', recipient: 'age1' + 'b'.repeat(58), ciphertextSHA256: h(98).slice(2), ciphertextBytes: 100 };
    const envelope = await sealResultDelivery(receipt, resultKey, payload);
    assert.equal((await openResultDelivery(envelope, resultKey, payload)).receiptAuthenticated, true);
    await assert.rejects(openResultDelivery(envelope, resultKey, { ...payload, value: { ...payload.value, leaseDigest: h(99) } }));
    const signed = { request, requesterSignature: await owner.signTypedData(payload.domain, payload.types, payload.value) };
    const token = syntheticEAR(key, p, challenge, request.channelJwk, d.clock()); let recoveries = 0;
    await assert.rejects(sealJobKeyDelivery(source, attestations, signed, token, d.network, () => { ++recoveries; throw Error('Reached owned key callback'); }, { clock: d.clock }), /Reached owned key callback/);
    assert.equal(recoveries, 1); // The positive chain and synthetic appraisal reach local custody.
    await (await d.escrow.connect(workers[0]).deliver(d.orderId, h(95))).wait();
    await assert.rejects(sealJobKeyDelivery(source, attestations, signed, token, d.network, () => { ++recoveries; throw Error('Must not recover'); }, { clock: d.clock }), /fully accepted active/);
    assert.equal(recoveries, 1); // A later inactive order cannot reach local custody.
  } finally { attestations.close(); g.funding.close(); }
});

async function configuredFixture(t,{contractProvider=false,transportTimeoutMs=60000}={}) {
  const f=launchFixture(),d=await setup({execution:f.configuration.execution,contractProvider});await d.setTime(d.start+1);
  const lease=verifyMarketLeaseProof(d.proof,d.context),r=lease.reservations.find(r=>!contractProvider||r.provider===d.addresses[0]),key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const configuration={...f.configuration,schema:'cannabis.guest-launch-configuration.v3',context:d.context,network:d.network,
    provider:r.provider,resourceId:r.resourceId,validFrom:d.start-10,validUntil:d.end+10};
  configuration.attestationPolicyTemplate.signingJwk=key.publicKey.export({format:'jwk'});
  configuration.transport.timeoutMs=transportTimeoutMs;
  const {configurationSHA256}=validateGuestConfiguration(configuration);
  const binding=configuredMarketAttestationBinding(d.proof,d.context,r.reservationId,d.run,configurationSHA256,d.clock());
  const initialization={schema:'cannabis.guest-initialization.v2',tee:'snp',requester:lease.requester,jobId:lease.job.id,binding};
  const policy=structuredClone(configuration.attestationPolicyTemplate);policy.measurements.initData=guestInitialization(initialization).digest;
  const attestations=new AttestationLedger(':memory:',policy,d.clock);t.after(()=>attestations.close());
  const challenge=attestations.challenge(binding);
  const source={schema:'cannabis.market-requester.v3',context:d.context,proof:d.proof,configuration:structuredClone(configuration),
    consent:(await bookedConsent({...d,configuration,initialization,lease,r})).signed};
  const descriptor={schema:'cannabis.package.v2',id:lease.job.id,ciphertextSHA256:lease.job.packageSHA256,policySHA256:lease.job.policySHA256,
    recipient:'age1'+'a'.repeat(58),keyCustody:{schema:'cannabis.job-key.custody.v1',format:'age-v1+json',ciphertextSHA256:h(96).slice(2),ciphertextBytes:100}};
  const request={releaseId:h(97),leaseId:lease.digest,nonce:challenge.nonce,channelJwk:key.publicKey.export({format:'jwk'}),descriptor,
    notBefore:d.clock(),expiresAt:d.clock()+60,resultKeySHA256:resultKeyCommitment(Buffer.alloc(32,7))};
  return {...d,f,lease,r,key,configuration,configurationSHA256,binding,initialization,policy,attestations,challenge,source,request};
}

test('bilateral launch admission binds canonical funding, exact configuration and challenge',async t=>{
  const x=await configuredFixture(t),c=await bookedConsent(x),request={proof:x.proof,challenge:x.challenge};
  const prepare=(signed,init=x.initialization,req=request)=>prepareGuestLaunch(signed,init,req,{clock:x.clock});
  const launch=await prepare(c.signed);assert.equal(launch.configurationSHA256,x.configurationSHA256);
  assert.equal(publicLaunchAdmission(launch).schema,'cannabis.guest-launch-admission.v1');
  assert.deepEqual(launch.funding.consent,c.signed);assert.equal(Object.hasOwn(launch,'authoritySHA256'),false);
  for(const alter of [s=>s.consents.pop(),s=>s.consents[1].signature=s.consents[0].signature,
    s=>s.configuration.network.rpc='https://other.invalid/',s=>s.configuration.transport.timeoutMs--]) {
    const changed=structuredClone(c.signed);alter(changed);await assert.rejects(prepare(changed));
  }
  for(const alter of [i=>i.schema='cannabis.guest-initialization.v1',i=>delete i.binding.configurationSHA256,
    i=>i.binding.configurationSHA256=h(99),i=>i.binding.rank=1]) {
    const init=structuredClone(x.initialization);alter(init);await assert.rejects(prepare(c.signed,init));
  }
  for(const alter of [r=>r.challenge.expiresAt=x.clock(),r=>r.challenge.attestationPolicySHA256=h(99).slice(2),
    r=>r.challenge.binding.configurationSHA256=h(99),r=>r.configuration=x.configuration]) {
    const changed=structuredClone(request);alter(changed);await assert.rejects(prepare(c.signed,x.initialization,changed));
  }
  await (await x.escrow.connect(workers[0]).deliver(x.orderId,h(95))).wait();
  await assert.rejects(prepare(c.signed),/fully accepted active/);
});

test('requester independently binds full configuration, appraisal policy and result channel before custody',async t=>{
  const x=await configuredFixture(t),payload=keyDeliveryPayload(x.source,x.attestations,x.request,x.clock());
  assert.equal(payload.domain.version,'3');assert.equal(payload.value.configurationSHA256,x.configurationSHA256);
  const legacy={schema:'cannabis.market-requester.v1',context:x.context,proof:x.proof};
  assert.throws(()=>keyDeliveryPayload(legacy,x.attestations,x.request,x.clock()),/configuration/i);
  const noResult={...x.request};delete noResult.resultKeySHA256;
  assert.throws(()=>keyDeliveryPayload(x.source,x.attestations,noResult,x.clock()),/result channel/);
  for(const alter of [c=>c.transport.timeoutMs--,c=>c.network.rpc='https://other.invalid/',c=>c.resourceId=h(99),
    c=>c.execution.profile.runtime.digestSHA256=h(99).slice(2),c=>c.attestationPolicyTemplate.measurements.launch='99'.repeat(48)]) {
    const changed=structuredClone(x.source);alter(changed.configuration);
    assert.throws(()=>keyDeliveryPayload(changed,x.attestations,x.request,x.clock()));
  }
  const changed=structuredClone(x.source);changed.configuration.transport.timeoutMs--;
  changed.consent.configuration=structuredClone(changed.configuration);
  const binding={...x.binding,configurationSHA256:validateGuestConfiguration(changed.configuration).configurationSHA256};
  const otherChallenge=x.attestations.challenge(binding);
  assert.throws(()=>keyDeliveryPayload(changed,x.attestations,{...x.request,nonce:otherChallenge.nonce},x.clock()),/appraisal policy/);
  const signed={request:x.request,requesterSignature:await owner.signTypedData(payload.domain,payload.types,payload.value)};
  const token=syntheticEAR(x.key,x.policy,x.challenge,x.request.channelJwk,x.clock());let recoveries=0;
  const recover=()=>{recoveries++;throw Error('Reached owned key callback');};
  for(const change of [{rpc:'https://other.invalid/'},{maxHeadAgeSeconds:119},{genesisHash:h(99)}])
    await assert.rejects(sealJobKeyDelivery(x.source,x.attestations,signed,token,{...x.network,...change},recover,{clock:x.clock}),/reviewed launch configuration/);
  assert.equal(recoveries,0);
  await assert.rejects(sealJobKeyDelivery(x.source,x.attestations,signed,token,x.network,recover,{clock:x.clock}),/Reached owned key callback/);
  assert.equal(recoveries,1);
  await (await x.escrow.connect(workers[0]).deliver(x.orderId,h(95))).wait();
  await assert.rejects(sealJobKeyDelivery(x.source,x.attestations,signed,token,x.network,recover,{clock:x.clock}),/fully accepted active/);
  assert.equal(recoveries,1);
});

async function bookedConsent(x) {
  const consents=[];
  for(const [role,signer,account] of [['requester',owner,x.lease.requester],
    ['provider',workers[x.addresses.indexOf(x.r.provider)],x.r.provider]]) {
    const p=launchConsentPayload(x.configuration,x.initialization,x.proof,role);
    consents.push({role,signer:account,signature:await signer.signTypedData(p.domain,p.types,p.value)});
  }
  const signed={schema:'cannabis.guest-launch-consent.v1',configuration:x.configuration,consents};
  return {signed,...inspectLaunchConsent(signed,x.initialization,x.proof,x.clock())};
}

async function requesterDelivery(x) {
  const ageKeygen=process.env.CANNABIS_AGE
    ? path.join(path.dirname(process.env.CANNABIS_AGE),process.platform==='win32'?'age-keygen.exe':'age-keygen') : 'age-keygen';
  // Disposable identity exists only in this test process, never owner custody.
  const generated=spawnSync(ageKeygen,[],{encoding:'utf8',windowsHide:true,stdio:['ignore','pipe','ignore']});
  assert.equal(generated.status,0,'Disposable age key generation failed');
  const identity=generated.stdout.match(/^AGE-SECRET-KEY-1[A-Z0-9]{58}$/m)?.[0]+'\n';
  const derived=spawnSync(ageKeygen,['-y'],{input:identity,encoding:'utf8',windowsHide:true,stdio:['pipe','pipe','ignore']});
  assert.equal(derived.status,0,'Disposable age public key derivation failed');
  const request=structuredClone(x.request);request.descriptor.recipient=derived.stdout.trim();
  const payload=keyDeliveryPayload(x.source,x.attestations,request,x.clock());
  const signed={request,requesterSignature:await owner.signTypedData(payload.domain,payload.types,payload.value)};
  const token=syntheticEAR(x.key,x.policy,x.challenge,request.channelJwk,x.clock());
  const load=async()=>({identity,jobId:x.lease.job.id,packageSHA256:x.lease.job.packageSHA256,
    policySHA256:x.lease.job.policySHA256,inputRecipient:request.descriptor.recipient,resultRecipient:'age1'+'b'.repeat(58)});
  const options={clock:x.clock,ageKeygen,loadResultKey:async()=>Buffer.alloc(32,7)};
  return {request,payload,signed,token,load,options};
}

test('requester refuses missing, substituted or downgraded launch consent before any key recovery',async t=>{
  const x=await configuredFixture(t),d=await requesterDelivery(x);let loads=0;
  for(const alter of [s=>delete s.consent,s=>s.consent.consents.pop(),s=>s.consent.consents.reverse(),
    s=>s.consent.consents[0].signature=s.consent.consents[1].signature,
    s=>s.consent.configuration.transport.timeoutMs--,
    s=>{s.schema='cannabis.market-requester.v2';delete s.consent;},
    s=>{s.schema='cannabis.market-requester.v1';delete s.configuration;delete s.consent;}]) {
    const source=structuredClone(x.source);alter(source);
    await assert.rejects(sealJobKeyDelivery(source,x.attestations,d.signed,d.token,x.network,()=>{loads++;},d.options));
  }
  assert.equal(loads,0);assert.equal(x.attestations.pending(x.challenge.nonce).nonce,x.challenge.nonce);
});

test('requester observes contract-provider consent before custody and again after result-key recovery',async t=>{
  const x=await configuredFixture(t,{contractProvider:true}),d=await requesterDelivery(x);
  const digest=inspectLaunchConsent(x.source.consent,x.initialization,x.proof,x.clock()).approvals[1].digest;
  const allow=async value=>(await contractWorker.connect(workers[0]).approveDigest(digest,value)).wait();
  let loads=0,resultLoads=0;
  const load=async()=>{loads++;return d.load();};
  await assert.rejects(sealJobKeyDelivery(x.source,x.attestations,d.signed,d.token,x.network,load,d.options),/signature is not valid/);
  assert.equal(loads,0);
  await allow(true);
  await assert.rejects(sealJobKeyDelivery(x.source,x.attestations,d.signed,d.token,x.network,load,
    {...d.options,loadResultKey:async()=>{resultLoads++;await allow(false);return Buffer.alloc(32,7);}}),/signature is not valid/);
  assert.equal(loads,1);assert.equal(resultLoads,1);
  assert.throws(()=>inspectKeyDelivery(x.attestations,d.request.releaseId),/Unknown/);
  assert.equal(x.attestations.pending(x.challenge.nonce).nonce,x.challenge.nonce);
  await allow(true);
  const record=await sealJobKeyDelivery(x.source,x.attestations,d.signed,d.token,x.network,load,d.options);
  const opened=await openJobKeyDelivery(record.envelope,x.key.privateKey,d.payload,d.options);
  assert.equal(opened.jobId,x.lease.job.id);assert.equal(resultKeyCommitment(opened.resultKey),d.request.resultKeySHA256);
  opened.resultKey.fill(0);assert.equal(loads,2);assert.equal(record.transmitted,false);
});

test('requester retains reviewed consent across recovery and historical result opening needs no later approval',async t=>{
  const x=await configuredFixture(t,{contractProvider:true}),d=await requesterDelivery(x);
  const digest=inspectLaunchConsent(x.source.consent,x.initialization,x.proof,x.clock()).approvals[1].digest;
  await (await contractWorker.connect(workers[0]).approveDigest(digest,true)).wait();
  const record=await sealJobKeyDelivery(x.source,x.attestations,d.signed,d.token,x.network,async()=>{
    x.source.consent.consents[1].signature='0x1234';x.source.configuration.network.rpc='https://unreviewed.invalid/';
    return d.load();
  },d.options);
  const opened=await openJobKeyDelivery(record.envelope,x.key.privateKey,d.payload,d.options);
  const receipt={schema:'cannabis.result.v1',jobId:x.lease.job.id,packageSHA256:x.lease.job.packageSHA256,
    attempt:1,rank:0,worldSize:1,taskId:'work',recipient:opened.resultRecipient,ciphertextSHA256:h(98).slice(2),ciphertextBytes:100};
  const envelope=await sealResultDelivery(receipt,opened.resultKey,d.payload);
  await (await contractWorker.connect(workers[0]).approveDigest(digest,false)).wait();
  await x.workerCall(0,x.escrow,'deliver',[x.orderId,h(95)]);
  await x.setTime(x.end+1);
  assert.equal(inspectKeyDelivery(x.attestations,d.request.releaseId).envelope,record.envelope);
  assert.equal((await openResultDelivery(envelope,opened.resultKey,record.expectedApproval)).receiptAuthenticated,true);
  opened.resultKey.fill(0);
});

test('booked EOA consent is observed with finalized and current active funding, without offline authorization',async t=>{
  const x=await configuredFixture(t),c=await bookedConsent(x),options={launchApprovals:c.approvals};
  const state=await readMarketLeaseState(x.proof,x.network,x.clock,options);
  for(const at of ['finalized','head']) {
    assert.deepEqual(state.launchSignatures[at].map(a=>a.digest),c.approvals.map(a=>a.digest));
    assert.deepEqual(state.launchSignatures[at].map(a=>a.method),['ecdsa','ecdsa']);
    assert.deepEqual(state.launchSignatures[at].map(a=>a.signer),[x.lease.requester,x.r.provider]);
  }
  assert.equal(state.executionAuthorized,false);assert.equal(state.keyReleaseAuthorized,false);
  assert.equal(c.chainVerified,false);
  for(const mutate of [a=>a[0].digest=h(99),a=>a[1].signature=a[0].signature,a=>a[1].signer=judge.address]) {
    const a=structuredClone(c.approvals);mutate(a);
    await assert.rejects(readMarketLeaseState(x.proof,x.network,x.clock,{launchApprovals:a}));
  }
  for(const options of [{launchApprovals:undefined},{launchApprovals:[]},{approvals:c.approvals}])
    await assert.rejects(readMarketLeaseState(x.proof,x.network,x.clock,options));
  await assert.rejects(readMarketLeaseState(x.proof,{...x.network,launchApprovals:c.approvals},x.clock),/assignment/);
});

test('contract-provider consent can follow funding, but revocation at the latest block refuses a finalized approval',async t=>{
  const x=await configuredFixture(t,{contractProvider:true}),c=await bookedConsent(x),a=c.approvals[1];
  await assert.rejects(readMarketLeaseState(x.proof,x.network,x.clock,{launchApprovals:c.approvals}),/signature is not valid/);
  await (await contractWorker.connect(workers[0]).approveDigest(a.digest,true)).wait();
  await x.setTime(x.start+10);
  const approvedBlock=await provider.send('eth_getBlockByNumber',['latest',false]);
  const state=await readMarketLeaseState(x.proof,x.network,x.clock,{launchApprovals:c.approvals});
  assert.equal(state.launchSignatures.finalized[1].method,'erc1271');
  assert.equal(state.launchSignatures.head[1].codeHash,keccak256(await provider.getCode(a.signer)));
  // The actual contract did not approve launch at the original funding block.
  const data=contractWorker.interface.encodeFunctionData('isValidSignature',[a.digest,a.signature]);
  const old=await provider.send('eth_call',[{to:a.signer,data},{blockHash:x.proof.fundedAnchor.hash,requireCanonical:true}]);
  assert.equal(contractWorker.interface.decodeFunctionResult('isValidSignature',old)[0],'0xffffffff');
  await (await contractWorker.connect(workers[0]).approveDigest(a.digest,false)).wait();
  await x.setTime(x.start+20);
  const revokedBlock=await provider.send('eth_getBlockByNumber',['latest',false]),seen=[];
  // Only the finality watermark is controlled; wallet code, approval state and
  // escrow reads execute on the real isolated chain at their requested hashes.
  const p=await proxy((m,r)=>{
    if(m.method==='eth_getBlockByNumber'&&m.params[0]==='finalized')return {...r,result:approvedBlock};
    if(m.method==='eth_call'&&m.params[0].to===a.signer) {
      assert.equal(m.params[1].requireCanonical,true);seen.push(m.params[1].blockHash);
    }
    return r;
  });
  try {
    await assert.rejects(readMarketLeaseState(x.proof,{...x.network,rpc:p.rpc},x.clock,{launchApprovals:c.approvals}),/signature is not valid/);
    assert.deepEqual(seen,[approvedBlock.hash,revokedBlock.hash]);
  } finally {await p.close();}
});

test('canonicality is rechecked after party signatures and unsupported wallet hash reads fail closed',async t=>{
  const x=await configuredFixture(t),c=await bookedConsent(x);
  for(const mode of ['replacement','unsupported']) {
    let walletRead=false;
    const p=await proxy((m,r)=>{
      if(m.method==='eth_getCode'&&c.approvals.some(a=>a.signer===m.params[0])) {
        assert.equal(m.params[1].requireCanonical,true);walletRead=true;
        if(mode==='unsupported')return {id:m.id,jsonrpc:'2.0',error:{code:-32602,message:'Wallet hash read unavailable'}};
      }
      if(mode==='replacement'&&walletRead&&m.method==='eth_getBlockByNumber'&&/^0x[0-9a-f]+$/.test(m.params[0]))
        return {...r,result:{...r.result,hash:h(999)}};
      return r;
    });
    try {
      await assert.rejects(readMarketLeaseState(x.proof,{...x.network,rpc:p.rpc},x.clock,{launchApprovals:c.approvals}),
        mode==='replacement'?/chain changed/:/RPC eth_getCode failed/);
      assert.equal(walletRead,true);
    } finally {await p.close();}
  }
});

test('consent observations retain approved bytes across asynchronous chain reads',async t=>{
  const x=await configuredFixture(t),c=await bookedConsent(x),approvals=structuredClone(c.approvals);
  const pending=readMarketLeaseState(x.proof,x.network,x.clock,{launchApprovals:approvals});
  approvals[1].digest=h(99);approvals[1].signature='0x1234';
  const state=await pending;
  assert.equal(state.launchSignatures.head[1].digest,c.approvals[1].digest);
  const retained=readLaunchConsentState(c.signed,x.initialization,x.proof,{clock:x.clock});
  c.signed.configuration.network.rpc='https://unreviewed.invalid/';
  x.proof.bookings[0].offer.manifestHash=h(99);
  const observed=await retained;
  assert.equal(observed.configurationSHA256,x.configurationSHA256);
  assert.equal(observed.funding.launchSignatures.head[1].digest,c.approvals[1].digest);
});

test('consent reader derives exact parties and network from retained review, and refuses expired or invented assignments',async t=>{
  const x=await configuredFixture(t),c=await bookedConsent(x);
  const state=await readLaunchConsentState(c.signed,x.initialization,x.proof,{clock:x.clock});
  assert.equal(state.bookingId,x.r.reservationId);assert.equal(state.provider,x.r.provider);
  assert.equal(state.configurationSHA256,x.configurationSHA256);
  assert.equal(state.funding.launchSignatures.head[1].digest,c.approvals[1].digest);
  assert.equal(state.executionAuthorized,false);assert.equal(state.keyReleaseAuthorized,false);assert.equal(state.hardwareVerified,false);
  const fake=structuredClone(x.proof);fake.bookings[0].offer.manifestHash=h(99);
  // Consistent offline records and signatures do not establish canonical state.
  inspectLaunchConsent(c.signed,x.initialization,fake,x.clock());
  await assert.rejects(readLaunchConsentState(c.signed,x.initialization,fake,{clock:x.clock}),/activated bookings differ/);
  let reads=0;
  await assert.rejects(readLaunchConsentState(c.signed,x.initialization,x.proof,{clock:()=>++reads<4?x.clock():x.end}));
  assert.ok(reads>=4);
  await x.setTime(x.end);
  await assert.rejects(readLaunchConsentState(c.signed,x.initialization,x.proof,{clock:x.clock}));
});

test('configured guest funding requires retained consent and exact independently expected network',async t=>{
  const x=await configuredFixture(t),c=await bookedConsent(x);
  const funding={proof:x.proof,context:x.context,network:x.network,provider:x.r.provider,
    resourceId:x.r.resourceId,serviceSHA256:x.r.serviceSHA256,consent:c.signed};
  const create=(options,init=x.initialization)=>new GuestFunding(options,init,{clock:x.clock});
  const missing={...funding};delete missing.consent;assert.throws(()=>create(missing),/approved guest funding/);
  for(const network of [{...x.network,rpc:'https://unreviewed.invalid/'},{...x.network,maxHeadAgeSeconds:119}])
    assert.throws(()=>create({...funding,network}),/jointly approved/);
  const unsigned={...funding,consent:{configuration:x.configuration,signatures:[]}};
  assert.throws(()=>create(unsigned),/consent/);
  const retained=create(funding);t.after(()=>retained.close());
  funding.consent.consents[1].signature='0x1234';funding.network.rpc='https://unreviewed.invalid/';
  assert.equal((await retained.refresh()).launchSignatures.head[1].signer,x.r.provider);
});

test('guest consent revocation closes retained funding and cannot be revived by later wallet approval',async t=>{
  const x=await configuredFixture(t,{contractProvider:true}),c=await bookedConsent(x),digest=c.approvals[1].digest;
  const request={proof:x.proof,challenge:x.challenge};
  await assert.rejects(prepareGuestLaunch(c.signed,x.initialization,request,{clock:x.clock}),/signature is not valid/);
  await (await contractWorker.connect(workers[0]).approveDigest(digest,true)).wait();
  const launch=await prepareGuestLaunch(c.signed,x.initialization,request,{clock:x.clock});
  const retained=new GuestFunding(launch.funding,launch.initialization,{clock:x.clock});t.after(()=>retained.close());
  assert.equal((await retained.refresh()).launchSignatures.head[1].method,'erc1271');
  await (await contractWorker.connect(workers[0]).approveDigest(digest,false)).wait();
  await assert.rejects(retained.refresh(),/signature is not valid/);
  await (await contractWorker.connect(workers[0]).approveDigest(digest,true)).wait();
  await assert.rejects(retained.refresh(),/closed/);
});

test('launch authorization cannot restart its transport clock or outlive the retained challenge',async t=>{
  const x=await configuredFixture(t),c=await bookedConsent(x),request={proof:x.proof,challenge:x.challenge};
  for(const next of [x.clock()-1,x.challenge.expiresAt]) {
    let reads=0;
    await assert.rejects(prepareGuestLaunch(c.signed,x.initialization,request,{clock:()=>++reads===1?x.clock():next}),/not authorized/);
    assert.ok(reads>=2);
  }
  const short=await configuredFixture(t,{transportTimeoutMs:1}),sc=await bookedConsent(short);
  await assert.rejects(prepareGuestLaunch(sc.signed,short.initialization,{proof:short.proof,challenge:short.challenge},{clock:short.clock}),/not authorized/);
});
