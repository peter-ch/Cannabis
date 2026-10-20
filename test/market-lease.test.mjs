import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { connect as connectTLS } from 'node:tls';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { spawnSync,execFileSync } from 'node:child_process';
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
import { peerChannelPayload, readPeerChannelState, authenticatePeerChannel, claimPeerChannel } from '../compute/peer_channel.mjs';
import { relayAuthenticatedSession } from '../operator/session-relay.mjs';
import { peerTLSPair } from './helpers/peer_tls.mjs';
import { connectBookedPeer, listenBookedPeers, peerRouteId } from '../compute/peer_network.mjs';
import { PeerDispatchJournal } from '../compute/peer_dispatch.mjs';
import tlsFixture from './helpers/peer-tls-fixture.json' with {type:'json'};
import {ProviderApprovals} from '../operator/provider-approvals.mjs';
import {validateProviderReview} from '../operator/provider-wallet.js';
import {sendLaunchHandoff,receiveLaunchHandoff,consumeLaunchHandoff,inspectLaunchHandoff} from '../compute/launch_handoff.mjs';
import {stageOperatingGuest,relayOperatingGuest} from '../operator/guest-boot-channel.mjs';
import {operatingBootFixture} from './helpers/operating_boot_fixture.mjs';
import {inspectExecutionPlan,taskCommitment} from '../compute/execution_plan.mjs';
import {dependencyHandoffPayload} from '../compute/dependency_handoff.mjs';
import {RequesterWorkflow,readWorkflow} from '../requester/workflow.mjs';
import {receiveEncryptedInput} from '../compute/input_transport.mjs';
import {sendEncryptedResult} from '../compute/result_transport.mjs';
import {createWorkServer} from '../service/work-server.mjs';
import {ResultSpool} from '../operator/result-spool.mjs';
import {bridgeEncryptedResult} from '../operator/result-bridge.mjs';
import {GuestWire} from '../compute/result_transport.mjs';
import {PassThrough} from 'node:stream';

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

async function setup({ token = false, activate = true, execution, contractProvider = false, planned = false, sequential = false, descriptor } = {}) {
  await provider.send('evm_revert', [initial]); initial = await provider.send('evm_snapshot', []);
  let time = (await provider.getBlock('latest')).timestamp;
  await provider.send('evm_setNextBlockTimestamp', [time + 1]); await provider.send('evm_mine', []); ++time;
  planned ||= sequential;
  const clock = () => time, start = time + 1000, end = start + (sequential ? 200 : 100), escrow = token ? tokenEscrow : native;
  const window = i => ({start:start+(sequential?i*100:0),end:start+(sequential?i*100:0)+100});
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
  if(descriptor){job.packageSHA256=descriptor.ciphertextSHA256;job.policySHA256=descriptor.policySHA256;}
  const settlement = { workers: addresses.map(account => ({ account, shareBps: 5000 })), deliveryManager: addresses[0],
    adjudicator: await judge.getAddress(), acceptBy: utc(time + 800), deliverBy: utc(end + 60), reviewSeconds: 86400, disputeSeconds: 86400 };
  let executionPlan;
  if(planned) {
    executionPlan=inspectExecutionPlan({schema:'cannabis.execution-plan.v1',chainId:31337,genesisHash:network.genesisHash,
      market:network.market,escrow:network.escrow,token:network.token,requester:account,jobId:job.id,packageSHA256:job.packageSHA256,policySHA256:job.policySHA256,
      requirements:descriptor?.requirements??addresses.map((_,task)=>({task,taskSHA256:taskCommitment(job.packageSHA256,task),dependsOn:sequential&&task===1?[0]:[],
        runtime:execution?.profile.runtime??{adapter:'native-linux-x86_64-v1',architecture:'x86_64',os:'linux',digestSHA256:h(73).slice(2)},
        resources:execution?.profile.resources??{cpus:1,memoryMiB:128,scratchMiB:8,wallSeconds:60,nodes:1}})),
      assignments:addresses.map((provider,i)=>({task:i,rank:0,attempt:1,acceleratorClass:'cpu',provider,serviceSHA256:execution?nativeServiceCommitment(execution).serviceSHA256:h(20+i),
        booking:{reservationId:h(50+i),offerId:keccak256(coder.encode(['address','bytes32'],[provider,h(40+i)])),
          start:String(window(i).start),end:String(window(i).end),units:'1',gross:'10000',holdUntil:String(time+600)}}))}).plan;
    job.schema='cannabis.compute.order.v3';job.executionPlanSHA256=inspectExecutionPlan(executionPlan).digestSHA256;
  }
  const terms = settlementTerms(job, settlement), orderId = await escrow.orderId(account, terms.terms.jobHash);
  const digest = termsDigest({ chainId: 31337, escrow: network.escrow, token: network.token, founderRecipient: policy.founderRecipient, ...terms });
  const bookings = [], signatures = [], ids = [];
  for (let i = 0; i < 2; ++i) {
    await workerCall(i,market,'publishResource',[h(10 + i),execution?nativeServiceCommitment(execution).serviceSHA256:h(20 + i),1]);
    const resource = await market.resourceKey(addresses[i], h(10 + i));
    const offer = { resource, escrow: network.escrow, policyHash: '0x' + job.policySHA256, manifestHash: h(30 + i), ...window(i),
      expiresAt: time + 900, units: 1, grossPerUnitSecond: 100 };
    await workerCall(i,market,'publishOffer',[h(40 + i),offer]);
    const offerId = keccak256(coder.encode(['address', 'bytes32'], [addresses[i], h(40 + i)]));
    const booking = { reservationId: h(50 + i), offerId, requester: account, orderId, termsDigest: digest, ...window(i), units: 1, gross: '10000', holdUntil: time + 600 };
    const p = bookingPayload(context, booking); bookings.push(booking); ids.push(p.digest);
    if(contractProvider&&i===0)await (await contractWorker.connect(workers[0]).approveDigest(p.digest,true)).wait();
    signatures.push(await workers[i].signTypedData(p.domain, p.types, p.value));
  }
  await (await market.reserveBatch(bookings, signatures)).wait();
  await (await escrow.fund(terms.terms, terms.accounts, terms.shares, { value: token ? 0 : 20000 })).wait();
  for (let i=0;i<workers.length;++i) await workerCall(i,escrow,'accept',[orderId]);
  if (activate) await (await market.activate(ids.sort())).wait();
  time = (await provider.getBlock('latest')).timestamp;
  const input = { job, settlement, bookingIds: ids,...(planned?{executionPlan}:{}) };
  const proof = activate ? await createMarketLeaseProof(network, input, clock) : null;
  const plannedAssignments=planned?verifyMarketLeaseProof(proof,context).assignments:undefined;
  const run = planned?(sequential?plannedAssignments.find(a=>a.task===1):plannedAssignments[0]).run:
    { runtimeSHA256: execution?.profile.runtime.digestSHA256??h(73).slice(2), taskSHA256: h(74).slice(2), attempt: 1, rank: 0, worldSize: 1, acceleratorClass: 'cpu' };
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

test('planned task and rank assignments survive actual isolated funding and reject substitutions', async () => {
  for(const token of [false,true]) {
    const d=await setup({token,planned:true});await d.setTime(d.start+1);
    const lease=verifyMarketLeaseProof(d.proof,{...d.context,genesisHash:d.network.genesisHash});
    assert.equal(lease.schema,'cannabis.market-lease.v2');assert.equal(lease.assignments.length,2);
    const state=await readMarketLeaseState(d.proof,d.network,d.clock);
    assert.equal(state.leaseDigest,lease.digest);assert.equal(state.executionAuthorized,false);
    const binding=marketAttestationBinding(d.proof,d.context,lease.assignments[0].reservationId,d.run,d.clock());
    assert.equal(binding.taskSHA256,d.run.taskSHA256);
    for(const change of [{attempt:2},{taskSHA256:lease.assignments[1].run.taskSHA256},{runtimeSHA256:'99'.repeat(32)}])
      assert.throws(()=>marketAttestationBinding(d.proof,d.context,lease.assignments[0].reservationId,{...d.run,...change},d.clock()),/complete booked execution plan/);
    const changed=structuredClone(d.proof);changed.executionPlan.assignments[0].attempt=2;
    assert.throws(()=>verifyMarketLeaseProof(changed,d.context));
    const downgraded=structuredClone(d.proof);downgraded.schema='cannabis.market-lease.v1';delete downgraded.executionPlan;
    assert.throws(()=>verifyMarketLeaseProof(downgraded,d.context));
    await assert.rejects(createMarketLeaseProof(d.network,{...d.input,bookingIds:[d.ids[0]]},d.clock));
    await assert.rejects(readMarketLeaseState(d.proof,{...d.network,genesisHash:h(998)},d.clock));
  }
});

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

async function configuredFixture(t,{contractProvider=false,transportTimeoutMs=60000,sequential=false}={}) {
  const f=launchFixture();
  if(sequential) {
    const p=f.configuration.execution.profile;p.schema='cannabis.guest-native-service.v3';p.maxDependencyBytes=1024;
    p.ciphertext.dependencyBytes=4*1024**2;p.ciphertext.bytes+=p.ciphertext.dependencyBytes;
  }
  const d=await setup({execution:f.configuration.execution,contractProvider,sequential});await d.setTime(d.start+(sequential?101:1));
  const lease=verifyMarketLeaseProof(d.proof,d.context),r=lease.reservations.find(r=>sequential?
    r.reservationId===lease.assignments.find(a=>a.task===1).reservationId:!contractProvider||r.provider===d.addresses[0]),key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
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

function providerCatalog(x,origin='https://independent.example') {
  return {schema:'cannabis.provider-catalog.v1',assignments:[{configuration:x.configuration,initialization:x.initialization,
    proof:x.proof,requesterConsent:x.source.consent.consents[0],origin}]};
}
function providerManager(t,x,{retained=false,origin}={}) {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-provider-approval-'));
  const key=launchConsentPayload(x.configuration,x.initialization,x.proof,'provider').value.assignmentSHA256.slice(2);
  if(retained){fs.mkdirSync(path.join(directory,key));fs.writeFileSync(path.join(directory,key,'approval.json'),JSON.stringify(x.source.consent));}
  const catalog=providerCatalog(x,origin),manager=new ProviderApprovals(catalog,directory,{clock:x.clock});
  t.after(async()=>{await manager.close();fs.rmSync(directory,{recursive:true,force:true});});return {manager,directory,key,catalog};
}
async function awaitApproval(manager,predicate) {
  const deadline=Date.now()+10000;
  while(Date.now()<deadline){const found=manager.snapshot().requests.find(predicate);if(found)return found;await new Promise(r=>setTimeout(r,20));}
  assert.fail('Provider approval did not reach the expected bounded state');
}

test('provider console retains only verified launch consent and preserves it across restart',async t=>{
  const x=await configuredFixture(t),{manager,key,directory,catalog}=providerManager(t,x);
  const {requestId}=manager.beginLaunch(key);assert.throws(()=>manager.detail(requestId));
  await awaitApproval(manager,r=>r.id===requestId&&r.state==='awaiting-wallet');
  const detail=validateProviderReview(manager.detail(requestId));assert.equal(detail.kind,'launch');
  assert.equal(detail.summary.workerBaseUnits, String(BigInt(detail.summary.grossBaseUnits)*99n/100n));
  const p=launchConsentPayload(x.configuration,x.initialization,x.proof,'provider');
  manager.submit(requestId,await peerOptions(x,{},'provider').signApproval(p));
  assert.throws(()=>manager.submit(requestId,'0x01'));
  await awaitApproval(manager,r=>r.id===requestId&&r.state==='consent-retained');
  assert.equal(manager.snapshot().executionAuthorized,false);assert.equal(manager.snapshot().keyReleaseAuthorized,false);
  assert.ok(!JSON.stringify(manager.snapshot()).includes('signature'));
  assert.throws(()=>manager.beginLaunch(key));const signed=manager.signed(key);
  await manager.close();const reopened=new ProviderApprovals(catalog,directory,{clock:x.clock});
  try{assert.deepEqual(reopened.signed(key),signed);assert.deepEqual(reopened.snapshot().requests,[]);
    await (await x.escrow.connect(workers[0]).deliver(x.orderId,h(95))).wait();
    await assert.rejects(readLaunchConsentState(reopened.signed(key),x.initialization,x.proof,{clock:x.clock}));
  }finally{await reopened.close();}
  const file=path.join(directory,key,'approval.json');fs.writeFileSync(file,'{"interrupted":');
  assert.throws(()=>new ProviderApprovals(catalog,directory,{clock:x.clock}));assert.equal(fs.readFileSync(file,'utf8'),'{"interrupted":');
});

test('provider console checks ERC-1271 at current state and refuses invalid, declined or inactive consent',async t=>{
  const x=await configuredFixture(t,{contractProvider:true}),{manager,key,directory}=providerManager(t,x);
  const p=launchConsentPayload(x.configuration,x.initialization,x.proof,'provider');
  const begin=async()=>{const {requestId}=manager.beginLaunch(key);await awaitApproval(manager,r=>r.id===requestId&&r.state==='awaiting-wallet');return requestId;};
  const first=await begin();manager.submit(first,await workers[0].signTypedData(p.domain,p.types,p.value));
  await awaitApproval(manager,r=>r.id===first&&r.state==='failed');assert.equal(fs.existsSync(path.join(directory,key)),false);
  const declined=await begin();manager.decline(declined);assert.throws(()=>manager.submit(declined,'0x01'));
  await (await contractWorker.connect(workers[0]).approveDigest(p.digest,true)).wait();
  const allowed=await begin();manager.submit(allowed,await workers[0].signTypedData(p.domain,p.types,p.value));
  await awaitApproval(manager,r=>r.id===allowed&&r.state==='consent-retained');
  await (await contractWorker.connect(workers[0]).approveDigest(p.digest,false)).wait();
  await assert.rejects(readLaunchConsentState(manager.signed(key),x.initialization,x.proof,{clock:x.clock}));
  const other=providerManager(t,x);await (await contractWorker.connect(workers[0]).invoke(await x.escrow.getAddress(),x.escrow.interface.encodeFunctionData('deliver',[x.orderId,h(95)]))).wait();
  const inactive=other.manager.beginLaunch(other.key).requestId;
  await awaitApproval(other.manager,r=>r.id===inactive&&r.state==='failed');assert.throws(()=>other.manager.detail(inactive));
});

test('provider console approves the actual TLS channel without consuming its relay capability',async t=>{
  const x=await configuredFixture(t),pair=await peerTLSPair(t),{manager,key}=providerManager(t,x,{retained:true,origin:pair.origin});
  let handled=0;
  const route=manager.peerRoute(key,channel=>{claimPeerChannel(channel,'provider',route.signed,route.initialization,route.proof);handled++;});
  const pending=Promise.all(['requester','provider'].map(role=>authenticatePeerChannel(pair[role],peerOptions(x,pair,role,
    role==='provider'?{signApproval:route.signApproval}:{}))));
  const request=await awaitApproval(manager,r=>r.kind==='peer'&&r.state==='awaiting-wallet');
  const detail=validateProviderReview(manager.detail(request.id));assert.equal(detail.typedData.message.origin,pair.origin);
  assert.ok(request.expiresAt-request.createdAt<=60000);
  const types={...detail.typedData.types};delete types.EIP712Domain;
  const signature=await workers[x.addresses.indexOf(x.r.provider)].signTypedData(detail.typedData.domain,types,detail.typedData.message);
  manager.submit(request.id,signature);assert.equal(manager.snapshot().requests[0].state,'submitted');
  const channels=await pending;t.after(()=>channels.forEach(c=>c.close()));
  await assert.rejects(route.handle({report:channels[1].report},{}));assert.equal(handled,0);
  await route.handle(channels[1],{});assert.equal(handled,1);assert.equal(manager.snapshot().requests[0].state,'channel-verified');
  assert.throws(()=>claimPeerChannel(channels[1],'provider',route.signed,route.initialization,route.proof));
  await assert.rejects(route.handle(channels[1],{}));
});

test('provider console preserves peer cancellation and deadlines and rejects changed retained payloads',async t=>{
  const x=await configuredFixture(t),{manager,key}=providerManager(t,x,{retained:true}),route=manager.peerRoute(key,()=>{});
  const p=peerChannelPayload(route.signed,route.initialization,route.proof,peerBinding(x),'provider',x.clock());
  for(const changed of [{...p,signer:x.lease.requester},{...p,value:{...p.value,origin:'https://other.invalid'}},{...p,digest:h(991)}])
    assert.throws(()=>route.signApproval(changed,{signal:new AbortController().signal,timeoutMs:1000}));
  const controller=new AbortController(),cancelled=route.signApproval(p,{signal:controller.signal,timeoutMs:1000});
  const rejection=assert.rejects(cancelled);const request=manager.snapshot().requests.at(-1);controller.abort();await rejection;
  assert.throws(()=>manager.submit(request.id,'0x01'));assert.equal(manager.snapshot().requests.at(-1).state,'cancelled');
  const expired=route.signApproval(p,{signal:new AbortController().signal,timeoutMs:50});await assert.rejects(expired);
  assert.equal(manager.snapshot().requests.at(-1).state,'expired');
  const closed=route.signApproval(p,{signal:new AbortController().signal,timeoutMs:1000}),closedCheck=assert.rejects(closed);
  await manager.close();await closedCheck;
});

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

function peerOptions(x,pair,role,changes={}) {
  const signer=role==='requester'?owner:workers[x.addresses.indexOf(x.r.provider)];
  return {role,origin:pair.origin,signed:x.source.consent,initialization:x.initialization,proof:x.proof,
    clock:x.clock,signApproval:p=>signer.signTypedData(p.domain,p.types,p.value),...changes};
}
async function peerSignatures(x,binding) {
  return Promise.all(['requester','provider'].map(async role=>{
    const p=peerChannelPayload(x.source.consent,x.initialization,x.proof,binding,role,x.clock());
    const signer=role==='requester'?owner:workers[x.addresses.indexOf(x.r.provider)];
    return {role,signature:await signer.signTypedData(p.domain,p.types,p.value)};
  }));
}
const peerBinding=x=>({origin:'https://independent.example',channelBinding:h(181),requesterNonce:h(182),providerNonce:h(183),
  validFrom:x.clock(),validUntil:x.clock()+50});

test('peer channel authenticates real TLS endpoints against bilateral booking observations before opaque traffic',async t=>{
  const x=await configuredFixture(t),pair=await peerTLSPair(t);
  const channels=await Promise.all(['requester','provider'].map(role=>authenticatePeerChannel(pair[role],peerOptions(x,pair,role))));
  t.after(()=>channels.forEach(c=>c.close()));
  const [requesterChannel,providerChannel]=channels;
  assert.deepEqual(requesterChannel.report.binding,providerChannel.report.binding);
  for(const c of channels) {
    assert.equal(c.report.channelAuthenticated,true);assert.equal(c.report.chainVerified,true);
    for(const flag of ['executionAuthorized','keyReleaseAuthorized','hardwareVerified'])assert.equal(c.report[flag],false);
    for(const at of ['finalized','head']) {
      assert.equal(c.report.funding.launchSignatures[at].length,2);
      assert.deepEqual(c.report.funding.channelSignatures[at].map(s=>s.digest),c.report.approvals.map(s=>s.digest));
    }
  }
  await requesterChannel.writeJSON({operation:'owned-ciphertext-fixture'});
  assert.deepEqual(await providerChannel.readJSON(1024),{operation:'owned-ciphertext-fixture'});
  await providerChannel.writeChunk(Buffer.from('opaque encrypted bytes fixture'));
  assert.equal((await requesterChannel.readChunk()).toString(),'opaque encrypted bytes fixture');
  requesterChannel.close();assert.equal(requesterChannel.signal.aborted,true);assert.equal(pair.requester.destroyed,true);
  await assert.rejects(authenticatePeerChannel(pair.requester,peerOptions(x,pair,'requester')));
});

test('peer channel refuses signatures replayed onto a different TLS connection',async t=>{
  const x=await configuredFixture(t),first=await peerTLSPair(t),saved={};
  const channels=await Promise.all(['requester','provider'].map(role=>authenticatePeerChannel(first[role],peerOptions(x,first,role,{
    signApproval:async p=>{const s=peerOptions(x,first,role).signApproval(p);saved[role]=await s;return saved[role];}
  }))));channels.forEach(c=>c.close());
  const next=await peerTLSPair(t),result=await Promise.allSettled(['requester','provider'].map(role=>
    authenticatePeerChannel(next[role],peerOptions(x,next,role,{signApproval:()=>saved[role]}))));
  assert.ok(result.every(r=>r.status==='rejected'));assert.ok(next.requester.destroyed&&next.provider.destroyed);
});

test('peer channel refuses wrong role signatures, selected origins, untrusted certificates and TLS downgrade',async t=>{
  const x=await configuredFixture(t);
  for(const mode of ['wallet','origin','tls12','alpn','untrusted','hostname']) {
    const pair=await peerTLSPair(t,{...(mode==='tls12'?{version:'TLSv1.2'}:{}),...(mode==='alpn'?{alpn:'other/1'}:{}),
      ...(mode==='untrusted'?{trusted:false}:{})});let signed=0;
    const result=await Promise.allSettled(['requester','provider'].map(role=>{
      const normal=peerOptions(x,pair,role);
      return authenticatePeerChannel(pair[role],{...normal,
        ...(mode==='origin'&&role==='provider'?{origin:'https://other.example'}:{}),
        ...(mode==='hostname'?{origin:'https://different.example'}:{}),
        signApproval:p=>{signed++;return mode==='wallet'&&role==='provider'?owner.signTypedData(p.domain,p.types,p.value):normal.signApproval(p);}});
    }));
    assert.ok(result.every(r=>r.status==='rejected'));assert.ok(pair.requester.destroyed&&pair.provider.destroyed);
    if(['tls12','alpn','untrusted','hostname'].includes(mode))assert.equal(signed,0);
  }
});

test('peer channel observes ERC-1271 channel and launch approval independently and refuses either revocation',async t=>{
  const x=await configuredFixture(t,{contractProvider:true}),launch=inspectLaunchConsent(x.source.consent,x.initialization,x.proof,x.clock());
  const allow=async(digest,value)=>(await contractWorker.connect(workers[0]).approveDigest(digest,value)).wait();
  await allow(launch.approvals[1].digest,true);
  const pair=await peerTLSPair(t);
  const channels=await Promise.all(['requester','provider'].map(role=>{
    const normal=peerOptions(x,pair,role);
    return authenticatePeerChannel(pair[role],{...normal,signApproval:async p=>{
      if(role==='provider')await allow(p.digest,true);return normal.signApproval(p);
    }});
  }));t.after(()=>channels.forEach(c=>c.close()));
  for(const c of channels)for(const at of ['finalized','head'])assert.equal(c.report.funding.channelSignatures[at][1].method,'erc1271');
  const report=channels[0].report,signatures=report.approvals.map(({role,signature})=>({role,signature}));
  for(const digest of [report.approvals[1].digest,launch.approvals[1].digest]) {
    await allow(digest,false);
    await assert.rejects(readPeerChannelState(x.source.consent,x.initialization,x.proof,report.binding,signatures,{clock:x.clock}));
    await allow(digest,true);
  }
  assert.equal((await readPeerChannelState(x.source.consent,x.initialization,x.proof,report.binding,signatures,{clock:x.clock})).channelAuthenticated,false);
  const approvedBlock=await provider.send('eth_getBlockByNumber',['latest',false]);
  await allow(report.approvals[1].digest,false);
  const p=await proxy((m,r)=>m.method==='eth_getBlockByNumber'&&m.params[0]==='finalized'?{...r,result:approvedBlock}:r);
  try {
    await assert.rejects(readMarketLeaseState(x.proof,{...x.network,rpc:p.rpc},x.clock,
      {launchApprovals:launch.approvals,channelApprovals:report.approvals}),/signature is not valid/);
  } finally {await p.close();}
});

test('peer channel payloads bind origin, exporter, both nonces, role and retained configuration',async t=>{
  const x=await configuredFixture(t),binding=peerBinding(x),signatures=await peerSignatures(x,binding);
  const read=b=>readPeerChannelState(x.source.consent,x.initialization,x.proof,b,signatures,{clock:x.clock});
  const state=await read(binding);assert.equal(state.chainVerified,true);assert.equal(state.channelAuthenticated,false);
  for(const alter of [b=>b.channelBinding=h(191),b=>b.requesterNonce=h(191),b=>b.providerNonce=h(191),
    b=>b.origin='https://different.example',b=>b.validUntil--,b=>b.validFrom--,b=>b.secret='no',
    b=>b.origin='http://independent.example',b=>b.origin='https://independent.example/path',b=>b.providerNonce=b.requesterNonce]) {
    const b=structuredClone(binding);alter(b);await assert.rejects(read(b));
  }
  const signaturesReversed=[...signatures].reverse();
  await assert.rejects(readPeerChannelState(x.source.consent,x.initialization,x.proof,binding,signaturesReversed,{clock:x.clock}));
  const pending=read(binding);binding.channelBinding=h(192);signatures[1].signature='0x1234';
  assert.equal((await pending).binding.channelBinding,h(181));
  await assert.rejects(readMarketLeaseState(x.proof,x.network,x.clock,{channelApprovals:state.approvals}),/requires launch consent/);
});

test('peer channel cancels stalled user signing and closes both sockets without forwarding application data',async t=>{
  const x=await configuredFixture(t),pair=await peerTLSPair(t);let attempts=0;
  const result=await Promise.allSettled(['requester','provider'].map(role=>authenticatePeerChannel(pair[role],peerOptions(x,pair,role,{
    timeoutMs:150,signApproval:()=>{attempts++;return new Promise(()=>{});}
  }))));assert.equal(attempts,1);assert.ok(result.every(r=>r.status==='rejected'));
  assert.ok(pair.requester.destroyed&&pair.provider.destroyed);
});

test('peer channel refuses clock rollback after authenticated handoff',async t=>{
  const x=await configuredFixture(t),pair=await peerTLSPair(t);let now=x.clock();
  const channels=await Promise.all(['requester','provider'].map(role=>authenticatePeerChannel(pair[role],peerOptions(x,pair,role,{clock:()=>now}))));
  t.after(()=>channels.forEach(c=>c.close()));now--;
  await assert.rejects(channels[0].writeJSON({never:'forwarded'}));
  assert.ok(pair.requester.destroyed);assert.equal(channels[0].signal.aborted,true);
});

test('peer channel relay consumes only its live matching local capability, never a serialized report',async t=>{
  const x=await configuredFixture(t),pair=await peerTLSPair(t);
  const channels=await Promise.all(['requester','provider'].map(role=>authenticatePeerChannel(pair[role],peerOptions(x,pair,role))));
  t.after(()=>channels.forEach(c=>c.close()));const real=channels[1];
  const claim=(c,role='provider',init=x.initialization)=>claimPeerChannel(c,role,x.source.consent,init,x.proof);
  assert.throws(()=>claim({...real}));assert.throws(()=>claim(real,'requester'));
  const changed=structuredClone(x.initialization);changed.binding.attempt++;
  assert.throws(()=>claim(real,'provider',changed));
  real.report.binding.origin='https://forged-report.example';
  assert.equal(claim(real).origin,pair.origin);assert.throws(()=>claim(real));
  let guestReads=0,stopped=0;
  const guest={readJSON:()=>{guestReads++;},fail:()=>{stopped++;}};
  await assert.rejects(relayAuthenticatedSession(guest,{report:real.report,fail:()=>{stopped++;}},
    {launch:{initialization:x.initialization,funding:{consent:x.source.consent,proof:x.proof}}}));
  assert.equal(guestReads,0);assert.equal(stopped,2);
});

test('peer channel cancellation aborts stalled chain HTTP requests within the same handshake budget',async t=>{
  const x=await configuredFixture(t);let requests=0,active=0;
  const server=http.createServer((req,res)=>{requests++;active++;req.resume();res.on('close',()=>active--);});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  x.configuration.network.rpc=`http://127.0.0.1:${server.address().port}`;
  x.initialization.binding=configuredMarketAttestationBinding(x.proof,x.context,x.r.reservationId,x.run,
    validateGuestConfiguration(x.configuration).configurationSHA256,x.clock());
  x.source.consent=(await bookedConsent(x)).signed;
  const pair=await peerTLSPair(t),started=performance.now();
  const result=await Promise.allSettled(['requester','provider'].map(role=>
    authenticatePeerChannel(pair[role],peerOptions(x,pair,role,{timeoutMs:1000}))));
  assert.ok(result.every(r=>r.status==='rejected'));assert.ok(performance.now()-started<2500);
  for(let i=0;i<30&&active;i++)await new Promise(resolve=>setTimeout(resolve,10));
  assert.ok(requests>0);assert.equal(active,0);assert.ok(pair.requester.destroyed&&pair.provider.destroyed);
});

test('peer channel refuses an order that leaves active funding while the wallets approve the connection',async t=>{
  const x=await configuredFixture(t),pair=await peerTLSPair(t);
  const result=await Promise.allSettled(['requester','provider'].map(role=>{
    const normal=peerOptions(x,pair,role);
    return authenticatePeerChannel(pair[role],{...normal,signApproval:async p=>{
      if(role==='provider')await (await x.escrow.connect(workers[0]).deliver(x.orderId,h(199))).wait();
      return normal.signApproval(p);
    }});
  }));assert.ok(result.every(r=>r.status==='rejected'));assert.ok(pair.requester.destroyed&&pair.provider.destroyed);
});

const later=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const localPeerRoute=(x,handle,signApproval=peerOptions(x,{},'provider').signApproval)=>({signed:x.source.consent,
  initialization:x.initialization,proof:x.proof,signApproval,handle});
async function localListener(x,routes,extra={}) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-dispatch-'));
  const journal=new PeerDispatchJournal(path.join(dir,'dispatch.sqlite'),{create:true,now:()=>x.clock()*1000});
  try {
    const listener=await listenBookedPeers({origin:'https://localhost:0',listenHost:'127.0.0.1',
      tlsCredentials:{key:tlsFixture.key,cert:tlsFixture.cert},routes,clock:x.clock,dispatchJournal:journal,...extra});
    after(()=>{journal.close();fs.rmSync(dir,{recursive:true,force:true});});
    return listener;
  }catch(error){journal.close();fs.rmSync(dir,{recursive:true,force:true});throw error;}
}
const localConnect=(x,listener,extra={})=>connectBookedPeer({...peerOptions(x,listener,'requester'),ca:tlsFixture.cert,...extra});
async function closedSocket(socket) {
  if(socket.destroyed)return;
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('Owned socket did not close')),3000);
    socket.once('close',()=>{clearTimeout(timer);resolve();});
  });
}
async function directTLS(listener) {
  const socket=connectTLS({host:'127.0.0.1',port:listener.address.port,servername:'localhost',ca:tlsFixture.cert,
    rejectUnauthorized:true,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:['cannabis-peer/1']});
  socket.on('error',()=>{});
  await new Promise((resolve,reject)=>{socket.once('secureConnect',resolve);socket.once('error',reject);});return socket;
}

test('peer listener and requester connect directly to a retained assignment and consume its local route once',async t=>{
  const x=await configuredFixture(t),done=later();let signatures=0,handled=0;
  const route=localPeerRoute(x,async(channel,local)=>{
    handled++;assert.equal(local.routeId,peerRouteId(x.source.consent,x.initialization,x.proof));
    claimPeerChannel(channel,'provider',local.signed,local.initialization,local.proof);
    assert.deepEqual(await channel.readJSON(1024),{operation:'owned-opaque-handoff'});
    await channel.writeJSON({operation:'ready'});const bytes=await channel.readChunk();
    await channel.writeChunk(bytes);done.resolve();
  },async p=>{signatures++;return peerOptions(x,{},'provider').signApproval(p);});
  const listener=await localListener(x,[route]);t.after(()=>listener.close());
  // Registration retains public bytes instead of rereading caller-owned objects.
  route.signed=structuredClone(route.signed);route.signed.configuration.network.rpc='https://unreviewed.invalid';
  const channel=await localConnect(x,listener);t.after(()=>channel.close());
  assert.equal(channel.report.channelAuthenticated,true);assert.equal(channel.report.binding.origin,listener.origin);
  await channel.writeJSON({operation:'owned-opaque-handoff'});assert.deepEqual(await channel.readJSON(1024),{operation:'ready'});
  await channel.writeChunk(Buffer.from('already encrypted fixture'));
  assert.equal((await channel.readChunk()).toString(),'already encrypted fixture');await done.promise;
  await assert.rejects(localConnect(x,listener));assert.equal(handled,1);assert.equal(signatures,1);
  assert.equal(listener.snapshot().admittedChannels,1);assert.equal(listener.snapshot().hardwareValidated,false);
  const closed=await listener.close();assert.equal(closed.liveSockets,0);assert.equal(closed.pendingTasks,0);
});

test('peer listener refuses unknown routes, malformed prefaces and slow TLS/header clients before wallet callbacks',async t=>{
  const x=await configuredFixture(t);let signed=0,handled=0;
  const listener=await localListener(x,[localPeerRoute(x,()=>{handled++;},()=>{signed++;})],{timeoutMs:250});t.after(()=>listener.close());
  for(const mode of ['unknown','malformed','partial','tcp']) {
    const socket=mode==='tcp'?net.connect(listener.address.port,'127.0.0.1'):await directTLS(listener);
    socket.on('error',()=>{});t.after(()=>socket.destroy());
    if(mode==='unknown')socket.write(Buffer.concat([Buffer.from('CANPEER1'),Buffer.alloc(32,9)]));
    if(mode==='malformed')socket.write(Buffer.alloc(40,7));
    if(mode==='partial')socket.write(Buffer.from('CAN'));
    await closedSocket(socket);
  }
  assert.equal(signed,0);assert.equal(handled,0);assert.equal(listener.snapshot().pendingHandshakes,0);
  assert.equal(listener.snapshot().routes[0].attempts,0);
});

test('peer listener caps pending connections and shuts down uncompleted TLS handshakes',async t=>{
  const x=await configuredFixture(t),listener=await localListener(x,[localPeerRoute(x,()=>{})],
    {maxConnections:2,maxHandshakes:1,timeoutMs:1000});t.after(()=>listener.close());
  const first=net.connect(listener.address.port,'127.0.0.1');first.on('error',()=>{});t.after(()=>first.destroy());
  await new Promise(resolve=>first.once('connect',resolve));
  const second=net.connect(listener.address.port,'127.0.0.1');second.on('error',()=>{});t.after(()=>second.destroy());
  await closedSocket(second);assert.equal(listener.snapshot().pendingHandshakes,1);
  assert.equal(listener.snapshot().rejectedConnections,1);
  const result=await listener.close();await closedSocket(first);
  assert.deepEqual(result,{closed:true,liveSockets:0,pendingHandlers:0,pendingTasks:0});
});

test('peer listener never prompts provider signing for a false requester and bounds per-route retries',async t=>{
  const x=await configuredFixture(t);let prompts=0,handled=0;
  const listener=await localListener(x,[localPeerRoute(x,()=>{handled++;},()=>{prompts++;})],{maxAttemptsPerRoute:2});
  t.after(()=>listener.close());
  for(let i=0;i<2;i++)await assert.rejects(localConnect(x,listener,{signApproval:p=>judge.signTypedData(p.domain,p.types,p.value)}));
  await assert.rejects(localConnect(x,listener));assert.equal(prompts,0);assert.equal(handled,0);
  assert.equal(listener.snapshot().routes[0].attempts,2);assert.equal(listener.snapshot().routes[0].state,'exhausted');
});

test('peer listener blocks simultaneous assignment handoff and reports an uncooperative handler at shutdown',async t=>{
  const x=await configuredFixture(t),entered=later(),release=later();let calls=0;
  const listener=await localListener(x,[localPeerRoute(x,async()=>{calls++;entered.resolve();await release.promise;})]);
  t.after(async()=>{release.resolve();await listener.close();});
  const channel=await localConnect(x,listener);t.after(()=>channel.close());await entered.promise;
  await assert.rejects(localConnect(x,listener));assert.equal(calls,1);
  const report=await listener.close(50);assert.equal(report.closed,true);assert.equal(report.liveSockets,0);
  assert.equal(report.pendingHandlers,1);assert.equal(report.pendingTasks,1);
  release.resolve();for(let i=0;i<20&&listener.snapshot().connections;i++)await new Promise(resolve=>setTimeout(resolve,10));
  assert.equal(listener.snapshot().connections,0);assert.equal(listener.snapshot().routes[0].state,'failed');
});

test('peer requester cancellation and total connect budget close stalled TLS before signing',async t=>{
  const x=await configuredFixture(t),sockets=new Set();let signed=0;
  const server=net.createServer(socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{for(const s of sockets)s.destroy();await new Promise(resolve=>server.close(resolve));});
  const origin=`https://localhost:${server.address().port}`;
  for(const cancel of [false,true]) {
    const controller=new AbortController(),started=performance.now();
    const pending=localConnect(x,{origin},{timeoutMs:300,signal:controller.signal,signApproval:()=>{signed++;}});
    const timer=cancel?setTimeout(()=>controller.abort(),75):null;
    try{await assert.rejects(pending);}finally{clearTimeout(timer);}
    assert.ok(performance.now()-started<1500);
  }
  assert.equal(signed,0);
});

test('peer listener keeps consumed assignments closed after restart and refuses before wallet signing',async t=>{
  const x=await configuredFixture(t),dir=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-dispatch-restart-'));
  const file=path.join(dir,'dispatch.sqlite'),options={now:()=>x.clock()*1000};
  let journal=new PeerDispatchJournal(file,{create:true,...options}),calls=0,signatures=0;
  const entered=later(),release=later(),route=localPeerRoute(x,async()=>{calls++;entered.resolve();await release.promise;},async p=>{
    signatures++;return peerOptions(x,{},'provider').signApproval(p);
  });
  const first=await localListener(x,[route],{dispatchJournal:journal});
  t.after(async()=>{release.resolve();await first.close();journal.close();fs.rmSync(dir,{recursive:true,force:true});});
  const channel=await localConnect(x,first);t.after(()=>channel.close());await entered.promise;
  // A second independent DB connection/listener already observes consumption.
  const secondJournal=new PeerDispatchJournal(file,options);
  const second=await localListener(x,[route],{dispatchJournal:secondJournal});
  try{await assert.rejects(localConnect(x,second));assert.equal(second.snapshot().routes[0].state,'consumed');}
  finally{await second.close();secondJournal.close();}
  release.resolve();await first.close();journal.close();journal=new PeerDispatchJournal(file,options);
  const restarted=await localListener(x,[route],{dispatchJournal:journal});
  try{await assert.rejects(localConnect(x,restarted));assert.notEqual(restarted.snapshot().routes[0].state,'idle');}
  finally{await restarted.close();}
  assert.equal(calls,1);assert.equal(signatures,1);
});

test('peer listener refuses missing or forged journals and cannot hand off with exhausted durable capacity',async t=>{
  const x=await configuredFixture(t);let calls=0;
  const routes=[localPeerRoute(x,()=>{calls++;})];
  await assert.rejects(localListener(x,routes,{dispatchJournal:undefined}));
  await assert.rejects(localListener(x,routes,{dispatchJournal:{status:()=>null,consume:()=>({finish(){}})}}));
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-dispatch-full-'));
  const journal=new PeerDispatchJournal(path.join(dir,'dispatch.sqlite'),{create:true,maxRecords:1,now:()=>x.clock()*1000});
  journal.consume('0x'+'ab'.repeat(32),x.clock()*1000+60000);
  const listener=await localListener(x,routes,{dispatchJournal:journal});
  try {
    // Authentication may finish, but no service handler/command is forwarded.
    let channel;try{channel=await localConnect(x,listener);}catch{}
    channel?.close();await listener.close();assert.equal(calls,0);
    assert.equal(journal.status(peerRouteId(x.source.consent,x.initialization,x.proof)),null);
  }finally{await listener.close();journal.close();fs.rmSync(dir,{recursive:true,force:true});}
});

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

const handoffLocal=x=>({signed:x.source.consent,initialization:x.initialization,proof:x.proof});
async function handoffPair(t,x) {
  const pair=await peerTLSPair(t);
  const channels=await Promise.all(['requester','provider'].map(role=>authenticatePeerChannel(pair[role],peerOptions(x,pair,role))));
  t.after(()=>channels.forEach(c=>c.close()));return channels;
}
async function handoffTicket(t,x) {
  const [requester,provider]=await handoffPair(t,x),local=handoffLocal(x),options={clock:x.clock};
  const [ack,ticket]=await Promise.all([sendLaunchHandoff(requester,local,x.challenge,options),receiveLaunchHandoff(provider,local,options)]);
  assert.equal(ack.challengeSHA256,ticket.challengeSHA256);assert.equal(ack.keyReleaseAuthorized,false);
  return {requester,provider,ticket};
}

test('dependent launch preserves signed input after the upstream booking ends and rechecks live funding',async t=>{
  const x=await configuredFixture(t,{sequential:true}),local=handoffLocal(x),target=x.lease.assignments.find(a=>a.task===1),
    source=x.lease.assignments.find(a=>a.task===0),descriptor=x.request.descriptor;
  assert.ok(x.lease.reservations.find(r=>r.reservationId===source.reservationId).end<x.clock());
  // Public receipt commitments are owned fixtures here; encrypted archive
  // authentication is exercised by dependency-handoff and actual-kernel checks.
  const handoff={schema:'cannabis.dependency-handoff.v1',format:'age-v1+ustar',recipient:descriptor.recipient,
    ciphertextSHA256:h(190).slice(2),ciphertextBytes:1024,context:{schema:'cannabis.dependency-context.v1',
      chainId:x.network.chainId,genesisHash:x.network.genesisHash,escrow:x.network.escrow,requester:x.lease.requester,
      jobId:x.lease.job.id,packageSHA256:x.lease.job.packageSHA256,policySHA256:x.lease.job.policySHA256,
      executionPlanSHA256:x.lease.executionPlan.digestSHA256,leaseDigest:x.lease.digest,orderId:x.orderId,
      reservationId:target.reservationId,task:1,...target.run,inputRecipient:descriptor.recipient,
      sources:[{reservationId:source.reservationId,task:0,taskSHA256:source.run.taskSHA256,attempt:1,rank:0,worldSize:1,
        approvalDigest:h(191),receiptSHA256:h(192).slice(2),ciphertextSHA256:h(193).slice(2),ciphertextBytes:1024}]}};
  const window={notBefore:x.clock(),expiresAt:x.clock()+60};
  const approval=dependencyHandoffPayload(x.proof,x.network,x.r.reservationId,descriptor,handoff,window);
  const dependency={descriptor,signed:{handoff,window,requesterSignature:await owner.signTypedData(approval.domain,approval.types,approval.value)}};
  const request={proof:x.proof,challenge:x.challenge,dependency};
  const launch=await prepareGuestLaunch(x.source.consent,x.initialization,request,{clock:x.clock});
  assert.equal(launch.dependency.approvalDigest,approval.digest);
  const funding=new GuestFunding(launch.funding,launch.initialization,{clock:x.clock});t.after(()=>funding.close());
  assert.equal((await funding.refresh()).leaseDigest,x.lease.digest);
  const [requester,providerChannel]=await handoffPair(t,x);
  const [ack,ticket]=await Promise.all([sendLaunchHandoff(requester,local,x.challenge,{clock:x.clock,dependency}),
    receiveLaunchHandoff(providerChannel,local,{clock:x.clock})]);
  assert.equal(ack.dependencyApprovalDigest,approval.digest);assert.equal(ticket.hardwareValidated,false);
  const staged=consumeLaunchHandoff(ticket);
  assert.deepEqual(JSON.parse(staged.publicFiles[2]).dependency,dependency);
  assert.equal(staged.launch.dependency.approvalDigest,approval.digest);
  await assert.rejects(prepareGuestLaunch(x.source.consent,x.initialization,{proof:x.proof,challenge:x.challenge},{clock:x.clock}),/Dependency/);
  const altered=structuredClone(request);altered.dependency.signed.handoff.ciphertextSHA256=h(194).slice(2);
  await assert.rejects(prepareGuestLaunch(x.source.consent,x.initialization,altered,{clock:x.clock}));
  await (await x.escrow.connect(workers[0]).deliver(x.orderId,h(195))).wait();
  await assert.rejects(prepareGuestLaunch(x.source.consent,x.initialization,request,{clock:x.clock}),/fully accepted active/);
  await assert.rejects(funding.refresh(),/fully accepted active/);
});

test('requester workflow runs the complete funded dependency plan over TLS and recovers without relaunch',async t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-workflow-')),ageCommand=process.env.CANNABIS_AGE||'age',
    pythonCommand=process.env.CANNABIS_PYTHON||'python',fixtureScript=path.resolve('test/helpers/dependency_bundle_fixture.py');
  const python=execFileSync(pythonCommand,['-c','import sys; print(sys.executable)'],{encoding:'utf8',windowsHide:true}).trim(),
    age=path.isAbsolute(ageCommand)?ageCommand:execFileSync(python,['-c','import shutil, sys; print(shutil.which(sys.argv[1]) or "")',ageCommand],
      {encoding:'utf8',windowsHide:true}).trim();
  assert.ok(path.isAbsolute(python)&&path.isAbsolute(age),'Owned workflow requires resolved Python and age executables');
  const fixture=(action,extra={})=>{
    const input=Buffer.from(JSON.stringify({root,age,action,...extra}));
    try{return JSON.parse(execFileSync(python,[fixtureScript],{input,encoding:'utf8',windowsHide:true,stdio:['pipe','pipe','ignore'],timeout:60000,maxBuffer:1024*1024}));}
    finally{input.fill(0);}
  };
  const packaged=fixture('setup',{workflow:true}),f=launchFixture(),profile=f.configuration.execution.profile;
  profile.schema='cannabis.guest-native-service.v3';profile.maxDependencyBytes=1024;
  profile.ciphertext.dependencyBytes=4*1024**2;profile.ciphertext.bytes+=profile.ciphertext.dependencyBytes;
  const d=await setup({execution:f.configuration.execution,sequential:true,descriptor:packaged.descriptor});await d.setTime(d.start+1);
  const lease=verifyMarketLeaseProof(d.proof,d.context),signer=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),contexts=new Map(),handled=[],failures=[];
  const trustee=http.createServer(async(req,res)=>{
    try {const chunks=[];for await(const b of req)chunks.push(b);const input=JSON.parse(Buffer.concat(chunks)),
      nonce=input.verification_requests[0].runtime_data.structured.nonce,x=contexts.get(nonce);assert.ok(x);
      assert.equal(input.verification_requests[0].evidence,Buffer.from('SYNTHETIC OWNED WORKFLOW EVIDENCE').toString('base64url'));
      res.end(syntheticEAR(signer,x.policy,x.challenge,x.jwk,d.clock()));
    }catch{res.writeHead(400);res.end();}
  });await new Promise(r=>trustee.listen(0,'127.0.0.1',r));
  const resultPort=await port(),resultOrigin='http://127.0.0.1:'+resultPort,
    hosted=createWorkServer({file:':memory:',resultFile:':memory:',origin:resultOrigin});
  await new Promise(r=>hosted.server.listen(resultPort,'127.0.0.1',r));
  const spoolDir=path.join(root,'spool');fs.mkdirSync(spoolDir);const spool=new ResultSpool(spoolDir,{create:true});
  const assignments=[];
  for(const planned of lease.assignments) {
    const r=lease.reservations.find(r=>r.reservationId===planned.reservationId),configuration={...structuredClone(f.configuration),
      schema:'cannabis.guest-launch-configuration.v3',context:d.context,network:d.network,provider:r.provider,resourceId:r.resourceId,
      validFrom:d.start-10,validUntil:d.end+10};
    configuration.attestationPolicyTemplate.signingJwk=signer.publicKey.export({format:'jwk'});
    const binding=configuredMarketAttestationBinding(d.proof,d.context,r.reservationId,planned.run,validateGuestConfiguration(configuration).configurationSHA256,r.start),
      initialization={schema:'cannabis.guest-initialization.v2',tee:'snp',requester:lease.requester,jobId:lease.job.id,binding};
    const signed=(await bookedConsent({...d,clock:()=>r.start,configuration,initialization,lease,r})).signed;
    assignments.push({task:planned.task,r,configuration,initialization,signed});
  }
  const routes=assignments.map(a=>({signed:a.signed,initialization:a.initialization,proof:d.proof,
    signApproval:p=>workers[d.addresses.indexOf(a.r.provider)].signTypedData(p.domain,p.types,p.value),handle:async channel=>{
      let opened;const wires=[];
      try {
        handled.push(a.task);const ticket=await receiveLaunchHandoff(channel,{signed:a.signed,initialization:a.initialization,proof:d.proof},{clock:d.clock}),
          launch=consumeLaunchHandoff(ticket).launch;
        await receiveEncryptedInput(channel,{destination:path.join(root,'received-'+a.task+'.age'),packageSHA256:packaged.descriptor.ciphertextSHA256,maxCiphertextBytes:profile.ciphertext.inputBytes});
        if(launch.dependency)await receiveEncryptedInput(channel,{destination:path.join(root,'received-dependency.age'),
          packageSHA256:launch.dependency.signed.handoff.ciphertextSHA256,maxCiphertextBytes:profile.ciphertext.dependencyBytes});
        const channelKey=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=channelKey.publicKey.export({format:'jwk'}),challenge=launch.challenge;
        contexts.set(challenge.nonce,{policy:launch.policy,challenge,jwk});
        await channel.writeJSON({protocol:'cannabis.guest-wire.v1',operation:'evidence',evidence:{nonce:challenge.nonce,channelJwk:jwk,
          evidence:Buffer.from('SYNTHETIC OWNED WORKFLOW EVIDENCE').toString('base64url')}});
        const command=await channel.readJSON();assert.equal(command.operation,'execute');
        opened=await openJobKeyDelivery(command.envelope,channelKey.privateKey,command.expected,{clock:d.clock,
          ageKeygen:path.join(path.dirname(age),process.platform==='win32'?'age-keygen.exe':'age-keygen')});
        assert.equal(command.expected.domain.version,a.task===0?'3':'4');
        const output=a.task===0?packaged.results[0]:fixture('workflow-result',{handoff:launch.dependency.signed.handoff,identity:opened.identity});
        const envelope=await sealResultDelivery(output.receipt,opened.resultKey,command.expected);
        const reserved=hosted.relay.reserve({approvalDigest:command.expected.digest,maxCiphertextBytes:profile.ciphertext.outputBytes,expiresAt:Date.now()+3600000});
        const {uploadToken,readToken,...common}=reserved,
          upload={...common,origin:resultOrigin,role:'upload',token:uploadToken},read={...common,origin:resultOrigin,role:'read',token:readToken};
        await channel.writeJSON({protocol:'cannabis.hosted-session.v1',operation:'result-access',approvalDigest:command.expected.digest,access:read});
        assert.equal((await channel.readJSON()).operation,'result-access-ready');
        const left=new PassThrough(),right=new PassThrough(),guest=new GuestWire(left,right,{timeoutMs:20000}),bridge=new GuestWire(right,left,{timeoutMs:20000});wires.push(guest,bridge);
        const reservation=spool.reserve({expected:command.expected,maxCiphertextBytes:profile.ciphertext.outputBytes,serviceEnd:a.r.end});
        spool.dispatch(reservation);
        await Promise.all([sendEncryptedResult(guest,{ciphertext:output.file,resultEnvelope:envelope},command.expected,{maxCiphertextBytes:profile.ciphertext.outputBytes}),
          bridgeEncryptedResult(bridge,channel,{expected:command.expected,access:upload,origin:resultOrigin,reservation,maxCiphertextBytes:profile.ciphertext.outputBytes,timeoutMs:20000,wait:async()=>{}})]);
      }catch(error){failures.push(error.message);throw error;}finally{opened?.resultKey.fill(0);for(const wire of wires){wire.fail();wire.close();}}
    }}));
  const listener=await localListener(d,routes);t.after(async()=>{
    await listener.close();trustee.closeAllConnections();await new Promise(r=>trustee.close(r));
    hosted.server.closeAllConnections();await new Promise(r=>hosted.server.close(r));spool.close();
    assert.equal(path.dirname(fs.realpathSync(root)),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});
  });
  const write=(name,value)=>{const file=path.join(root,name);fs.writeFileSync(file,JSON.stringify(value));return file;};
  const cert=path.join(root,'fixture-ca.pem');fs.writeFileSync(cert,tlsFixture.cert);
  const spec={schema:'cannabis.requester-workflow.v1',proofFile:write('lease.json',d.proof),descriptorFile:path.join(root,'job/descriptor.json'),
    manifestFile:path.join(root,'workload.json'),ciphertextFile:path.join(root,'job/workload.age'),directory:path.join(root,'requester'),
    keySource:{python,age,identity:path.join(root,'owner.key'),capsule:path.join(root,'job/job-key.age'),descriptor:path.join(root,'job/descriptor.json')},
    reconstruction:{python:'',age,identity:path.join(root,'owner.key')},resultRecipient:packaged.spec.resultRecipient,maxParallel:1,maxStoredBytes:64*1024**2,
    assignments:assignments.map(a=>({reservationId:a.r.reservationId,origin:listener.origin,resultOrigin,
      consentFile:write('consent-'+a.task+'.json',a.signed),initializationFile:write('init-'+a.task+'.json',a.initialization),
      trusteeEndpoint:'http://127.0.0.1:'+trustee.address().port+'/attestation',caFile:cert}))};
  spec.reconstruction.python=spec.keySource.python;
  const config=write('workflow.json',spec),workflow=new RequesterWorkflow(readWorkflow(config),{create:true,clock:d.clock});
  const controller=new AbortController();t.after(()=>controller.abort());
  const source=assignments.find(a=>a.task===0);
  let interruptStorage=true;
  const signApproval=({kind,reservationId,payload})=>{
    if(interruptStorage&&kind==='stored'&&reservationId===source.r.reservationId)throw Error('Owned interruption after durable result publication');
    return owner.signTypedData(payload.domain,payload.types,payload.value);
  };
  let running=workflow.run({signApproval,signal:controller.signal});
  try {
    const interrupted=await running;
    assert.equal(interrupted.slots.find(r=>r.reservationId===source.r.reservationId).state,'uncertain');
    assert.equal(interrupted.slots.find(r=>r.reservationId!==source.r.reservationId).state,'queued');
    assert.deepEqual(handled,[0]);interruptStorage=false;
    // Only this owned test copy is removed; the provider retains the complete
    // uploaded ciphertext. Recovery downloads it without a peer relaunch.
    fs.unlinkSync(path.join(spec.directory,source.r.reservationId.slice(2),'result.age'));
    const restored=await workflow.recover(source.r.reservationId,{signApproval,signal:controller.signal});
    assert.equal(restored.executionRetried,false);assert.equal(restored.storageSignatureForwarded,false);assert.deepEqual(handled,[0]);
    const interruption=path.join(spec.directory,source.r.reservationId.slice(2),'interrupted.json');
    assert.equal(workflow.snapshot().slots.find(r=>r.reservationId===source.r.reservationId).state,'stored',
      failures.join(' | ')+' '+(fs.existsSync(interruption)?fs.readFileSync(interruption,'utf8'):''));
    await d.setTime(d.start+101);running=workflow.run({signApproval,signal:controller.signal});const report=await running;
    assert.ok(report.slots.every(r=>r.state==='stored'),failures.join(' | '));assert.deepEqual(handled,[0,1]);
    assert.equal(report.paymentAuthorized,false);
    const assembled=await workflow.assemble(path.join(root,'assembled'));assert.equal(assembled.integrityVerified,true);
    assert.equal(fs.readFileSync(path.join(root,'assembled/answer.txt'),'utf8'),'42');
    // The real input/consent files can go away after delivery. Recovery opens
    // the retained manifest and never repeats a network launch or signature.
    fs.unlinkSync(spec.ciphertextFile);fs.unlinkSync(spec.manifestFile);fs.unlinkSync(spec.proofFile);
    for(const a of spec.assignments)fs.unlinkSync(a.consentFile);
  }finally{controller.abort();await running.catch(()=>{});workflow.close();}
  const recovered=new RequesterWorkflow(readWorkflow(path.join(spec.directory,'config.json'),{verifyInput:false}),{clock:d.clock});
  try {for(const a of assignments)assert.equal((await recovered.recover(a.r.reservationId)).executionRetried,false);
    assert.deepEqual(handled,[0,1]);assert.throws(()=>new RequesterWorkflow(readWorkflow(path.join(spec.directory,'config.json'),{verifyInput:false}),{create:true,clock:d.clock}));
  }finally{recovered.close();}
});

test('launch handoff retains exact public boot files and refuses copied or reused capabilities',async t=>{
  const x=await configuredFixture(t),{ticket,provider}=await handoffTicket(t,x);
  const selected=inspectLaunchHandoff(ticket);
  assert.equal(selected.request.initData,guestInitialization(x.initialization).digest);
  assert.equal(selected.request.expectedLaunchDigest,x.policy.measurements.launch);
  assert.equal(selected.signal,provider.signal);assert.ok(selected.request.timeoutMs<=x.configuration.transport.timeoutMs);
  assert.throws(()=>inspectLaunchHandoff({...ticket}));
  assert.throws(()=>consumeLaunchHandoff(structuredClone(ticket)));
  const fixture=await operatingBootFixture({...handoffLocal(x),request:{proof:x.proof,challenge:x.challenge}});
  t.after(()=>fixture.close());
  const session=await stageOperatingGuest(fixture.socket,ticket);t.after(()=>session.close());
  assert.equal(fixture.staged(),true);assert.equal(session.publicPrefixStaged,true);
  assert.deepEqual(session.snapshot(),{phase:'staged',guestRetirementVerified:false,hardwareValidated:false});
  assert.throws(()=>consumeLaunchHandoff(ticket));
  assert.equal(provider.signal.aborted,false);
  await assert.rejects(relayOperatingGuest({...session}));
  // Raw/copied spool status cannot turn boot acknowledgements into execution.
  await assert.rejects(relayOperatingGuest(session,{spool:{}}));
  assert.equal(provider.signal.aborted,true);assert.equal(session.snapshot().phase,'failed');
});

test('launch handoff refuses substituted metadata, stale challenges and an inactive funded order',async t=>{
  const x=await configuredFixture(t),local=handoffLocal(x);
  for(const alter of [m=>m.proof=x.proof,m=>m.assignmentSHA256=h(91),m=>m.channelBinding=h(92),
    m=>m.challenge.binding.taskSHA256='ef'.repeat(32),m=>m.challenge.attestationPolicySHA256='ab'.repeat(32),
    m=>m.challenge.expiresAt=x.clock(),m=>m.challengeSHA256=h(93)]) {
    const [requester,provider]=await handoffPair(t,x);
    const message={protocol:'cannabis.launch-handoff.v1',operation:'challenge',assignmentSHA256:provider.report.assignmentSHA256,
      channelBinding:provider.report.binding.channelBinding,challengeSHA256:'0x'+createHash('sha256').update(
        // Canonical encoding is part of the wire commitment, not fixture data.
        canonicalHandoff(x.challenge)).digest('hex'),challenge:structuredClone(x.challenge)};
    alter(message);const rejected=assert.rejects(receiveLaunchHandoff(provider,local,{clock:x.clock}));
    await requester.writeJSON(message);await rejected;assert.equal(provider.signal.aborted,true);
  }
  const [requester,provider]=await handoffPair(t,x);
  await (await x.escrow.connect(workers[0]).deliver(x.orderId,h(95))).wait();
  const result=await Promise.allSettled([sendLaunchHandoff(requester,local,x.challenge,{clock:x.clock}),
    receiveLaunchHandoff(provider,local,{clock:x.clock})]);assert.ok(result.every(r=>r.status==='rejected'));
});

test('launch handoff and operating boot retain cancellation, deadlines and failure consumption',async t=>{
  const x=await configuredFixture(t),local=handoffLocal(x);
  for(const cancel of [false,true]) {
    const [,provider]=await handoffPair(t,x),controller=new AbortController();
    const rejected=assert.rejects(receiveLaunchHandoff(provider,local,{clock:x.clock,timeoutMs:75,signal:controller.signal}));
    if(cancel)controller.abort();await rejected;assert.equal(provider.signal.aborted,true);
  }
  for(const mode of ['silent','wrong-ready','missing-staged','wrong-staged','cancel']) {
    const {ticket,provider}=await handoffTicket(t,x),controller=new AbortController();
    const fixture=await operatingBootFixture({...local,request:{proof:x.proof,challenge:x.challenge}},{mode:mode==='cancel'?'silent':mode});
    try {
      const rejected=assert.rejects(stageOperatingGuest(fixture.socket,ticket,{timeoutMs:100,signal:controller.signal}));
      if(mode==='cancel')controller.abort();await rejected;
      assert.throws(()=>consumeLaunchHandoff(ticket));assert.equal(provider.signal.aborted,true);assert.equal(fixture.socket.destroyed,true);
    }finally{await fixture.close();}
  }
});

test('launch handoff failure keeps listener dispatch consumed across a new connection',async t=>{
  const x=await configuredFixture(t),entered=later();
  const listener=await localListener(x,[localPeerRoute(x,async(channel,local)=>{
    try{await receiveLaunchHandoff(channel,{signed:local.signed,initialization:local.initialization,proof:local.proof},
      {timeoutMs:75,clock:x.clock});}finally{entered.resolve();}
  })]);t.after(()=>listener.close());
  const channel=await localConnect(x,listener);t.after(()=>channel.close());await entered.promise;
  await assert.rejects(localConnect(x,listener));assert.notEqual(listener.snapshot().routes[0].state,'idle');
  assert.equal(listener.snapshot().admittedChannels,1);
});

function canonicalHandoff(v) {
  const encode=x=>Array.isArray(x)?'['+x.map(encode).join(',')+']':x&&typeof x==='object'?
    '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+encode(x[k])).join(',')+'}':JSON.stringify(x);
  return encode(v)+'\n';
}

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
