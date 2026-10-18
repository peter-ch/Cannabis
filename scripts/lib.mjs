import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { Contract, ContractFactory, JsonRpcProvider } from 'ethers';
import { Identity } from '@semaphore-protocol/identity';
import { Group } from '@semaphore-protocol/group';
import { generateProof } from '@semaphore-protocol/proof';
import { root } from './compile.mjs';

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
export const runtime = path.join(root, '.runtime');
export const localIdentity = index => new Identity(`Cannabis LOCAL DEVELOPMENT ONLY identity ${index}`);
export const localGroup = count => new Group(Array.from({ length: count }, (_, i) => localIdentity(i).commitment));
export const closeProver = async () => { await globalThis.curve_bn128?.terminate(); };
export async function localProof(provider, token, recipient, index = 1) {
  if ((await provider.getNetwork()).chainId !== 31337n) throw Error('Mock verification is only for local chain 31337');
  return generateProof(localIdentity(index), localGroup(128), BigInt(recipient), await token.claimScope());
}
export async function localProvider(url) {
  const endpoint = new URL(url);
  if (endpoint.hostname !== '127.0.0.1' || endpoint.protocol !== 'http:' || endpoint.username || endpoint.password)
    throw Error('Security verification tools accept only loopback HTTP RPC');
  const provider = new JsonRpcProvider(url, undefined, { cacheTimeout: -1, pollingInterval: 100 });
  if ((await provider.getNetwork()).chainId !== 31337n) { provider.destroy(); throw Error('Only local chain 31337 is supported'); }
  return provider;
}
export async function startNode(port = 8545, logName = 'node.log') {
  fs.mkdirSync(runtime, { recursive: true });
  const fd = fs.openSync(path.join(runtime, logName), 'w');
  const child = spawn(process.execPath, [path.join(root, 'node_modules/hardhat/dist/src/cli.js'), 'node', '--hostname', '127.0.0.1', '--port', String(port)],
    { cwd: root, windowsHide: true, stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  const rpc = `http://127.0.0.1:${port}`;
  try {
    for (let n = 0; n < 100; n++) {
      if (child.exitCode !== null) throw Error(`Node exited. See .runtime/${logName}`);
      try {
        const res = await fetch(rpc, { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }), signal: AbortSignal.timeout(300) });
        if ((await res.json()).result === '0x7a69') return { child, rpc, provider: await localProvider(rpc) };
      } catch {}
      await sleep(100);
    }
    throw Error('Local chain startup timeout');
  } catch (error) { child.kill(); throw error; }
}
export function end24Months(start) {
  const date = new Date(start * 1000);
  const originalDay = date.getUTCDate();
  date.setUTCDate(1);
  date.setUTCMonth(date.getUTCMonth() + 24);
  const lastDay = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 0)).getUTCDate();
  date.setUTCDate(Math.min(originalDay, lastDay));
  return Math.floor(date.getTime() / 1000);
}
export async function deploy(provider, artifact, { delay = 100, semaphoreAddress, registrar } = {}) {
  const founder = await provider.getSigner(0);
  const block = await provider.getBlock('latest');
  const start = block.timestamp + delay;
  const end = end24Months(start);
  registrar ??= await (await provider.getSigner(2)).getAddress();
  const token = await new ContractFactory(artifact.abi, artifact.bytecode, founder)
    .deploy(await founder.getAddress(), start, end, semaphoreAddress, registrar);
  await token.waitForDeployment();
  return { token, start, end, founder: await founder.getAddress(), registrar };
}
export const localSources = { 'LocalDependencies.sol': { content: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "@semaphore-protocol/contracts/Semaphore.sol";
import "@semaphore-protocol/contracts/base/SemaphoreVerifier.sol";
import "poseidon-solidity/PoseidonT3.sol";
` } };
export async function deployLocal(provider, artifacts, { memberCount = 128, delay = 100 } = {}) {
  const signer = await provider.getSigner(0);
  const deployArtifact = async (artifact, args = [], bytecode = artifact.bytecode) => {
    const contract = await new ContractFactory(artifact.abi, bytecode, signer).deploy(...args);
    await contract.waitForDeployment(); return contract;
  };
  const poseidon = await deployArtifact(artifacts.PoseidonT3);
  const verifier = await deployArtifact(artifacts.SemaphoreVerifier);
  let linked = artifacts.Semaphore.bytecode.slice(2);
  for (const libraries of Object.values(artifacts.Semaphore.linkReferences)) {
    for (const [name, positions] of Object.entries(libraries)) {
      if (name !== 'PoseidonT3') throw Error('Unexpected library link');
      for (const { start, length } of positions) {
        if (length !== 20) throw Error('Unexpected link width');
        linked = linked.slice(0, start * 2) + (await poseidon.getAddress()).slice(2).toLowerCase() + linked.slice((start + length) * 2);
      }
    }
  }
  const semaphore = await deployArtifact(artifacts.Semaphore, [await verifier.getAddress()], '0x' + linked);
  const result = await deploy(provider, artifacts.Cannabis, { semaphoreAddress: await semaphore.getAddress(), delay });
  const enrollment = new Contract(await result.token.enrollment(), artifacts.CannabisEnrollment.abi, await provider.getSigner(2));
  const commitments = Array.from({ length: memberCount }, (_, i) => localIdentity(i).commitment);
  for (let i = 0; i < commitments.length; i += 32) await (await enrollment.addVerifiedMembers(commitments.slice(i, i + 32))).wait();
  return { ...result, semaphore, verifier, enrollment };
}
export async function connected() {
  const state = JSON.parse(fs.readFileSync(path.join(runtime, 'deployment.json'), 'utf8'));
  const provider = await localProvider(state.rpc);
  if (await provider.getCode(state.address) === '0x') throw Error('Verification chain was reset; restart npm run verify:local');
  const artifact = JSON.parse(fs.readFileSync(path.join(root, 'artifacts/Cannabis.json'), 'utf8'));
  return { state, provider, token: new Contract(state.address, artifact.abi, provider) };
}
