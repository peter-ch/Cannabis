import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import solc from 'solc';
import { ContractFactory, keccak256 } from 'ethers';
import { validateLaunch, prepare } from '../scripts/prepare-launch.mjs';
const now = Date.parse('2026-10-18T00:00:00Z');
const valid = { founder: '0x1111111111111111111111111111111111111111', launch: '2026-11-01T12:00:00Z', network: 'base', semaphore: '0x2222222222222222222222222222222222222222', registrar: '0x3333333333333333333333333333333333333333', semaphoreCodeHash: '0x' + '11'.repeat(32) };
test('mainnet launch validates a concrete beneficiary, network, schedule and emissions', () => {
  const result = validateLaunch(valid, now);
  assert.equal(result.network.chainId, 8453);
  assert.equal(result.registrarAddress, valid.registrar);
  assert.equal(new Date(result.end * 1000).toISOString(), '2028-11-01T12:00:00.000Z');
});
test('launch preparation rejects unsafe or ambiguous parameters', () => {
  for (const changes of [{ founder: '0x0000000000000000000000000000000000000000' },
    { founder: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' }, { launch: '2026-10-19T12:00:00Z' },
    { launch: '2026-11-31T12:00:00Z' }, { launch: '2026-11-01' }, { network: 'unknown' },
    { semaphore: '0x0000000000000000000000000000000000000000' }, { registrar: undefined }, { semaphoreCodeHash: '0x00' }]) assert.throws(() => validateLaunch({ ...valid, ...changes }, now));
});

test('exported source independently reproduces the unsigned deployment data', async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'cannabis-release-'));
  try {
    const launch = new Date(Date.now() + 14 * 86400000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    await prepare({ ...valid, launch, out });
    const manifest = JSON.parse(fs.readFileSync(path.join(out, 'launch-manifest.json'), 'utf8'));
    assert.equal(manifest.maxSupply, '420000000');
    assert.equal(manifest.founderAllocation, '4200000');
    assert.equal(manifest.communityAllocation, '415800000');
    assert.equal(manifest.claimAmount, '420');
    assert.equal(manifest.maxClaimants, 990000);
    const input = fs.readFileSync(path.join(out, 'compiler-input.json'), 'utf8');
    // No import callback: every dependency must be in the exported package.
    const compiled = JSON.parse(solc.compile(input));
    assert.deepEqual((compiled.errors ?? []).filter(e => e.severity === 'error'), []);
    const contract = compiled.contracts['Cannabis.sol'].Cannabis;
    const bytecode = `0x${contract.evm.bytecode.object}`;
    assert.equal(keccak256(bytecode), manifest.creationBytecodeKeccak256);
    const transaction = await new ContractFactory(contract.abi, bytecode).getDeployTransaction(...manifest.constructorArguments);
    assert.equal(transaction.data, manifest.transaction.data);
    assert.equal(keccak256(transaction.data), manifest.deploymentDataKeccak256);
    assert.equal(manifest.transaction.value, '0x0');
    assert.equal(manifest.status, 'UNSIGNED_DRAFT');
  } finally {
    const tempRoot = fs.realpathSync(os.tmpdir());
    const resolved = fs.realpathSync(out);
    if (path.dirname(resolved) !== tempRoot || !path.basename(resolved).startsWith('cannabis-release-'))
      throw Error('Refusing cleanup outside the temporary release directory');
    fs.rmSync(out, { recursive: true, force: true });
  }
});
