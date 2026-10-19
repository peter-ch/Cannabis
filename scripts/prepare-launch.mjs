// Produce a reviewable unsigned deployment package. This command never signs or broadcasts.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { ContractFactory, getAddress, keccak256 } from 'ethers';
import { compile, root } from './compile.mjs';
import { end24Months } from './lib.mjs';
import { readBounded } from '../claims/identity.mjs';
import { validateDependencies, verifyLaunchDependencies } from '../launch/dependencies.mjs';

export const networks = {
  ethereum: { chainId: 1, name: 'Ethereum', currency: 'ETH', explorer: 'https://etherscan.io', rpc: 'https://ethereum-rpc.publicnode.com' },
  base: { chainId: 8453, name: 'Base', currency: 'ETH', explorer: 'https://basescan.org', rpc: 'https://mainnet.base.org' },
  arbitrum: { chainId: 42161, name: 'Arbitrum One', currency: 'ETH', explorer: 'https://arbiscan.io', rpc: 'https://arb1.arbitrum.io/rpc' }
};
export function validateLaunch({ founder, launch, network = 'base', semaphore, registrar, semaphoreCodeHash }, now = Date.now()) {
  if (!Object.hasOwn(networks, network)) throw Error('Choose ethereum, base or arbitrum');
  const beneficiary = getAddress(founder);
  if (beneficiary === '0x0000000000000000000000000000000000000000' ||
      ['0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266', '0x70997970c51812dc3a010c7d01b50e0d17dc79c8'].includes(beneficiary.toLowerCase()))
    throw Error('Use a user-controlled beneficiary, not a zero or known development address');
  if (typeof launch !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(launch)) throw Error('Launch must be an explicit UTC timestamp, YYYY-MM-DDTHH:MM:SSZ');
  const timestamp = Date.parse(launch);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString().slice(0, 19) + 'Z' !== launch) throw Error('Invalid launch date');
  if (timestamp < now + 7 * 86400000) throw Error('Allow at least seven days to publish the community claim opening time');
  const semaphoreAddress = getAddress(semaphore), registrarAddress = getAddress(registrar);
  if ([semaphoreAddress, registrarAddress].includes('0x0000000000000000000000000000000000000000')) throw Error('Verified Semaphore and enrollment registrar addresses are required');
  if (!/^0x[0-9a-fA-F]{64}$/.test(semaphoreCodeHash) || /^0x0+$/.test(semaphoreCodeHash)) throw Error('Pin the reviewed Semaphore runtime-code hash');
  return { beneficiary, start: timestamp / 1000, end: end24Months(timestamp / 1000), network: networks[network], semaphoreAddress, registrarAddress, semaphoreCodeHash };
}
export async function prepare(options) {
  const config = validateLaunch(options);
  const dependencies = validateDependencies(options.dependencyConfig?.dependencies);
  if (dependencies.chainId !== String(config.network.chainId) || dependencies.semaphore.address !== config.semaphoreAddress || dependencies.semaphore.codeHash !== config.semaphoreCodeHash.toLowerCase())
    throw Error('Dependency pins do not match the launch network and Semaphore parameters');
  const dependencyObservation = await verifyLaunchDependencies(options.dependencyConfig);
  const artifact = compile().Cannabis;
  const args = [config.beneficiary, config.start, config.end, config.semaphoreAddress, config.registrarAddress];
  const transaction = await new ContractFactory(artifact.abi, artifact.bytecode).getDeployTransaction(...args);
  const source = fs.readFileSync(path.join(root, 'contracts/Cannabis.sol'));
  const manifest = {
    name: 'Cannabis', status: 'UNSIGNED_DRAFT', prepared: new Date().toISOString(),
    chain: config.network, founderBeneficiary: config.beneficiary,
    claimsOpen: new Date(config.start * 1000).toISOString(), founderVestingEnds: new Date(config.end * 1000).toISOString(),
    maxSupply: '420000000', founderAllocation: '4200000', communityAllocation: '415800000', claimAmount: '420', maxClaimants: 990000,
    issuance: 'One claim per enrolled identity, Semaphore zero-knowledge membership, no proof-of-work',
    minimumAnonymitySet: 128, semaphore: config.semaphoreAddress, semaphoreCodeHash: config.semaphoreCodeHash, registrar: config.registrarAddress,
    dependencyObservation,
    compiler: artifact.compiler, sourceSHA256: createHash('sha256').update(source).digest('hex'),
    creationBytecodeKeccak256: keccak256(artifact.bytecode), deploymentDataKeccak256: keccak256(transaction.data),
    constructorArguments: args, transaction: { chainId: `0x${config.network.chainId.toString(16)}`, from: config.beneficiary, data: transaction.data, value: '0x0' },
    releaseRequirements: ['Portable wallet backup confirmed by owner', 'Exact opening time and parameters accepted',
      'Independent security and privacy review completed', 'Reviewed recurring Cannabis ceremonies, independent venue/registry quorums, durable cross-round human uniqueness and same-identity recovery',
      'At least 128 independently verified members; admission batching policy published', 'Semaphore deployment, verifier version and code hash verified on selected chain',
      'Applicable launch requirements addressed',
      'Reviewed decentralized compute market and both escrow deployments; direct participation without a required founder service',
      'Protected execution verifies on-chain capacity and funding; genuine paid acceptance and exact 99/1 settlement completed',
      'Current fees reviewed and funded by owner', 'Owner reviews and signs using their wallet']
  };
  const out = path.resolve(options.out);
  fs.mkdirSync(out, { recursive: true });
  const manifestPath = path.join(out, 'launch-manifest.json');
  if (fs.existsSync(manifestPath)) throw Error('A launch manifest already exists at this path; use a new review directory');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  fs.copyFileSync(path.join(root, 'artifacts/compiler-input.json'), path.join(out, 'compiler-input.json'));
  fs.writeFileSync(path.join(out, 'Cannabis.abi.json'), JSON.stringify(artifact.abi, null, 2));
  return { manifestPath, founder: config.beneficiary, network: config.network.name, status: manifest.status, sent: false };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
  const argv = process.argv.slice(2), options = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith('--') || !argv[i + 1]) throw Error('Arguments must be --name value pairs');
    options[argv[i].slice(2)] = argv[i + 1];
  }
  if (!options.out) throw Error('Set --out to a private review directory');
  if (options['semaphore-code-hash']) options.semaphoreCodeHash = options['semaphore-code-hash'];
  if (!options['dependency-config']) throw Error('Set --dependency-config to reviewed source-derived pins and a trusted RPC');
  options.dependencyConfig = JSON.parse(readBounded(path.resolve(options['dependency-config']), 16384).toString('utf8'));
  console.log(JSON.stringify(await prepare(options), null, 2));
  } catch {
    console.error('Launch preparation failed. Check the documented parameters, private dependency configuration, current canonical chain state and unused output directory. No transaction was sent.');
    process.exitCode = 1;
  }
}
