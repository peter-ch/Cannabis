// Complete unsigned release planning. No wallet access, signing or broadcasting.
import { ContractFactory, ZeroAddress, getAddress, getCreateAddress, keccak256, toQuantity } from 'ethers';
import { validateLaunch } from '../scripts/prepare-launch.mjs';
import { validateDependencies } from './dependencies.mjs';

export const releaseArtifacts = ['CommunityRegistrar', 'Cannabis', 'CannabisEnrollment', 'FounderVesting', 'ComputeEscrow', 'ComputeMarket'];
const fields = ['schema', 'chainId', 'deployer', 'founder', 'firstNonce', 'launch', 'minimumClaimMembers', 'registryReviewers', 'registryQuorum'];
const knownDevelopment = new Set(['0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266', '0x70997970c51812dc3a010c7d01b50e0d17dc79c8']);
function address(value) {
  const result = getAddress(value);
  if (result === ZeroAddress || knownDevelopment.has(result.toLowerCase())) throw Error('Require nonzero owner-controlled release addresses');
  return result;
}
export function validateRelease(input, dependencies, now = Date.now()) {
  if (!input || Array.isArray(input) || Object.keys(input).sort().join(',') !== fields.toSorted().join(',') ||
      input.schema !== 'cannabis.release-configuration.v1' || input.chainId !== '1') throw Error('Require the exact Ethereum release configuration');
  if (typeof input.firstNonce !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(input.firstNonce) ||
      BigInt(input.firstNonce) > BigInt(Number.MAX_SAFE_INTEGER) - 5n) throw Error('Invalid first deployment nonce');
  const pins = validateDependencies(dependencies);
  if (pins.chainId !== input.chainId) throw Error('Release and dependency chains differ');
  const deployer = address(input.deployer), founder = address(input.founder);
  const reviewers = input.registryReviewers;
  if (!Array.isArray(reviewers) || reviewers.length < 3 || reviewers.length > 9 ||
      !Number.isSafeInteger(input.registryQuorum) || input.registryQuorum < Math.ceil(2 * reviewers.length / 3) ||
      input.registryQuorum > reviewers.length) throw Error('Require the registrar reviewer quorum');
  const registryReviewers = reviewers.map(address);
  for (let i = 1; i < registryReviewers.length; ++i)
    if (BigInt(registryReviewers[i]) <= BigInt(registryReviewers[i - 1])) throw Error('Registry reviewers must be distinct and ordered');
  // Explicit input is required; do not silently default a release policy.
  if (!Object.hasOwn(input, 'minimumClaimMembers') || input.minimumClaimMembers === undefined)
    throw Error('Require the selected initial claim minimum');
  const firstNonce = BigInt(input.firstNonce);
  const addresses = Object.fromEntries(['registrar', 'token', 'nativeEscrow', 'cannabisEscrow', 'market']
    .map((name, offset) => [name, getCreateAddress({ from: deployer, nonce: firstNonce + BigInt(offset) })]));
  addresses.enrollment = getCreateAddress({ from: addresses.token, nonce: 1 });
  addresses.founderVesting = getCreateAddress({ from: addresses.token, nonce: 2 });
  const distinct = [...Object.values(addresses), ...['semaphore', 'verifier', 'poseidon'].map(name => pins[name].address)];
  if (new Set(distinct).size !== distinct.length || distinct.includes(deployer) || distinct.includes(founder) ||
      registryReviewers.some(reviewer => distinct.includes(reviewer))) throw Error('Release addresses conflict');
  const launch = validateLaunch({ founder, launch: input.launch, network: 'ethereum', semaphore: pins.semaphore.address,
    registrar: addresses.registrar, semaphoreCodeHash: pins.semaphore.codeHash, minimumClaimMembers: input.minimumClaimMembers }, now);
  return { configuration: { ...input, deployer, founder, registryReviewers }, dependencies: pins, addresses, launch };
}

export async function buildRelease(input, dependencies, artifacts, now = Date.now()) {
  const { configuration, addresses, launch, dependencies: pins } = validateRelease(input, dependencies, now);
  artifacts = structuredClone(artifacts);
  const compilers = new Set();
  for (const name of releaseArtifacts) {
    const artifact = artifacts[name];
    if (!artifact || artifact.contractName !== name || !Array.isArray(artifact.abi) ||
        typeof artifact.bytecode !== 'string' || !/^0x(?:[a-fA-F0-9]{2})+$/.test(artifact.bytecode) ||
        typeof artifact.compiler !== 'string' || Object.keys(artifact.linkReferences ?? {}).length)
      throw Error('Complete unlinked release artifacts are required');
    compilers.add(artifact.compiler);
  }
  if (compilers.size !== 1) throw Error('Release compiler versions differ');
  const specs = [
    ['registrar', 'CommunityRegistrar', [addresses.enrollment, configuration.registryReviewers, configuration.registryQuorum], []],
    ['token', 'Cannabis', [configuration.founder, launch.start, launch.end, pins.semaphore.address, addresses.registrar, configuration.minimumClaimMembers], ['registrar']],
    ['nativeEscrow', 'ComputeEscrow', [ZeroAddress, configuration.founder], ['token']],
    ['cannabisEscrow', 'ComputeEscrow', [addresses.token, configuration.founder], ['token']],
    ['market', 'ComputeMarket', [addresses.nativeEscrow, addresses.cannabisEscrow], ['nativeEscrow', 'cannabisEscrow']]
  ];
  const transactions = [];
  for (const [role, contract, constructorArguments, requiresConfirmed] of specs) {
    const artifact = artifacts[contract], { data } = await new ContractFactory(artifact.abi, artifact.bytecode).getDeployTransaction(...constructorArguments);
    if ((data.length - 2) / 2 > 49152) throw Error('Release creation data exceeds the EVM initcode limit');
    transactions.push({ role, contract, expectedAddress: addresses[role], constructorArguments, requiresConfirmed,
      creationBytecodeKeccak256: keccak256(artifact.bytecode), deploymentDataKeccak256: keccak256(data),
      transaction: { chainId: '0x1', from: configuration.deployer,
        nonce: toQuantity(BigInt(configuration.firstNonce) + BigInt(transactions.length)), data, value: '0x0' } });
  }
  return { schema: 'cannabis.unsigned-network-release.v1', status: 'UNSIGNED_DRAFT', configuration,
    dependencies: pins, addresses, transactions, compiler: [...compilers][0],
    claimsOpen: new Date(launch.start * 1000).toISOString(), founderVestingEnds: new Date(launch.end * 1000).toISOString(),
    expected: { cap: '420000000', founderAllocation: '4200000', communityAllocation: '415800000',
      claimAmount: '420', maxClaimants: 990000, feeBps: 100,
      enrollmentRegistrar: addresses.registrar, registrarEnrollment: addresses.enrollment,
      vestingToken: addresses.token, vestingBeneficiary: configuration.founder,
      nativeEscrowAsset: ZeroAddress, cannabisEscrowAsset: addresses.token, escrowFeeRecipient: configuration.founder,
      marketNativeEscrow: addresses.nativeEscrow, marketCannabisEscrow: addresses.cannabisEscrow },
    signingAuthorized: false, sent: false,
    limits: [
      'Predictions require this undelegated EOA, exact consecutive nonces and unchanged creation data; any intervening transaction or failed creation invalidates the remaining sequence.',
      'Enrollment and vesting are created by Cannabis at child nonces 1 and 2. Verify actual child addresses and all contract links after deployment.',
      'Address observations are not reservations. Recheck canonical state and pending nonce immediately before each owner-reviewed signature.',
      'Reviewer wallet addresses and signatures do not establish independent people, ceremony continuity or review approval.',
      'Independent security/privacy/release review, actual protected paid acceptance and a fresh complete cost review remain required.',
      'No fee estimate, funded balance, owner approval, actual deployment, claim opening or live worker is established by this package.'
    ] };
}
