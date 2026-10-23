import { AbiCoder, Interface, ZeroAddress, keccak256, parseEther } from 'ethers';

// Fixed read-only postconditions, independent of caller-supplied ABI metadata.
export function releaseGetters(plan) {
  const a = plan.addresses, c = plan.configuration, getters = [];
  function add(role, signature, expected, args = []) {
    const abi = new Interface([`function ${signature.replace(' returns ', ' view returns ')}`]);
    const method = signature.slice(0, signature.indexOf('('));
    getters.push({ role, method, to: a[role], data: abi.encodeFunctionData(method, args),
      expected: abi.encodeFunctionResult(method, [expected]) });
  }
  for (const [method, value] of [['CAP', '420000000'], ['FOUNDER_ALLOCATION', '4200000'],
    ['COMMUNITY_ALLOCATION', '415800000'], ['CLAIM_AMOUNT', '420'], ['totalSupply', '4200000']])
    add('token', `${method}() returns (uint256)`, parseEther(value));
  add('token', 'MAX_CLAIMANTS() returns (uint256)', 990000);
  add('token', 'balanceOf(address) returns (uint256)', parseEther('4200000'), [a.founderVesting]);
  add('token', 'balanceOf(address) returns (uint256)', 0, [c.founder]);
  add('token', 'communityIssued() returns (uint256)', 0);
  add('token', 'minimumClaimMembers() returns (uint32)', c.minimumClaimMembers);
  add('token', 'claimsStartAt() returns (uint64)', Date.parse(plan.claimsOpen) / 1000);
  add('token', 'claimPolicyAuthority() returns (address)', c.founder);
  add('token', 'enrollment() returns (address)', a.enrollment);
  add('token', 'founderVesting() returns (address)', a.founderVesting);
  add('token', 'claimScope() returns (uint256)', BigInt(keccak256(AbiCoder.defaultAbiCoder().encode(
    ['string', 'uint256', 'address'], ['Cannabis community claim v1', plan.configuration.chainId, a.token]))));
  for (const role of ['token', 'enrollment']) add(role, 'semaphore() returns (address)', plan.dependencies.semaphore.address);
  for (const role of ['token', 'enrollment']) {
    add(role, 'groupId() returns (uint256)', 0);
    getters.at(-1).expected = null;
    getters.at(-1).relation = 'sameSemaphoreGroup';
  }
  add('enrollment', 'registrar() returns (address)', a.registrar);
  add('enrollment', 'enrolledCount() returns (uint256)', 0);
  add('enrollment', 'MAX_MEMBERS() returns (uint256)', 990000);
  add('registrar', 'enrollment() returns (address)', a.enrollment);
  add('registrar', 'registryQuorum() returns (uint8)', c.registryQuorum);
  add('registrar', 'roundCount() returns (uint64)', 0);
  add('registrar', 'reviewerEpoch() returns (uint64)', 0);
  add('registrar', 'registryReviewerCount() returns (uint256)', c.registryReviewers.length);
  c.registryReviewers.forEach((address, i) => {
    add('registrar', 'registryReviewers(uint256) returns (address)', address, [i]);
    add('registrar', 'isRegistryReviewer(address) returns (bool)', true, [address]);
  });
  add('founderVesting', 'token() returns (address)', a.token);
  add('founderVesting', 'beneficiary() returns (address)', c.founder);
  add('founderVesting', 'start() returns (uint64)', Date.parse(plan.claimsOpen) / 1000);
  add('founderVesting', 'end() returns (uint64)', Date.parse(plan.founderVestingEnds) / 1000);
  add('founderVesting', 'allocation() returns (uint256)', parseEther('4200000'));
  add('founderVesting', 'released() returns (uint256)', 0);
  for (const [role, asset] of [['nativeEscrow', ZeroAddress], ['cannabisEscrow', a.token]]) {
    add(role, 'token() returns (address)', asset);
    add(role, 'founderRecipient() returns (address)', c.founder);
    add(role, 'FEE_BPS() returns (uint256)', 100);
    add(role, 'totalLiability() returns (uint256)', 0);
  }
  add('market', 'nativeEscrow() returns (address)', a.nativeEscrow);
  add('market', 'cannabisEscrow() returns (address)', a.cannabisEscrow);
  return getters;
}
