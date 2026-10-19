# Cannabis technical specification

Status: preparing mainnet launch. This describes the current production contract implementation; canonical network and deployment addresses are published only after verification.

## Supply and issuance

The ERC-20 name is exactly Cannabis; symbol CANNABIS; decimals 18. Maximum supply is 420,000,000. At deployment, 4,200,000 (1%) is minted to FounderVesting. The remaining 415,800,000 (99%) is issued in one-time community claims of 420, for a maximum of 990,000 claims.

Founder vesting is linear from the common claim opening to its exact 24-calendar-month anniversary. The preparation tool clamps leap-day anniversaries to the last valid day. Anyone may trigger release; it always pays the immutable founder beneficiary.

No token-level proof-of-work, hash search, staking yield, tax, blacklist, emergency mint, upgrade or administrator withdrawal exists. Consensus is supplied by the chosen network, with Ethereum proof-of-stake settlement as the target architecture.

## Private eligibility

Cannabis uses a reviewed synchronized in-person ceremony to admit one user-generated Semaphore identity commitment per person. Venue witness quorums attest continuous presence; no external person-verification provider is required. The [permanent registrar](person-verification.md) supports recurring rounds and future newcomers while retaining consumed person tags and commitments. Separate venue and registry quorums approve enrollment. Recovery restores the same identity; durable human continuity across rounds still requires independent validation. CannabisEnrollment controls the Semaphore group and permits only append operations by its immutable registrar. It cannot remove or replace members, transfer group administration, or admit more than 990,000 commitments. Enrollment must not contain raw identity data.

The user generates a Semaphore proof locally. Its message is the receiving wallet address; its scope is a hash of the Cannabis claim domain, chain ID and token address. The proof establishes membership without exposing which commitment belongs to the claimant.

Cannabis.claim checks the public opening, recipient binding, scope, unused nullifier, unused receiving wallet, remaining allocation, at least 128 enrolled commitments, the current group root and the real Semaphore verifier result. The token stores its own nullifiers and uses Semaphore's view verification; an outsider calling Semaphore.validateProof cannot burn a user's Cannabis claim.

Anyone may relay a proof, but the reward always reaches the proof-bound recipient. Relaying can separate the claimant from the gas-paying address. It does not conceal token balances, transfers or all network metadata.

## Membership operations

Only the current root is accepted. This prevents use of an earlier, smaller membership snapshot to bypass the anonymity threshold. Enrollment batches may invalidate in-flight proofs, so Cannabis ceremony operators must publish stable claim windows and support regeneration before submission.

The count measures distinct commitments, not an independently proven number of humans. Registrar integrity and one-person enrollment/recovery rules remain essential. A lost identity must not simply be replaced with another commitment that allows a second claim.

## Computing services and economic design

The [decentralized market](decentralized-compute.md) coordinates provider offers and bilateral capacity bookings through public contracts. Its shared inventory spans ETH and Cannabis escrows; direct client tools discover offers and inspect finalized reservations without a founder service. No administrator admits providers to the market. Physical capacity, confidential execution and requester-selected verification remain separate requirements, and protected execution still needs integration with these on-chain bookings.

Cannabis is intended as money for useful computing services. The [compute economy specification](compute-economy.md) defines the provider commitments, capacity reservations, redemption terms and delivery evidence needed for service backing. Fixed token supply and community allocation remain unchanged; paid work transfers existing tokens.

The [universal client](universal-compute.md) packages arbitrary software through runtime adapters, plans dependency graphs and coordinated groups, and decrypts/reconstructs outputs on the requester. Worker execution requires a validated confidential path. The [payment escrow](compute-payments.md) holds agreed budgets, records worker shares and applies the 1% founder fee to accepted payments. Its review timeout and dispute rules are part of each job's terms. Mainnet settlement, capacity redemption and protected workers still require integration and independent review.

## Verification evidence

Automated checks use actual Semaphore proofs and contracts. They cover invalid proofs, recipient substitution, duplicate identities, wrong scopes, relayer behavior, external nullifier burning, group permissions, small/stale groups, supply exhaustion, vesting and local API isolation. Compilation exports complete source input for bytecode reproduction. Independent security and privacy review remains a production release requirement.
