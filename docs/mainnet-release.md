# Cannabis mainnet release

Cannabis is preparing a production mainnet launch with efficient verified-person claims, zero-knowledge eligibility privacy, and 1% founder vesting over 24 calendar months.

## Current release status

As of 19 October 2026, the status is **Preparing mainnet launch**. Ethereum mainnet (chain ID 1) is the selected preparation target, with direct Ethereum proof-of-stake settlement. The website and local worker console are available; neither is evidence of token deployment or an operating paid-compute service.

| Requirement | Current state |
| --- | --- |
| Network dependency checks | Ethereum Semaphore, verifier and library pins checked against finalized and current chain state; independent review still required |
| Canonical token, enrollment, vesting and settlement addresses | No verified Cannabis production deployment published |
| Person verification and permanent registrar | Recurring Cannabis registrar implemented; durable human continuity, real venues/witnesses/reviewers and independent review outstanding |
| Enrollment | No recruitment quota for deployment; initial claim minimum is configurable (default 1); later founder increases are bounded by enrolled membership, with small-group privacy disclosed |
| Common opening | Not announced; the release tool requires at least seven days' notice |
| Independent security, privacy and applicable release review | Outstanding |
| Protected paid computing | Runtime software checkpoint completed; actual confidential hardware, protected operation, independent review and genuine paid acceptance outstanding |
| Decentralized compute coordination | On-chain discovery/booking/settlement, direct peer transport and requester recovery implemented; actual operation and independent review outstanding |

The [worker console](worker-console.md) displays actual local machine observations and these admission requirements. Its paid-worker control is unavailable. Canonical addresses, the opening time and operational claims will be published only after their evidence is verified. Source checks and automated tests do not replace independent review.

## Prepare the reviewed release

The preparation command checks reviewed dependency pins against finalized and current canonical chain state, then exports unsigned deployment data, constructor arguments, exact dates, allocations, dependency observations, ABI and complete compiler input. It does not load a key or broadcast a transaction. See [dependency verification](dependency-verification.md) for the source checks, configuration format and evidence limits.

`prepare:launch` prepares the token creation transaction. Use the complete network
package below to review the registrar, both payment escrows and the
[shared market contract](decentralized-compute.md) together. Actual protected paid
acceptance and operation without a mandatory founder service remain release requirements.

~~~sh
npm run prepare:launch -- --founder YOUR_PUBLIC_ADDRESS --launch YYYY-MM-DDTHH:MM:SSZ --network ethereum --minimum-claim-members 1 --semaphore VERIFIED_SEMAPHORE_ADDRESS --registrar REVIEWED_REGISTRAR_ADDRESS --semaphore-code-hash VERIFIED_RUNTIME_CODE_HASH --dependency-config config/ethereum-dependencies.json --out ../private/launch-review
~~~

Ethereum mainnet is the preparation target. The supplied `config/ethereum-dependencies.json` records observed, source-reproduced dependencies; it does not approve a release. Base and Arbitrum One remain supported candidates in the tooling, but switching the release target requires renewed security-model, compatibility, funding and cost review. Use the selected network's matching dependency configuration. The unsigned package is a draft until independently reviewed. The tool requires seven days' opening notice and concrete ceremony/registrar and dependency details.

After preparation, use the [read-only deployment fee checker](deployment-fees.md) against the exact reviewed creation-data hash. It accounts for the selected chain's fee model, including Base's separate L1 and operator fees. The estimate covers one creation transaction; the full release and operating budget includes additional costs.

The constructor creates immutable founder vesting and an append-only enrollment controller. The new token's group is not automatically populated; real eligibility verification remains mandatory before enrolling each person. Deployment does not require a preassembled group. With the default minimum of one, the first real enrolled member can claim with a valid proof after the announced opening. The reviewed release can instead specify another initial minimum, such as 4 or 8; it must be met before claims succeed. Later founder-wallet increases cannot exceed current enrollment and cannot revoke completed claims. A singleton group gives no membership anonymity; participants can wait for a larger real group. No fake commitments are added to satisfy a threshold.

Before signing, check chain ID, complete creation-data hash, founder address, initial claim minimum, bounded threshold authority, dates, Semaphore implementation/verifier, registrar controls and expected fee. After deployment, verify source and constructor values on the explorer, publish canonical addresses, validate the founder allocation, and test real ceremony enrollment and claims.

Earlier proof-of-work packages are superseded and must not be deployed.

## Complete network package

`prepare:network-release` exports five unsigned creation transactions for Ethereum
mainnet, the selected release target. It introduces no deployment factory or
administrator. The sender uses their own wallet to review and sign each transaction.

| Order | Contract | Bound relationships |
| --- | --- | --- |
| 1 | CommunityRegistrar | Predicted enrollment address, sorted reviewer wallets and reviewed quorum |
| 2 | Cannabis | Registrar, Semaphore, founder, opening/vesting dates and initial claim minimum |
| 3 | Native ETH ComputeEscrow | Native asset and fixed founder fee recipient |
| 4 | Cannabis ComputeEscrow | Cannabis token and the same fee recipient |
| 5 | ComputeMarket | Both immutable escrow addresses |

Cannabis creates the enrollment controller and founder vesting contract itself.
Their predicted addresses are included. The registrar can therefore bind the
future enrollment address before the token exists. The package records exact
consecutive sender nonces, constructor arguments, creation data and hashes for
every transaction, plus compiler input and all six contract artifacts.

Create a private JSON configuration with exactly these fields:

| Field | Value |
| --- | --- |
| `schema` | `cannabis.release-configuration.v1` |
| `chainId` | String `"1"` |
| `deployer`, `founder` | Owner-selected wallet addresses; they may be the same |
| `firstNonce` | Canonical decimal string for the sender's next transaction nonce |
| `launch` | Explicit UTC opening timestamp, with at least seven days' notice |
| `minimumClaimMembers` | Explicit integer, normally `1`; other reviewed values are supported |
| `registryReviewers` | Three to nine actual reviewer wallet addresses, strictly increasing by numeric address |
| `registryQuorum` | Integer from two-thirds rounded up through the reviewer count |

Reviewers are the permanent ceremony registry quorum. Wallet addresses alone do
not establish independent people, real ceremony operations or completed review.
Choose real reviewers through that process; do not fill the configuration with
synthetic people. The claim minimum and the registry quorum serve different purposes.

~~~sh
npm run prepare:network-release -- --config ../private/release-configuration.json --dependency-config ../private/release-dependencies.json --out ../private/network-release-review
~~~

The output directory must be new, outside the source directory, with an existing
parent. The separate dependency configuration uses the format from
[dependency verification](dependency-verification.md). Its RPC credentials are
not included in the exported package.

Preparation checks the dependency implementations and links against finalized
and current canonical state. It then checks the same anchors for an undelegated
EOA sender, the exact nonce, and empty code/zero nonce at all seven predicted
addresses. A different pending nonce, occupied target, changed canonical block
or advancing head during the observation refuses preparation. Retry against
fresh state after resolving the cause. These observations do not reserve addresses.

`network-release.json` is written last. Its file hashes bind compiler input and
artifacts; `packageSHA256` hashes the UTF-8 JSON encoding of `{ plan, files }`,
where `plan` is the manifest without `preparedAt`, `files`, `packageSHA256`,
`dependencyObservation` and `stateObservation`, and `files` is its file-hash map.
Preserve JSON property order when reproducing that commitment.

The package is an unsigned review draft. It contains no gas estimate and does
not authorize a transaction. Use the [complete Ethereum release quote](deployment-fees.md#complete-ethereum-release)
with its independently reviewed package hash to simulate all five creations in
order and check their combined fee budget. The older single-creation checker
does not cover this sequence. Subsequent operational transactions still require
separate cost review before signing.

Recheck nonce, dependency state and exact transaction data before each signature.
Require successful confirmed receipts in order, and verify each sender, nonce,
creation address, runtime, constructor state and cross-contract link. An
intervening sender transaction or failed creation invalidates the remaining
predictions; stop and prepare a new reviewed plan. Never alter a nonce in the
exported data to continue. Publish canonical addresses and live status only after
the complete release and operating evidence have been verified.
