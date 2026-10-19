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
| Protected paid computing | Runtime isolation, real hardware admission and end-to-end paid acceptance outstanding |

The [worker console](worker-console.md) displays actual local machine observations and these admission requirements. Its paid-worker control is unavailable. Canonical addresses, the opening time and operational claims will be published only after their evidence is verified. Source checks and automated tests do not replace independent review.

## Prepare the reviewed release

The preparation command checks reviewed dependency pins against finalized and current canonical chain state, then exports unsigned deployment data, constructor arguments, exact dates, allocations, dependency observations, ABI and complete compiler input. It does not load a key or broadcast a transaction. See [dependency verification](dependency-verification.md) for the source checks, configuration format and evidence limits.

~~~sh
npm run prepare:launch -- --founder YOUR_PUBLIC_ADDRESS --launch YYYY-MM-DDTHH:MM:SSZ --network ethereum --minimum-claim-members 1 --semaphore VERIFIED_SEMAPHORE_ADDRESS --registrar REVIEWED_REGISTRAR_ADDRESS --semaphore-code-hash VERIFIED_RUNTIME_CODE_HASH --dependency-config config/ethereum-dependencies.json --out ../private/launch-review
~~~

Ethereum mainnet is the preparation target. The supplied `config/ethereum-dependencies.json` records observed, source-reproduced dependencies; it does not approve a release. Base and Arbitrum One remain supported candidates in the tooling, but switching the release target requires renewed security-model, compatibility, funding and cost review. Use the selected network's matching dependency configuration. The unsigned package is a draft until independently reviewed. The tool requires seven days' opening notice and concrete ceremony/registrar and dependency details.

After preparation, use the [read-only deployment fee checker](deployment-fees.md) against the exact reviewed creation-data hash. It accounts for the selected chain's fee model, including Base's separate L1 and operator fees. The estimate covers one creation transaction; the full release and operating budget includes additional costs.

The constructor creates immutable founder vesting and an append-only enrollment controller. The new token's group is not automatically populated; real eligibility verification remains mandatory before enrolling each person. Deployment does not require a preassembled group. With the default minimum of one, the first real enrolled member can claim with a valid proof after the announced opening. The reviewed release can instead specify another initial minimum, such as 4 or 8; it must be met before claims succeed. Later founder-wallet increases cannot exceed current enrollment and cannot revoke completed claims. A singleton group gives no membership anonymity; participants can wait for a larger real group. No fake commitments are added to satisfy a threshold.

Before signing, check chain ID, complete creation-data hash, founder address, initial claim minimum, bounded threshold authority, dates, Semaphore implementation/verifier, registrar controls and expected fee. After deployment, verify source and constructor values on the explorer, publish canonical addresses, validate the founder allocation, and test real ceremony enrollment and claims.

Earlier proof-of-work packages are superseded and must not be deployed.
