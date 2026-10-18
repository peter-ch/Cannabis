# Cannabis mainnet release

Cannabis is preparing a production mainnet launch with efficient verified-person claims, zero-knowledge eligibility privacy, and 1% founder vesting over 24 calendar months.

The preparation command exports unsigned deployment data, constructor arguments, exact dates, allocations, dependency addresses, expected Semaphore runtime-code hash, ABI and complete compiler input. It does not load a key or broadcast a transaction.

~~~sh
npm run prepare:launch -- --founder YOUR_PUBLIC_ADDRESS --launch YYYY-MM-DDTHH:MM:SSZ --network base --semaphore VERIFIED_SEMAPHORE_ADDRESS --registrar REVIEWED_REGISTRAR_ADDRESS --semaphore-code-hash VERIFIED_RUNTIME_CODE_HASH --out ../private/launch-review
~~~

Base and Arbitrum One are candidate EVM networks. Their actual deployment/version compatibility, cost and operational assumptions must be checked before selecting one. The unsigned package is a draft until independently reviewed. The tool requires seven days' opening notice and concrete provider/dependency details.

The constructor creates immutable founder vesting and an append-only enrollment controller. The new token's group is not automatically populated; real eligibility enrollment is a separate release requirement. Claims require at least 128 commitments and one proof per enrolled identity.

Before signing, check chain ID, complete creation-data hash, founder address, dates, Semaphore implementation/verifier, registrar controls and expected fee. After deployment, verify source and constructor values on the explorer, publish canonical addresses, validate the founder allocation, and test real provider enrollment and claims.

Earlier proof-of-work packages are superseded and must not be deployed.
