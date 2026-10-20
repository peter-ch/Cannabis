# Deployment fee quotes

The complete Ethereum release quote covers the registrar, Cannabis and its enrollment/vesting children, both payment escrows and the compute market. It binds the exact unsigned package to a separately reviewed hash and leaves signing with the owner. It never opens a wallet key or submits a transaction.

## Complete Ethereum release

Prepare the complete [mainnet release package](mainnet-release.md) first, then retain its reviewed `packageSHA256` separately. Create a private configuration:

~~~json
{
  "rpc": "https://YOUR_TRUSTED_RPC",
  "manifestFile": "/absolute/protected/path/network-release.json",
  "expectedPackageSHA256": "YOUR_SEPARATELY_REVIEWED_64_CHARACTER_SHA256"
}
~~~

~~~sh
npm run quote:network-release -- --config /protected/network-fees.json --out /protected/network-quote.json
~~~

The consumer verifies every packaged artifact and reconstructs all five creation transactions, consecutive nonces, constructor arguments and predicted addresses. It checks the pinned Semaphore dependencies, undelegated sender, empty target addresses, pending nonce and actual ETH balance against canonical RPC state.

Using [Ethereum's sequential simulation API](https://ethereum.github.io/execution-apis/api/methods/eth_simulateV1/), it executes one creation per simulated block and checks the resulting allocations, contract links, ceremony quorum, vesting and fees. A second pass validates the same five creations with explicit gas and fee limits. No balance, code, storage or block overrides are used. The initial diagnostic view calls use zero fees and are excluded from deployment costs. Both passes must succeed; changed or partial results are refused.

The report separates simulated gas consumption, maximum gas before refunds, buffered gas limits, a current-price estimate and the aggregate planning budget. By default it adds 20% to maximum gas before refunds and proposes at least twice the observed base fee plus the suggested priority fee. The budget must fit the sender's actual native balance; otherwise the tool refuses a complete validated quote. Each creation must fit the supported 16,777,216 transaction gas cap and block limit.

An API funding refusal carries `UNVALIDATED_FUNDING_SHORTFALL` details from the initial simulation. These preliminary amounts have not passed fee validation or the final freshness checks; they are not a completed quote.

Simulation checks are observations from the selected RPC. They do not prove consensus, validate a wallet signature, reserve addresses or promise inclusion in future blocks. The zero-fee postcondition pass and fee-validation pass are recorded separately. Both must return identical creation runtime bytes and gas observations. Refresh before owner review and each signature. Prices, nonce, state and inclusion timing can change.

This quote includes the five creation transactions only. Community ceremonies, claims, compute jobs, reviews and running services have separate costs. Provisional reviewer addresses or opening dates remain planning scenarios, never canonical production parameters. The report retains `spendAuthorized: false` and `sent: false`.

## Single-transaction quotes

The older `quote:launch` tool covers one unsigned Cannabis creation on Ethereum, Base or Arbitrum One. It does not provide the complete network deployment budget.

Prepare the [mainnet release package](mainnet-release.md) first. Create a private configuration with these three fields:

~~~json
{
  "rpc": "https://YOUR_TRUSTED_RPC",
  "manifestFile": "/absolute/protected/path/launch-manifest.json",
  "expectedDataHash": "0xYOUR_SEPARATELY_REVIEWED_DEPLOYMENT_DATA_HASH"
}
~~~

Use the reviewed `deploymentDataKeccak256`, rather than accepting a new hash from an untrusted replacement manifest. Windows paths must be absolute and correctly escaped in JSON. Keep RPC credentials, funding observations and quote files private.

~~~sh
npm run quote:launch -- --config /protected/fee-config.json --out /protected/fee-quote.json
~~~

The CLI checks the manifest's project, draft status, sender, chain and data hash. Its underlying API accepts only zero-value contract creation with no destination address, access list or caller-supplied fee overrides. The output is an estimate, not a deployment approval or a source audit.

## Chain-specific accounting

| Chain | Fee calculation |
| --- | --- |
| Ethereum | Estimated gas multiplied by the greater of the RPC gas-price quote and current base fee plus its suggested priority fee |
| Base | Execution fee plus the canonical GasPriceOracle's L1 data fee and operator fee |
| Arbitrum One | Its RPC gas estimate already includes the L1 posting component; that component is not charged twice |

These models follow the [Ethereum gas documentation](https://ethereum.org/en/developers/docs/gas/), [Base predeploy specification](https://docs.base.org/specifications/base-protocol/execution/predeploys) and [Arbitrum gas-estimation documentation](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/gas-and-fees).

Base quotes require GasPriceOracle version `1.6.0` with Fjord, Isthmus and Jovian active. The adapter calls `getL1Fee` with the complete unsigned type-2 transaction, including chain ID, nonce, gas limit, fee fields and creation data. It also queries `getL1FeeUpperBound` using that encoding's byte length and `getOperatorFee` for both estimated and buffered gas. The [oracle implementation](https://github.com/ethereum-optimism/optimism/blob/develop/packages/contracts-bedrock/src/L2/GasPriceOracle.sol) accounts for signature overhead; the caller does not add it again. Unknown profiles or unavailable fee components fail the quote rather than returning an incomplete total.

Arbitrum output marks `l1FeeIncludedInGasEstimate: true`; separate L1 fee fields are `null`. This does not mean its L1 fee is zero. The quote uses the RPC's current priority-fee suggestion; it does not assume that Arbitrum ignores tips.

## Observation and budget limits

The RPC chain ID must match. Gas estimation uses a recorded block number; balance, nonce and Base oracle reads use that block's canonical hash. The block hash, metadata and chain are rechecked before returning. Heads older than 120 seconds or more than 30 seconds in the future are rejected. Requests have a 15-second deadline and the operation a 60-second deadline, with bounded responses and no HTTP redirects. The gas estimate must cover basic contract-creation intrinsic gas and fit the supported transaction/block limits after buffering. These checks rely on the selected RPC's view; they do not independently prove consensus.

The default planning budget adds 20% to estimated gas and uses at least twice the observed base fee plus the suggested priority fee. On Base it adds twice the oracle's L1 size estimate and the operator fee for buffered gas. `quoteDeploymentFee` permits an explicit gas buffer from 0 through 100%; the CLI uses the default. The report compares this budget with native ETH at the observed block. Other tokens and balances on other networks are not counted as available gas funding.

`planningBudgetWei` is **not a guaranteed spending cap**. Fee rates, compression estimates, operator settings, nonce and execution state can change. In particular, Base's L1 estimate is separate from the transaction's L2 fee cap, and its size-bound method is an estimate. Refresh the quote and simulate the exact transaction immediately before owner review and signing. A failed transaction can still consume gas.

The quote covers only the supplied creation transaction. Bridge transfers, an escrow deployment, registrar setup, community enrollment, relayers, confidential workers and ongoing operations have separate costs. A planning scenario with provisional registrar or opening parameters must not be presented as the final release package. Successful output keeps `spendAuthorized: false` and `sent: false`.
