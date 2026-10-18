# Deployment fee quotes

The release tools can quote the cost of one unsigned Cannabis deployment on Ethereum, Base or Arbitrum One. The quote binds the exact creation data to a separately reviewed hash, reads current chain state and leaves signing with the owner. It never opens a wallet key or submits a transaction.

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
