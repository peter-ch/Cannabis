# Small compute jobs

Cannabis supports very small exact payment amounts in its escrow implementation. Real paid operation still requires an admitted confidential worker, a reviewed deployment, signed provider terms and requester-controlled signing. The integration exercise below checks software without claiming those release dependencies are complete.

## Reproduce the integration checks

Install the pinned project dependencies, Python 3.12 or later, and age 1.3.2. Set `CANNABIS_AGE` if age is outside PATH, then run:

```sh
npm run exercise:microjobs
```

The runner starts a temporary chain on loopback only. It owns its fixed, nonsensitive inputs and ephemeral encryption keys, accepts no RPC/key/workload arguments, and never reads participant or founder custody. Reports are saved under ignored `.runtime/`.

It funds and executes three fixed arithmetic fixtures through the existing encrypted package and result-assembly clients:

| Workload | Requester acceptance |
| --- | --- |
| Matrix multiplication | Exact expected matrix |
| Two parallel sum-of-squares tasks | Reconstructed total equals the independent closed-form result |
| Small linear model fit on the CPU | Coefficients and error satisfy stated numerical bounds |

Each result is encrypted, decrypted and reconstructed on the requesting side, then independently checked before settlement. Changed ciphertext and another job's package binding must be rejected. The runner verifies per-order fees, worker balances, one cancelled order, one rejected delivery, complete refunds, exhausted allowance and zero outstanding liability. Batch gas is compared against the same operations from identical temporary-chain snapshots.

The local decoder is a verification harness, not a confidential worker adapter. It cannot accept customer programs and does not establish operator-resistant confidentiality, remote execution, real payments, revenue or public demand. Those claims require hardware and live service evidence. The production planner continues to reject execution and key release without that evidence.

## Every accepted paid job contributes its fee

Every positive accepted gross amount is a multiple of 100 base units. The minimum divides exactly into one unit for the founder and 99 for the workers. Quotes, signed reservations, funding and dispute awards enforce this precision. There is no silently waived dust fee and no surcharge rounded up beyond the agreed amount. A refund has no fee.

For an asset with six decimals, the precision rule would support the following amounts. This is a denomination illustration, not a published provider offer or an announced payment asset:

| Gross | Included fee | Worker pool |
| --- | --- | --- |
| 0.000100 | 0.000001 | 0.000099 |
| 0.001000 | 0.000010 | 0.000990 |
| 0.010000 | 0.000100 | 0.009900 |

Cannabis itself has 18 decimals. Neither its decimal precision nor a local receipt establishes a currency exchange rate.

## Keep network costs smaller than the work

The founder's credit accumulates as jobs settle and can be withdrawn in one transfer. Workers can collect multiple orders together. Batch approval retains each order's receipt, fee and requester authorization. These are aggregation features, not a payment channel or off-chain custody service.

Fees for funding, worker acceptance, delivery, approval and withdrawal still need to be budgeted. Ethereum mainnet can cost more than the smallest work item even after aggregation. Rollups move execution off the base chain and amortize settlement costs, but their actual fees and security assumptions must be assessed before choosing a network. [Ethereum scaling documentation](https://ethereum.org/developers/docs/scaling/)

A real run needs a fresh quote covering provider time, storage, transfer, settlement, withdrawals and applicable minimum charges. The included service fee is part of the accepted gross quote. Retries and any extra charges must stay within the requester's all-in cap. Spot market rates are indicative and must be refreshed before signing; do not infer a Cannabis exchange rate from an ETH or stablecoin quote.
