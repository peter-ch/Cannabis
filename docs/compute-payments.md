# Compute job payments

`ComputeEscrow.sol` implements a fixed-budget, multi-worker escrow with an immutable **1% founder fee**, included in the accepted gross amount. It is implemented and covered by automated checks, but has not been independently audited or deployed. No customer deposits are being accepted.

## Terms before funding

The requester chooses the total budget, encrypted job commitment, worker roster and basis-point shares, delivery manager, independent dispute resolver, acceptance deadline, delivery deadline, review window and dispute-resolution window. Every worker must accept before the job becomes active. Up to 128 worker payment recipients are supported by this escrow version; larger compute groups need a separately reviewed settlement design.

The founder recipient and fee are immutable. The token is fixed at escrow creation. The contract has no mint function, administrator withdrawal or upgrade mechanism. Deposits must transfer the exact budget; tokens that deduct transfer fees are rejected.

## Delivery and deadlines

| State | Outcome |
| --- | --- |
| Funded, not active | Requester can cancel; full refund, no founder fee |
| Workers miss acceptance deadline | Full refund can be settled after the deadline |
| Active job misses delivery deadline | Full refund can be settled after the deadline |
| Delivery submitted | Review window begins; requester can approve or dispute |
| Delivery remains undisputed when review expires | Full budget becomes payable to workers and founder |
| Disputed delivery | Named resolver can award an amount from zero through the budget; the remainder is refunded |
| Resolver misses resolution deadline | Full refund, no founder fee |

**Requesters must monitor the review window.** Silence after delivery eventually permits full payment. Workers accept the risk that an unresponsive dispute resolver causes a refund. The named resolver can determine a partial award; its independence, availability, access to encrypted evidence and decision policy must be reviewed and agreed beforehand. No resolver service is selected yet.

Only an encrypted result digest is submitted on-chain. The contract does not read private results, verify attestation or judge computation quality. These checks belong to the protected execution and acceptance systems.

## Exact amounts

For a gross accepted amount of 100 Cannabis, the founder earns 1 and the worker pool receives 99. Every funded budget and nonzero award must be an exact multiple of 100 token base units. This makes the 1% fee exact and nonzero for every accepted paid job, including the smallest supported amount. The contract and clients reject unrepresentable amounts instead of rounding the fee away or increasing the charge. Partial dispute awards follow the same rule; a zero award is a full refund.

Cannabis uses 18 decimals, so the minimum and increment are 0.0000000000000001 Cannabis. This is a token precision rule, not a fiat price. Worker payouts use cumulative basis-point rounding so their sum exactly equals the pool. Refunded amounts incur no founder fee. Network transaction fees are separate.

Withdrawals use pull payments and reentrancy protection. The escrow tracks outstanding liabilities. Neither a file hash nor an unsigned transaction review is evidence that any real-world service was delivered or paid.

## Small jobs and aggregated withdrawals

Each accepted job immediately credits its fee to the founder's withdrawable contract balance. `withdrawCredit` collects accumulated fees in one token transfer; a separate transfer is not required for every tiny fee. `approveBatch` approves up to 128 independently reviewed orders belonging to the caller. `withdrawWorkers` combines positive, unwithdrawn payments from up to 128 orders into one transfer controlled by that worker. A duplicate, invalid or unauthorized item reverts the entire batch. An approval batch still emits a separate settlement event for every order.

Aggregation reduces transaction overhead; it does not make Ethereum mainnet gas disappear. A viable fraction-of-a-cent service needs a compatible low-cost settlement network or a separately reviewed payment-channel design, economical provider quotes and an explicit all-in budget. No live microjob prices or paid service are advertised yet. See [microjob verification and economics](microjobs.md).

## Wallet review commands

```sh
npm run compute:escrow -- fund funding-config.json unsigned-funding.json
npm run compute:escrow -- inspect inspection-config.json order-review.json
npm run compute:escrow -- accept acceptance-config.json unsigned-acceptance.json
npm run compute:escrow -- approve-batch approvals-config.json unsigned-approvals.json
npm run compute:escrow -- withdraw-workers withdrawals-config.json unsigned-withdrawals.json
npm run compute:escrow -- withdraw-credit credit-config.json unsigned-credit.json
```

These commands verify chain identity, escrow/token runtime hashes, fee and founder recipient. Funding preparation quotes an exact-budget token allowance and exports unsigned approval/funding transactions. Worker acceptance requires a digest of the full immutable settlement terms. The commands do not sign or send transactions.

Batch approval additionally requires `requester` and an `approvals` array containing `orderId`, `expectedTermsDigest` and `expectedOutputDigest` for each verified result. The tool checks the delivered state and exact commitments and simulates the approval. It cannot determine output quality; requester acceptance remains required. Worker withdrawal takes `worker`, `recipient` and `orderIds`. Credit withdrawal takes `account` and `recipient`. All use the same RPC, chain, escrow, token and runtime-hash pins as inspection. These commands also simulate without signing or sending.

Arbitrary workloads use a `cannabis.compute.order.v2` job object containing an opaque `id`, `requester`, the encrypted `packageSHA256`, confidential `policySHA256`, encrypted `acceptanceSHA256`, and `payment: {totalBudget, feeBasisPoints, founderRecipient}`. SHA256 fields are lowercase 64-character hex strings without `0x`; the budget is an exact decimal token amount. This binds the universal client's package to payment without exposing its adapter launch instructions or restricting its application type. The legacy `cannabis.compute.job.v1` format remains accepted for earlier manifests.

## Quoted rates and delivery incentives

The [pricing diagram](https://cannabiss.online/assets/diagrams/compute-pricing.png) illustrates the proposed next pricing layer. It is not a live price feed or an implemented metered settlement service. Node quotes may be derived from accepted resources and bounded durations, and an explicitly agreed bonus may reward a correct complete result delivered by a deadline. Quotes should include the founder fee so the requester sees the entire gross cost.

In the illustration, A quotes 4 minutes at 10 Cannabis per minute; B quotes 6 minutes at 5; assembly quotes 2 minutes at 10. Accepted base quotes total 90. A and B run concurrently, so the estimated end-to-end duration is `max(4, 6) + 2 + 1 overhead = 9 minutes`. The 1 minute represents total queue, transfer, attestation and client-verification overhead in this hypothetical example. An agreed gross delivery bonus of 10 makes the charged total 100: workers 99, founder 1. Without an earned bonus, a gross award of 90 would allocate 89.10 to workers, 0.90 to the founder and refund the remaining 10 of a 100 budget.

Metered rates require trustworthy usage evidence, agreed billing units/caps, signed quotes and rules for failure, retries and partial outputs. Faster hardware must not automatically earn more merely by reporting inflated runtime. A completion bonus concerns the accepted final result, measured against a trusted deadline, including assembly and delivery overhead. Neither worker self-reports nor hashes alone prove these facts.

The existing escrow can settle an agreed fixed gross award and fixed worker shares. It does **not** autonomously meter resource rates, distribute task-specific bonuses or verify a delivery timer. Those features need additional implementation and review before public operation.
