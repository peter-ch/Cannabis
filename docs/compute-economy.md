# Cannabis: an economy built on computing work

Cannabis is being built as money for useful computing: requesters buy services, providers earn for accepted delivery, and the founder receives a disclosed 1% service fee. The objective is a market sustained by useful jobs and dependable capacity. No proof-of-work competition is involved.

## What compute backing must mean

The intended service backing is **a contractual right to redeem a specified amount of Cannabis for a defined computing service from an identified provider, within published availability and validity limits**. This requires capacity that can actually be delivered, reservation controls, enforceable terms and a remedy when delivery fails.

Compute is heterogeneous and perishable. A protected GPU hour with a particular memory size, runtime and deadline is different from a CPU hour or a completed render. Quotes must name the service precisely. There is no universal compute-hour exchange rate, fixed fiat peg or promise that every circulating token can simultaneously redeem the same service.

The token's existing supply and allocation remain unchanged: a 420 million cap, 99% community claims and 1% founder vesting over 24 calendar months. Work transfers tokens between participants; it does not mint more tokens. Holding a token alone is not yet an issued provider capacity reservation. The token contract does not currently grant a universal redemption entitlement.

## From capacity to a completed purchase

1. **Publish an offer.** A provider signs a versioned offer with its identity, eligible execution measurements, runtime and accelerator requirements, capacity units, service window, full price in Cannabis, expiry, acceptance criteria and failure remedy. Publish only necessary scheduling metadata.
2. **Reserve capacity.** The requester selects a compatible offer. A reservation binds the offer, time window, resource quantities, workload commitment and requester. An authoritative reservation record prevents the same capacity being sold twice. A planner's proposed placement is not a confirmed reservation.
3. **Fund the agreed work.** Escrow locks the budget and discloses worker shares, the included founder fee, delivery and review windows, and dispute terms. Capacity commitments need enforceable provider responsibility; escrow of requester funds alone does not prove or guarantee provider capacity.
4. **Deliver privately.** Keys are released only to approved attested environments. Workers return encrypted outputs. The requester verifies, decrypts and reconstructs them, then checks the agreed acceptance criteria. A signed hash proves a commitment to bytes, not computational correctness.
5. **Settle and measure.** Accepted work earns payment. Failed work follows the agreed refund and dispute rules. Publish privacy-preserving aggregate evidence of availability, reservations, accepted delivery, lateness and remedies.

Public claims about backing must state their scope: the actual providers, services, unreserved capacity, dates and redemption terms. Historical delivery receipts demonstrate activity; they cannot be counted as future capacity. One machine cannot be counted multiple times across offers, and external commitments must reduce its available capacity.

## Transparent prices and incentives

Providers compete on compatible resources, total price, delivery time and verified service history. Requesters choose a budget and deadline. Any metering rules, assembly charges or completion bonus must be agreed before work starts and bounded by the funded maximum. A bonus is earned only for the accepted complete result, including assembly and transfer, by the agreed deadline.

For a gross accepted payment of 100 Cannabis, workers share 99 and the founder receives 1. A refunded amount earns no founder service fee. Token transfers use exact integer base units; the [payment guide](compute-payments.md) describes rounding and all timeout outcomes. Network transaction fees are separate from the service budget.

The implemented escrow uses a fixed budget and pre-agreed worker shares. It does not yet meter resource consumption or verify delivery-speed bonuses. Those features require reviewed evidence, dispute rules and settlement integration before they become live pricing options.

## Evidence required for operation

- Validated confidential execution for each advertised hardware/runtime combination.
- Signed, enforceable provider commitments and a working reservation ledger with expiry, cancellation and overbooking protection.
- A requester able to redeem a real published offer, receive an accepted result and settle the correct payment and 1% fee.
- Measured availability and fulfillment, including capacity reconciliation and failure remedies.
- Independent security/privacy review and review of the final offer, marketing and redemption terms in the intended markets.

**Current status: preparing mainnet launch.** Encrypted workload packaging, candidate placement, client-side result reconstruction and the escrow contract are implemented with automated verification. [Signed offers, local reservations and atomic promotion into funded capacity leases](capacity-commitments.md) are also implemented. Lease promotion verifies a finalized, fully accepted escrow order and preserves the booking through its signed interval; it does not authorize confidential execution. Actual provider commitments, operational redemption, protected worker execution and mainnet settlement are not operational yet. No capacity reserve or completed commercial job is represented as already existing.

The legal classification depends on the rights and promises of the final offering, including any redemption or stabilization mechanism. The review must use the applicable [EU Markets in Crypto-assets Regulation](https://eur-lex.europa.eu/eli/reg/2023/1114/oj/eng) and the final operating arrangements; this design does not assign itself a regulatory category.
