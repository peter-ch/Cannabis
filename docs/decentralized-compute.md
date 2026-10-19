# A decentralized computing market

Cannabis is being built for independent providers and requesters to trade useful computing directly. Public contracts coordinate offers, reservations and payments. Your wallet and client remain in control; the network must work without a required Cannabis website, project account, founder-operated scheduler or central database.

**Preparing mainnet launch.** The market contract and direct client tools are implemented for review. They have not been deployed as a live market. Protected worker execution and real paid acceptance remain required.

## Who controls what

| Function | Authority | Website or founder required? |
| --- | --- | --- |
| Publish a resource or offer | Its provider's wallet | No |
| Reserve capacity | Requester transaction and provider signature | No |
| Decide conflicting bookings | The shared market contract on the selected chain | No |
| Fund, accept and settle a job | The existing immutable payment escrow | No |
| Choose providers, runtime and privacy policy | The requester and agreeing providers | No protocol-wide founder approval |
| Protect running customer content | An independently validated confidential execution path | Blockchain alone does not supply this |
| Decide a disputed result | The adjudicator agreed for that job, under its timeout rules | No mandatory global adjudicator; the selected party remains trusted |
| Find offers and carry encrypted bytes | Direct clients, optional indexers and interchangeable relays | The production transport integration is unfinished |

The intended settlement network uses Ethereum proof of stake. There is no proof-of-work mining race, token minting for jobs or protocol administrator that approves every worker. Existing website servers provide optional supporting services; they do not constitute the computing network.

## Shared capacity on the chain

`ComputeMarket` records immutable provider resource declarations and offers. A provider declares a resource ID, service-definition hash and unit capacity. Offers commit to the resource, payment escrow, confidential-policy and public-manifest hashes, availability, expiry, quantity and gross rate. Anyone can publish from their own wallet. Events and public contract reads let independent clients find the same offers.

One market references two immutable reviewed `ComputeEscrow` deployments: native ETH and Cannabis. Both payment assets consume the same resource inventory. Separate offers for a provider's registered resource cannot reserve more than that resource's declared capacity within this market. Each offer also has its own limit. Intervals are half-open: a booking ending at a given instant does not overlap one starting then.

The public manifest must be available through independently usable, content-addressed distribution and provide provider contact, service terms and compatible runtime details. The current contract commits its hash; it does not supply a peer-discovery transport, guarantee manifest availability or automatically fetch an arbitrary URL. Do not place customer code, arguments, inputs, output contents or secret keys in public manifests or transaction data.

A reservation contains a requester-scoped nonce, offer ID, requester, escrow order ID, exact settlement-terms digest, interval, units, total gross amount and hold expiry. The provider signs its [EIP-712](https://eips.ethereum.org/EIPS/eip-712) payload; the requester submits it directly. The domain includes chain ID and market address. Provider contract wallets use [ERC-1271 signature validation](https://docs.openzeppelin.com/contracts/5.x/api/utils#SignatureChecker). A third party cannot submit another requester's booking or consume their nonce through its own booking. Used nonces remain consumed after expiry. The stored booking ID is the complete typed-data digest, not the nonce alone.

`reserveBatch` records up to 64 bookings atomically. Every signature, price, interval and capacity check must pass. Holds last at most 30 minutes and expire before service begins. A provider can withdraw an offer to stop new bookings; this preserves existing holds and activated leases. Resource declarations and recorded offer terms cannot be edited. A local writable database has no authority over these on-chain reservations.

## Booking, funding and activation

1. Agree the workload commitment, providers, exact quotes, protected runtime, acceptance criteria and settlement terms. Review the canonical chain, contract runtime hashes and provider evidence.
2. Record the signed capacity holds on the market contract. Confirm the complete group fits before submitting funding.
3. Fund the corresponding escrow order using your wallet. Each provider reviews the same terms and records its own acceptance.
4. Before hold expiry and work start, anyone can activate the complete booking group. The market requires a fully accepted `Active` escrow order, matching requester and settlement digest, covered deadlines, exact total budget and exactly matching per-provider gross shares. Duplicate, partial or mixed-order groups fail. Activation reserves capacity through each booked end time.
5. The requester and protected guest must independently verify finalized booking and funding state, current assignment and fresh hardware evidence before any key release. This integration is still pending; a market reservation alone cannot authorize execution.
6. Return encrypted outputs for requester verification and reconstruction. Settle through the existing [payment escrow](compute-payments.md), retaining the included 1% founder fee and 99% worker payment.

Funding, provider acceptance and booking activation are separate transactions. Allow time for signing and finality. Expired holds cannot be resurrected after another booking takes the capacity. If funding succeeded but activation missed its deadline, the existing escrow cancellation, delivery and dispute rules apply; an already active escrow does not offer an immediate unconditional refund. A production client must make this sequence and its failure recovery explicit.

The market never holds job deposits or earns another fee. Even after an early settlement, activated capacity remains reserved until the signed service end. Early release, rescheduling and reservation migration require a separate reviewed design. Network gas is additional to the job price and must fit the requester's approved cost ceiling.

## Direct client tools

The tools prepare unsigned transactions and read the chain. They do not connect to a founder service, load a wallet, submit payments or authorize execution.

```sh
node scripts/compute-market.mjs booking-payload context.json booking.json
node scripts/compute-market.mjs prepare context.json operation.json
node scripts/compute-market.mjs offers network.json range.json
node scripts/compute-market.mjs bookings network.json selection.json
```

`context.json` contains `chainId` and `market`. A preparation operation contains `from`, `method` and ABI `args`; supported methods are `publishResource`, `publishOffer`, `withdrawOffer`, `reserveBatch` and `activate`. Activation uses strictly ascending unique booking digests. The [public client source](../compute/market.mjs) defines the booking fields. The reviewed contract source and ABI are in the public repository.

Offline preparation is not verification of a deployed contract. Inspect the pinned runtime and current state, simulate and obtain a current gas quote before signing. No production market address is supplied yet.

`network.json` additionally contains `rpc`, `genesisHash`, `marketCodeHash`, `finality: "rpc-finalized"` and `maxFinalizedAgeSeconds` from 1 to 7,200. Use an independently operated or appropriately trusted HTTPS RPC; loopback HTTP is supported for isolated verification. Runtime pins include constructor immutables, including both escrow addresses. Funding verification separately checks the selected escrow and payment asset.

Offer ranges contain `fromBlock` and `toBlock`, at most 256 blocks per request. A range with more than 128 offer events must be split. Booking selections contain `bookingIds`, up to 64 unique digests. Reads bind contract state to the same finalized canonical block through [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898), check offer events against stored terms and recheck canonicality afterward. Unsupported hash queries, stale state and changed deployment pins fail closed. Results report their block and never claim key-release authorization.

RPC-reported finality is still trust in that RPC, not a locally verified consensus proof. The production client needs an independently validated consensus view or an explicitly reviewed RPC arrangement; a founder RPC cannot be the mandatory trust root. A log scan can be censored by an untrusted endpoint even when returned offers pass state checks. Indexers are discovery aids, never booking authorities.

## Limits and remaining trust

The contract bounds active or unexpired inventory to 64 bookings per resource and each batch to 64 entries. These are safety bounds, not promised throughput. Gas grows with the number and arrangement of overlapping bookings. A larger planner graph does not imply it fits in one market batch or transaction. The current time-rate quote uses integer base units with rates in multiples of 100, preserving exact fee precision. Other pricing models need reviewed formats.

On-chain inventory prevents conflicting recorded reservations for the same declared resource **within that market**. It cannot stop a dishonest provider registering one machine under different identities, selling it on another chain or using it outside Cannabis. Hardware inventory reconciliation, protected scheduling, provider obligations and failure remedies remain necessary. An offer is a provider declaration, not proof of physical capacity or operational token backing.

Blockchain makes agreement and payment state shared; public amounts, wallet activity, booking intervals and commitments remain visible. It does not conceal software running on an ordinary host. Keys must remain under requester control and reach only a correctly attested protected runtime. Attestation trust must be requester-selected or locally verified; a single founder verifier, signing service or software allowlist cannot become mandatory network admission. Hardware manufacturer roots and any chosen external verifier remain explicit trust dependencies.

The existing SQLite capacity module is a legacy local coordination component. Its records do not become decentralized by being copied or renamed. Existing guest lease proofs still use that format. Replacing this guest gate with independently verified on-chain bookings, finishing peer transport and manifest distribution, removing any mandatory launch authority, integrating the visible worker GUI, and independently reviewing the complete system remain launch work. No claim of a fully decentralized operational network is made before those paths work together.
