# Signed capacity offers and reservations

The capacity module gives the compute economy a concrete offer format, a local reservation ledger and a bridge from temporary holds to funded service leases. Providers sign service terms; requesters and providers both sign reservations and the subsequent lease bundle. The ledger rejects overlapping commitments that exceed either an offer's limit or its admitted resource capacity, including when separate offers refer to the same resource.

This is a component of the [compute-backed service design](compute-economy.md). It does not claim physical capacity exists, create token redemption rights by itself, authorize work, or move funds.

## What is signed

An EIP-712 offer binds a provider, resource identity, service definition hash, confidential policy hash, token address, service window, expiry, available units, gross price per unit-second, included 1% fee and terms hash. The signing domain binds the chain and a unique registry identifier. Altering prices, fees, services, token or domain invalidates the signature.

The service definition must explain what a unit contains: runtime, architecture, memory, accelerators, bandwidth and any other promised resources. The terms must include acceptance, availability, failure remedies and dispute arrangements. The software checks these documents' commitments; it cannot decide whether their legal terms are enforceable.

A reservation binds the offer digest, requester, encrypted package SHA-256, interval, number of units, exact gross price and hold expiry. Both parties sign the same payload. The computed gross amount is `units × seconds × signed gross rate`, in token base units. This format prices capacity time; completed-output quotes or other pricing models need their own versioned formats.

## Inventory and overbooking

The local operator admits an immutable resource identity, service definition and capacity limit. Multiple offers from the same provider/resource consume the same pool. A SQLite immediate transaction checks all intersecting reservations and inserts the new hold atomically. Touching intervals do not overlap. Used reservation IDs cannot be replayed. Separate local connections share the same reservation state.

Admission is trusted and needs real hardware inventory, attestation and reconciliation before operation. A provider could otherwise register one machine under multiple identities or commit it elsewhere. The local ledger does not prevent that, does not synchronize independent registries and is not decentralized consensus. Never copy a writable database between machines as a coordination mechanism. Run one authoritative ledger for a resource, with a reviewed replication/recovery design before production.

## From a hold to a funded lease

Reservations initially create **pre-funding holds** of at most 30 minutes. They expire no later than work start or offer expiry. Unpromoted expired holds release capacity; their records remain for replay prevention.

`compute/leases.mjs` promotes a group of holds into a durable **funded capacity lease**. The requester and every provider must sign the same EIP-712 bundle, binding all reservation digests, escrow address, order ID, immutable settlement-terms digest, lease ID and expiry. It supports up to 4,096 reservations per bundle and aggregates multiple resources belonging to the same payment recipient. These are format bounds, not measured throughput.

Before promotion, the coordinator checks the encrypted package and confidential-policy commitments, requester, service intervals, provider roster and exact gross prices. Every provider's aggregate quote must match its agreed share of the escrow budget exactly. The existing escrow represents shares in basis points; an unrepresentable split is rejected. Use explicitly agreed new quotes or separate orders instead of silently rounding a provider's price. The contract's documented rounding of the net worker pool after the founder fee still applies.

The coordinator then reads a finalized, fully accepted `Active` escrow order. It requires pinned chain ID, genesis hash, token and escrow runtime hashes, the published 1% founder fee, and matching signed terms. Every code and contract-state read uses the same canonical block hash through [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898). Missing hash-query support, missing finality, stale blocks and a changed canonical block fail closed. There is no fallback to `latest` or an arbitrary confirmation count.

After the network reads, a SQLite immediate transaction rechecks hold expiry and ownership, stores the evidence and promotes every reservation together. An expired hold cannot be resurrected after capacity has been booked by someone else. Reservation IDs and escrow order IDs cannot be funded twice in this ledger. Separate database connections see the same promoted bookings. A funded booking continues to consume capacity for its entire signed interval after the original hold expiry.

The [guest funding gate](guest-workload.md#fresh-funding-inside-the-guest) can independently verify an exported signed agreement and reread its original funding block, current finalized state and latest head. It binds the selected reservation to the guest's retained assignment and independently approved provider/resource/service configuration. It refuses inactive orders and elapsed service intervals before returning a delivered job key. This does not replace physical capacity enforcement or the operating launcher's resource and deadline controls.

Choose hold duration and work start to allow signing, funding, all provider acceptances, network finality and promotion to finish. If promotion is late, it fails even when payment was already submitted; the parties must follow the escrow's cancellation, delivery and dispute rules. Do not promise an immediate refund from an already active order. This software prepares and inspects agreements; it never signs or sends a financial transaction.

**Capacity booking does not authorize execution or key release.** Both flags remain false. The dispatcher must separately validate fresh hardware attestation, the protected runtime, private peer networking and the current order before launching a workload. No private customer job is being executed by this module.

The finalized tag is the configured RPC's report, not a locally verified consensus proof. The final deployment must review the network's finality semantics, especially any layer-two settlement relationship, and use an appropriate trusted or independently validated RPC. Pinning a genesis and runtime code prevents configuration substitution; it does not make a dishonest RPC truthful. A catastrophic finality change requires quarantine and reconciliation before work can proceed.

The ledger conservatively retains funded capacity through the agreed end time, including after early delivery or failure. It does not yet release capacity early, extend a running lease, stop an overrun, synchronize registries or attest that a machine exists. The protected scheduler and recovery service must enforce those operational rules before service launch.

The current escrow supports up to 128 payment recipients per order. The generic planner's larger node limit is not a promise that a single escrow can settle every such plan; larger groups need a reviewed settlement design.

## Tools

The guest and CI pin Node.js 22.23.3; the Windows setup pins Node.js 24.22.0. A database runtime check refuses the documented [SQLite WAL-reset bug](https://sqlite.org/wal.html#the_wal_reset_bug) before opening persistent data. SQLite 3.51.3 or later, or the documented 3.50.7/3.44.6 backport lines, is required. An engine-version warning alone is not this protection. No additional database package is installed.

```sh
node scripts/compute-capacity.mjs offer-payload context.json offer.json
node scripts/compute-capacity.mjs verify context.json signed-offer.json
node scripts/compute-capacity.mjs admit-resource context.json resource.json ../private/capacity.sqlite
node scripts/compute-capacity.mjs add-offer context.json signed-offer.json ../private/capacity.sqlite
node scripts/compute-capacity.mjs reservation-payload context.json reservation.json
node scripts/compute-capacity.mjs reserve context.json signed-reservation.json ../private/capacity.sqlite
node scripts/compute-capacity.mjs lease-payload context.json lease-request.json ../private/capacity.sqlite
node scripts/compute-capacity.mjs promote-lease context.json signed-lease-with-network.json ../private/capacity.sqlite
node scripts/compute-capacity.mjs inspect-lease context.json lease-id.json ../private/capacity.sqlite
```

`context.json` contains `chainId`, a nonzero 32-byte hex `registryId`, and the canonical token address. Payload commands return `domain`, `types`, `value` and digest for review and external wallet signing. They never access a wallet or sign automatically. Signed offers contain `{offer, signature}`; signed reservations contain `{reservation, requesterSignature, providerSignature}`. The field definitions are in [capacity.mjs](../compute/capacity.mjs). Keep the database outside the public repository and protect access to its scheduling metadata.

A lease request contains `leaseId`, `reservationIds`, the universal `job` order, `settlement` terms in the [escrow preparation format](compute-payments.md), `escrow`, and the integer UTC `expiresAt`. Its expiry must be covered by every hold. The bundle's reservation digests are ordered by reservation ID, regardless of input order. Review the referenced offer/service/acceptance documents before signing.

Promotion input has two objects:

- `agreement`: `{request, requesterSignature, providerSignatures}`, where each provider signature is `{provider, signature}` over the returned lease payload.
- `network`: `{rpc, chainId, genesisHash, escrow, escrowCodeHash, token, tokenCodeHash, finality, maxFinalizedAgeSeconds}`. Set `finality` to `rpc-finalized`; set an explicit maximum block age of 1–7,200 seconds suitable for the reviewed network. HTTP is allowed only on `127.0.0.1`; other RPC endpoints require HTTPS. Credentials in the URL username/password fields are rejected. Runtime hashes must correspond to the reviewed deployed immutable contracts. No production values are supplied because deployment is still pending.

Inspection input is `{leaseId}`. It returns the persisted agreement, booking intervals, code/genesis pins and observed finalized block. This is historical evidence, not fresh launch authorization. Store any RPC credentials privately; the persisted record excludes the RPC URL.

The implementation uses [ethers typed-data verification](https://docs.ethers.org/v6/api/hashing/#verifyTypedData), [Node's SQLite interface](https://nodejs.org/docs/v22.23.3/api/sqlite.html) and Ethereum's [JSON-RPC finality tags](https://ethereum.org/developers/docs/apis/json-rpc/). Automated checks exercise real contract deployments on an isolated verification chain, plus controlled RPC failure/reorganization cases, altered signatures and terms, concurrent promotion, expiry races, offer/resource overbooking, exact prices and persistence. Independent review and real provider integration remain required.
