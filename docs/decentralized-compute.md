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
5. The requester and protected guest independently verify the original activation/funding anchor, fresh finalized bookings and escrow, and current canonical state. The versioned market proof binds the complete booking group to the retained assignment. Fresh hardware evidence and protected execution admission remain separate requirements; a market reservation alone cannot authorize execution.
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
node scripts/compute-market.mjs lease-proof funding-network.json group.json
node scripts/compute-market.mjs lease-state funding-network.json market-proof.json
```

`context.json` contains `chainId` and `market`. A preparation operation contains `from`, `method` and ABI `args`; supported methods are `publishResource`, `publishOffer`, `withdrawOffer`, `reserveBatch` and `activate`. Activation uses strictly ascending unique booking digests. The [public client source](../compute/market.mjs) defines the booking fields. The reviewed contract source and ABI are in the public repository.

Offline preparation is not verification of a deployed contract. Inspect the pinned runtime and current state, simulate and obtain a current gas quote before signing. No production market address is supplied yet.

`network.json` additionally contains `rpc`, `genesisHash`, `marketCodeHash`, `finality: "rpc-finalized"` and `maxFinalizedAgeSeconds` from 1 to 7,200. Use an independently operated or appropriately trusted HTTPS RPC; loopback HTTP is supported for isolated verification. Runtime pins include constructor immutables, including both escrow addresses. Funding verification separately checks the selected escrow and payment asset.

Offer ranges contain `fromBlock` and `toBlock`, at most 256 blocks per request. A range with more than 128 offer events must be split. Booking selections contain `bookingIds`, up to 64 unique digests. Reads bind contract state to the same finalized canonical block through [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898), check offer events against stored terms and recheck canonicality afterward. Unsupported hash queries, stale state and changed deployment pins fail closed. Results report their block and never claim key-release authorization.

RPC-reported finality is still trust in that RPC, not a locally verified consensus proof. The production client needs an independently validated consensus view or an explicitly reviewed RPC arrangement; a founder RPC cannot be the mandatory trust root. A log scan can be censored by an untrusted endpoint even when returned offers pass state checks. Indexers are discovery aids, never booking authorities.

## Protected booking and key-delivery binding

`group.json` contains the universal encrypted `job`, agreed `settlement` and complete `bookingIds`. The funding network adds the selected `escrow`, `token`, `escrowCodeHash`, `tokenCodeHash` and `maxHeadAgeSeconds` (1–120) to the market reader configuration. Native ETH uses the zero token address and a null token hash. The proof builder reads activated bookings and fully accepted funding at the same canonical finalized block; it never creates bookings or signs transactions.

The portable `cannabis.market-lease.v1` document carries immutable bookings, offers, resource declarations, workload/settlement commitments and the original block anchor. Its group digest commits a distinct versioned domain, chain, market, escrow, order, settlement digest and sorted booking digests. The existing attestation/key-delivery field `leaseDigest` carries this group digest; `reservationId` carries the full on-chain booking digest, not its requester nonce. The approved `resourceId` is the contract's provider-qualified resource key. Service hashes retain their `0x` prefix.

Offline proof validation only checks internal commitments. The requester and guest each reread the original canonical state, fresh finalized state and latest state before key use; requester wrapping also rechecks after local key recovery. Invented records, partial groups, changed deployments, inactive orders, expired intervals and changed anchors fail closed. An offer withdrawal preserves an already activated booking. The original observation may occur after the hold expiry because finality can lag activation; the immutable contract enforces the activation deadline.

Requester key-delivery configuration requires `marketProofFile`, the independently reviewed `launchConfigurationFile`, bilateral `launchConsentFile` and `{ chainId, market, token }` as its context. No `capacityLedger` is opened in that path. Its attestation/replay journal remains local requester state, not shared reservation authority. Key approvals and encrypted result receipts continue to bind the exact group, booking, package, policy, runtime, task, rank and attempt.

The retained operating launcher requires `cannabis.guest-launch-configuration.v3`, including market address/runtime pins, and rejects older configuration and local-ledger proof formats. Its complete canonical configuration hash enters the version-2 initialized assignment and version-3 requester key approval. The requester retains the full reviewed configuration locally and independently checks its network, booked service, runtime and derived appraisal policy. Encrypted result receipts, relay checks and browser recovery retain this same approval commitment; stripping it cannot downgrade the session. Legacy utilities remain for historical component checks. The fixed guest entry now requires requester/provider consent and fresh canonical observations, with no embedded global signer. Requester source v3 also checks bilateral consent before local custody recovery and after key wrapping; configuration-only source v2 is refused for new deliveries. Updated measured images, actual confidential hardware, independent review and genuine paid acceptance remain release requirements.

## Booked launch consent under integration

The consent reader now prepares separate requester and provider signatures over
the complete configuration hash, initialized assignment hash, booking-group
digest, selected booking, parties and service interval. Its typed-data domain
includes the chain and market. Offline inspection checks these commitments but
does not establish that a booking exists or permit execution.

`readLaunchConsentState` independently reads the approved network. Both parties'
signatures are checked with the active escrow at the same canonical block hash,
at fresh finalized and current observations. Provider contract wallets use
[ERC-1271](https://eips.ethereum.org/EIPS/eip-1271); code and approval queries use
[EIP-1898 canonical block hashes](https://eips.ethereum.org/EIPS/eip-1898).
Approval created after funding need not have existed at the original funding
block. Revoked approval at the current block, changed canonicality, malformed
responses and unsupported hash queries cause refusal. Contract code never falls
back to an ordinary signature check after refusing an approval.

Requester signatures currently require an EOA signing key, consistent with the
existing key-delivery flow. Signature and funding observations do not establish
hardware admission. The fixed operating entry now verifies this consent before allocation and inside
the contained control process. Retained guest funding rechecks party approval
before and after key opening. The requester independently retains the reviewed
configuration and consent, and rechecks both signatures before and after key
recovery/wrapping. Later revocation does not prevent recovery of already encrypted
results. New measured images/boots and real hardware acceptance remain unfinished.

## Limits and remaining trust

The contract bounds active or unexpired inventory to 64 bookings per resource and each batch to 64 entries. These are safety bounds, not promised throughput. Gas grows with the number and arrangement of overlapping bookings. A larger planner graph does not imply it fits in one market batch or transaction. The current time-rate quote uses integer base units with rates in multiples of 100, preserving exact fee precision. Other pricing models need reviewed formats.

On-chain inventory prevents conflicting recorded reservations for the same declared resource **within that market**. It cannot stop a dishonest provider registering one machine under different identities, selling it on another chain or using it outside Cannabis. Hardware inventory reconciliation, protected scheduling, provider obligations and failure remedies remain necessary. An offer is a provider declaration, not proof of physical capacity or operational token backing.

Blockchain makes agreement and payment state shared; public amounts, wallet activity, booking intervals and commitments remain visible. It does not conceal software running on an ordinary host. Keys must remain under requester control and reach only a correctly attested protected runtime. Attestation trust must be requester-selected or locally verified; a single founder verifier, signing service or software allowlist cannot become mandatory network admission. Hardware manufacturer roots and any chosen external verifier remain explicit trust dependencies.

The existing SQLite capacity module is a legacy local coordination component. Its records do not become decentralized by being copied or renamed. The new requester/guest market path replaces that authority with direct chain verification, while historical helpers retain their original format. Finishing peer transport and manifest distribution, integrating the visible worker GUI, admitting actual hardware and independently reviewing the complete system remain launch work. No claim of a fully decentralized operational network is made before those paths work together.
