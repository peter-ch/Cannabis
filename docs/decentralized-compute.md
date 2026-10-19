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

The public manifest supplies provider contact, public service terms and declared runtime details. The direct client retrieves it from independently selected mirrors and checks its exact content hash and offer/resource bindings against fresh chain observations. The contract does not guarantee availability or automatically fetch an arbitrary URL. Do not place customer code, arguments, inputs, output contents or secret keys in public manifests or transaction data.

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

## Provider manifests and mirrors

`cannabis.provider-manifest.v1` commits public metadata to the offer. It contains
the chain ID, genesis hash, market and offer ID; the complete resource declaration;
the exact offer terms except its own `manifestHash`; public terms; HTTPS origins
for booking/session contacts and optional result routes; and declared runtime,
architecture, operating system, accelerator and confidential-hardware identifiers.
Runtime declarations are not measured execution evidence. Adapters and accelerator
identifiers are extensible; an unsupported confidential path still cannot run work.

The provider prepares the offer ID from its wallet and nonce before encoding the
manifest, then uses the returned hash in the offer transaction. This avoids a hash
depending on itself. The byte format is sorted compact UTF-8 JSON followed by one
line feed, limited to 64 KiB. Its SHA-256 digest, including that line feed, is the
on-chain `manifestHash`. Ambiguous encodings, duplicate fields, altered terms,
unknown fields and mismatched providers/resources are refused.

```sh
node scripts/compute-provider-manifest.mjs encode public-manifest-input.json canonical-manifest.json
node scripts/compute-provider-manifest.mjs inspect canonical-manifest.json observed-offers.json OFFER_ID
node scripts/compute-provider-manifest.mjs fetch network.json manifest-selection.json downloaded-manifest.json
```

`encode` prepares bytes and a hash without signing or publishing. `inspect` compares
against a supplied observation and explicitly does not claim fresh chain verification.
`fetch` independently reads the selected offer before and after retrieval. Its
selection contains `offerId`, `fromBlock`, `toBlock` and one to eight `mirrors` chosen
by the requester. Each mirror is an exact HTTPS origin; loopback HTTP is available
for isolated checks. No project mirror, account or founder website is required.
Output files are created exclusively; existing files are preserved.

Mirrors serve the identical canonical bytes at:

```text
/.well-known/cannabis/manifests/sha256/LOWERCASE_HASH_WITHOUT_0X.json
```

The client can try another selected mirror for the same hash. It sends no cookies
or bearer credentials, refuses redirects/compression, bounds received bytes and
keeps one cancellation/time budget across RPC reads and download. RPC replies are
limited to 1 MiB for this discovery operation. A withdrawn or expired offer, changed
canonical observation, wrong network or changed commitment refuses the result.
RPC-reported finality retains the trust boundary described above.

Success proves that the retrieved public bytes match the provider's on-chain
commitment at the observed state. It does not guarantee a booking, authenticate a
live peer's wallet or admit physical hardware. Advertised contact origins are not
automatically contacted by manifest retrieval. Authenticated session transport,
physical storage enforcement and end-to-end independent operation remain release work.

## Direct peer channel authentication

The Node adapter in `compute/peer_channel.mjs` authenticates a requester and booked
provider over one completed TLS 1.3 connection, using ALPN `cannabis-peer/1`.
Each side retains its own reviewed configuration, initialization and market proof.
The requester selects the endpoint and TLS trust store and checks its certificate
and hostname. No founder certificate authority, signing key or website is required.
Manifest retrieval does not open this connection automatically.

Each wallet signs a distinct EIP-712 role payload committing the genesis, chain,
market, configuration, assignment, complete booking group, selected booking, both
parties, endpoint origin, both fresh nonces and a bounded service interval. It also
commits the connection's [RFC 9266 TLS exporter binding](https://www.rfc-editor.org/rfc/rfc9266.html#section-2),
obtained directly from [Node's TLS socket](https://nodejs.org/api/tls.html#tlssocketexportkeyingmateriallength-label-context).
These public binding bytes are not a content key. A new TLS connection requires
new approvals; signatures cannot authorize another connection or role.

`authenticatePeerChannel` takes the established socket and a user-controlled
`signApproval` callback. The requester signs first; the provider verifies that
booked EOA proof on the actual connection before prompting its own signer. It
exchanges only bounded public authentication frames until both parties'
signatures and active funding are observed. Requester EOA
and provider EOA/ERC-1271 signatures are checked alongside launch consent at the
same canonical finalized and current block hashes. Contract-wallet revocation,
inactive funding, changed commitments, clock rollback, cancellation and a stalled
wallet or RPC cause refusal and socket closure. One handshake budget covers the
exchange, signing and chain reads; the connection also expires within the reviewed
transport budget and booking interval. A successful observation retains the RPC
trust limits described above; it does not continuously monitor revocations.

The returned channel carries framed public control messages and already encrypted
customer content. It does not release content keys or attest the worker.
`relayAuthenticatedSession` consumes its matching live provider-side capability
once for the retained launch before handing it to the existing opaque relay.
Copying a report or setting an authentication flag cannot create that capability.
The protected guest and requester still independently verify funding, consent and
attestation before any key use. Closing the session disposes the TLS connection.

This is a Node transport under review. The provider listener and requester
connector described below retain user-controlled signing callbacks; a signing UI,
protected lifecycle reconciliation and independent operating acceptance remain work.
Browser APIs do not expose this TLS
exporter; no browser authentication fallback is enabled. The offline payload and
state readers explicitly do not claim to authenticate a live socket. Channel
authentication alone is not hardware admission, paid-job acceptance or mainnet.

## Independent listener and requester connection

`compute/peer_network.mjs` provides `listenBookedPeers` and `connectBookedPeer`.
The provider registers an explicit, bounded local catalog of signed configuration,
initialization and booking proofs, plus its signing and session-handling callbacks.
A caller-selected HTTPS origin and local TLS certificate identify the listener.
The requester retains the same reviewed commitments and selects its own endpoint
and TLS trust store. No project website is needed to establish the connection.

The first encrypted application bytes are a fixed 40-byte preface: `CANPEER1`
followed by the 32-byte initialized assignment hash. It selects a retained route;
it cannot upload a configuration, RPC URL, command or runtime path. The subsequent
wallet authentication commits that exact assignment to the actual TLS channel.
The route catalog is limited to 64 entries and 16 MiB of retained public data.
Connection and pending-handshake limits cover clients that never finish TLS or
the preface. Retry counts are bounded per route, with no automatic renewal.

Only one authentication/handoff may occupy an assignment within a listener.
The mandatory `PeerDispatchJournal` in `compute/peer_dispatch.mjs` commits a local
consumed marker **before** calling the session handler. Concurrent listeners must
share that same local journal; after a restart they reopen it. A consumed,
completed or failed assignment cannot be handed off again. An interrupted process
may leave a consumed marker even if the callback never started. Recover existing
results and reconcile protected guest/requester state; do not erase the marker or
blindly re-execute. Handler completion is only a local callback observation.

First journal creation requires `create: true`; normal reopening refuses a missing
or empty file and changed limits. The journal uses the pinned patched SQLite
runtime with a [fully synchronized WAL](https://www.sqlite.org/pragma.html#pragma_synchronous).
Keep its database and live WAL together on a local filesystem, following
[SQLite's WAL requirements](https://www.sqlite.org/wal.html). Do not copy a running
database or replace it with an older backup. This ordinary-host state cannot
defend against deliberate deletion, rollback or another independent journal;
protected guest/requester replay checks remain essential. It is not a physical
capacity reservation, shared network scheduler or hardware admission.

The default journal holds at most 4,096 markers and retains each for seven days
after the signed service interval ends. Limits are fixed at creation; a full or
unwritable journal refuses handler handoff. Cleanup only removes expired metadata,
never customer ciphertext. Backward local time fails closed against its persisted
clock high-water mark; this does not supply a trusted hardware clock. Failed
authentication may retry within the listener's in-memory attempt limit. Aggregate
local ciphertext reservations now precede execution forwarding, as described below;
physical storage enforcement and protected lifecycle reconciliation remain release work.

`connectBookedPeer` validates the selected certificate/hostname, sends the fixed
preface and performs booked-party authentication. TCP/TLS setup, selection,
wallet signing and RPC share one handshake deadline; setup time also reduces
the remaining service transport budget. Cancellation remains attached after
handoff. The connector does not redirect, try unselected endpoints or unlock a
wallet. A replacement route requires an explicit selection and fresh signatures.

The operator's session callback can use `relayAuthenticatedSession` with its
retained prepared launch and sealed guest channel. Closing the listener stops
intake and destroys connections. Its bounded shutdown report distinguishes closed
sockets from handlers still pending cleanup; such a report cannot claim that a
worker, VM or customer keys have been retired. Resource/VM guardians and checked
cleanup remain required. The visible signing workflow, complete operator storage
accounting and durable independent operation remain release requirements.

## Local encrypted result reservations and recovery

The operator session requires a persistent `ResultSpool`. Before forwarding a
sealed execution command it reserves the maximum encrypted output, two copies of
the bounded encrypted receipt (journal and recovery file), and metadata allowance.
The selected HTTP delivery relay has a separate reservation. Exhaustion of either
reservation prevents execution forwarding; a late remote response cannot revive
a cancelled session. The local ledger commits the uncertain execution state before
the command write, including when that write fails without a known outcome.

SQLite transactions enforce aggregate byte and record limits across processes
sharing the same intact store. Creation is explicit and requires an empty private
directory. Reopening a missing ledger or changing its saved limits fails closed.
Retain the entire directory, database and any recovery journal together. The
result ledger uses checked SQLite DELETE rollback journaling with synchronous
EXTRA and a maximum database page count. A held reader can delay or refuse a
writer; it cannot cause a growing WAL. To convert an older WAL store, stop all
its users and let SQLite perform the transition. Never remove a database, WAL
or recovery journal to force an open.

The network-facing `relayAuthenticatedSession` requires `PhysicalResultSpool`.
The selected Linux adapter keeps the ledger, ciphertext and receipts on a bounded
ext4 loop volume with preallocated backing space. It checks the mounted device,
backing inode and allocated blocks, mount options, managed files, available bytes
and inodes at startup, before reservation and again before dispatch. Capacity
includes the configured archive allowance, capped database, rollback journal and
filesystem headroom. An open store retains a directory descriptor so ordinary
unmount fails while it is in use. Missing or changed storage fails closed.

This path currently requires a root-managed Linux operator and local ext4 backing
storage; there is no Windows, sparse-file or ordinary-folder fallback for network
dispatch. The logical `ResultSpool` remains useful for isolated protocol checks.
Host allocation cannot guarantee underlying thin-provisioned device capacity,
power-loss survival, hostile-host integrity or storage on another machine. These
controls do not admit a TEE. The dispatch journal and HTTP relay are separate
stores; whole-operator disk accounting and monitoring remain integration work.

### Prepare and retain the result volume

An operator explicitly creates a fresh private directory on its existing Linux
ext4 disk, then uses the native helper. For example, this configures a 256 MiB
logical allowance and at most 16 records; the backing file is larger to cover
database, journal and filesystem overhead:

```sh
sudo install -d -m 700 /var/lib/cannabis/result-volume
sudo /usr/bin/python3 -I -B operator/result_volume.py create /var/lib/cannabis/result-volume --max-bytes 268435456 --max-records 16
```

The adapter opens `/var/lib/cannabis/result-volume/mount/spool`. `create` refuses
existing contents and does not resize or replace a store. After all operator
processes close, `unmount` preserves both `result-volume.ext4` and `volume.json`;
`mount` reopens the retained volume. `inspect` reports its current device and
capacity. Keep both files and their private directory together; never replace
an occupied store with an empty one after an error. Moving or restoring it to a
different backing inode requires reviewed reconciliation and is deliberately
refused by the current adapter.

The ledger distinguishes unused reservations, uncertain dispatch, partial output,
sealed output, complete output and requester-acknowledged storage. Cancellation or
expiry can release unused space. Uncertain dispatch and partial output stay
charged: timeout alone does not prove that a protected guest stopped. Checked
guest-termination reconciliation for reclaiming those records is unfinished.
Transfers write bounded chunks; a durable end-frame hash and encrypted receipt
allow restart recovery to verify the complete archive and reconstruct interrupted
metadata publication without content keys or another execution.

`ResultSpool.list()` and `status(id)` expose local recovery state. `recover(id)`
checks the archive and immutable metadata. `uploadRetainedResult` sends that same
retained ciphertext and receipt to an explicitly selected replacement relay using
its upload capability; the requester needs the separate read capability and its
own approval/recovery material. Retries are bounded by the configured retention
window and each relay's expiry. Neither a successful upload nor route replacement
is requester storage acknowledgement, output acceptance or payment approval.

Complete unacknowledged results remain charged even after retries expire, preserving
the sole recoverable copy and refusing new work when capacity is exhausted. Only a
verified requester storage signature starts the deletion retention period (seven
days by default, configurable at store creation from one to thirty days). Cleanup
persists deletion intent and releases capacity only after checked file removal;
interrupted cleanup resumes from the ledger. Windows file flushing and SQLite
durability have component checks, but Windows directory flush and physical power-loss
guarantees are not established by process-termination tests. These controls
are implemented in the compute review branch; live protected operation remains
in preparation.

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
