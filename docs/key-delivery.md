# Requester-approved encrypted key delivery

Cannabis can now prepare a per-job key envelope for the exact public key bound to a fresh Trustee CPU appraisal, a signed requester approval and an active funded capacity lease. The encrypted workload itself stays unchanged, preserving its escrow commitment.

This is a local requester-side integration. It creates and journals encrypted delivery artifacts; it does **not** transmit them, start a worker, move funds or prove that protected hardware is operating. A reviewed guest launcher, authenticated dispatcher, accelerator/interconnect profiles, rank coordination and resource enforcement are still release work.

## Checks before a key is wrapped

`compute/key_delivery.mjs` combines [per-job custody](job-key-custody.md), [Trustee appraisals](trustee-attestation.md), [funded leases](capacity-commitments.md) and escrow state inspection:

1. Derive the workload, policy, reservation and lease bindings from the trusted local capacity ledger. The requester supplies the approved runtime, task, attempt, rank and world size when creating the challenge.
2. Prepare an EIP-712 `JobKeyDelivery` approval. The wallet-review payload commits the release ID, lease/order/reservation, package and policy, attestation-policy digest, runtime and task, key capsule, input recipient, guest channel key, challenge nonce, rank/attempt/world size and validity interval. Its domain binds chain ID and escrow address. The requester must sign it using the funded order's EOA. No wallet is unlocked or signed by this tool; contract-wallet signatures are not implemented.
3. Verify the requester signature, fresh Trustee result and every challenge binding. Current integrated profiles are SNP/TDX CPU only. Unsupported accelerators have no fallback to CPU-only approval.
4. Read accepted funding at an RPC-reported finalized block, pinned by block hash, genesis, token and escrow runtime code. Confirm the original signed settlement terms and every provider's acceptance.
5. Independently inspect the canonical latest head and require the order to remain Active. This catches a delivered or otherwise changed order even when an earlier finalized snapshot still shows Active. Latest-state observation supplements finality; it does not replace it and can be reorganized later. The RPC remains a configured trust boundary.
6. Only then recover the approved job key through the local Python custody helper. The requester identity remains in that helper; only the per-job input identity enters the local encryptor's anonymous pipe. Derive the input public recipient again using `age-keygen` and compare it with the signed approval.
7. Encrypt the job key and requester approval with standard JOSE `ECDH-ES+A256KW` and `A256GCM`, using the attested P-256 public key. A fresh JWE ephemeral key and encryption material come from the JOSE library. The protected header binds the approval digest and public-key thumbprint. The encrypted payload's expiry is the earlier of approval and appraisal expiry.
8. Recheck latest escrow state after recovery/wrapping. Recheck challenge cancellation, expiry, lease binding and requester window while holding the local write lock. Atomically journal the encrypted envelope and consume the nonce.

The local journal permits one delivery per signed release and per `(lease, task, attempt, rank)`. Concurrent requests cannot both commit. The journal contains ciphertext, commitments and block references, not plaintext keys or full hardware reports. A failed attempt does not publish an envelope. Explicit challenge cancellation consumes that challenge. Keep both ledgers private and do not restore an old snapshot to reuse challenges or deliveries.

The latest-head age limit is explicit and capped at 120 seconds. Finalized-block age follows the separately reviewed chain policy. These checks establish observed state at particular blocks, not an atomic lock on a blockchain while an off-chain message travels. Guest-side expiry, requester cancellation, runtime termination and delivery acknowledgments remain necessary. Resource units and actual physical-node ownership must be enforced by the dispatcher/worker admission system; a key envelope is not permission to exceed a reservation.

## Local CLI

Use `scripts/compute-key-delivery.mjs`. Its private configuration contains:

| Field | Meaning |
| --- | --- |
| `context` | Capacity ledger's existing chain ID, registry ID and token |
| `capacityLedger` | Existing private funded-lease SQLite path |
| `attestationPolicyFile` | Requester-pinned Trustee policy file |
| `attestationLedger` | Private challenge/delivery SQLite path |
| `network` | Reviewed RPC, chain/genesis/code pins, token/escrow, `finality: rpc-finalized`, `maxFinalizedAgeSeconds`, `maxHeadAgeSeconds` |
| `keySource` | Trusted local `python`, `age`, `identity`, `capsule`, `descriptor` paths; Python and age executables must be absolute paths for `seal` |
| `resultKeySource` | Local `python`, `age`, `identity`, `custody` paths for reopening the encrypted per-release result secret; required for version-2 approvals |
| `trusteeEndpoint` | Requester-controlled AS `/attestation` URL used by `appraise`; never taken from a worker's message |

These paths and executable choices are requester configuration, never worker-supplied protocol fields. Python 3.12+, Node 22.22+ and the pinned age/age-keygen installation are required.

```sh
node scripts/compute-key-delivery.mjs challenge ../private/delivery-config.json ../private/run-binding.json
node scripts/compute-key-delivery.mjs appraise ../private/delivery-config.json ../private/guest-evidence.json
node scripts/compute-key-delivery.mjs create-result-key ../private/delivery-config.json ../private/result-key-binding.json
node scripts/compute-key-delivery.mjs prepare ../private/delivery-config.json ../private/delivery-request.json
node scripts/compute-key-delivery.mjs seal ../private/delivery-config.json ../private/signed-delivery.json
node scripts/compute-key-delivery.mjs inspect ../private/delivery-config.json ../private/release-id.json
```

- `challenge` input: `{leaseId, reservationId, run}`. `run` contains `runtimeSHA256`, `taskSHA256`, `attempt`, `rank`, `worldSize`, `acceleratorClass`. Values must come from the approved workload and placement. The challenge must be created close enough to the reserved service window to remain fresh.
- `appraise` input: the guest's `nonce`, `channelJwk` and base64url `evidence`. It calls the configured Trustee, verifies the EAR and returns `{token, appraisal, challengeConsumed: false, ...}`. Keep the response private and pass its token into `seal`; it does not recover a key or consume the challenge. This supports the [guest-held session](guest-attestation.md).
- `prepare` input: `{releaseId, leaseId, nonce, channelJwk, descriptor, notBefore, expiresAt}`. `descriptor` is the requester's saved package-v2 descriptor. Times are integer Unix seconds and must fit inside both the reservation and challenge lifetime. The returned typed-data payload is ready for wallet review; it does not sign anything.
- `create-result-key` input: `{releaseId, recipient}` using the requester's own result recipient. Save its encrypted custody record privately and durably before delivery, with the existing requester identity backup. Add its `resultKeySHA256` to the `prepare` request to produce a version-2 approval. The result secret is never printed. Native execution requires this version; legacy version-1 envelopes support only the earlier internal preparation path.
- `seal` input: `{approval: {request, requesterSignature}, token}`. `token` is the Trustee EAR. Successful output reports `keyWrapped: true`, `transmitted: false`, `executionAuthorized: false` and includes the encrypted envelope. It contains no raw identity key.
- `inspect` input: `{releaseId}`. Retrieves the original encrypted journal record after an interrupted caller. It does not renew expiry or create a new release.

Obtain the EAR for the same pending challenge without consuming it through the standalone attestation `verify` or `attest` command first. The key-delivery operation performs that verification and consumes the challenge together with its encrypted journal record. A previously consumed challenge requires a new challenge, quote and signed approval. Both latest-head inspections also recheck that the finalized funding anchor is still canonical and has not lost its finality watermark.

The `appraise` command provides that non-consuming EAR acquisition directly. The later `seal` operation still repeats cryptographic, freshness and funding checks; a saved appraisal does not authorize a future delivery.

Do not run `scripts/compute-key-capsule-pipe.py` as an export command. It is an internal anonymous-pipe helper invoked by the local encryptor. It refuses interactive terminal input/output and accepts a bounded internal protocol request. Its secret output must never be logged, redirected to a file or sent to a worker operator. The CLI above outputs only wallet-review data or encrypted records. Process memory, swap and crash dumps remain the requester's security responsibility; best-effort buffer clearing is not a guarantee that every runtime copy is erased.

## Protected guest integration

Use [GuestEvidenceSession](guest-attestation.md) to retain a guest-generated channel key across evidence collection and one envelope opening. It checks the payload against the assignment retained before collection and keeps the private channel key non-extractable through WebCrypto APIs.

`openJobKeyDelivery(...)` must run **inside** the approved confidential guest, using the private channel key generated there and the guest's independently retained expected approval. It restricts algorithms, authenticates the envelope, verifies the exact requester-signed ticket, checks both expiry limits and job/key bindings, then returns the one input key in memory as a non-enumerable `identity` property. Ordinary JSON serialization omits that property; explicit access remains sensitive. It does not print a secret or launch code. The launcher must still verify the original workload ciphertext commitment, decode its private contract, enforce the runtime/resource policy, and encrypt returned results to that contract's requester recipient.

Every rank and replacement needs its own fresh admission. A replacement must use a new approved attempt; replaying a delivery cannot revoke a key already learned by an earlier guest. Teardown, lease-end enforcement and revocation require the reviewed protected runtime. Multi-rank rendezvous and collective traffic must be authenticated and encrypted, with no plaintext paths. The decryption helper is not an execution replay controller or a complete worker implementation.

Automated integration checks use actual age packages and requester recovery, actual escrow contracts on an isolated chain, real EIP-712 signatures and real JWE encryption/decryption. Disposable signed EAR fixtures exercise the result consumer; they do not establish real hardware attestation. Checks cover wrong signatures and guest keys, cross-binding, envelope tampering, expiry, cancellation, concurrent delivery, state changes during recovery, and a finalized Active order whose latest state is already Delivered. Independent review and hardware validation remain required before operational customer delivery.

The JOSE implementation is the pinned [jose library](https://github.com/panva/jose/tree/v6.2.12); its [compact JWE API](https://github.com/panva/jose/blob/v6.2.12/docs/jwe/compact/encrypt/classes/CompactEncrypt.md) supplies the standard encryption construction.

## Authenticated private result return

Each version-2 approval commits to a fresh, random 256-bit result secret, separate
from the workload input key. The requester first encrypts this secret into an age
custody record for its own recipient, using the pinned [age TypeScript
implementation](https://github.com/FiloSottile/typage). Losing that custody record
prevents recovery of this result channel; the workload capsule alone is not enough.
The requester-held identity and encrypted record must both remain recoverable.

After signature, attestation and funding checks, `sealJobKeyDelivery` opens the
result custody through a private local helper and checks its recipient, release ID
and signed key commitment. The result secret travels only inside the guest's
existing authenticated key envelope. Native execution rejects version-1 approvals
before opening keys. The trusted guest control plane retains the result secret;
the untrusted workload and its decoder/runtime do not receive it.

After successful execution, cleanup and fresh funding inspection,
`GuestEvidenceSession.executeNative` seals the private receipt with JOSE `dir` and
`A256GCM`. The protected header and encrypted payload bind the entire approval
digest, including chain, escrow, lease, reservation, package, task, attempt and
attested channel. The returned `resultEnvelope` contains encrypted receipt data;
the native session no longer returns a plaintext `receipt` property. Output and
logs remain age-encrypted to the original requester recipient.

The requester recovers its saved result secret, calls `openResultDelivery`, then
uses the authenticated receipt's ciphertext commitment when decrypting and
reconstructing the result archive. Receipt authentication is not output integrity,
application quality acceptance or permission to pay. Those checks remain separate.
Version-2 delivery records retain the complete public `expectedApproval` and
requester signature, so reopening the private journal also recovers the original
approval context. Keep this journal with the encrypted result custody and existing
requester identity recovery material; it contains no raw result key.
The requester may decrypt the same receipt again after interruption; that recovery
does not represent another execution or another payment. A changed approval or
another attempt's secret fails. Keep the active approved attempt in requester
state; do not adopt a server-supplied approval as the expected one.

This is shared-secret authentication between requester and admitted session, not a
publicly verifiable proof or a signature preventing the requester from producing
its own receipt. An earlier guest that learned the workload input key cannot derive
a later fresh result secret. Host metadata, language-runtime memory copies,
hardware/launcher assurance and protected transport operation still require their
separate controls and independent review. The combined local verification uses
synthetic appraisal and disposable custody; it does not establish live hardware.

## Requester receipt recovery and approved attempts

The requester-local `ResultInbox` stores the selected signed version-2 approval
for each order, encrypted package, task and rank. Select it from the requester's
own delivery journal before handing work to the guest. Never let an incoming
server response select an expected approval. The SQLite database fixes its chain,
escrow and requester on first use; keep it on the requester's device with its
recovery material.

Replacing an attempt requires the current approval digest and a strictly higher
attempt number. The retained job, runtime, policy, recipient and group size cannot
change through a replacement. A retired approval cannot be reactivated. Retirement
only changes local result eligibility: it does not stop a guest, revoke a key it
already learned, cancel a lease or send a payment transaction.

Only authenticated encrypted receipt envelopes are stored. A repeated identical
envelope recovers the existing delivery; a conflicting envelope for that approval
is refused. Reopening custody rechecks the active selection after decryption, so a
concurrent replacement or retirement cannot save an obsolete result. Bounded release
count and total encrypted-receipt storage apply; the defaults are 4,096 releases
and 64 MiB. Preserve the database and its SQLite WAL coherently when backing it up.
Its public approval context still contains linkable order and timing metadata.
The inbox checks the actual SQLite library version before opening its file and
refuses runtimes affected by the documented concurrent WAL-reset bug. Use the
pinned Node tools; upgrading a runtime does not repair an already corrupt database.

Use the local CLI with a private configuration:

```json
{
  "inbox": "../private/requester/results.sqlite",
  "context": { "chainId": 1, "escrow": "REVIEWED_ESCROW_ADDRESS", "requester": "YOUR_ADDRESS" },
  "resultKeySources": {
    "SIGNED_RELEASE_ID": { "python": "ABSOLUTE_PYTHON_PATH", "age": "ABSOLUTE_AGE_PATH", "identity": "OWNER_IDENTITY_PATH", "custody": "ENCRYPTED_RESULT_KEY_PATH" }
  },
  "reconstruction": { "python": "ABSOLUTE_PYTHON_PATH", "age": "ABSOLUTE_AGE_PATH", "identity": "OWNER_IDENTITY_PATH" }
}
```

These placeholders are not a deployed release or permission to use an arbitrary
escrow. Resolve all paths on the requester device; tool paths must be absolute.

```sh
node scripts/compute-results.mjs activate ../private/results-config.json ../private/selection.json
node scripts/compute-results.mjs receive ../private/results-config.json ../private/receipt-input.json
node scripts/compute-results.mjs recover ../private/results-config.json ../private/approval-id.json
node scripts/compute-results.mjs assemble ../private/results-config.json ../private/assembly-input.json
```

| Action | Input fields |
| --- | --- |
| `activate` | `deliveryRecord` (local journal file), `resultRecipient`, optional `previousApprovalDigest` for an explicit replacement |
| `receive` | `approvalDigest`, `envelopeFile`; that file contains exactly `approvalDigest` and `resultEnvelope` |
| `recover`, `inspect`, `retire` | `approvalDigest` |
| `assemble` | `manifest` (original private workload), `packageSHA256` (without `0x`), `results` containing `{approvalDigest, file}` for each encrypted archive, and a new `destination` |
| `export-browser` | `approvalDigests` containing up to 128 current approvals with stored authenticated encrypted receipts; writes the public/encrypted recovery JSON to stdout |

Each command can run in a fresh process. `recover` authenticates the saved receipt
using local key custody and prints metadata, never the private receipt or result
secret. `assemble` checks the authenticated receipt against the original workload,
package, policy, task index, runtime, rank and exact approved attempt. It holds the
local selection lock during synchronous reconstruction, refusing a stale snapshot.
The trusted helper verifies and reconstructs files without executing customer code.
Reconstruction still requires separate application quality acceptance and reviewed
requester-controlled settlement; this CLI neither signs nor approves payment.

For browser recovery, export only the current receipts you intend to reconstruct:

```sh
node scripts/compute-results.mjs export-browser ../private/results-config.json ../private/browser-selection.json > ../private/browser-recovery.json
```

`browser-selection.json` contains `{"approvalDigests":["APPROVED_DIGEST"]}`. The
requester configuration supplies each release's encrypted `custody` file. Export
does not open an identity key or sign anything. It reads current selections and
stored encrypted receipts under the inbox transaction, verifies the encrypted
custody bindings, and emits a bounded `cannabis.browser-recovery.v1` file. Keep it
private: public approval and timing metadata can link activity even though the
receipt and result secret remain encrypted. It is a snapshot of this requester
database, not a promise that an attempt remains current on another device.

The [website result panel](website-orders.md#decrypt-and-reconstruct-results)
requires an explicit review before importing these selections. It verifies the
signed approval and encrypted receipt, checks original workload bindings and
reconstructs locally. Its IndexedDB history prevents older or retired attempts
being reused on that browser and serializes concurrent-tab changes against result
publication/download. Browser and desktop selections are not synchronized; export
again after changing attempts. Plaintext identity secrets and result contents are
never stored in the browser cache or uploaded by this flow.

When the website enables encrypted delivery, its read-access files provide only
retrieval credentials. The browser derives expected archive hashes and sizes from
the authenticated local receipts before making requests, checks that the selected
attempt remains current, and rejects a host-supplied change to the encrypted
receipt or archive. It requests only ciphertext from the same website origin,
with no redirected credentials, and verifies the complete hash before local
reconstruction. Interrupted encrypted chunks can be retried while that page stays
open; they and read-access tokens are not added to its persistent recovery cache.
Retrieval alone never marks an output verified or authorizes payment. See the
[delivery controls and limits](website-orders.md#encrypted-result-relay).

The [operator upload tool](website-orders.md#uploading-an-encrypted-result) can
resume delivery of an already encrypted age archive and compact encrypted receipt.
It checks local bytes against the declared hash and bounds retries, but it holds
no result key and cannot authenticate that private receipt. Its completion report
is only the relay's assertion. It never produces the requester's signed storage
acknowledgement, marks output verified or authorizes payment. Connecting the admitted
guest handoff and requester acknowledgement to hosted storage remains required.

Operational encrypted delivery and acknowledgement, protected hardware
and live settlement remain required before paid intake can open. Local tests use
disposable custody, an isolated chain and synthetic attestation; they do not count
as paid jobs or establish confidentiality from a real worker operator.

## Encrypted streaming handoff

`compute/result_transport.mjs` connects an existing protected guest session to a
requester through bounded binary frames. It sends public evidence, accepts the
requester's encrypted version-2 delivery, and streams the encrypted result receipt
and age ciphertext. It never transports local file paths, requester custody files,
identity secrets, content keys, private receipts or decrypted outputs. Relay
operators can still observe public commitments, message timing and ciphertext sizes.

The requester authenticates the receipt against its locally selected approval
before accepting the ciphertext. It bounds the transfer, hashes the stream, checks
the exact ciphertext length and digest, flushes a temporary file and publishes it
without overwriting any existing destination. It rechecks active selection before
publication and again after acknowledgement signing. Failed or truncated transfers
remove incomplete files; already verified ciphertext remains available if a later
acknowledgement is interrupted. Windows flushes the file; directory durability
depends on the requester's filesystem and recovery policy.

The guest requires a separate EIP-712 `ResultStored` acknowledgement from the
requester, binding the approval, encrypted-receipt hash, ciphertext hash and byte
count to the chain and escrow. The wallet message is named **Cannabis encrypted
result stored**. It acknowledges storage of those bytes only. It does not verify
output quality, approve an escrow payment or prove the requester will keep a
backup. The requester reviews and controls this signature; it is never substituted
for payment approval. Guest handoff fails on a wrong signer or binding, cancellation,
truncation, missing acknowledgement or the retained transport deadline.

The integrated kernel check now uses separate requester and guarded guest
processes, with this framed stream carrying evidence, key envelopes, ciphertext and
the signed acknowledgement. The requester reconstructs the downloaded copy in a
fresh process before separate owned application acceptance and isolated-chain
settlement. Fixture setup still creates disposable custody and uses synthetic
attestation on one ordinary machine. Process separation is not confidentiality
from that machine's operator. The measured production entry, outer VM/key lifecycle,
authenticated network channel, durable relay/retry operation, actual hardware and
independent review remain required. No public transport endpoint or paid intake is
enabled by this component.
