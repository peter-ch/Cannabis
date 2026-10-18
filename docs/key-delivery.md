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
| `trusteeEndpoint` | Requester-controlled AS `/attestation` URL used by `appraise`; never taken from a worker's message |

These paths and executable choices are requester configuration, never worker-supplied protocol fields. Python 3.12+, Node 22.22+ and the pinned age/age-keygen installation are required.

```sh
node scripts/compute-key-delivery.mjs challenge ../private/delivery-config.json ../private/run-binding.json
node scripts/compute-key-delivery.mjs appraise ../private/delivery-config.json ../private/guest-evidence.json
node scripts/compute-key-delivery.mjs prepare ../private/delivery-config.json ../private/delivery-request.json
node scripts/compute-key-delivery.mjs seal ../private/delivery-config.json ../private/signed-delivery.json
node scripts/compute-key-delivery.mjs inspect ../private/delivery-config.json ../private/release-id.json
```

- `challenge` input: `{leaseId, reservationId, run}`. `run` contains `runtimeSHA256`, `taskSHA256`, `attempt`, `rank`, `worldSize`, `acceleratorClass`. Values must come from the approved workload and placement. The challenge must be created close enough to the reserved service window to remain fresh.
- `appraise` input: the guest's `nonce`, `channelJwk` and base64url `evidence`. It calls the configured Trustee, verifies the EAR and returns `{token, appraisal, challengeConsumed: false, ...}`. Keep the response private and pass its token into `seal`; it does not recover a key or consume the challenge. This supports the [guest-held session](guest-attestation.md).
- `prepare` input: `{releaseId, leaseId, nonce, channelJwk, descriptor, notBefore, expiresAt}`. `descriptor` is the requester's saved package-v2 descriptor. Times are integer Unix seconds and must fit inside both the reservation and challenge lifetime. The returned typed-data payload is ready for wallet review; it does not sign anything.
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
