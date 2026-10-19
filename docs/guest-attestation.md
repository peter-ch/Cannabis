# Guest-held channels and hardware evidence

The guest-side integration connects the local Confidential Containers attestation agent to Cannabis's requester-approved key-delivery flow. It generates and retains the channel private key inside one session, obtains evidence bound to that public key and the approved assignment, and opens one matching encrypted job-key delivery.

The implementation is `compute/guest_session.mjs`. It targets [guest-components v0.22.0, revision eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a](https://github.com/confidential-containers/guest-components/tree/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a), with the existing [Trustee appraisal](trustee-attestation.md) and [requester key delivery](key-delivery.md). The integrated hardware profiles are SNP and TDX CPU. Real hardware, a measured protected launcher and secure deployment remain required before customer execution.

## One session, one guest key

`GuestEvidenceSession.create({initialization, policy, challenge, expectedBinding, requester, jobId, funding, agentUrl})` takes the requester's pinned appraisal policy, fresh challenge and retained initialization assignment. It checks the [initialization commitment](guest-initialization.md) before generating a channel key. `InitializedGuestControlPlane` supplies the expected binding, requester and job identifier from the assignment retained during service startup and requires [signed funding configuration](guest-workload.md#fresh-funding-inside-the-guest). Direct low-level sessions may omit `funding` for protocol checks; those sessions do not perform guest funding verification. The measured launcher must also check the actual loaded runtime and placement against that assignment. Never copy untrusted host input into both the challenge and the expected assignment and treat equality as approval.

The session checks the challenge against that retained assignment and policy. It generates a non-extractable WebCrypto P-256 ECDH private key and exposes only a copy of its public JWK. Callers cannot provide an external channel key. The private key has no serialization, file or environment export path in this API. Non-extractability restricts software APIs; it does not protect an ordinary process from its host administrator. The session must run inside the reviewed confidential guest control plane.

`await session.evidence()` first checks the guest-local `/info` response. The expected version string is `Guest Components Version: v0.22.0`, the primary TEE must match the policy, the REST server must use `feature: attestation`, and additional TEEs must be absent. A reported version is a compatibility check, not proof of the installed binary. `protocolRevision` identifies the source used for this adapter; actual guest provenance comes from the approved measured build and verified hardware report.

The session then requests `/aa/evidence` with `encoding=base64`. `runtime_data` is unpadded base64url of **64 raw bytes**: SHA-384 of the canonical structured challenge/public-key data, followed by 16 zero bytes. It is neither the JSON text nor printable hex. This matches the pinned upstream SNP/TDX attesters and Cannabis's independent Trustee-result check. The response's original evidence bytes are encoded as base64url for the Trustee request.

Only literal loopback HTTP origins are accepted, by default `http://127.0.0.1:8006`. Requests use direct HTTP connections, without DNS, proxy configuration or redirect following. Agent information is capped at 4 KiB and raw evidence at 3 MiB, fitting the requester's 4 MiB encoded bound. Each request has a 15-second default deadline, configurable up to 60 seconds; challenge expiry also closes the session. Errors never include response bodies. Unsupported platforms, accelerator profiles, failures and expired challenges have no alternative execution path.

The evidence result reports `hardwareVerified: false`. The requester must submit it to its trusted Trustee deployment and verify the returned signed appraisal. The local evidence collector does not validate vendor signatures or establish trust from `/info`.

## Connect collection to requester approval

1. The requester creates a fresh challenge for the exact funded lease, reservation, runtime, task, attempt and rank.
2. The approved guest launcher creates the session and calls `evidence()`. Retain that same live session; only the public channel JWK and evidence travel to the requester.
3. On the requester, `requestTrusteeResult(...)` obtains and verifies the EAR while leaving the challenge pending. The key-delivery CLI exposes this as `appraise`, using the trusted local configuration's `trusteeEndpoint`.
4. The requester prepares and signs the existing EIP-712 delivery approval. `sealJobKeyDelivery(...)` verifies the appraisal again, rechecks current funding and the service window, recovers the per-job input key, and atomically journals its encrypted envelope while consuming the challenge.
5. Deliver the encrypted envelope and approved payload to that same guest session through the forthcoming authenticated dispatcher. `await session.open(envelope, payload)` compares every retained challenge binding, requester, job and channel key before checking the signed envelope. Concurrent opening calls cannot both succeed. A successful opening consumes the session; a failed opening closes it.
6. Keep the returned non-enumerable `job.identity` exclusively inside the guest. Alternatively, use `session.prepare(envelope, payload, trustedSource, {maxBytes})` to open the envelope and run the [guest workload decoder](guest-workload.md) directly through private control-plane pipes. It verifies the original package, private contract, selected task, runtime/rank binding and result recipient before exposing files. The reviewed launcher must still enforce resource limits, allowed networking, output encryption and execution admission.

`session.close()` aborts pending requests, retires references to the channel key and evidence, and stops the session timer. Expiry does the same automatically. This is a process-local lifecycle, not a durable execution replay database or a guarantee of immediate erasure from all runtime copies. Clock integrity, VM rollback, teardown and enforcement after key delivery remain responsibilities of the reviewed runtime and its operational control protocol.

## Inspect an installed guest agent

Inside the intended guest control plane:

```sh
node scripts/compute-guest-probe.mjs snp
node scripts/compute-guest-probe.mjs tdx http://127.0.0.1:8006
```

Choose the one profile actually provisioned. This command checks `/info` only. It creates no channel key, collects no quote and reports no verified hardware. An unavailable agent is a failure, rather than an emulated TEE. No agent is installed or started by this command.

## Deployment boundary

The upstream REST bridge's loopback restriction alone does not separate mutually untrusted programs inside a guest. Its attestation feature also exposes other AA routes. The measured launcher must restrict the bridge, attestation socket and hardware devices to the trusted control plane, keep customer code in separately enforced isolation, and bind the actual runtime/initialization policy into measured boot. Do not expose these routes through a host proxy or enable a general evidence service for arbitrary workloads. Upstream documents the [evidence-factory risk](https://confidentialcontainers.org/docs/features/get-attestation/): interchangeable guest measurements can otherwise let another workload obtain evidence accepted by the same policy.

A complete deployment still needs approved image construction, a real Trustee deployment and vendor collateral, physical resource admission, authenticated envelope transport, protected storage and workload launch, encrypted peer channels, execution replay/termination controls and independent review. CPU-only evidence does not authorize CUDA, AMD GPU or other accelerator work. Each protected accelerator/interconnect path remains a separate integration.

Automated checks exercise the pinned REST wire format with an explicitly synthetic local agent, real ephemeral channel keys, a signed EAR fixture, actual encrypted age packages and requester signatures, and funded escrow contracts on an isolated chain. They cover byte-for-byte report binding, profile mismatch, host-assignment substitution, response limits, cancellation, timeout, expiry and concurrent opening. They establish the software protocol behavior; actual SNP/TDX evidence and protected execution are not claimed by these fixtures.

Pinned upstream references: [REST routing](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/api-server-rest/src/router.rs), [version construction](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/api-server-rest/build.rs), [SNP attester](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attester/src/snp/mod.rs), [TDX attester](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attester/src/tdx/mod.rs).
