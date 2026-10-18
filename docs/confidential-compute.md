# Confidential computation

Every Cannabis customer job requires encrypted code and data, plus protection during execution. **This is a mandatory service requirement.** The repository contains authenticated-encryption primitives, a planner that refuses plaintext workload fields, a [Trustee attestation-result integration](trustee-attestation.md) with pinned verifier trust and single-use challenges, and [requester-approved encrypted key-delivery preparation](key-delivery.md). Vendor evidence verification must run in the requester's trusted Trustee deployment. The protected worker runtime, authenticated dispatcher and accelerator/interconnect profiles remain to be integrated and independently reviewed. No private customer workload is currently being dispatched.

## Protected data path

1. The requester encrypts the private job bundle, inputs and starting weights locally. Entrypoints, arguments, input filenames, acceptance details and credentials stay inside encrypted objects. Use opaque job IDs.
2. Storage providers and worker operators receive ciphertext. Public scheduling metadata contains only the required resource/runtime information, ciphertext digests and payment terms.
3. Before keys are released, the requester's trusted verifier validates fresh, vendor-rooted CPU and accelerator attestation evidence, approved boot/runtime measurements, supported firmware/security versions, revocation status and disabled debug access.
4. A job-specific ephemeral public key is generated inside the protected environment and cryptographically bound to its attestation, job, policy, challenge and lease. Deliver wrapped content keys only to that verified channel, never to a host agent or an ordinary container.
5. Custom programs run within the attested confidential environment. Use protected memory and the supported CPU–accelerator path. Encrypt scratch storage, swap, logs, checkpoints and crash reports; do not send plaintext telemetry to operators.
6. Every distributed rank must pass the same policy. Authenticate and encrypt rendezvous, gradients, collectives, checkpoint transfers and other peer traffic. Disable unprotected RDMA or network paths. Re-attest replacements before they join or receive keys.
7. Encrypt outputs for the requester before they leave the protected environment. Evaluate them in another approved protected environment or on the requester's own machine. Expire job credentials and destroy ephemeral keys at teardown.

There is no downgrade to ordinary workers when confidential capacity is unavailable. A worker advertising “confidential=true” is not evidence. The current planner can identify candidate capacity but always reports **executionAuthorized=false** and **keyReleaseAuthorized=false**.

## Hardware support

Before provisioning a worker, check its measured boot and initialization controls against the [worker deployment requirements](worker-deployment.md). Confidential VM products differ in the evidence and launch controls they expose.

Confidential CPU execution can use supported [AMD SEV-SNP platforms](https://www.amd.com/en/developer/sev.html) or [Intel TDX platforms](https://www.intel.com/content/www/us/en/security/confidential-computing.html), subject to verified configuration and current security policy. An AMD CPU TEE does not automatically protect an attached AMD GPU.

NVIDIA documents confidential GPU execution and attestation for supported hardware/configurations, including [H100-class confidential GPU environments](https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/gpu_and_switch_attestation.html). GPU, CPU and interconnect protection must all cover the job's data path.

CUDA, ROCm, CPU and other accelerator runtimes remain scheduling targets. Each needs a validated confidential execution path before it may process customer data. Ordinary consumer GPUs and ordinary containers do not satisfy this requirement merely because disks and connections are encrypted. No broad claim of confidential support across all AMD, NVIDIA or other chips is made.

## Encryption primitive

`scripts/compute-crypto.mjs` implements bounded AES-256-GCM envelopes for private instructions and metadata, using Node's standard cryptography library. It uses 32-byte content keys, random 12-byte nonces, 16-byte authentication tags and authenticated job/policy context. Keys are supplied in memory; the module never saves or logs them. Use a fresh content key per bundle, keep it out of manifests, and store any owner recovery copy in an encrypted key store.

This primitive is not a sandbox or attestation service. It supports bundles up to 32 MiB. Large datasets need a separately reviewed chunked encryption/storage format, with integrity, ordering, completeness and replay protection. Do not invent unauthenticated chunking around the primitive.

The general-purpose [workload client](universal-compute.md) uses age's established authenticated streaming format for larger archives and per-rank results. Its [per-job key custody](job-key-custody.md) creates separate input identities and encrypts their recovery capsules for the requester, while results use the requester identity. It verifies context, file commitments and complete decryption before exposing returned files. Independent review and attested key delivery are still required. Packaging alone does not authorize a worker.

The manifest commits to ciphertext digests. The protected launcher must verify those digests, signed requester terms and the key-release policy before decoding instructions. Never import, deserialize or execute job code in the host control plane.

## Threat model and release evidence

Protect job contents against ordinary worker administrators, storage operators and network observers within the selected platform's security assumptions. Hardware/firmware vulnerabilities, side channels, denial of service and malicious requested code still require review and mitigation; encryption is not an unconditional guarantee.

Resource requirements, job timing, ciphertext sizes and public-chain payments can reveal metadata. ZK community eligibility does not hide those payments. Minimize and expire off-chain records, avoid public dataset/model names, and document the remaining visibility.

Release checks include wrong-key and tampering rejection, policy/job substitution, stale or forged attestations, downgraded firmware, debug mode, host memory access, plaintext logs/swap, unsafe GPU paths, unauthorized peer joins, unencrypted collective traffic, key-release retries, cancellation and encrypted output recovery. Passing envelope tests alone does not establish confidential execution.
