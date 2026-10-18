# A separate input key for every job

`pack-job` gives each workload a fresh age X25519 identity. The job's input key can decrypt its encrypted workload; the requester retains a separate identity for key recovery and returned results. This prepares confidential key delivery without sharing a general requester identity or changing a package already committed in escrow.

The implementation is `compute/job_keys.py`, exposed by `scripts/compute-client.py`. It uses the existing pinned [age tool](https://github.com/FiloSottile/age/tree/v1.3.2). No new encryption algorithm is introduced.

## Files and commitments

```sh
python scripts/compute-client.py pack-job workload.json ./artifacts REQUESTER_AGE_RECIPIENT ../private/jobs/job-id
```

This creates an exclusive directory containing:

| File | Contents and handling |
| --- | --- |
| `workload.age` | Streaming encrypted private manifest and allowlisted artifacts, encrypted to the new job input key |
| `job-key.age` | Small encrypted key record for the requester; keep in private custody |
| `descriptor.json` | Public `cannabis.package.v2` metadata: package digest/size, input public recipient, resource/runtime requirements, dependency indices and key-capsule digest/size |

The requester public recipient is embedded as `resultRecipient` in the **encrypted** manifest. It is not added to the public descriptor. `seal-result` rejects a recipient different from that private contract, and requester assembly rejects a mismatched result receipt. The requester identity is different from the job input identity; knowing the latter does not unlock returned ciphertext. A worker still knows the result while computing it inside the protected environment, so confidential execution remains mandatory.

The key capsule contains the job ID, encrypted package SHA-256 and byte count, policy digest, input public recipient, requester return recipient and exactly one job input identity. It is encrypted to the requester's public recipient. The corresponding private requester identity is not needed to package a job and is never included in the capsule.

Only ciphertext and public metadata are written during packaging. Input keys and the small plaintext key record stay in process memory and pipes. Python and child processes do not provide a guaranteed memory-zeroization or swap/crash-dump guarantee; the requester machine must be trusted and protected. No plaintext archive or private-key temporary file is created by this path.

The implementation stages the encrypted files locally, reserves the destination directory exclusively, then publishes `descriptor.json` last as the ready marker. Existing files/directories are never overwritten. A process or system crash can leave an incomplete directory; do not submit it or treat it as ready without its complete descriptor, verified commitments and recovery check. This is not a multi-file filesystem transaction. Errors clean up owned staging and published links while preserving unrelated files. The filesystem must support hard links within the destination volume.

## Verify requester recovery

Keep the descriptor saved by the requester when packaging. Do not substitute metadata supplied by a worker or storage operator. Compare the package and policy commitments with the ones approved for the intended order:

```sh
python scripts/compute-client.py verify-job-key ../private/jobs/job-id/job-key.age ../private/requester.dpapi.json ../private/jobs/job-id/descriptor.json --package-sha256 APPROVED_PACKAGE_SHA256 --policy-sha256 APPROVED_POLICY_SHA256
```

On Windows, `init-key` creates a CurrentUser DPAPI requester vault. Other platforms can use one native age X25519 identity from protected local custody. Existing identity comments are accepted. This path does not support plugin identities, SSH keys, multiple requester identities or post-quantum age recipients. No secret is accepted on the command line or printed by the recovery command.

Recovery checks the bounded capsule's exact digest and size, authenticates its entire age stream, checks its inner job/package/policy bindings, derives the public recipient from the recovered input key, and confirms that the return recipient belongs to the supplied requester identity. It reads from a private temporary copy of the checked **ciphertext**, avoiding a change between source-file hashing and decryption. Duplicate record fields, malformed identities, cross-job capsules, wrong owners, tampering and oversized records are rejected.

The Python API `recover_job_key(...)` returns a `RecoveredJobKey` object in memory. Its ordinary representation hides the identity. Trusted callers must still avoid logging or serializing its `identity` member. The CLI returns only `jobKeyVerified`, job/package/policy identifiers and `keyReleaseAuthorized: false`. The check validates the saved capsule and descriptor bindings; it is not an independent statement that a worker executed anything.

Keep the encrypted capsule, original descriptor and protected requester identity available for recovery. A DPAPI vault still depends on its Windows account keys; syncing the encrypted capsule does not replace an owner-verified backup of the requester identity. Capsules can be moved between supported operating systems when the owner supplies the corresponding protected native identity.

## Attested delivery integration

The [requester-approved key-delivery component](key-delivery.md) now wraps the input key to a fresh, attested guest-generated channel key after requester-signature, workload/policy, accepted funded-lease, current-head and service-window checks. It journals encrypted delivery artifacts locally. [Trustee result checks](trustee-attestation.md) supply one part of that decision. A complete protected runtime, device/interconnect path, authenticated dispatcher and peer network still require integration and hardware validation.

The package is encrypted to a stable per-job identity, so channel wrapping preserves its original ciphertext commitment. Never re-encrypt a funded workload silently or hand a worker the requester's recovery identity. Packaging and recovery leave execution/key-release authorization false; the delivery component reports a wrapped artifact separately and never claims transmission or execution.
