# From an attested channel to the approved workload

The guest control-plane integration can now open its requester-approved key delivery and decode the corresponding workload. It checks the encrypted package, private job contract, selected task, runtime digest, execution rank, group size, artifact inventory and return recipient before publishing decoded files at the configured guest path. It never starts a program.

`compute/guest_workload.py` implements the decoder. `compute/guest_workload.mjs` connects it to `GuestEvidenceSession.prepare(...)` through anonymous local pipes. This is a software integration for an approved confidential guest; measured guest construction, real vendor evidence, protected storage and the runtime launcher still need validation.

## Task identity without exposing launch arguments

New package descriptors include `requirements[i].taskSHA256`. The commitment is SHA-256 over these concatenated bytes:

1. ASCII `cannabis.task.v1` followed by one zero byte.
2. The 32 raw bytes of the encrypted package's SHA-256.
3. The zero-based task index as an unsigned, four-byte, big-endian integer.

The package commitment already binds the complete encrypted manifest and artifacts. The index selects the exact task within that manifest. This avoids publishing a separate hash of private launch arguments that someone could attempt to guess. The existing public descriptor already exposes dependency indices and resource requirements. Python's `task_binding_sha256(...)` and the descriptor provide the value; the integration checks the same byte encoding from JavaScript.

Use that value in the task's attestation challenge and signed key-delivery approval. Existing packages can derive it from their saved ciphertext commitment and task index without re-encrypting anything. The protected decoder rejects a task commitment that does not select a task in the authenticated package.

## Prepare inside the guest

After collecting evidence from the same live guest session and obtaining the approved encrypted envelope:

```js
const prepared = await session.prepare(envelope, expectedApproval, {
  python: trustedPythonPath,
  age: trustedAgePath,
  ciphertext: encryptedPackagePath,
  destination: protectedInputDirectory
}, {
  maxBytes: approvedInputByteLimit,
  timeoutMs: 600000
});
```

All four paths must be absolute, trusted guest configuration. The Python helper runs in isolated mode; the per-job secret and private contract cross anonymous pipes, never command-line arguments, environment variables or log files. The helper does not need the requester's recovery identity. Its private `workload` result is non-enumerable on the returned JavaScript report, reducing accidental disclosure through ordinary object serialization. Trusted code can read `prepared.workload`; it must keep that data inside the protected control plane.

The original guest session still enforces requester signatures, its retained assignment, its non-extractable channel key and single consumption. Preparing files consumes that session too. `executionAuthorized` remains false. Hardware admission, current funding, task dependencies, permitted networking, resource enforcement and actual runtime measurement must be checked by the reviewed launcher before execution. In particular, comparing two supplied runtime digests does not prove that a runtime binary has been loaded.

## Verify before publishing files

The archive reader copies the ciphertext into a private staging directory while hashing those exact bytes. It then decrypts that verified snapshot, avoiding a source-path replacement between verification and decryption. Links, reparse points and non-regular input files are rejected. Ciphertext staging has a size bound derived from the permitted plaintext size plus bounded archive/encryption overhead.

The decoder authenticates the complete age stream and every artifact hash. It then requires a workload archive whose job, policy and requester return recipient match the delivered key. Its file inventory must exactly match the private manifest. The selected runtime digest and node count must match the retained approval, and the rank must be valid. Current CPU appraisal rejects requested accelerators or accelerator memory; other device profiles require their own validated integration.

Decoded files stay in owned staging until every check passes. Ordinary failures clean up that staging, and existing destinations are never reused or overwritten. The returned report exposes only public bindings, index, rank, byte/file counts and verification status. It contains no launch arguments, artifact names, code or secret key.

## Storage, interruption and deployment

The measured launcher must provide protected guest storage for both staging and destination. An ordinary host-visible directory, shared mount or unencrypted VM disk does not meet the worker-operator privacy requirement. Reserve space for the ciphertext snapshot **and** decoded inputs; `maxBytes` limits decoded file bytes, not total volume usage. Keep swap, crash dumps and diagnostics within the reviewed protection policy.

The pipe defaults to a ten-minute deadline and accepts a configured deadline up to one hour. Closing the guest session also cancels an ongoing preparation, including after its envelope has been consumed. A cancelled, timed-out or failed preparation returns no successful report. The consumed session cannot be reused.

The decoder and its trusted decryption subprocesses have a shared termination boundary. On POSIX systems the helper starts in a separate session; timeout, cancellation, oversized output and helper exit terminate that process group. On Windows the helper establishes a non-inheritable kill-on-close job before reading keys or spawning descendants. If containment cannot be established, preparation fails. The parent handles helper exit before waiting for pipe closure, so an orphan holding an inherited pipe cannot keep a completed preparation waiting indefinitely. These mechanisms follow [Node's process-session behavior](https://nodejs.org/api/child_process.html#optionsdetached) and [Windows job limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information).

This boundary contains the trusted decoder's subprocesses; it is not isolation for arbitrary customer programs. It does not enforce CPU, memory, disk or network limits. If the controlling Node process itself crashes, the reviewed worker supervisor must dispose of the helper and its descendants independently. It must also discard incomplete staging and any unacknowledged destination, enforce storage quotas and keep those files protected throughout cleanup. Pipe shutdown waits up to five additional seconds before reporting a failure without a cleanup guarantee. Never launch from directory existence alone. Cleanup does not promise physical erasure from underlying storage or all language-runtime memory copies.

Verification uses real age packages and disposable keys, signed requester approvals and funded escrow on an isolated local chain, with explicitly synthetic attestation-agent and verifier fixtures. It covers source substitution, malformed or mismatched private contracts, task/runtime/rank mismatch, inventory and return-recipient checks, CPU/device mismatch, byte limits and concurrent session consumption. Process tests create a helper, child and grandchild, check their termination after timeouts and other faults, and verify that an unrelated process remains running. Real SNP/TDX execution and protection against a hostile worker host remain tracked in the [hardware-validation milestone](https://github.com/peter-ch/Cannabis/issues/1).
