# From an attested channel to the approved workload

The guest decoder can open its requester-approved key delivery and decode the corresponding workload. It checks the encrypted package, private job contract, selected task, runtime digest, execution rank, group size, artifact inventory and return recipient before publishing decoded files at the configured guest path. The decoder itself never starts a program. A separate native execution API connects a retained service profile to runtime preparation and execution, as described below.

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

The original guest session still enforces requester signatures, its retained assignment, its non-extractable channel key and single consumption. Preparing files consumes that session too. `executionAuthorized` remains false. A session configured with funding performs the checks below; hardware admission, task dependencies, permitted networking, resource enforcement and actual runtime measurement still require the reviewed launcher. In particular, comparing two supplied runtime digests does not prove that a runtime binary has been loaded.

## Fresh funding inside the guest

`createMarketLeaseProof` in `compute/market_lease.mjs` reads the complete activated [on-chain booking group](decentralized-compute.md#protected-booking-and-key-delivery-binding) and its fully accepted escrow at one finalized canonical block. The portable proof contains public commitments and an anchor, with no customer code, arguments, content keys or decrypted artifacts. It is limited to 1 MiB and 64 bookings; bound transport before parsing too. Offline `verifyMarketLeaseProof` reconstructs commitments, quotes and exact worker shares but does not prove the records exist. Both requester and guest independently reread the chain before keys are used. Historical `exportLeaseProof` utilities remain for isolated legacy checks and are rejected by the retained operating launcher.

The initialized control plane requires this configuration when creating a session:

```js
const funding = {
  proof: marketLeaseProof,
  context: approvedMarketDomain, // chainId, market, token
  network: approvedNetwork,      // authenticated RPC and pinned release hashes
  provider: approvedProvider,
  resourceId: approvedResourceKey, // provider-qualified on-chain resource key
  serviceSHA256: approvedServiceCommitment
};
```

The guest retains its own copies. The approved domain, provider, resource, service and RPC/release pins must come from reviewed measured configuration. They cannot be taken from the same host message as the proof. Resource promises still require actual capacity admission and enforcement; checking a signed service commitment does not supply hardware or prove exclusive allocation across separate registries.

`GuestFunding` rereads the original block and verifies the activated booking group and fully accepted escrow funding. Activation deadlines are enforced by the immutable market contract; the finalized observation itself may be later than hold expiry. It then checks a fresh finalized snapshot and a canonical latest head, including all worker acceptances, exact settlement terms, fee policy, market/escrow/asset runtime pins and network identity. The original and fresh finalized anchors must remain canonical through the last read. State reads use hash-bound requests with `requireCanonical`, as specified by [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898). The selected RPC is a reviewed trust dependency; these observations are not a consensus light client or a guarantee against later chain changes.

A funded session repeats those reads before and after opening its requester-approved envelope. Cancellation, a changed order, stale observations or an elapsed service interval retire the session without returning a key. The short challenge/key-delivery expiry is separate from the signed service interval. A signing hold may have expired while a genuinely funded reservation remains valid. The session exposes a copy of `serviceInterval`; its preparation timeout is capped by the remaining interval, with a final expiry check before returning success. A retained monotonic deadline prevents refreshing the gate from restarting that interval, and backward wall-clock changes fail. Trustworthy time and resistance to a hostile host pausing or rolling back the entire VM still require the outer protected lifecycle.

Native ETH uses the zero address only for the payment asset and an explicit
`tokenCodeHash: null`. Its signed offers, durable reservations, lease proof and
key-release checks preserve that asset binding. The escrow implementation remains
pinned and its on-chain asset is checked at canonical block hashes. ERC-20 funding
also requires the pinned nonempty token implementation; neither path permits zero
provider, requester or escrow addresses. An ETH service order does not depend on
opening Cannabis community claims first.

This gate does not launch `NativeTaskPlan`. The [native execution path](guest-image-build.md#encrypted-native-task-execution) now requires one retained deadline across decoding, execution, result sealing, publication and cleanup; its helpers and runtime guardians enforce the same remaining reservation. The operating bridge must bind that deadline to this session's independently verified service interval without resetting it, enforce whole-VM resource reservations and retire the guest/key state on every failure. Current checks use real signatures, encrypted packages and escrow contracts on an isolated chain with synthetic attestation fixtures; they do not establish hardware admission or a real paid job.

## Verify before publishing files

The archive reader copies the ciphertext into a private staging directory while hashing those exact bytes. It then decrypts that verified snapshot, avoiding a source-path replacement between verification and decryption. Links, reparse points and non-regular input files are rejected. Ciphertext staging has a size bound derived from the permitted plaintext size plus bounded archive/encryption overhead.

The decoder authenticates the complete age stream and every artifact hash. It then requires a workload archive whose job, policy and requester return recipient match the delivered key. Its file inventory must exactly match the private manifest. The selected runtime digest and node count must match the retained approval, and the rank must be valid. Current CPU appraisal rejects requested accelerators or accelerator memory; other device profiles require their own validated integration.

Decoded files stay in owned staging until every check passes. Ordinary failures clean up that staging, and existing destinations are never reused or overwritten. The returned report exposes only public bindings, index, rank, byte/file counts and verification status. It contains no launch arguments, artifact names, code or secret key.

## Storage, interruption and deployment

The measured launcher must provide protected guest storage for both staging and destination. An ordinary host-visible directory, shared mount or unencrypted VM disk does not meet the worker-operator privacy requirement. Reserve space for the ciphertext snapshot **and** decoded inputs; `maxBytes` limits decoded file bytes, not total volume usage. Keep swap, crash dumps and diagnostics within the reviewed protection policy.

The pipe defaults to a ten-minute deadline and accepts a configured deadline up to one hour. Closing the guest session also cancels an ongoing preparation, including after its envelope has been consumed. A cancelled, timed-out or failed preparation returns no successful report. The consumed session cannot be reused.

The decoder and its trusted decryption subprocesses have a shared termination boundary. On POSIX systems the helper starts in a separate session; timeout, cancellation, oversized output and helper exit terminate that process group. On Windows the helper establishes a non-inheritable kill-on-close job before reading keys or spawning descendants. If containment cannot be established, preparation fails. The parent handles helper exit before waiting for pipe closure, so an orphan holding an inherited pipe cannot keep a completed preparation waiting indefinitely. These mechanisms follow [Node's process-session behavior](https://nodejs.org/api/child_process.html#optionsdetached) and [Windows job limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information).

This boundary contains the trusted decoder's subprocesses; it is not isolation for arbitrary customer programs. It does not enforce CPU, memory, disk or network limits. If the controlling Node process itself crashes, the reviewed worker supervisor must dispose of the helper and its descendants independently. It must also discard incomplete staging and any unacknowledged destination, enforce storage quotas and keep those files protected throughout cleanup. Pipe shutdown waits up to five additional seconds before reporting a failure without a cleanup guarantee. Never launch from directory existence alone. Cleanup does not promise physical erasure from underlying storage or all language-runtime memory copies.

The [encrypted native task path](guest-image-build.md#encrypted-native-task-execution) adds a separate Linux integration using this decoder: each decode/encode helper enters a resource group before reading its private request and has an independent guardian, while staging uses an explicitly bounded unswappable filesystem. That path verifies the retained runtime tree, executes one supported native task in the sandbox, and seals declared outputs for requester reconstruction. It does not upgrade `session.prepare()` implicitly. The native API below supplies the session connection; a complete admitted launcher, protected transport and the outer guest/key lifecycle remain required before customer operation.

## Funded native execution readiness

`GuestJobScope` starts a pinned trusted control program inside a bounded cgroup
leaf before that program creates the initialized session. An independent outer
guardian holds no customer keys and owns the whole job subtree. The parent limits
cover the control leaf and every decoder, runtime and encoder leaf. Parent death,
deadline expiry, aggregate memory exhaustion and failed completion retire the
subtree. A shorter control-plane time limit also shortens the whole job deadline.

Create the session with `execution: { profile, source }` alongside its approved
funding configuration. Both objects must come from independently approved measured
configuration. `source` contains trusted absolute `python`, `rootfs`, `age`,
`ciphertext` and `destination` paths. Version 2 of the native service profile
(`cannabis.guest-native-service.v2`) specifies the native
runtime inventory, task resources, control/helper limits, aggregate limits, scratch
and staging quotas, ciphertext storage, extraction bound and tool hashes. Its canonical SHA-256 must
match the signed reservation's `serviceSHA256` and its exact unit count. This
adapter represents one reserved service unit; it cannot reinterpret a group or
accelerator reservation as one CPU task. The profile reserves concurrent control,
helper and workload capacity, plus scratch, staging and ciphertext filesystem
quotas. Version-1 profiles are refused because they do not budget ciphertext.

The mandatory `ciphertext` object contains `bytes`, `inodes`, `inputBytes` and
`outputBytes`. The page-rounded input and output limits must fit concurrently
inside the byte quota, which also counts against the aggregate service budget.
The fixed outer launcher creates a new dedicated `noswap` tmpfs with signed
byte/inode limits and `nosuid,nodev,noexec` restrictions. Its two paths must be
`workload.age` and `result.age` in that same private directory. These filesystem
ceilings do not reserve physical machine capacity; whole-VM admission is separate.

The requester streams the already encrypted package with bounded frames before
the guest creates evidence/session keys. Intake checks the complete size and
assignment hash, then publishes an exclusive read-only input file. An upload
acknowledgement is only a peer report, not hardware attestation or key approval.
Native admission independently verifies the actual kernel mount, quotas,
permissions, file identity and package hash before readiness. Output publication
also enforces `outputBytes`; checked retirement removes the whole volume.

```js
const session = await control.createSession({
  policy, challenge, funding,
  execution: { profile: approvedNativeService, source: approvedGuestPaths }
});
// Collect and verify this session's hardware evidence before approving delivery.
const result = await session.executeNative(envelope, expectedApproval);
// result.resultEnvelope is encrypted; result.ciphertext identifies encrypted output.
// The requester opens the receipt with its separately recovered result secret.
```

The helper first checks its real shared cgroups, the live parent process, the
approved runtime inventory, tool pins, retained ciphertext and storage limits,
and remaining service deadline. Only then
does it issue a fresh readiness nonce. The session rechecks funding around key
opening and sends the key in a nonce-bound second frame. A session bound to this
execution profile refuses direct `open()` and `prepare()` calls. Closing the
session cancels the channel; late key-opening completion cannot transmit a key
after cancellation. Frames have byte limits and travel through anonymous local
pipes or unnamed Unix socket pairs. Regular files and named/network sockets are
not accepted as key channels.

The native plan consumes the same deadline for decoding, execution, sealing and
checked cleanup. Native sessions require a version-2 approval with a fresh result
secret commitment. The private receipt is authenticated and encrypted as described
in [result return](key-delivery.md#authenticated-private-result-return); the API
exposes its encrypted envelope and no plaintext receipt. The output path remains
non-enumerable. Fresh funding is checked again before result sealing and the
remaining deadline is checked after sealing. A successful report is still not
requester quality acceptance, a payment authorization or hardware attestation.

Owned kernel checks cover encrypted execution and separate requester reconstruction,
changed resource controls/runtime inventory, changed input or storage limits,
insufficient reservation capacity,
control-process death and the common deadline. Protocol checks cover malformed and
out-of-order frames, mismatched service/nonce, failed exit and cancellation during
key opening. Local-chain checks verify signed service/unit matching and refusal to
bypass readiness. An additional combined Linux check now carries one signed ETH
reservation through fresh funded admission, the actual native runtime, encrypted
result reconstruction and exact 99% worker / 1% founder settlement, including
worker withdrawal and whole-tree cleanup. It uses disposable keys, an isolated
chain and synthetic appraisal. The requester and guarded guest now run in separate
processes using the [encrypted streaming handoff](key-delivery.md#encrypted-streaming-handoff),
with requester recovery, active-attempt checks and a signed storage acknowledgement.
The requester reconstructs its downloaded copy in a fresh process before separate
application acceptance and settlement. The outer process now verifies the signed
launch package before creating the job scope. A changed package is refused before
allocation; the contained session rechecks the same sealed snapshot. An opaque
relay watches the guardian and control process while carrying encrypted input
and results under separate directional byte limits. The guest starts with an
empty ciphertext volume; input is streamed from the separate requester process
before evidence, and the volume must be retired after delivery.
Fixture setup still creates disposable
custody on the same ordinary machine; this does not establish protection from its
operator, an admitted production launcher or hardware admission. After compiling and installing the pinned
verification prerequisites, run:

```sh
sudo env PATH="$PATH" /usr/bin/python3 -I -B scripts/check-funded-native.py
```

The complete operating launcher and genuine paid acceptance,
whole-VM overhead/disposal, trustworthy time against host pause or rollback,
protected distributed/accelerator paths and independent review remain unfinished.

Verification uses real age packages and disposable keys, signed requester approvals and funded escrow on an isolated local chain, with explicitly synthetic attestation-agent and verifier fixtures. It covers source substitution, malformed or mismatched private contracts, task/runtime/rank mismatch, inventory and return-recipient checks, CPU/device mismatch, byte limits and concurrent session consumption. Process tests create a helper, child and grandchild, check their termination after timeouts and other faults, and verify that an unrelated process remains running. Real SNP/TDX execution and protection against a hostile worker host remain tracked in the [hardware-validation milestone](https://github.com/peter-ch/Cannabis/issues/1).
