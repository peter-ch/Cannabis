# Binding a guest to its approved assignment

Each confidential guest must retain the same assignment the requester approved. Cannabis commits that assignment into the hardware initialization field before opening an evidence session. A changed package, runtime, task, payment binding, requester or execution rank changes the commitment.

`compute/guest_initialization.mjs` defines this commitment. `compute/guest_bootstrap.mjs` starts the pinned evidence services and retains one assignment for one session. The current boot image exercises refusal on unsupported hardware; actual SNP/TDX acceptance and protected customer execution remain separate deployment requirements.

## Prepare the commitment

Start with the complete activated on-chain booking group and a separately reviewed version-3 launch configuration. `validateGuestConfiguration(...)` validates and hashes the full public configuration. Pass that hash to `configuredMarketAttestationBinding(...)`, together with the market proof, selected booking and approved run. Take the requester and opaque job identifier from that same verified booking group. The input has exactly five fields:

```json
{
  "schema": "cannabis.guest-initialization.v2",
  "tee": "snp",
  "requester": "<requester public address>",
  "jobId": "<opaque job identifier>",
  "binding": "<complete approved binding object>"
}
```

The placeholders illustrate the shape; the preparation command requires actual validated values. The binding includes the network, escrow, order, lease, reservation, encrypted package, workload policy, runtime, task, attempt, rank, group size, accelerator class and `configurationSHA256` as a nonzero `0x`-prefixed 32-byte digest. Current evidence profiles accept CPU only. Customer source, arguments, data, identity secrets and keys do not belong in this file. Keep scheduling metadata private even though the initialization commitment is not a secret.

```sh
node scripts/prepare-guest-init.mjs \
  --input /private/approved-assignment.json \
  --out /private/initialization.json
```

The command validates the assignment, normalizes Ethereum addresses and writes sorted compact JSON followed by one newline. It refuses to overwrite an existing destination. The digest covers the JSON bytes without the trailing newline: SHA-256 for SNP's 32-byte `HOST_DATA`, SHA-384 for TDX's 48-byte `MRCONFIGID`. The output supplies both hex and standard base64. Put the hex digest in the requester's pinned appraisal policy; supply the identical bytes through the reviewed VMM's initialization controls. Neither preparing a file nor setting a launch field proves hardware acceptance.

The guest accepts only that canonical file encoding, at most 64 KiB. Unknown fields, duplicate-key encodings, invalid UTF-8, unsupported hardware classes and invalid rank placement fail. Linux opens refuse symlinks and nonregular files before reading. The file is copied into retained process state once; subsequent edits cannot replace the running assignment.

The configuration policy template has `measurements.initData: null`. First hash
that complete configuration, then include its hash in the assignment, and finally
derive the hardware initialization digest and concrete appraisal policy. This
order avoids a circular hash. The requester compares the resulting policy to its
own pinned policy before key recovery. Changing an RPC, contract pin, verifier,
runtime, tool, service or transport limit changes the assignment commitment.

The operating entry requires configuration v3 and initialization v2 together.
Historical v1 initialization and older configuration parsing remain explicit
offline component utilities. They cannot be substituted into the operating entry
or used to remove the configuration field from a v3 key approval.

## Start inside the measured control plane

```js
const plane = await InitializedGuestControlPlane.start({
  initializationFile: '/run/approved/initialization.json'
});
try {
  const session = await plane.createSession({ policy, challenge, funding, execution });
  const evidence = await session.evidence();
  // Send evidence to the requester through the reviewed authenticated transport.
} finally {
  await plane.close();
}
```

The caller must import `InitializedGuestControlPlane` from `compute/guest_bootstrap.mjs`. This API is for a dedicated measured Linux guest with trusted control-plane access. It is not a host-side worker installer or a public HTTP service.

Startup verifies both service executable hashes against the image input lock, reserves a private runtime directory and starts the agent with `--initdata-digest`. It passes no TOML override and inherits no caller environment. The pinned upstream agent compares the supplied bytes with the hardware field before binding its RPC socket. Cannabis additionally rejects the upstream unsupported-platform branch, which otherwise continues without that comparison. The REST bridge is restricted to attestation on literal loopback; startup verifies the listening socket belongs to the process it launched before querying it.

`createSession` derives requester, job and placement from the retained assignment. It requires `funding`: the signed lease proof plus independently approved capacity domain, provider, resource/service commitments and network configuration described in [fresh guest funding](guest-workload.md#fresh-funding-inside-the-guest). It also requires the independently approved `execution` profile and guest paths described in [native execution readiness](guest-workload.md#funded-native-execution-readiness); the profile commitment and exact unit count must match the signed service. These pins and the RPC endpoint belong to trusted measured configuration; accepting host-chosen values would defeat this check. The session verifies the signatures, assignment, initialization digest and challenge before generating the channel key. Current escrow state is reread before and after opening the delivered job key. A failed session creation closes the control plane. Only one session may be issued. Cancellation or either service exiting retires the session and terminates both process groups. `close()` waits for cleanup and reports failures; callers must await it and tear down the guest on failure.

## Fixed session entry and signed configuration

`scripts/compute-guest-launch.py` is the fixed outer process entry. It reads the
public files below, authenticates them and allocates the contained job before
starting `scripts/compute-guest-session.mjs`. Neither entry accepts command-line
overrides for signers, runtime, service binaries or agent.

| Path | Role |
| --- | --- |
| `/run/cannabis-launch/configuration.json` | `cannabis.guest-launch-consent.v1`: complete configuration v3 and ordered requester/provider consents |
| `/run/cannabis-launch/initialization.json` | Canonical retained assignment prepared by the initialization tool |
| `/run/cannabis-launch/request.json` | Exactly the complete market-lease `proof` and fresh attestation `challenge` |

All inputs use compact sorted-key JSON and one trailing newline. Files
and their ancestor directories must be root-owned and not writable by group or
others. Reads refuse nonregular files, symlinks, oversized data, changed
length and alternative/duplicate-key encodings. Customer keys, program contents,
arguments and private output
metadata do not belong in these files.

The outer process retains the original three public input strings in one anonymous
memory file sealed against writes, growth, truncation and further seal changes.
The pinned public authorization helper checks that snapshot before the process
creates `GuestJobScope`. The contained session receives the same descriptor and
independently verifies the same signatures, assignment, challenge and service.
Replacing an input pathname after allocation cannot replace the retained package.
The descriptor itself supplies no authorization. Both the preallocation helper and contained entry independently check requester/provider consent against fresh canonical booking and funding state. No embedded global signer or legacy authority envelope is accepted. The guest retains the consent with its funding configuration and rechecks wallet approval at every required funding refresh, including before and after opening customer keys. Revocation or a failed observation closes that retained funding session.

The outer process pins Node and both fixed entries against the measured image's
file inventory. It validates the signed aggregate/control/helper/storage resource
accounting before allocation and retains one service deadline. Authorization time
also consumes the transport allowance. The opaque relay holds bounded queues,
watches the child and independent guardian together, and refuses failed exit,
expired or stalled transport, and descendants left running after control exit.
Success requires the whole job tree's checked cleanup and retirement of its
runtime mount and dedicated ciphertext volume before the retained deadline.
The outer process and
guardian receive no customer content key.

The fixed outer entry also requires the image's [whole-guest budget](guest-image-build.md#resource-enforcement-inside-the-guest).
It checks actual capacity and mounts and refuses to proceed outside the bounded
outer cgroup. The operating boot must establish that containment before launching
the process; the component image does not activate an operating worker. Signed
job limits cannot borrow from image, kernel or outer-launcher allowances.

Before starting the control process, the outer entry creates the empty ciphertext
volume from the signed version-2 service profile. The contained entry receives
bounded encrypted input, verifies its assignment hash and publishes it without
overwriting existing files. It then checks actual cgroups, runtime, storage
permissions and kernel quotas before starting evidence services or creating a
session key. Native execution repeats admission before key release. The peer's
input acknowledgement establishes neither hardware protection nor payment
authorization. See [native execution readiness](guest-workload.md#funded-native-execution-readiness).

The image contains the fixed consent and state-verification code, not a global
signer list. The ordinary acceptance image still runs checks and powers off without
job intake. The separate `--operating` image uses a fixed
[PID-1 supervisor and public prefix](guest-image-build.md#one-use-operating-boot).
It creates bounded outer/job-parent groups and supervises one launcher/VM lifetime.
Readiness and staging responses never replace the signed configuration, funded
assignment or hardware appraisal.

The external consent uses EIP-712 **Cannabis booked guest launch**, version 1, with
chain ID and market address in its domain. Distinct requester and provider roles
sign the full configuration SHA-256, canonical assignment SHA-256, group digest,
selected booking, parties and booked interval. The configuration includes the
funding RPC/genesis/contract pins, provider/resource, service profile, tool/runtime
paths, attestation policy and transport limits. Signatures sit outside the hashes.
Each consent entry has exactly `role`, `signer` and `signature`; requester precedes
provider. The existing escrow prohibits a requester acting as its own worker.

The requester signature uses its EOA key. Provider contract wallets use ERC-1271
at the same canonical block as escrow state, at both fresh finalized and current
observations; approval need not predate original funding. A failed contract call
never falls back to EOA recovery. Missing, duplicate, wrong-party, substituted or
expired consent fails closed. Credentials and query parameters are refused in RPC
URLs; never put API secrets in public launch configuration. RPC-reported finality
remains trust in the selected RPC arrangement, not local consensus verification.

Keeping the signed configuration outside the image avoids a self-reference: a
reviewer can sign the completed image's measurement without changing those image
bytes. The signed policy template requires `measurements.initData: null`; the entry
replaces only that field with the retained assignment's actual digest. The image
measurement, verifier key, TCB requirements and other policy fields remain signed.
The challenge, lease, service commitment and reserved interval must all match. A
configuration ID is an identifier, not a monotonic rollback counter. Expiry and
current requester appraisal pins do not replace an operational revocation policy,
trustworthy time or outer protection against VM rollback.

Local review tooling never signs or starts a worker:

```sh
node scripts/prepare-guest-launch.mjs prepare requester /private/configuration.json /private/initialization.json /private/market-proof.json
node scripts/prepare-guest-launch.mjs prepare provider /private/configuration.json /private/initialization.json /private/market-proof.json
node scripts/prepare-guest-launch.mjs inspect /private/consent.json /private/initialization.json /private/market-proof.json
node scripts/prepare-guest-launch.mjs verify /private/consent.json /private/initialization.json /private/market-proof.json
```

`prepare` emits unsigned wallet-review data; each party signs its own payload.
`inspect` checks offline commitments and the requester signature, without claiming
provider wallet validity or chain state. `verify` adds fresh canonical observations
using the network in the reviewed configuration. None admits hardware or releases
keys. `compute/guest_launch.mjs` exports `encodeLaunchJSON` for canonical files.
Retain independent security/privacy review and user-controlled release approval.
Asynchronous `prepareGuestLaunch` and `readRetainedLaunch` return a total transport
budget: callers must start wall and monotonic clocks before awaiting them. The
fixed entries charge authorization latency; waiting for RPC never restarts time.

Before creating a session key, the entry invokes the pinned public admission
helper. That helper checks the actual cgroup containment, signed resource profile,
runtime tree and tool pins under the retained outer deadline. This is a point-in-time
inspection; execution repeats admission before opening customer keys. The entry
then starts only the pinned SNP/TDX services, retains the assignment without
rereading a host replacement, and serves the [encrypted result handoff](key-delivery.md#encrypted-streaming-handoff).
Failure closes the session and services. The outer owner must still retire the
entire VM and its key-bearing processes, including failures during cleanup.

## What remains for deployment

The requester still verifies the signed Trustee appraisal, including vendor evidence, approved boot measurements, initialization digest, fresh challenge and channel key. The startup API does not independently validate a hardware report or authorize workload execution.

The outer process creates the authenticated `GuestJobScope`. The separate measured
operating entry initializes the budgeted layout and fixed outer/job-parent groups,
stages bounded public configuration and independently supervises VM retirement.
An admitted successful operating job, authenticated network transport, actual
provider capacity and reviewed VM/key lifecycle still require completion.
Runtime isolation, result transport and local receipt
recovery are connected components; they do not establish the complete operating
worker. Do not expose the raw bridge through a host proxy. Passing a matching job
binding is not a substitute for enforcing the actual runtime.

The [boot check](guest-image-build.md) runs the pinned binaries and requires both SNP and TDX initialization attempts to reject ordinary hardware. It also checks cancellation, changed binaries, occupied ports and cleanup. These are negative acceptance checks. A real worker must additionally reject a hardware-field mismatch, accept the independently approved measured image and complete the [full worker acceptance run](worker-deployment.md#complete-the-worker-acceptance-run).

Pinned upstream implementation: [agent initialization](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attestation-agent/src/lib.rs), [SNP binding](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attester/src/snp/mod.rs), [TDX binding](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attester/src/tdx/mod.rs).
