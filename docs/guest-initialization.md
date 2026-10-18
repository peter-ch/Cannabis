# Binding a guest to its approved assignment

Each confidential guest must retain the same assignment the requester approved. Cannabis commits that assignment into the hardware initialization field before opening an evidence session. A changed package, runtime, task, payment binding, requester or execution rank changes the commitment.

`compute/guest_initialization.mjs` defines this commitment. `compute/guest_bootstrap.mjs` starts the pinned evidence services and retains one assignment for one session. The current boot image exercises refusal on unsupported hardware; actual SNP/TDX acceptance and protected customer execution remain separate deployment requirements.

## Prepare the commitment

Start with the approved funded-lease binding, produced by `leaseAttestationBinding(...)`, and the requester and opaque job identifier from that same approved record. The input has exactly five fields:

```json
{
  "schema": "cannabis.guest-initialization.v1",
  "tee": "snp",
  "requester": "<requester public address>",
  "jobId": "<opaque job identifier>",
  "binding": "<complete approved binding object>"
}
```

The placeholders illustrate the shape; the preparation command requires actual validated values. The binding includes the network, escrow, order, lease, reservation, encrypted package, workload policy, runtime, task, attempt, rank, group size and accelerator class. Current evidence profiles accept CPU only. Customer source, arguments, data, identity secrets and keys do not belong in this file. Keep scheduling metadata private even though the initialization commitment is not a secret.

```sh
node scripts/prepare-guest-init.mjs \
  --input /private/approved-assignment.json \
  --out /private/initialization.json
```

The command validates the assignment, normalizes Ethereum addresses and writes sorted compact JSON followed by one newline. It refuses to overwrite an existing destination. The digest covers the JSON bytes without the trailing newline: SHA-256 for SNP's 32-byte `HOST_DATA`, SHA-384 for TDX's 48-byte `MRCONFIGID`. The output supplies both hex and standard base64. Put the hex digest in the requester's pinned appraisal policy; supply the identical bytes through the reviewed VMM's initialization controls. Neither preparing a file nor setting a launch field proves hardware acceptance.

The guest accepts only that canonical file encoding, at most 64 KiB. Unknown fields, duplicate-key encodings, invalid UTF-8, unsupported hardware classes and invalid rank placement fail. Linux opens refuse symlinks and nonregular files before reading. The file is copied into retained process state once; subsequent edits cannot replace the running assignment.

## Start inside the measured control plane

```js
const plane = await InitializedGuestControlPlane.start({
  initializationFile: '/run/approved/initialization.json'
});
try {
  const session = await plane.createSession({ policy, challenge });
  const evidence = await session.evidence();
  // Send evidence to the requester through the reviewed authenticated transport.
} finally {
  await plane.close();
}
```

The caller must import `InitializedGuestControlPlane` from `compute/guest_bootstrap.mjs`. This API is for a dedicated measured Linux guest with trusted control-plane access. It is not a host-side worker installer or a public HTTP service.

Startup verifies both service executable hashes against the image input lock, reserves a private runtime directory and starts the agent with `--initdata-digest`. It passes no TOML override and inherits no caller environment. The pinned upstream agent compares the supplied bytes with the hardware field before binding its RPC socket. Cannabis additionally rejects the upstream unsupported-platform branch, which otherwise continues without that comparison. The REST bridge is restricted to attestation on literal loopback; startup verifies the listening socket belongs to the process it launched before querying it.

`createSession` derives requester, job and placement from the retained assignment. It checks the policy's initialization digest and challenge binding before generating the channel key. A failed session creation closes the control plane. Only one session may be issued. Cancellation or either service exiting retires the session and terminates both process groups. `close()` waits for cleanup and reports failures; callers must await it and tear down the guest on failure.

## What remains for deployment

The requester still verifies the signed Trustee appraisal, including vendor evidence, approved boot measurements, initialization digest, fresh challenge and channel key. The startup API does not independently validate a hardware report or authorize workload execution.

The measured launcher must isolate customer code from the agent, bridge, attestation devices and control-plane memory; enforce resource and network policy; and provide protected storage, encrypted results, replay controls and teardown. Do not expose the raw bridge through a host proxy. Passing a matching job binding is not a substitute for enforcing the actual runtime.

The [boot check](guest-image-build.md) runs the pinned binaries and requires both SNP and TDX initialization attempts to reject ordinary hardware. It also checks cancellation, changed binaries, occupied ports and cleanup. These are negative acceptance checks. A real worker must additionally reject a hardware-field mismatch, accept the independently approved measured image and complete the [full worker acceptance run](worker-deployment.md#complete-the-worker-acceptance-run).

Pinned upstream implementation: [agent initialization](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attestation-agent/src/lib.rs), [SNP binding](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attester/src/snp/mod.rs), [TDX binding](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attester/src/tdx/mod.rs).
