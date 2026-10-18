# Building the guest evidence services

The guest image needs identifiable attestation binaries before its boot measurements can be approved. `scripts/build-guest-services.py` builds the two upstream components used by the Cannabis guest integration: the ttRPC attestation agent and its local REST bridge. The source revision, Cargo lock digest, compiler distribution and selected features are pinned in [guest-service-build.json](../compute/guest-service-build.json).

This build produces image components. It does not construct a bootable guest, establish confidential hardware, authorize jobs or launch customer programs. The approved image must also include the kernel, runtime, protected storage, service isolation and enforced initialization policy described in [worker deployment](worker-deployment.md).

## Prepare the build host

Use Ubuntu 24.04 on x86_64, Python 3.12+, Git, a C build toolchain, OpenSSL development headers, pkg-config and GNU binutils. Use a Linux filesystem path without whitespace for this profile, with room for source, dependency caches and two independent build targets. Keep outputs and reports outside the public repository.

Check out upstream tag `v0.22.0` and verify its revision is `eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a`. Install Rust 1.95.0 from the compiler archive named in the build lock. Verify the archive's SHA256 before installation; select the `rustc`, `cargo` and `rust-std-x86_64-unknown-linux-gnu` components. Install into a dedicated prefix. The build tool checks the compiler version and records executable hashes; those checks do not replace verifying the distribution archive or trusting the build host.

The build uses a dedicated Cargo cache and a minimal environment. Initial dependency retrieval can fetch optional upstream Git repositories and their submodules while Cargo resolves the pinned workspace; those downloads do not enable their attesters in the selected binary. Review the full locked dependency supply chain before release.

## Build and compare

From this repository, substituting your local directories:

```sh
python3 scripts/build-guest-services.py \
  --source /work/guest-components \
  --rust-prefix /opt/rust-1.95.0 \
  --build-root /work/cannabis-agent-build --label first

python3 scripts/build-guest-services.py \
  --source /work/guest-components \
  --rust-prefix /opt/rust-1.95.0 \
  --build-root /work/cannabis-agent-build --label second --offline
```

Each label uses its own source worktree and compilation target. The first build requires the existing Cargo lock; the offline build uses `--frozen` and refuses missing dependencies. The source commit timestamp supplies `SOURCE_DATE_EPOCH`, incremental compilation is disabled, and compiler source paths are remapped. The default concurrency is four build jobs; `--jobs` accepts 1–16.

The image components are written to `guest-agent-artifacts-first/` and `guest-agent-artifacts-second/`. Compare SHA256 hashes for both `ttrpc-aa` and `api-server-rest`. Each JSON report records binary hashes and sizes, compiler identity, host package versions, dynamic dependencies and whether the target was absent at the start. A reused target is explicitly recorded as an incremental run and is not evidence of a clean reproduction. Existing reports and artifact directories are never overwritten.

Packaging uses GNU `objcopy --strip-all --remove-section=.note.gnu.build-id`. The two observed clean builds had matching code and data sections but different LLVM local-symbol metadata and build IDs. This packaging step removes those differences. The resulting complete binaries are the files whose hashes must be pinned in the guest image. Original unstripped binaries remain in each target's `release/` directory for debugging, and their hashes are also recorded. This step does not change the upstream source or bypass runtime checks.

Two matching builds on one host demonstrate repeatability under that recorded environment. Independent reconstruction on a separately controlled build host, compiler/dependency review and whole-image measurement validation remain required. A matching agent binary alone does not measure the OS, its dynamic libraries or the customer runtime.

## Keep unsupported profiles closed

The selected upstream features enable SNP and TDX CPU attesters. Upstream also includes sample attesters. On a system without a supported TEE, its agent can identify itself as `sample`; the Cannabis evidence collector rejects that profile before requesting hardware evidence or accepting job keys.

Run the REST bridge only with `--features attestation` inside the protected control plane. Restrict its loopback endpoint, agent socket and hardware devices from customer code. Configure and enforce the exact initialization policy through the measured launcher; the upstream agent's startup alone does not establish that policy enforcement. CPU services do not authorize confidential accelerator execution.

The integrated runtime check starts the actual compiled services in a disposable namespace with isolated networking and temporary service storage. It verifies their pinned version and confirms that both Cannabis CPU probes reject the unsupported sample profile. No evidence, channel key or workload-key delivery is requested by that check. Real SNP/TDX acceptance still requires the [hardware-validation milestone](https://github.com/peter-ch/Cannabis/issues/1).

Upstream source and build behavior: [agent features](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attestation-agent/Cargo.toml), [REST version construction](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/api-server-rest/build.rs), [TEE detection](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attester/src/lib.rs). Preserve the upstream Apache-2.0 notices and applicable dependency license notices when distributing these components.
