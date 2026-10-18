# Assembling and checking the guest boot image

`scripts/build-guest-image.py` assembles a Linux kernel and complete in-memory boot filesystem containing the [pinned guest evidence services](guest-service-build.md), Node, Python, age and the Cannabis control-plane modules. The current entry point checks those components and powers off. It has no customer-job intake, operating worker endpoint or confidential-hardware authorization.

This image is a step toward the measured worker described in [worker deployment](worker-deployment.md). It is not a mainnet service release. Assignment initialization is integrated into the control-plane startup API; its hardware acceptance, the workload launcher, protected runtime, resource limits and authenticated transport remain required.

## Inputs and assembly

Use Linux x86_64, Python 3.12+, `dpkg-deb`, `depmod` and internet access for the first input download. The [input lock](../compute/guest-image/inputs.json) pins 39 Ubuntu 24.04 package archives, the kernel release, Node and age distributions, the JavaScript dependency lock and both guest-service binary hashes. The package pins were obtained from Ubuntu's signed package indices with an empty installation state and separate empty archive cache, so already cached host packages were not omitted from the dependency closure.

Build the evidence services first. Then run from this repository:

```sh
python3 scripts/build-guest-image.py \
  --guest-services /work/cannabis-agent-build/guest-agent-artifacts-first \
  --cache /work/cannabis-image-downloads \
  --output /work/cannabis-image-first

python3 scripts/build-guest-image.py \
  --guest-services /work/cannabis-agent-build/guest-agent-artifacts-second \
  --cache /work/cannabis-image-downloads \
  --output /work/cannabis-image-second
```

Use fresh, separate output directories outside the public repository. An existing output is refused. Every package/download hash and the service hashes are checked before use. Package maintainer scripts and npm lifecycle scripts are not executed. The builder restores the merged `/usr` directory layout after package extraction and computes module dependencies for the pinned kernel.

The output contains `vmlinuz`, `initramfs.cpio.gz`, `cmdline`, `build.json`, the unpacked `rootfs/` and private build-tool staging. The initramfs uses a deterministic `newc` archive with fixed ownership, timestamps, ordering and gzip metadata. Compare the final kernel, initramfs and command-line file hashes across builds. The command-line file's terminating newline is removed when passing its contents to QEMU.

The embedded file manifest checks regular-file contents during the boot check. This is local integrity evidence, not a hardware signature or proof against an operator controlling an ordinary VM. There is no persistent root disk or host filesystem mount. Customer execution will additionally require enforced isolation and protected temporary storage; the boot image does not establish those properties by itself.

The JavaScript runtime carries ethers and jose with locked transitive dependencies. Escrow inspection uses a checked-in ABI instead of loading the Solidity compiler inside the guest. Automated checks compare that ABI with the current compiled contract. Contract source, deployed-code hash checks and payment semantics are unchanged.

## Run the actual VM boot check

Install `qemu-system-x86_64`, then run:

```sh
python3 scripts/verify-guest-boot.py \
  --image /work/cannabis-image-first \
  --output /work/cannabis-image-first-boot
```

This uses QEMU's ordinary TCG CPU emulation, two vCPUs and 2 GiB of RAM. It attaches no NIC, disk, shared filesystem, monitor, QMP or debugger. The default deadline is five minutes; failure or timeout does not count as a successful boot. Keep the serial log and verification JSON private.

Inside the VM, the entry point mounts ephemeral runtime storage, disables core dumps and further kernel-module loading, checks embedded files, exercises the Python extensions and age executable, and starts the actual attestation agent and REST bridge on loopback. Both production CPU probes must reject the unsupported sample profile with their exact structured refusal. Import errors, missing libraries and unexpected success fail the check. No hardware evidence, channel key, job key or customer computation is requested. The services are terminated and the VM powers off.

The boot check also runs the [initialization gate](guest-initialization.md) with both CPU profiles. It requires exact refusal on unsupported hardware and verifies that child services and sockets are removed. A cancelled startup, changed service binary and occupied loopback port must fail. An existing listener is never queried as if it were the spawned bridge.

The check deliberately does not treat execution on real SNP/TDX hardware as an accepted deployment: that requires the separate initialization, measurement, negative-case and full workload acceptance run. Do not turn an ordinary boot result into an attestation policy.

## Connect these artifacts to measured launch

For SNP, the reviewed launch chain must cover firmware, kernel, initramfs, kernel arguments and initial vCPU state. QEMU's [SNP launch controls](https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html#launching-sev-snp) include initialization host data; the [sev-snp-measure tool](https://github.com/virtee/sev-snp-measure) calculates expected digests using the corresponding firmware, kernel, initrd and CPU configuration. Pin and review the actual firmware, VMM and measurement-tool revisions before using their outputs as trusted reference values.

For TDX, firmware and runtime measurement registers must cover the entire boot chain. [Contrast's reference-value documentation](https://docs.edgeless.systems/contrast/1.22/architecture/components/manifest) illustrates this distinction, including binding an external root filesystem through its integrity root in measured kernel arguments. Cannabis's current image has its userspace inside the initramfs; it does not yet have a reviewed firmware/TDX measurement calculation. Do not substitute a firmware-only measurement or an ordinary SHA256 file digest for that evidence.

The separate [firmware and SNP measurement tools](guest-firmware.md) calculate candidate reference values from pinned firmware and verified private copies of these boot artifacts. They do not establish a hardware-approved reference. The initialization gate binds the retained assignment to `HOST_DATA`/`MRCONFIGID` through the pinned agent; actual hardware mismatch/success cases and enforcement of the loaded workload policy still require the [worker acceptance run](worker-deployment.md#complete-the-worker-acceptance-run).

The published artifacts are build source and instructions. Before distributing guest binaries, complete the dependency/source and license review, preserve upstream and distribution notices, and satisfy the source-availability obligations of included components. A repeat build on one machine is not independent reconstruction or a security audit.
