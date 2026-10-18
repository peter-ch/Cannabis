# Building the firmware and calculating SNP reference candidates

The firmware builder pins EDK II source and submodules, builds its AMD SEV
profile, and records the resulting firmware hash and host tool versions. The
measurement command then calculates a candidate SNP launch digest over that
firmware, the guest kernel, initramfs, command line and explicit virtual CPU
configuration. These are inputs for hardware validation. They do not admit a
worker or authorize customer execution.

## Build from the pinned source

Use Linux x86_64 with Python 3.12+, Git, GCC 13, G++, binutils, make, nasm,
acpica-tools and uuid-dev. See the complete pins in
[guest-firmware-build.json](../compute/guest-firmware-build.json).

```sh
git clone https://github.com/tianocore/edk2.git /work/edk2
git -C /work/edk2 checkout 2970e5699ba6267f3384ffab20f96647578aebc8
git -C /work/edk2 submodule update --init --recursive
python3 scripts/build-guest-firmware.py \
  --source /work/edk2 --output /work/cannabis-firmware-first
python3 scripts/build-guest-firmware.py \
  --source /work/edk2 --output /work/cannabis-firmware-second
```

The output must be new, outside this repository, and have no whitespace in its
path. The builder exports committed source rather than compiling the working
tree. It verifies the source revision, release tag, timestamp and every listed
submodule. The three exact configuration-line removals disable the embedded
GRUB image and its build hook. The upstream blob-verification library is kept;
the UEFI shell and source debugging are disabled. `EmulatorPkg` is excluded from
the source export and is not part of this platform's build.

The build produces `OVMF.fd`, `build.json`, a private source tree and build log.
Compare firmware hashes across independent output directories. Two local builds
with the recorded host tools produced the same firmware bytes. The compiler
environment is recorded, not independently reproduced or audited; another
builder must reproduce and review the result before it is trusted for deployment.

## Calculate the candidate

First assemble the [guest image](guest-image-build.md). Clone the measurement
tool at the revision in the same lock file:

```sh
git clone https://github.com/virtee/sev-snp-measure.git /work/sev-snp-measure
git -C /work/sev-snp-measure checkout 8f2b337e38bc83f87cd30f3253cdfe8e3e12cc3a
python3 scripts/measure-guest-snp.py \
  --firmware /work/cannabis-firmware-first \
  --image /work/cannabis-image-first \
  --measurement-source /work/sev-snp-measure \
  --vcpu-type EPYC-Milan --vcpus 2 --guest-features 0x21 \
  --output /work/cannabis-snp-candidate
```

The CPU and feature values above are an explicit calculation example. They are
not an approved deployment profile. They must match the actual VMM launch and
the vendor-reported hardware state before use in an admission policy.

The tool checks the recorded boot-file hashes and copies the exact bytes into a
private `boot-inputs/` directory. It hashes each copy while writing it and measures
only those copies, so replacing the original file during processing cannot
silently change a successful result. The measurement library is also exported
from its pinned commit; ignored files and cached bytecode in the checkout are
excluded. The output includes `reference.json`, `hashes-table.bin` and retained
input/source snapshots. Keep the output private.

The candidate binds firmware, kernel, initramfs, command line (with the hash
table's terminating NUL), virtual CPU count/model and guest feature bits. Local
checks changed each of these seven inputs and observed a different digest.
Separate regression checks reject changed or oversized copied data, symbolic
links and special files, and preserve an existing output. These checks establish
software behavior, not equivalence with a real SNP launch report.

## Interpreting an ordinary VM boot

QEMU's ordinary x86 direct-boot path changes Linux setup-header fields. Its
[SEV path preserves the original kernel header](https://github.com/qemu/qemu/blob/v8.2.2/hw/i386/x86.c#L1022-L1031)
so the firmware can check the original kernel-file hash. Consequently, inserting
an SNP hash table into an ordinary TCG VM does not by itself create a valid boot
verification configuration.

A local diagnostic read the actual emulated setup bytes through QEMU's private
test interface before CPU execution, then used their kernel hash in that
diagnostic VM's table. With the unchanged firmware, the guest booted, verified
all 4,872 embedded files, rejected both unsupported production CPU profiles and
powered off. It requested no evidence or job keys. That diagnostic table and its
debug interfaces are not used for the SNP candidate or any customer deployment.
The original SNP reference continues to use the original kernel bytes.

## Remaining acceptance evidence

Pin and review the actual VMM and firmware integration. On real SNP hardware,
compare a fresh vendor-verified report against the candidate, verify debug and
security policy, and prove that altered boot inputs and initialization policy
are refused. Then enforce the retained assignment before opening an evidence or
key-delivery endpoint. The protected launcher, resource isolation, encrypted
transport and complete paid-job acceptance remain required. Follow the
[worker deployment requirements](worker-deployment.md#complete-the-worker-acceptance-run).

Only build source and instructions are published here. Firmware and guest binary
distribution require the corresponding source and license review and notices.
