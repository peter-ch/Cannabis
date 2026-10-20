# Assembling and checking the guest boot image

`scripts/build-guest-image.py` assembles a Linux kernel and complete in-memory boot filesystem containing the [pinned guest evidence services](guest-service-build.md), Node, Python, age and the Cannabis control-plane modules. Its default entry checks components and powers off. A separate measured operating entry stages public launch configuration and supervises the fixed launcher for one VM lifetime. Neither image supplies confidential-hardware authorization or a live worker service by itself.

This image is a step toward the measured worker described in [worker deployment](worker-deployment.md). It is not a mainnet service release. Assignment initialization, kernel resource enforcement and native runtime isolation are integrated into its component checks. The complete admitted workload launcher, protected transport, outer VM/key lifecycle, hardware acceptance and independent review remain required.

## Inputs and assembly

Use Linux x86_64, Python 3.12+, `dpkg-deb`, `depmod` and internet access for the first input download. The [input lock](../compute/guest-image/inputs.json) pins 42 Ubuntu 24.04 package archives, including Bubblewrap, libcap and libseccomp, plus the kernel release, Node and age distributions, the JavaScript dependency lock and both guest-service binary hashes. The initial package closure was obtained from Ubuntu's signed package indices with an empty installation state and separate empty archive cache. The isolation additions and their dependencies were checked against the distribution's package metadata; cached host packages are not substitutes for pinned guest inputs.

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

## CPU PyTorch runtime

The default `--runtime native` includes Python's standard library. Select
`--runtime pytorch-cpu` to embed the separately pinned CPU PyTorch and NumPy
runtime, including its complete Python wheel dependency closure. The lock at
`compute/guest-image/pytorch-cpu-wheels.json` records exact versions, upstream
URLs, sizes, SHA-256 hashes and package metadata. Assembly verifies those pins,
rejects unsafe paths, special files and collisions, and retains package licenses.
It extracts wheel contents without running package or installer code. Runtime
startup still executes the pinned libraries, including their normal Python
startup hooks; this is part of the runtime that must be reviewed.

```sh
python3 scripts/build-guest-image.py \
  --runtime pytorch-cpu \
  --guest-services /work/cannabis-agent-build/guest-agent-artifacts-first \
  --cache /work/cannabis-image-downloads \
  --output /work/cannabis-pytorch-first
```

This selection embeds `vm-profile-pytorch-cpu.json`: a four-CPU, 8 GiB reference
VM, a 2 GiB root ceiling and a 2 GiB aggregate job ceiling. Its boot reservation
includes both early root copies and a 512 MiB compressed-archive allowance.
Every native runtime inventory is bounded at 1 GiB and 50,000 entries; actual
bytes and the exact digest are checked before execution. The minimal profile
retains its smaller ceilings. These are separate measured images and require
separate repeated-build, boot and hardware qualification evidence.

The PyTorch image uses the existing native adapters and its **own inventory
digest**. It does not add a scheduler or a central service. A single-process
task invokes `/usr/bin/python3 -I -B /input/train.py`; a distributed task uses
`native-group-linux-x86_64-v1` and `attested-tls-ip-v1`. Each rank receives its
bound `RANK`, `WORLD_SIZE`, `MASTER_ADDR`, `MASTER_PORT` and
`GLOO_SOCKET_IFNAME=cannabis0`. Initialize PyTorch with the CPU Gloo backend and
`env://`; run one process per admitted rank. Reserve worker memory, threads and
scratch space explicitly, and declare every returned checkpoint and log as an
encrypted output.

Owned component checks train a small neural layer in one process and across two
Gloo ranks, reconstruct encrypted numeric checkpoints and verify predictions on
unseen inputs. These checks use disposable fixture identities and data. They
do not establish hardware confidentiality, a paying customer or independent
review. Actual support remains conditional on admission of the exact runtime
image. CUDA, ROCm, other accelerators, JIT/toolchain extensions and automatic
partitioning are separate capabilities; this CPU recipe supplies none of them.

PyTorch's distributed primitives do not provide their own confidentiality or
authorization. Cannabis runs them inside the private namespace and authenticated
encrypted group transport; exposing Gloo or TCPStore on the host network is not
an alternative. See the [upstream security guidance](https://github.com/pytorch/pytorch/blob/main/SECURITY.md).

The group syscall profile permits `NETLINK_ROUTE` solely inside the retained
private network namespace so glibc/Gloo can enumerate its interfaces. The kernel
checks `CAP_NET_ADMIN` for route/link mutations; workloads run with all
capabilities dropped in a child user namespace and cannot administer the owning
network namespace. Component checks verify that only `lo` and `cannabis0` appear,
an attempted link change returns `EPERM`, and other netlink protocols, raw IP,
packet, IPv6 and vsock sockets remain refused. Standalone tasks retain no netlink
access. This additional kernel interface requires review with the measured image.

The image embeds fixed consent verification code with no universal signer file.
The [fixed session entry](guest-initialization.md#fixed-session-entry-and-signed-configuration)
requires the exact funded assignment and separate requester/provider consent over
the complete configuration. A configuration can bind the completed image's
measurement without changing those image bytes. The `--operating` option selects
the operating entry; no authority-list argument is supported. Updated code changes
the image hash and requires fresh repeated builds, boot checks and hardware
references. Building an image does not authorize execution.

The output contains `vmlinuz`, `initramfs.cpio.gz`, `cmdline`, `build.json`, the unpacked `rootfs/` and private build-tool staging. The initramfs uses a deterministic `newc` archive with fixed ownership, timestamps, ordering and gzip metadata. Compare the final kernel, initramfs and command-line file hashes across builds. The command-line file's terminating newline is removed when passing its contents to QEMU.

The embedded file manifest checks regular-file contents during the boot check. This is local integrity evidence, not a hardware signature or proof against an operator controlling an ordinary VM. There is no persistent root disk or host filesystem mount. Customer execution will additionally require enforced isolation and protected temporary storage; the boot image does not establish those properties by itself.

The build uses its pinned guest Python interpreter and libraries to prepare
source-hash-validated bytecode caches. This avoids compiling the same trusted
libraries during each bounded guardian or helper startup. Cache filenames refer
to guest paths, optimization stays at zero so assertions remain enabled, and the
builder validates every generated cache against its source. Caches and compiler
metadata enter the embedded manifest and image measurement. They must reproduce
across the two builds. No guardian, workload or cleanup deadline is increased.
The cache mode follows Python's documented
[source-hash invalidation](https://docs.python.org/3.12/library/compileall.html).

The actual VM also imports the control modules while source compilation is
disabled for that check, proving the caches are usable. A separate owned file
changes content while keeping its size and timestamps; Python must reject its
stale cache. These checks use no customer keys or workload data.

Early boot copies only the embedded top-level image paths into a separate 1 GiB,
unswappable tmpfs root, then uses the pinned BusyBox `switch_root` to release the
original initramfs tree and start the guest initializer. The handoff is necessary
because Linux does not permit `pivot_root` from the initial rootfs; the workload
sandbox relies on that operation. No external disk or files enter this handoff.
The component check verifies the new root's filesystem and mount restrictions
before checking its file manifest. [Linux root-switching requirements](https://www.man7.org/linux/man-pages/man2/pivot_root.2.html).

The JavaScript runtime carries ethers and jose with locked transitive dependencies. Escrow inspection uses a checked-in ABI instead of loading the Solidity compiler inside the guest. Automated checks compare that ABI with the current compiled contract. Contract source, deployed-code hash checks and payment semantics are unchanged.

## Run the actual VM boot check

The builder also assembles `/opt/cannabis/runtime` from the pinned guest Python
interpreter, standard library and shared libraries. The recipe does not inspect
the builder's installed dependencies or execute submitted software. It copies
image-contained files, preserves executable modes and source-validated caches,
and supplies empty sandbox mount destinations. Control-plane code, authorities,
attestation services and customer data are outside this runtime tree. Other
software environments require additional reviewed recipes or runtime adapters.

`/opt/cannabis/runtime.json` records the native inventory digest, regular-file
bytes and entry count; `build.json` records that descriptor and the recipe hash.
These byte counts describe the files, not a whole-VM memory reservation. The
runtime pages, image, kernel and services still need independently budgeted
capacity outside the job subtree.

After public signature verification, the fixed outer launcher requires the
signed runtime path and inventory to match this embedded descriptor. It verifies
root ownership, permissions, protected `noswap` storage, content and empty mount
destinations, then creates and checks a read-only `nosuid,nodev` bind mount in its
private namespace before starting the job controller. Runtime inspection inside
the contained session remains required before key creation. Failure to unmount
after the job is fatal and requires disposal of the whole VM.

The owned kernel checks reject changed contents, writable permissions, hard
links, symlink or occupied mount destinations and storage outside protected
memory. They also verify that root cannot write through the prepared mount, a
mount-permission downgrade is detected, an isolated program loads the embedded
interpreter and libraries, and the mount retires after execution. These checks do
not establish hardware confidentiality or solve whole-VM rollback and disposal.

Install `qemu-system-x86_64`, then run:

```sh
python3 scripts/verify-guest-boot.py \
  --image /work/cannabis-image-first \
  --output /work/cannabis-image-first-boot
```

This uses QEMU's ordinary TCG CPU emulation and the measured reference profile:
four vCPUs and 4 GiB of RAM for the minimal runtime, or 8 GiB for the CPU PyTorch
profile. It attaches no NIC, disk, shared filesystem, monitor,
QMP or debugger. Before the full boot, two separate guests must refuse insufficient
RAM or CPUs and power off before the second root copy. Each negative boot has a
two-minute deadline. The full component boot allows thirty minutes for the minimal
runtime and sixty minutes for the optional CPU PyTorch runtime. Runtime inventory verification allows ten minutes for the
larger CPU PyTorch image and three minutes for the minimal runtime under
emulation. Owned PyTorch fixtures explicitly select an emulation budget of ten
minutes for the workload within a fifteen-minute shared service interval, with
five minutes for collective rendezvous. Ordinary kernel/CI checks retain their
shorter budgets. These fixture settings do not change production enforcement:
each real job must still finish within its approved workload and shared deadlines.
Failure or timeout does not count as success. Keep the serial
logs and verification JSON private. Bounded phase names distinguish slow or
stalled checks without customer content.

Inside the VM, the entry point mounts ephemeral runtime storage, disables core dumps and further kernel-module loading, checks embedded files, exercises the Python extensions and age executable, and starts the actual attestation agent and REST bridge on loopback. Both production CPU probes must reject the unsupported sample profile with their exact structured refusal. Import errors, missing libraries and unexpected success fail the check. No hardware evidence, channel key, job key or customer computation is requested. The services are terminated and the VM powers off.

The boot check also runs the [initialization gate](guest-initialization.md) with both CPU profiles. It requires exact refusal on unsupported hardware and verifies that child services and sockets are removed. A cancelled startup, changed service binary and occupied loopback port must fail. An existing listener is never queried as if it were the spawned bridge.

It also invokes the fixed outer launcher and session entry with no staged launch configuration and
requires refusal before any session key or workload is created. This checks the
unprepared entry's closed state; the separate owned integration exercises signed
configuration and kernel admission using disposable authorities and synthetic
appraisal. Neither check establishes a production signer set or actual hardware
admission.

Nine additional kernel cases check immutable public launch snapshots, unsafe
input refusal, successful opaque relay and cleanup after failed control exit,
write backpressure, a stopped control process, guardian death before or during
relay startup, or a lingering descendant. Failed cleanup channels must still
release retained control-group descriptors. These are owned lifecycle checks. The boot initializer still powers
off; it does not activate the operating launcher or accept customer jobs.

## One-use operating boot

Build the separate operating image with bilateral booked-launch admission:

```sh
python3 scripts/build-guest-image.py \
  --guest-services /work/cannabis-agent-build/guest-agent-artifacts-first \
  --cache /work/cannabis-image-downloads \
  --operating --output /work/cannabis-operating-first
```

Repeat the same inputs into a second fresh directory and compare all artifact
hashes. This image has a different initializer, command line and measurement from
the component image. `operatingEntryConfigured: true` records its purpose;
`executionAuthorized` and `hardwareValidated` remain false. Building it does not
approve participant signatures, hardware or customer execution.

`compute-guest-boot.py` requires privileged PID 1 and accepts no command-line
override. It checks the measured layout, starts a separate key-free shutdown
watchdog, configures the measured control-plane network and opens exactly one nonterminal virtio port named
`org.cannabis.control`. The host supplies an untrusted byte stream on this port.
There is no disk intake, shell service or plaintext customer-work fallback.

### Control-plane network

Fresh funding and wallet-validity checks must run inside the guest before key
release. The operating entry therefore requires exactly one `virtio_net` device
named `eth0`, with MAC `52:54:00:ca:42:00`. The measured profile fixes IPv4
`10.0.2.15/24`, gateway `10.0.2.2` and resolver `10.0.2.3`; DHCP, IPv6, forwarding
and ICMP redirects are disabled. Startup observation refuses changed device,
address, route, resolver or control settings. Setup never adopts an already
configured network; these checks are not continuous network monitoring.

For a QEMU provider, the corresponding control-plane device arguments are:

```text
-netdev user,id=controlnet,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,ipv6=off
-device virtio-net-pci,netdev=controlnet,mac=52:54:00:ca:42:00
```

These are networking arguments only, not a confidential launch command. The
reviewed firmware, SNP/TDX policy, exact image and vCPU measurements, initialization
binding and lifecycle controls remain mandatory. The addresses follow QEMU's
[user networking model](https://www.qemu.org/docs/master/system/devices/net.html).
There is no host port forwarding or file-sharing service in this profile.

The selected RPC endpoint belongs to the signed configuration. Production uses
HTTPS with certificate and hostname validation inside the guest, followed by the
existing chain, genesis, runtime-code, hash-bound funding and wallet checks. A
host-controlled DNS/router cannot replace TLS verification. The current RPC trust
model remains explicit; routing and TLS are not local consensus validation.
Network metadata, such as destination and DNS queries, is visible to the host.

This network belongs to the trusted control plane. Customer processes retain
their separate network namespace, denied IP/netlink/packet/vsock creation and
absence of control-plane descriptors. The current native adapter still has no
customer Internet or distributed-network access. This is not a kernel destination
allowlist for arbitrary privileged guest programs; the measured control programs
and existing workload isolation define the boundary. Other adapters and protected
multi-node traffic require their separately reviewed paths.

`verify-guest-network.py` creates a distinct private diagnostic image from a
verified operating image's retained rootfs. It checks static NIC setup, changed
configuration refusal, real DNS, TLS/hostname/redirect/timeout handling through
loopback-hosted owned RPC fixtures, and actual workload socket refusal while the
control network is active. The diagnostic image has a different entry and a
public fixture CA used only by its check process. The production image and its
trust roots remain unchanged; it has no diagnostic mode.

```sh
sudo python3 scripts/verify-guest-network.py \
  --image /work/cannabis-operating-first \
  --output /work/cannabis-network-check
```

These checks make no real payment or hardware-admission claim. Updated measured
network source requires new image hashes and reference candidates; older image
measurements cannot authorize the changed operating image.

The public prefix is deliberately separate from the later encrypted protocol:

1. The guest emits the fixed bytes `CANNABIS-READY` followed by byte `0x01`.
2. The peer sends `CANNABIS-BOOT` plus `0x01`, then three unsigned 32-bit big-endian
   lengths and the corresponding canonical public JSON bytes: configuration
   (at most 256 KiB), initialization (64 KiB), and request (16 MiB).
3. Intake has one 30-second deadline, reads in bounded chunks and writes fresh
   root-owned files under the measured unswappable `/run` mount. It leaves the
   subsequent stream bytes unread. `compute.guest_boot.encode_public_launch`
   constructs this prefix for a trusted host-side coordinator.
4. The guest creates the bounded outer leaf and separate empty job parent, then
   emits `CANNABIS-STAGED` plus `0x01`. Both public messages indicate boot/setup
   progress only. Neither authenticates hardware, approves configuration, releases
   a key, accepts a result or authorizes payment.
5. A fixed small BusyBox bootstrap joins the outer leaf before executing the
   Python launcher. Its initial/shared pages belong to the VM overhead allowance;
   launcher initialization and later allocations occur inside the leaf. The
   existing signature, funded-assignment, runtime and attestation gates still run
   before customer-key release. No bootstrap command or supervisor path comes
   from the prefix.

The supervisor accepts the actual mounted cgroup hierarchy root as well as a
normal nested domain. Linux exposes `cgroup.type` only on non-root cgroups. If
that file is absent, the retained descriptor must match the fixed cgroup2 mount
root; CPU, memory and PID controllers must still be enabled. Owned checks include
the real root in addition to nested domains, and operating boots exercise the
root path before acknowledging staged public configuration.

PID 1 and its watchdog stay outside the outer and job groups. The supervisor
watches the exact launcher and watchdog, rejects changed limits and premature
transport loss, and requires successful exit with empty groups. Cleanup stops
and reaps a possibly not-yet-enrolled bootstrap before removing groups; it empties
outer creators before killing the separate job tree. Failed cleanup is terminal.
The watchdog independently watches owner loss and one immutable VM expiry.
Completion, error, expiry or lost supervision ends the entire VM; it is never
reused for a second job. The PID-1 entry also reaps orphaned descendants.

The operating command line pins `console=null` to suppress host-visible kernel
output, including error paths that could otherwise print customer process names.
Its initializer enables immediate panic retirement on any group OOM and disables
crash dumps and further module loading. Customer logs remain inside the existing
encrypted result path. These choices follow Linux's
[console parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html),
[OOM policy](https://docs.kernel.org/admin-guide/sysctl/vm.html#panic-on-oom) and
[reboot interface](https://man7.org/linux/man-pages/man2/reboot.2.html).

Nineteen owned kernel cases exercise prefix bounds and deadlines, initial
containment, changed controls, detached descendants, stopped/failed launchers,
outer OOM with work left in the separate job tree, transport/watchdog loss and
retirement of isolated PID namespaces. Namespace retirement is not physical-VM
or hardware acceptance. The separate ordinary-VM refusal check is:

```sh
python3 scripts/verify-operating-boot.py \
  --image /work/cannabis-operating-first \
  --output /work/cannabis-operating-refusals
```

It sends only invalid owned public requests. It requires public staging followed
by refusal, malformed/oversized prefix refusal, bounded stalled intake, and
shutdown when the port or required network device is absent or the device identity
differs. The kernel console must remain silent. A local
QMP connection observes the
[guest shutdown event](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#event-SHUTDOWN);
host termination, reset or panic does not substitute for the expected power-off.
QMP issues no VM-control or memory-read command. The NIC uses a restricted user
backend with external access disabled. No shared filesystem, customer key,
authorized job or real payment participates in these refusal checks.

These paths still require actual confidential hardware, reviewed production
authorities, an integrated successful operating job, authenticated network and
browser delivery, trustworthy time and rollback protection, and independently
reviewed VM/key lifecycle. Guest power-off cannot prove destruction of a hostile
host's prior snapshots or physical erasure. The bounded CPU profile does not
replace universal adapters, coordinated groups or protected accelerator support.

Twelve ciphertext-storage cases check the dedicated `noswap` tmpfs, actual byte
and inode exhaustion, changed quota refusal, input hash/size/permission/link
checks, retained-file replacement and checked retirement. A busy volume cannot
be lazily detached and reported as retired. Two execution-channel cases refuse
changed input or quotas before key release, and native publication enforces the
signed encrypted-output limit. The signed profile budgets both input and output
concurrently; mount quotas remain ceilings, not physical capacity commitments.

```sh
sudo /usr/bin/python3 -I -B scripts/check-guest-ciphertext.py
```

The check deliberately does not treat execution on real SNP/TDX hardware as an accepted deployment: that requires the separate initialization, measurement, negative-case and full workload acceptance run. Do not turn an ordinary boot result into an attestation policy.

## Resource enforcement inside the guest

The image embeds the selected runtime's budget as `vm-profile.json`. The default
uses `compute/guest-image/vm-profile.json`; the CPU PyTorch selection uses
`compute/guest-image/vm-profile-pytorch-cpu.json`.
Early boot checks the kernel's memory and allowed-CPU views before duplicating the
root. The root and `/run`, `/tmp` and `/dev/shm` receive the profile's explicit byte
and inode ceilings, with swap disabled. The builder rejects an image whose
page-rounded file data, entry count or compressed archive exceed those allowances.

The default native profile budgets a 1 GiB root, 128/64/16 MiB volatile mounts,
256 MiB for the outer launcher, up to 1 GiB for the job and 512 MiB of kernel/PID-1
headroom. Boot also budgets the temporary second root and a 256 MiB compressed
archive allowance. Its peak requires at least 3,280 MiB in the guest's `MemTotal`
view. The four-vCPU reference also covers the job's 3,000 millicpu ceiling, the
outer launcher's 500 and 500 for kernel/supervisor activity. These are limits for
this measured CPU profile, not a promise of dedicated host cores or service backing.
The separate CPU PyTorch profile is described [above](#cpu-pytorch-runtime).

`VmAdmission` retains the outer launcher's actual cgroup, checks its CPU/memory/PID
and swap controls, and refuses a launcher outside it, changed mounts or controls,
and a signed job exceeding the measured job allowance. The fixed entry applies
this check before reading public launch inputs and rechecks it around allocation
and retirement. An operating boot must create the outer group and start the
launcher there before its allocations. Moving an existing process later does
not move its earlier memory charges. [Linux cgroup memory ownership](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-ownership).

Jobs use a separate empty bounded parent at `/sys/fs/cgroup/cannabis-jobs`; the
root cgroup contains PID 1 and cannot be used as the empty allocation parent.
Admission retains this parent's identity, verifies its aggregate CPU/memory/PID,
depth and descendant limits, and requires it empty before allocation and after
retirement. The operating entry creates both this parent and the outer leaf.

Nine actual-VM cases cover capacity/layout, a reduced CPU affinity mask, a changed
mount quota in a private namespace, contained and uncontained launchers, changed
outer or job-parent limits, an oversized job and checked nested-group retirement. The default image
still runs these checks and powers off. The separate operating entry supplies
PID-1 supervision and outer/job-parent setup; a complete admitted operating job,
trustworthy time, physical provider admission and reviewed whole-VM/key lifecycle
remain required. Kernel headroom is a budget allowance, not an
enforced hard bound on every kernel allocation. Guest-visible capacity and mount
ceilings do not establish a provider commitment or confidential hardware.
An outer-group OOM can kill the launcher and its inherited guardians together.
The operating PID-1 supervisor must remain outside that group and retire the
entire VM on this failure; creating the cgroup alone does not supply that boundary.

`compute/guest_resources.py` supplies a cgroup-v2 boundary for the trusted launcher.
It creates one fresh group beneath an already configured, empty parent, without
changing ancestor limits or moving other services. It requires the real kernel
filesystem, root-owned paths without writable ancestors or symlinks, and enabled
CPU, memory and process controllers. Ordinary files cannot stand in for enforcement.

The boundary sets a CPU quota, aggregate memory ceiling, process/thread ceiling,
whole-group out-of-memory handling, and zero swap allowance. It disables compressed
swap where that control exists and prevents child cgroups. Controls are read back
before admission. A single-threaded trusted helper moves itself into the group
before starting customer execution, so its descendants inherit the limits.
Normal scheduling is required; the isolated runtime must remove capabilities and
real-time scheduling privileges that could bypass these controls.

The live supervisor waits for completion, cancellation or a monotonic wall deadline.
Expiry and cancellation take precedence even when the group is already empty;
late observation cannot establish that the job finished on time.
Cleanup uses the kernel's tree-wide kill operation, checks that no processes remain,
then removes only the group it created. A new process session does not escape that
cleanup. Failure to prove cleanup is an error requiring guest retirement. The
independent guardian below handles supervisor death and stopped supervisors. These
semantics follow the [Linux cgroup-v2 interface](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

The boot check executes bounded owned programs to verify CPU throttling, whole-group
memory exhaustion, fork refusal, successful completion, cancellation and deadline
cleanup. It also rejects changed limits, missing controllers, ordinary directories
and intermediate symlinks. CI runs the same kernel checks on Linux. They do not
use customer data, job keys or payments. To run them on a disposable Linux system
whose root hierarchy already enables CPU, memory and process controllers:

```sh
sudo python3 -I -B scripts/check-guest-resources.py
```

These controls are one part of runtime isolation. They do not hide the control
plane, implement a root filesystem or network policy, reserve provider capacity,
or bound scratch storage and output logs. Memory already charged outside the
group is not transferred by moving a process; staging buffers and input storage
need their own protected budgets. Kernel counters are operational evidence, not
trusted billing or proof of useful work. Admission must bind the actual loaded
adapter, all resource limits, devices, network peers and funded assignment before
any customer program or content key is exposed to it.

## Independent process guardian

`compute/guest_guardian.py` adds a separate trusted process to enforce cleanup even
when the supervisor exits, receives SIGKILL, or stops responding. Arm
`GuardedResources(parent, limits)` before key release or starting a runtime, retain
it throughout the job, and call `assert_alive()` before admission. It does not
execute a customer program or establish confidential hardware.

While work runs, monitor `guard.fileno()` alongside the runtime's process handle
in the supervisor's selector. Readability means call `wait()` to collect a terminal
result or handle unexpected guardian failure. Once the runtime has exited, request
`wait(action='finish')`. Do not leave a guardian failure unobserved while waiting
indefinitely for the runtime. The control socket is non-inheritable and must never
be passed to customer processes.

The owner opens a Linux process handle before spawning the guardian. Both retain
descriptors for the same newly created resource group. Startup data is queued on
a private bounded socket before spawn, and the owner waits for an armed response.
Only descriptor numbers enter the helper command line; the helper inherits no
customer file handles, environment, terminal or log output. It runs outside the
workload resource group. The guardian watches the process handle rather than a
reusable PID or socket EOF alone, so a leaked copy of the owner's socket cannot
conceal owner death. This uses [Python's Linux pidfd interface](https://docs.python.org/3/library/os.html#os.pidfd_open).

The guardian independently enforces the retained monotonic deadline, kills the
complete process tree, verifies it empty and removes the original group. An early
`wait(action='finish')` while work remains terminates the job and reports
`not-empty`; it never disables protection for a live job. Late completion remains
a deadline failure. `wait(action='cancel')` terminates and cleans up. The owner
checks actual kernel removal before accepting a terminal response. If the guardian
unexpectedly dies, the owner uses its retained group descriptors for cleanup and
raises a fatal error instead of restarting protection around an uncertain job.

Explicit finish and cancellation wait at most ten seconds for the guardian's
acknowledgement before invoking retained-object fallback cleanup. This bound does
not grow with the purchased job duration. Fallback failure remains fatal.

After the leader exits, `finish_after_exit()` observes natural whole-tree exit
for at most two seconds while monitoring cancellation and the original deadline.
This handles launcher monitors that exit just after their leader. It requests
successful finish only after observed emptiness; a remaining tree is killed and
refused. Cancellation and expiry still take precedence. Direct busy finish remains
a refusal.

Thirteen kernel checks cover normal finish, cancellation, refused busy finish, owner
SIGKILL, owner exit without finalizers, a stopped owner's deadline, a deliberately
leaked control socket, guardian failure, bounded cancellation of a stopped guardian,
natural trailing-process exit, refused lingering descendants, independent expiry
and late finish. The
same checks run in CI and in the pinned boot image:

```sh
sudo python3 -I -B scripts/check-guest-guardian.py
```

This guardian contains workload processes; it does not erase staging data, retire
keys, or power off a VM. The deployment controller must still dispose of the guest
on fatal failure. Simultaneous loss of owner and guardian, kernel failure and a
privileged attacker inside the guest require that outer lifecycle boundary.
Filesystem, network and device isolation must keep workloads away from both
control processes and their handles before customer execution is admitted.

## Native runtime isolation

`compute/guest_sandbox.py` implements one native Linux CPU execution boundary
inside a measured guest. It launches arbitrary software supported by the approved
runtime tree; the check's Python program is an example workload. Other runtimes,
coordinated groups and accelerators remain part of the network scope and require
their own compatible, validated adapters. This boundary alone neither admits
hardware nor releases a key, accepts payment or proves useful output.

Create `NativeSandbox` only in a dedicated, privileged, single-threaded trusted
supervisor. Supply the retained approved runtime-tree digest, authenticated input
directory, validated `ResourceLimits` and `ScratchLimits`, and the configured
cgroup parent. Root and input trees must be root-owned on protected unswappable
memory storage, without writable ancestors, special files or hard links. The
runtime digest binds file contents, paths, executable permissions and symlink
targets; mount destinations must be real empty directories. The runtime is checked
again before launch. The enclosing launcher must obtain its expected digest from
the retained approved assignment, rather than trusting a worker-supplied value.

The supervisor arms its independent guardian before creating runtime storage.
A private mount namespace contains the read-only runtime and input mounts, plus
one scratch filesystem shared by work files, output, temporary files, shared
memory and stdout/stderr logs. Its byte and inode limits therefore apply across
those paths. The input copy also consumes that quota. These tmpfs mounts explicitly
disable swapping; ordinary tmpfs can use swap unless configured otherwise.
[Linux tmpfs documentation](https://docs.kernel.org/filesystems/tmpfs.html).
Authenticated staging uses the separate explicitly budgeted protected scope
described below; it does not borrow the customer's scratch allowance.

The trusted trampoline joins the resource group before executing pinned
Bubblewrap. It drops groups, capabilities and host privileges, clears the
environment, disables core dumps and locked memory, bounds file descriptors and
file size, and enables `no_new_privs`. Namespaces isolate users, processes, IPC,
networking, hostname and cgroup visibility. Further user namespaces are disabled.
The workload sees only its root, inputs, writable paths, private read-only proc
and minimal synthetic devices. Control processes, sockets and hardware devices
are not included. Control descriptors are closed before customer instructions.

A pinned libseccomp implementation constructs an explicit x86-64 syscall policy.
It permits ordinary processes, threads, files and local Unix sockets, while
denying unapproved syscalls, privilege changes, namespace creation, process
inspection, kernel administration and IP/netlink/packet/vsock socket creation.
There is currently no external or distributed network path in this primitive.
Authenticated, encrypted rank communication requires a separately reviewed
transport integration; do not enable unrestricted networking as a shortcut.
CUDA, ROCm and other device paths are similarly conditional on validated
confidential hardware and an appropriate device policy.

`run()` permits one bounded command and an explicit bounded private environment.
Host environment variables are never inherited. The supervisor monitors the guardian and
runtime together. Completion requires the whole resource group to be empty and
removed before it can report success. Cancellation and expiry report failure.
Guardian failure uses retained group descriptors to stop the workload and raises
a fatal error requiring guest retirement. The final guardian response is
acknowledged before socket closure, with a bounded drain for racing requests.

Keep the sandbox context alive while a trusted encoder consumes outputs and logs
inside the protected guest. Unmounting is checked and never uses lazy detachment;
failure requires guest retirement. Owner-process death kills the job tree and
releases its private mounts when the final namespace owner exits. This does not
implement outer VM disposal, key retirement, protection against simultaneous
supervisor/guardian loss, or physical erasure of every memory copy.

Nine actual-kernel checks exercise read-only roots and inputs, hidden control
paths/devices, syscall and network refusal, unprivileged identity, descriptor
closure, allowed local IPC/processes/threads, aggregate storage, inode and log
quotas, expiry, cancellation, owner death, guardian failure and a changed runtime.
The same owned checks are included in the boot image and Linux CI:

```sh
sudo python3 -I -B scripts/check-guest-sandbox.py
```

Use a disposable Linux environment with the exact pinned tools and enabled
cgroup controllers. The checker runs owned fixture code, not customer programs.
A successful ordinary VM check does not demonstrate confidentiality against a
worker operator. Real attestation, actual runtime admission, protected transport,
outer lifecycle integration and end-to-end paid acceptance remain
required before this becomes an operating worker.

## Encrypted native task execution

`compute/guest_native.py` connects package authentication, native execution and
result encryption. A retained `NativeTaskPlan` checks the approved runtime tree
before use. For `native-linux-x86_64-v1`, `runtime.digestSHA256` means the canonical
path/type/mode/content inventory produced by `tree_digest`, not the digest of a
downloaded archive. The measured launcher must select and approve this plan
before releasing a key. Caller-supplied matching values are not admission.

The plan requires one retained `ExecutionDeadline` from
`compute/guest_deadline.py`. Convert the independently authenticated, currently
active service interval with `ExecutionDeadline.from_service_interval(start, end)`
once, before preparing the plan or releasing its key. Pass that same object as
the plan's `deadline` argument. Decoding, runtime startup, execution, result
encryption and publication consume its remaining time. Each stage's own limit
can shorten that time; it cannot restart or extend the reservation. Helpers and
runtime guardians receive the absolute deadline before accepting work, so a
stopped supervisor does not let their process trees continue indefinitely.

The plan checks expiry after each stage and after checked cleanup. It also checks
around every ciphertext write; a supervisor resumed after expiry removes its
new result and returns no successful receipt. This does not remove ciphertext
or retire control-plane memory while that supervisor remains stopped. The
outer lifecycle must enforce guest disposal and key retirement. Converting UTC
to a monotonic deadline requires trustworthy guest time; it does not prevent a
host from pausing or rolling back the entire VM.

The private package must match the retained runtime, resource limits, package,
task, attempt, rank and return recipient. The plan permits one execution. It
supports a single CPU rank with an absolute argument vector and private
environment. Programs read `/input` and write declared files under `/output`.
Optional stdout/stderr destinations must be distinct declared encrypted outputs.
The adapter refuses groups, accelerators, unknown launch settings and dependency
tasks needing upstream reconstruction. These capabilities need further adapters
and transport integration; they are not silently reduced to standalone work.

Trusted decoding and result encryption run as separate bounded helpers. Each
joins a checked cgroup before reading its anonymous request pipe and has an
independent guardian. CPU, memory, process count, wall time and control-response
size are bounded. No key, launch contract or decoded log is written to process
arguments, environment variables or host-visible helper diagnostics. Customer
programs still run only in the native sandbox.

One private `noswap,nodev,nosuid,noexec` tmpfs holds authenticated staging and the
encrypted result. Its byte and inode budgets are additional explicit reservation
requirements. Native inputs and output/log storage retain their own shared quota.
The control plane must reserve all these capacities and its own bounded memory,
including the approved immutable runtime. Linux cgroup limits follow process
membership and hierarchy; they do not replace those whole-VM reservations.
[Linux cgroup documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).

The encoder runs only after the native process tree is verified empty. It checks
declared regular outputs and encrypts to the requester-bound recipient while the
sandbox context is still protected. Only complete ciphertext is copied out, with
its size and digest rechecked. The receipt remains private. Failed programs,
missing files, symlinks, quota exhaustion, cancellation and late helper completion
produce no accepted result. Requester decryption and reconstruction still precede
quality acceptance and payment.

The real-kernel owned check runs encrypted input through the native program and
reconstructs encrypted output and logs with a separate requester key. It also
exercises ciphertext tampering, mismatched resource metadata, unsupported groups
and dependencies, missing/symlink outputs, decode/encode staging exhaustion,
helper expiry, cancellation, owner death and a stopped owner. Shared-deadline
cases verify refusal before plan creation, expiry during actual native execution
and result encryption, and owner suspension during ciphertext publication:

```sh
sudo env PATH="$PATH" /usr/bin/python3 -I -B scripts/check-guest-native.py
```

The boot image runs these owned checks and powers off. Its additional aggregate-job
and execution-channel checks exercise the [funded native readiness API](guest-workload.md#funded-native-execution-readiness)
with owned fixture workloads. It is still not a customer launcher: full integration
of the initialized evidence session, finalized funded lease, hardware appraisal,
protected distributed transport and outer VM/key lifecycle remains unfinished. An ordinary VM check proves neither protection
against its host operator nor an independently reviewed paid service. A stopped
control plane may retain memory after its helpers are killed; external lifecycle
enforcement must dispose of the guest. No physical-erasure claim is made.

## Connect these artifacts to measured launch

### Owned SNP host launcher

The host adapter in `operator/snp-vm.mjs` connects the retained booked challenge
to a fixed Python/QEMU process, then to the existing encrypted session relay.
`runSnpBookedSession` is suitable for the provider's retained route handler; it
waits for checked local VM termination before returning. This source is under
integration, with no successful hardware launch or paid-worker admission claimed.

The first host profile supports EPYC-Milan SNP and at least four vCPUs. Preparation
selects guest memory from the retained operating image's measured budget: 4096 MiB
for the minimal runtime or 8192 MiB for CPU PyTorch. It checks that the build record
matches the actual kernel, initramfs and command-line hashes and that the selected
CPU count covers the budget. It pins QEMU, stateless OVMF, kernel, initramfs, command line and the
matching measurement candidate. Root-owned artifacts and parent directories are
required. QEMU's [SNP object](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#object-SevSnpGuestProperties)
requires a supporting build; the adapter also checks the actual KVM/SEV devices
and enabled host SNP parameter. It offers no TCG, ordinary KVM or remote-program
fallback. Host observations are never a replacement for requester attestation.

After installing reviewed artifacts privately, prepare a profile with
`scripts/prepare-host-vm.py --qemu /path/to/qemu-system-x86_64 --firmware /path/to/OVMF.fd
--image /path/to/image --reference /path/to/reference.json --machine pc-q35-VERSION
--cbitpos HOST_VALUE --reduced-phys-bits HOST_VALUE --cgroup-parent /sys/fs/cgroup/PROVIDER_SLOT
--output /private/root-owned/profile.json`. Select the actual reviewed machine
version and hardware parameters; the tool does not guess or create infrastructure.
Preparation does not start work or validate the reference on hardware.

The slot is an existing empty cgroup-v2 domain, with CPU/memory/PID controllers,
finite limits covering the selected host profile, and zero swap. The adapter
locks its actual inode for one VM at a time and refuses residual child groups.
It neither creates nor resizes ancestors or moves unrelated processes. Its own
VM leaf enforces the configured limits. Boot/executable snapshots are copied and
sealed only after joining that leaf. Preparation reserves the selected guest
memory plus 2 GiB for boot copies and QEMU headroom: a 6 GiB host process ceiling
for the minimal runtime or 10 GiB for CPU PyTorch. The retained profile independently
checks that its ceiling covers the actual artifact snapshots and QEMU overhead.

The VM receives only fixed devices, the measured control-plane network, inherited
local control sockets and public initialization `HOST_DATA`. No customer-content
keys enter the host launcher. An independent cgroup guardian and owner pidfds
cover owner death and the immutable deadline; heartbeat loss also cancels a
stalled operator. QMP is limited to configuration queries and shutdown-event
observation. Successful completion requires QEMU exit, guest-originated shutdown
and checked empty-tree removal. Cancellation does not become successful work.

The Node owner, supervisor, shared page cache, dispatch metadata and result HTTP
service still need complete aggregate operator accounting. Process cleanup does
not prove hostile-host snapshot destruction, protected key retirement or rollback
resistance. Uncertain execution and complete ciphertext retain their existing
recovery rules. These limits, actual SNP hardware acceptance and independent
review remain requirements before admitting paid customer jobs.

For SNP, the reviewed launch chain must cover firmware, kernel, initramfs, kernel arguments and initial vCPU state. QEMU's [SNP launch controls](https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html#launching-sev-snp) include initialization host data; the [sev-snp-measure tool](https://github.com/virtee/sev-snp-measure) calculates expected digests using the corresponding firmware, kernel, initrd and CPU configuration. Pin and review the actual firmware, VMM and measurement-tool revisions before using their outputs as trusted reference values.

For TDX, firmware and runtime measurement registers must cover the entire boot chain. [Contrast's reference-value documentation](https://docs.edgeless.systems/contrast/1.22/architecture/components/manifest) illustrates this distinction, including binding an external root filesystem through its integrity root in measured kernel arguments. Cannabis's current image has its userspace inside the initramfs; it does not yet have a reviewed firmware/TDX measurement calculation. Do not substitute a firmware-only measurement or an ordinary SHA256 file digest for that evidence.

The separate [firmware and SNP measurement tools](guest-firmware.md) calculate candidate reference values from pinned firmware and verified private copies of these boot artifacts. They do not establish a hardware-approved reference. The initialization gate binds the retained assignment to `HOST_DATA`/`MRCONFIGID` through the pinned agent; actual hardware mismatch/success cases and enforcement of the loaded workload policy still require the [worker acceptance run](worker-deployment.md#complete-the-worker-acceptance-run).

The published artifacts are build source and instructions. Before distributing guest binaries, complete the dependency/source and license review, preserve upstream and distribution notices, and satisfy the source-availability obligations of included components. A repeat build on one machine is not independent reconstruction or a security audit.
