# Assembling and checking the guest boot image

`scripts/build-guest-image.py` assembles a Linux kernel and complete in-memory boot filesystem containing the [pinned guest evidence services](guest-service-build.md), Node, Python, age and the Cannabis control-plane modules. The current entry point checks those components and powers off. It has no customer-job intake, operating worker endpoint or confidential-hardware authorization.

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

The output contains `vmlinuz`, `initramfs.cpio.gz`, `cmdline`, `build.json`, the unpacked `rootfs/` and private build-tool staging. The initramfs uses a deterministic `newc` archive with fixed ownership, timestamps, ordering and gzip metadata. Compare the final kernel, initramfs and command-line file hashes across builds. The command-line file's terminating newline is removed when passing its contents to QEMU.

The embedded file manifest checks regular-file contents during the boot check. This is local integrity evidence, not a hardware signature or proof against an operator controlling an ordinary VM. There is no persistent root disk or host filesystem mount. Customer execution will additionally require enforced isolation and protected temporary storage; the boot image does not establish those properties by itself.

Early boot copies only the embedded top-level image paths into a separate 1 GiB,
unswappable tmpfs root, then uses the pinned BusyBox `switch_root` to release the
original initramfs tree and start the guest initializer. The handoff is necessary
because Linux does not permit `pivot_root` from the initial rootfs; the workload
sandbox relies on that operation. No external disk or files enter this handoff.
The component check verifies the new root's filesystem and mount restrictions
before checking its file manifest. [Linux root-switching requirements](https://www.man7.org/linux/man-pages/man2/pivot_root.2.html).

The JavaScript runtime carries ethers and jose with locked transitive dependencies. Escrow inspection uses a checked-in ABI instead of loading the Solidity compiler inside the guest. Automated checks compare that ABI with the current compiled contract. Contract source, deployed-code hash checks and payment semantics are unchanged.

## Run the actual VM boot check

Install `qemu-system-x86_64`, then run:

```sh
python3 scripts/verify-guest-boot.py \
  --image /work/cannabis-image-first \
  --output /work/cannabis-image-first-boot
```

This uses QEMU's ordinary TCG CPU emulation, two vCPUs and 2 GiB of RAM. It attaches no NIC, disk, shared filesystem, monitor, QMP or debugger. The default boot-check deadline is fifteen minutes, allowing CPU emulation of all component checks; individual workload deadlines remain enforced separately. Failure or timeout does not count as a successful boot. Keep the serial log and verification JSON private. The owned entry point emits bounded phase names so slow or stalled checks can be distinguished without customer content.

Inside the VM, the entry point mounts ephemeral runtime storage, disables core dumps and further kernel-module loading, checks embedded files, exercises the Python extensions and age executable, and starts the actual attestation agent and REST bridge on loopback. Both production CPU probes must reject the unsupported sample profile with their exact structured refusal. Import errors, missing libraries and unexpected success fail the check. No hardware evidence, channel key, job key or customer computation is requested. The services are terminated and the VM powers off.

The boot check also runs the [initialization gate](guest-initialization.md) with both CPU profiles. It requires exact refusal on unsupported hardware and verifies that child services and sockets are removed. A cancelled startup, changed service binary and occupied loopback port must fail. An existing listener is never queried as if it were the spawned bridge.

The check deliberately does not treat execution on real SNP/TDX hardware as an accepted deployment: that requires the separate initialization, measurement, negative-case and full workload acceptance run. Do not turn an ordinary boot result into an attestation policy.

## Resource enforcement inside the guest

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

The boot image runs these owned checks and powers off. It is still not a customer
launcher: connection to the initialized evidence session, finalized funded lease,
fresh key-delivery admission, protected distributed transport and outer VM/key
lifecycle remains unfinished. An ordinary VM check proves neither protection
against its host operator nor an independently reviewed paid service. A stopped
control plane may retain memory after its helpers are killed; external lifecycle
enforcement must dispose of the guest. No physical-erasure claim is made.

## Connect these artifacts to measured launch

For SNP, the reviewed launch chain must cover firmware, kernel, initramfs, kernel arguments and initial vCPU state. QEMU's [SNP launch controls](https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html#launching-sev-snp) include initialization host data; the [sev-snp-measure tool](https://github.com/virtee/sev-snp-measure) calculates expected digests using the corresponding firmware, kernel, initrd and CPU configuration. Pin and review the actual firmware, VMM and measurement-tool revisions before using their outputs as trusted reference values.

For TDX, firmware and runtime measurement registers must cover the entire boot chain. [Contrast's reference-value documentation](https://docs.edgeless.systems/contrast/1.22/architecture/components/manifest) illustrates this distinction, including binding an external root filesystem through its integrity root in measured kernel arguments. Cannabis's current image has its userspace inside the initramfs; it does not yet have a reviewed firmware/TDX measurement calculation. Do not substitute a firmware-only measurement or an ordinary SHA256 file digest for that evidence.

The separate [firmware and SNP measurement tools](guest-firmware.md) calculate candidate reference values from pinned firmware and verified private copies of these boot artifacts. They do not establish a hardware-approved reference. The initialization gate binds the retained assignment to `HOST_DATA`/`MRCONFIGID` through the pinned agent; actual hardware mismatch/success cases and enforcement of the loaded workload policy still require the [worker acceptance run](worker-deployment.md#complete-the-worker-acceptance-run).

The published artifacts are build source and instructions. Before distributing guest binaries, complete the dependency/source and license review, preserve upstream and distribution notices, and satisfy the source-availability obligations of included components. A repeat build on one machine is not independent reconstruction or a security audit.
