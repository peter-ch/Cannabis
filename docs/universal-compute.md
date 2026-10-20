# One workload format, extensible runtimes

Cannabis packages arbitrary software artifacts with a private execution contract. The core format does not enumerate allowed application types. A runtime adapter can describe an executable, container, VM checkpoint, scientific solver, rendering engine, distributed model, or another workload. Its runtime digest, architecture and capabilities determine compatible placement.

**Implemented:** streaming encrypted packaging with fresh per-job input keys; requester-encrypted key custody; general task-graph validation; budget/deadline-aware candidate placement; whole-job and compatible multi-node groups; encrypted per-rank results; requester-side integrity verification, decryption and file reconstruction; signed offers, local holds and durable capacity leases tied to finalized escrow funding; pinned Trustee CPU appraisals, [requester-approved key wrapping](key-delivery.md), [guest-held channels with hardware-evidence collection](guest-attestation.md), and [assignment-bound guest workload decoding](guest-workload.md). **Release integration:** attested worker runtime, authenticated dispatcher and envelope transport, lease enforcement/recovery, protected peer traffic and operational payments. The software never authorizes execution from an advertisement or payment alone. See [capacity commitments](capacity-commitments.md).

## From software to returned files

1. Describe the runtime and its adapter-specific `launch` object. Pin the runtime by SHA256. Declare an explicit file allowlist, resource limits, task dependencies, expected output paths and assembly destinations.
2. Package the allowlisted artifacts. The private manifest and file names are inside the encrypted archive. The public descriptor contains opaque job ID, ciphertext commitment, runtime/resource requirements and dependency indices.
3. Compare compatible worker quotes. The current greedy planner can prioritize estimated finish time or cost, respecting the total budget and deadline. It models exclusive node leases to avoid proposing overlapping assignments on one node. A candidate schedule does not reserve capacity.
4. A protected dispatcher must verify signed terms, funded escrow, fresh hardware evidence, approved runtime measurements and all rank assignments before granting leases and releasing keys.
5. Each approved runtime executes its declared program inside the protected boundary. Intermediate dependency transfers, collective traffic and checkpoints remain encrypted. Replacements must satisfy the same policy.
6. Workers seal result files to the requester's age public recipient. Result context binds the original package digest, job, task, attempt, rank and world size. The requester verifies committed ciphertext and authenticated contents before publishing reconstructed files locally.
7. Output integrity is one acceptance check. Application correctness, quality and delivery obligations still determine whether payment is approved under the agreed terms.

## Task semantics

| Mode | Contract |
| --- | --- |
| Whole job | One task, one node; the compatible runtime runs the entire program |
| Task graph | Explicit `dependsOn` edges; independent tasks can run concurrently |
| Coordinated group | A task requests multiple nodes with compatible runtime, collective backend and group identity |
| Per-rank outputs | `outputScope: per-rank`; each rank returns an authenticated result package |
| Client reconstruction | An assembly item with `rank: all` expands destinations containing `{rank}` |
| Custom reduction | Declare a reducer as a dependent task in an approved runtime, or explicitly run trusted application logic on the requester's own machine |

The core client reconstructs files; it never imports returned Python, unpickles checkpoints, executes binaries or mathematically merges model tensors. Distributed checkpoint shards remain a coherent set for the declared model/runtime to load. Arbitrary programs do not automatically become parallel programs: the workload or adapter supplies partitioning, dependencies and merging semantics.

## Runtime adapters

### Bind task and rank bookings before funding

A `cannabis.execution-plan.v1` commits the entire public task graph and every
rank assignment. Build it from the requester's saved package descriptor, with
the reviewed network, provider, service digest, booking nonce, offer, interval
and exact gross price for every rank. It contains public runtime/resource
metadata and opaque task indices; customer commands, file names and outputs stay
in the encrypted workload. Keep the original descriptor and independently check
it against the packaged workload before signing; a worker-supplied descriptor
does not establish the original contract.

The plan requires one booked service unit per rank, all ranks present exactly
once, and one common attempt and window for each coordinated group. A successor
starts after its dependencies' reserved windows. Every window must cover the
task wall allowance. Duplicate booking nonces, missing ranks, changed resources,
cycles and early successors are refused. The atomic market path supports at
most **64 rank bookings** and therefore at most 64 distinct worker recipients,
within the escrow's 128-recipient limit. These are contract limits, unrelated to
the configurable community enrollment minimum. Larger workloads are rejected,
not truncated or automatically split into separately funded orders.

The offline preparation commands are:

```sh
node scripts/compute-execution-plan.mjs prepare context.json inputs.json
node scripts/compute-execution-plan.mjs commit-order context.json order-input.json
node scripts/compute-execution-plan.mjs market-plan market-context.json market-input.json
```

For `prepare`, the context contains `chainId`, `genesisHash`, `market`, `escrow`,
`token` and `requester`; input contains `descriptor` and `assignments`. Each
assignment contains `task`, `rank`, `attempt`, `acceleratorClass`, `provider`,
`serviceSHA256` and its public `booking`. The returned `plan` is the complete
execution plan. `commit-order` takes an agreed v2 `job` and `executionPlan`, checks
the total without changing the price, and returns a v3 order that commits the
plan digest. It never overwrites an existing plan commitment. `market-plan` takes
`asset`, that v3 `job`, `executionPlan` and `settlement`, with the reviewed market
console configuration. Its output is directly importable through **Open an
offer, order or shared plan** on the website or worker console. The simpler
provider selection form remains for orders without preassigned task bookings.

The funded v3 job hash and the resulting v2 market lease both bind the plan.
The complete lease matches each rank to the actual booked provider and service;
requester/provider consent also compares the selected runtime, resources and
network. A v3 order cannot fall back to an unplanned lease. Revised attempts,
providers or assignments require a revised plan and order commitment, with
explicit review of old-order refunds, replacement costs and new signatures.
These offline commitments do not reserve capacity, prove hardware, transfer
dependency outputs or authorize payment. Fresh chain observations and protected
execution remain required; cross-worker dataflow and collective networking are
still release work.

### Private step graphs on one worker

The native Linux adapter now implements `cannabis.native-step-graph.v1` as an
explicit private `launch` contract. This runs a bounded DAG **sequentially inside
one protected worker booking**, using one pinned runtime. Each step has its own
fresh sandbox. Only allowlisted package files and outputs of declared dependencies
are copied into that step's read-only `/input`. Programs write to `/output`.
The [step-graph example](../compute/examples/native-step-graph.json) shows the
format; the named programs and their partition/reduction logic are supplied by
the requester. Python is just the example interpreter.

Declare each step's `id`, `dependsOn`, `inputs`, native `launch`, `outputs` and
`outputMaxBytes`. Input mappings select either a `package` path or a preceding
`step`/`output`, with an explicit destination. Final `collect` mappings must
exactly cover the enclosing workload task's outputs. Paths, dependencies, cycles
and final collection are checked before packaging and again inside the guest.
There are at most 64 steps. The graph belongs inside **one** workload task;
top-level dependencies between separately placed tasks are not silently folded
into this booking.

Every step uses the enclosing task's CPU, memory, process and scratch limits.
One task wall allowance spans the whole graph, while the signed booking deadline
bounds decoding, graph execution, encryption, publication and cleanup. All retained
intermediate outputs, temporary input copies and the final collection share the
already reserved staging filesystem; size and inode quotas are never multiplied
by the number of steps. Size the staging allowance for all retained outputs plus
the current input copy and final collection. A quota, cancellation, deadline or
step failure rejects the entire result. Output links, hard links, devices and
FIFOs are refused. No partial result is published or billed.

Intermediate files stay inside protected guest storage. Only the declared final
collection is encrypted to the requester and bound to the original package,
task, rank and attempt. This requires a newly measured launcher containing the
graph implementation; older image evidence does not qualify it. Actual hardware
admission and independent review remain required. This path does not add
cross-worker transfers, parallel step execution, accelerator admission, automatic
partitioning or checkpoint migration. Those require their own compatible adapters
and encrypted communication paths.

### Requester-mediated dependency handoffs

The requester client can prepare encrypted inputs for a separately booked task
from authenticated upstream results. Each dependent task declares private
`dependencyInputs` entries containing `task`, `rank`, `output` and `destination`,
plus a `dependencyInputMaxBytes` limit. For example:

```json
{
  "dependsOn": ["prepare"],
  "dependencyInputs": [
    {"task": "prepare", "rank": 0, "output": "dataset.bin", "destination": "inputs/dataset.bin"}
  ],
  "dependencyInputMaxBytes": 1048576
}
```

Every predecessor must have an explicit mapping. Only its declared output ranks
and paths can be selected. Destinations cannot overlap each other or original
package files, including case and directory collisions. The mappings stay inside
the encrypted workload; the original package and complete execution plan remain
unchanged.

Use `node scripts/compute-results.mjs prepare-handoff requester.json handoff-input.json`
with the same local inbox and `reconstruction` custody configuration used for
result assembly. The input identifies the retained `lease` and `descriptor`
files, network `context` (including its genesis hash), target `reservationId`,
private `manifest`, encrypted `destination`, `window` (`notBefore`, `expiresAt`),
and `results` entries containing `approvalDigest` and the local ciphertext `file`.
All local file paths are absolute. Keep the prepared response in requester custody.

Preparation authenticates the current inbox selections, matches their exact
task/rank/attempt to the booked plan, decrypts and checks each complete result
archive on the requester device, and copies only the mapped files. It encrypts
the resulting capsule to the job's fresh input recipient. The owner's result
identity stays on the requester device. Temporary plaintext requires private
requester storage and is removed when preparation finishes or fails. Selected
data files do not inherit executable permissions.

The response includes an unsigned **Cannabis dependency handoff** wallet payload.
It binds the capsule hash and size, provenance context, network, funded order
commitments, target reservation/task/attempt/rank and validity window. Public-key
encryption alone cannot authenticate a handoff. `review-handoff` rechecks the
saved response against current inbox selections before signing; its input has
`lease`, `descriptor`, `context`, `reservationId` and `prepared` file paths.
Retiring an upstream selection invalidates that pending review. Approval of
these input bytes neither accepts upstream output quality nor authorizes payment.

The native guest path now accepts this signed capsule for the exact dependent
booking. Native service profile v3 reserves `ciphertext.dependencyBytes` and
`maxDependencyBytes` in addition to the original package and result capacity.
The launch handoff carries `{descriptor, signed}` as its `dependency` option;
`signed` contains `handoff`, `window` and `requesterSignature`. Both parties and
the guest verify that approval against the retained complete booking plan.

The original package and the separate dependency ciphertext arrive before the
guest creates its evidence key. Both files must match their reserved hashes and
sizes. Key-delivery approval v4 binds `dependencyApprovalDigest`, and its validity
must fit inside the dependency approval and booking windows. Current funding,
bilateral consent and confidential-hardware admission remain separate checks.
A preceding booking may have ended while the dependent booking is active; the
complete funded order must remain active throughout execution.

Inside the protected guest, guarded helpers decrypt and validate the capsule,
then copy only the private declared inputs into the selected task's input tree.
Original files, decoded dependencies and combined copies share the reserved
staging quota; preparation, execution and sealing share the booking deadline and
cleanup controls. Missing, substituted, oversized or unsigned inputs are refused.
Approval of input data still does not establish upstream output quality.

Focused software checks cover encrypted two-task execution, signed launch and
funding, key delivery, resource refusal and requester reconstruction. New measured
images, hardware admission and independent review are still required before
operating this version. No founder coordinator is required: the requester controls
its own handoff. Direct protected peer transfers, collective execution and
additional runtime admission remain separate work. The [requester workflow
client](requester-workflow.md) now schedules a complete supported native plan,
retains each dispatch before network handoff, requests explicit wallet approvals
and recovers results without repeating an uncertain launch.

### Adapter requirements

The adapter identifier is an extensible name, not a built-in application allowlist. An operational adapter must implement:

- **Inspect/export:** identify the environment and produce a consistent artifact set, with versions, architecture, device needs and pinned runtime.
- **Plan:** describe independent tasks or a coordinated group, expected communication, resource limits, inputs and outputs.
- **Launch inside protection:** validate the private launch object and execute only within the reviewed confidential boundary. Host-side commands must not contain customer arguments or secrets.
- **Checkpoint/recover:** persist encrypted state, enforce attempt identity and replay protection, and resume only on a compatible runtime.
- **Collect:** produce declared output files and bind them to the accepted job and rank.

Existing VM state needs a consistent export from its hypervisor. Copying an active disk file does not capture a running machine safely. CPU state, devices, disks, firmware, hypervisor version and external services affect migration compatibility. The package format can carry VM disks and checkpoint artifacts; an automatic live-VM exporter is not implemented yet. Similarly, a container image or arbitrary executable can be packaged now, while actual execution requires its validated adapter and confidential environment.

## Encryption and local storage

Large artifacts use [age's authenticated streaming format](https://age-encryption.org/v1), invoked through the [official age tool](https://github.com/FiloSottile/age). The client streams a USTAR archive into age without creating a plaintext archive file. An encrypted manifest records file sizes and SHA256 commitments. The receiver first hashes a private ciphertext snapshot, then decrypts those same verified bytes. It enforces portable paths, an explicit inventory, byte limits, context binding and complete stream authentication. Unverified extraction remains in a temporary directory until the entire stream passes validation; failures remove that directory. Budget local space for both the ciphertext snapshot and decoded files.

Use `pack-job` to create a fresh input identity for each job, with the private key encrypted to the requester's own public recipient in a separate key capsule. The encrypted workload binds that requester recipient for returned results. A job's input key therefore cannot decrypt other jobs or returned results. See [per-job key custody](job-key-custody.md). The funded workload ciphertext stays unchanged when a later protected channel delivers its job key.

The lower-level `pack` command still encrypts directly to the supplied recipient. An owner's general identity must never be given to a worker. Moving an already funded package to a different recipient changes its ciphertext commitment and requires explicitly approved new terms. Public descriptors and payments still disclose metadata. Neither packaging mode authorizes dispatch.

On Windows, `init-key` creates an age identity protected by CurrentUser DPAPI. Keep the vault outside the public repository. A synchronized DPAPI file still depends on the original Windows keys; arrange a separately protected portable backup. On other platforms, supply an age identity from a protected local store. The client accepts an identity file path, never a key in command-line arguments.

## Use the client

Requires Python 3.12+ and age. The checked Windows installation uses age 1.3.2; CI verifies the pinned release checksum. Set `CANNABIS_AGE` if the executable is not on PATH.

For separate job keys, keep the complete output directory private and upload only its `workload.age` and public `descriptor.json` when an authorized dispatcher is available:

```sh
python scripts/compute-client.py pack-job workload.json ./artifacts REQUESTER_AGE_RECIPIENT ../private/jobs/opaque-job-id
python scripts/compute-client.py verify-job-key ../private/jobs/opaque-job-id/job-key.age ../private/requester.dpapi.json ../private/jobs/opaque-job-id/descriptor.json --package-sha256 APPROVED_PACKAGE_SHA256 --policy-sha256 APPROVED_POLICY_SHA256
```

The recovery check prints a verification report, never the private key. On other platforms, use one native age X25519 identity from protected requester custody instead of a DPAPI vault.

```sh
python scripts/compute-client.py init workload.json --id opaque-job-id --policy-sha256 POLICY_SHA256 --runtime runtime.json --launch launch.json --file software.bundle --output result.bundle
python scripts/compute-client.py validate workload.json
python scripts/compute-client.py pack workload.json ./inputs age1... job.age --descriptor job.public.json
python scripts/compute-client.py plan workload.json workers.json --budget-base-units 100000000000000000000 --objective fastest
python scripts/compute-client.py seal-result workload.json task-id PACKAGE_SHA256 ./outputs age1... result.age --rank 0 --receipt result.receipt.json
python scripts/compute-client.py assemble workload.json PACKAGE_SHA256 results.json owner-identity-file ./returned
```

`age1...` and `PACKAGE_SHA256` are placeholders for the actual public recipient and the original encrypted package hash. `results.json` is an array of `{ "file": "result.age", "receipt": { ... } }` records whose ciphertext commitments the requester has accepted for inspection. Do not trust a receipt merely because it exists: encryption does not authenticate worker performance or prove an escrow payment.

The output limit defaults to 1 GiB per task/rank and can be explicitly raised through `outputMaxBytes`, up to the client's 1 TiB bound. Artifact packaging also has a 1 TiB bound. Configure practical storage budgets before large jobs. Metadata is bounded to 4 MiB. The planner validates up to 4,096 task templates and 100,000 advertised nodes; these are parser/planner limits, not measured operational throughput.

See [workload examples](../compute/examples/) and [payment rules](compute-payments.md). All generated plans leave execution, key release and payment unauthorized pending the real integrations.
