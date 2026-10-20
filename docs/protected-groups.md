# Protected worker groups

A coordinated workload places one rank on each independently booked worker.
Cannabis binds the complete task, attempt, runtime and booking roster before
funding. Your requester client coordinates the group from your own device.

**Preparing mainnet launch.** The group implementation is undergoing integration.
Protocol checks cover two- and four-rank encrypted meshes and durable dispatch.
An owned Linux check separately supervises two ranks, computes 42 over private
TCP/TLS, reconstructs both encrypted outputs and checks cleanup. It uses synthetic
appraisals and no real funding. An isolated-chain requester checkpoint covers
four funded bookings across two coordinated tasks, encrypted dependencies, and
recovery after interrupted delivery or service expiry. Kernel failure checks
cover helper death/stalls, invalid traffic, cancellation and cleanup. These are
software checks with owned fixtures. A combined Linux checkpoint connects two
retained guest sessions, actual native execution, separate operator relays,
authenticated reconstruction and exact 99%/1% isolated-chain settlement. It also
rejects early key release, downgrade and replay. Refreshed release images, actual
confidential hardware, independent review and genuine paid acceptance remain
necessary for operation.

## The supported adapter

`native-group-linux-x86_64-v1` uses the `attested-tls-ip-v1` collective backend.
It runs one explicit application entrypoint per CPU rank. Each task must declare
`outputScope: "per-rank"` and provide its own partitioning, communication and
result assembly. The adapter does not automatically parallelize software.
Private native step graphs inside a rank are outside this adapter; task DAGs and
requester-mediated encrypted dependencies remain part of the complete plan.

The current complete-plan limit is 64 rank bookings across all tasks. The network
is designed for 2–64 ranks per group, subject to the booked resource and control
budgets. The current protocol checks exercise two and four ranks. An accelerator,
PyTorch installation, compatible checkpoint format or cross-architecture migration
requires its own runtime and confidential hardware path.

## Admission and start

Every guest holds its own non-extractable ephemeral channel key. Each peer
independently checks the entire roster, bilateral launch consent, initialization,
attestation appraisal and current booking state. The requester signs the exact
group, including peer endpoints and channel keys.

Peer channels use TLS 1.3 with keys derived from the attested guest keys. After
every listener exists, the peers connect. The requester verifies authenticated
readiness using a separate ephemeral key, then signs one common start. Each rank
also receives the same start commitment from every peer before becoming active.
Key-delivery approvals bind both the group and its common start.

This is coordinated readiness. Network partitions can still interrupt execution
at different times on different ranks. Missing peers, disagreement, cancellation
or deadlines stop the affected attempt; they never authorize a replacement rank
or a plaintext connection. Application failure and payment acceptance remain
separate decisions.

## Application networking

Each rank receives a private network namespace and the `cannabis0` interface.
Only bounded IPv4 TCP/UDP packets addressed between the exact group ranks cross
the encrypted peer mesh. There is no workload default route or access to the
worker's control network, TUN device, raw sockets, netlink, IPv6 or vsock.
The adapter uses an MTU of 1280 and refuses fragments and IP options.

The adapter supplies `RANK`, `WORLD_SIZE`, `LOCAL_RANK=0`, `LOCAL_WORLD_SIZE=1`,
`MASTER_ADDR=10.211.0.1`, `CANNABIS_GROUP_IP`, `CANNABIS_GROUP_INTERFACE=cannabis0`
and `GLOO_SOCKET_IFNAME=cannabis0`. Conflicting application values are refused.
`MASTER_PORT` defaults to 29500. These variables alone do not establish library
compatibility; the selected runtime must contain and support the application.

A signed v4 native service profile reserves control memory, processes, buffering
and traffic. The host forwards one fixed TCP port to the protected guest's TLS
listener. It receives encrypted traffic and public coordination metadata, not
customer content keys. Each production rank still needs its own admitted
protected VM and enforceable resource/lifecycle reservation.

## Requester setup and recovery

Follow the [booked workflow guide](requester-workflow.md). Add a `groupEndpoint`
such as `tls://worker.example:29420` to every group assignment, and select
`maxParallel` large enough for the whole group. Review the endpoints together
with the providers' consent and hardware policies.

The requester consumes all rank bookings in one durable local transaction before
dispatch. It retains the group approval, authenticated readiness, signed start,
per-rank key approvals and encrypted results. A crash or ambiguous response leaves
the complete attempt consumed. Recovery retrieves retained output; it does not
relaunch an uncertain rank. A new attempt needs a new reviewed complete plan.

Recovery revalidates the original group and start signatures at their signed
historical time, including after the booking expires. It cannot renew the start
window, reopen workload keys or turn an old receipt into another execution.

Each rank keeps its packet bridge alive until every rank has completed. Only
after local namespace/pump cleanup does it return its encrypted result receipt.
Reconstruction rejects ranks from different approved group starts. Stored output
does not establish useful work or authorize payment: the requester must still
verify results and explicitly accept the [payment](compute-payments.md).

The [allocation and service terms](tokenomics.md) remain unchanged. The included
founder service fee is exactly 1% of each accepted paid job; workers receive 99%.
