# Your worker console

The Cannabis worker console shows actual CPU activity, memory use and local hardware inventory in a browser window. It is available in the [project source](https://github.com/peter-ch/Cannabis). With an existing result volume selected, it also shows retained attempts and provides encrypted-result recovery and deliberate replacement delivery. The compute review branch additionally contains provider-controlled wallet approvals and an optional booked-service lifecycle connecting retained assignments to the fixed SNP launcher. A reviewed paid worker is not available yet. These controls remain under integration; the older published tools do not include them.

## Open the console

On Windows, use the pinned Node.js 24.22.0 tools (or the reviewed Node.js 22.23.3 runtime), download the project source and double-click `Start-Cannabis-Worker.cmd`. Chrome opens the console when installed; otherwise Windows opens the default browser. Keep the command window open. Press Ctrl+C there to stop the local server.

From the project source directory on another platform, run:

~~~sh
npm run worker:console
~~~

Open `http://127.0.0.1:4201/`. Machine observation uses Node's built-in modules. Provider signing requires the pinned project dependencies. Selecting a result store additionally requires the supported Linux volume adapter. The older Windows participant kit is a separate release and does not contain this console.

## Read the observations

CPU and memory figures describe the whole computer, including unrelated applications. Windows graphics names come from the operating system; other platforms may report graphics inventory as unavailable. Neither hardware discovery nor utilization establishes confidential execution, useful completed work or billable usage.

Refresh requests a current observation. Pause monitoring stops automatic updates in that browser view; it does not stop the server, an upload or other software. Resume restarts observation. If the connection fails, the page marks retained readings as stale and disables recovery controls. Save readiness report downloads the latest observation with its timestamp and admission limitations. With a store selected, it includes attempt identifiers, capacity and upload progress. It contains no local storage paths, encrypted receipts, relay access tokens or content keys. Review this scheduling metadata before sharing.

## Connect retained results

First prepare the [bounded result volume](decentralized-compute.md#prepare-and-retain-the-result-volume) and its store through the configured operator. The console opens an existing store; it never creates or resets a missing ledger. The selected adapter requires root-managed Linux and local ext4 backing. Ordinary Windows folders are not a physical-store fallback.

From the reviewed source checkout, with pinned dependencies installed, start the
console using a locally selected store and any permitted replacement-relay origins:

```sh
sudo /path/to/pinned/node operator/server.mjs --result-store /var/lib/cannabis/result-volume/mount/spool --relay-origin https://your-selected-relay.example
```

Replace the example relay with the independently selected provider's actual
origin. Up to eight explicit `--relay-origin` options are supported. Omitting
them leaves local recovery available while replacement uploads remain unavailable.
`--port` selects another loopback port if needed. No browser request can supply
a storage path, change the permitted origins or mount a volume.

The result panel shows logical reserved bytes separately from free space within
the physical volume. Attempts have distinct reserved, uncertain, incomplete,
sealed, complete, requester-stored and cleanup states. Filter and pagination help
inspect larger stores. Records are not counted as paid jobs or earnings.

**Verify and recover** rehashes a complete retained archive and reconstructs
interrupted recovery metadata. It neither opens customer content nor restarts
execution. Partial output and uncertain dispatch cannot be promoted to completion
through this control. No deletion or retention-bypass button is exposed.

## Arrange another delivery

Select a complete result and choose **Arrange another delivery**. Obtain separate
upload and read grants for that approval from the selected relay, and paste the
provider's `{ "upload": { ... }, "read": { ... } }` document into the console.
The local backend checks their roles, origin, approval, relay identifier and
expiry. The remote relay still validates access when used.

Review the destination, archive fingerprint, size and expiry, then save the read
access file for the requester before confirming upload. The review expires within
five minutes and is single-use. Editing the destination requires a new review;
discarding it invalidates that approval. Grant tokens stay in process/browser
memory and the deliberately downloaded read-access file, never in status reports,
URLs or server logs. Share that file through the agreed private channel.

The GUI reports actual bytes uploaded and already present at the selected relay.
**Stop upload** cancels delivery while retaining the source. Closing the console
server aborts and awaits its upload before closing storage. Closing the browser
or pausing monitoring does not stop an upload. After a restart, retained results
remain in the store; the previous process's review and upload controls are not
reused. A fresh review may resume the same immutable ciphertext at the relay.

The relay reporting completion is not requester storage acknowledgement, useful
output acceptance or payment authorization. The requester still needs its own
approval/recovery material and verified decryption. Unacknowledged complete
results remain retained; only the existing verified acknowledgement and retention
policy can permit cleanup outside this console.

## Review provider approvals

The optional provider panel consumes a startup-selected catalog of public retained
assignments and an existing private approvals directory:

```sh
node operator/server.mjs --provider-catalog /absolute/provider-catalog.json --provider-approvals /absolute/approvals
```

The catalog has schema `cannabis.provider-catalog.v1` and an `assignments` array
(at most 64 entries, 16 MiB total). Each entry contains exactly `configuration`,
`initialization`, `proof`, `requesterConsent` and the canonical HTTPS peer `origin`.
These are the reviewed configuration, retained initialization, on-chain market
proof and already-signed requester launch consent used by the booked peer protocol.
The catalog contains no content keys or plaintext customer software/data. Choose
its RPC network and origin locally; neither can be replaced by a browser request.
The browser cannot add assignments or arbitrary wallet messages.

Choose **Prepare launch approval** for an assignment. The backend checks its
requester signature, retained commitments and fresh booking/funding observations
before offering wallet review. Select a wallet explicitly and connect its booked
provider account. Review the parties, chain and genesis, market/escrow, interval,
resource and runtime commitments, and gross/worker/service-fee amounts. Expand
**Inspect the complete wallet message** to see the exact EIP-712 fields.
Amounts are token base units; the displayed split is exactly 99% worker and 1%
service fee. Signing does not send a transaction or transfer those amounts.

**Review and sign in wallet** requests only `eth_signTypedData_v4` for that
provider launch consent or live peer approval. The client checks the account,
chain and genesis before and after the prompt. There is no automatic network
switch, personal-signing fallback or wallet-key entry. Wallet discovery uses
EIP-6963, with an explicit legacy-injected-wallet option where available. A
contract wallet must expose the booked provider account; the backend verifies
ERC-1271 at fresh finalized and current hash-bound observations. The GUI does not
substitute a contract owner's EOA for that account.

After launch signature verification, the complete bilateral consent is written
once beneath its assignment identifier. Existing or incomplete approval files are
never overwritten. Preserve the directory and reconcile interrupted writes
locally. Reopening validates retained consent structure and requester binding;
every actual launch or peer authentication still rechecks current funding and
wallet signature validity. Retention alone is not ongoing authorization.

A locally configured booked listener can use `ProviderApprovals.peerRoute(id,
handle)` with `listenBookedPeers`. That adapter sends the actual TLS callback to
this panel, retaining its origin, exporter, fresh nonces and remaining handshake
budget. The requester signature is checked before the provider prompt. A
submitted peer signature becomes **channel verified** only after the native
authenticated-channel capability passes the retained assignment check; the
subsequent execution handler still consumes its one-use capability. The optional
service below composes this adapter with the fixed host launcher; the signing
adapter itself supplies no hardware admission.

There are at most four pending requests and a bounded recent history. Reviews
expire within 60 seconds; peer requests retain the shorter remaining handshake
deadline. Decline, expiry, account/network changes, disconnection and console
shutdown discard pending responses. The wallet may keep its own prompt open;
dismiss it rather than signing a stale request. Browser closure does not revoke
an already saved consent, and no pending approval is restored after restart.
Readiness reports include public assignment addresses and commitments, but never
signatures, wallet keys or local paths. Review them before sharing.

## Configure the booked service

The review branch supports a single independently operated provider service on
a root-managed Linux SNP host with systemd 254 or newer and cgroup v2. The selected
systemd unit starts its loopback console through the fixed resource bootstrap.
Invoking `node operator/server.mjs --operator-config /absolute/operator.json`
outside that unit is refused. Observation-only consoles still work independently.
This mode owns the provider manager, existing dispatch journal and physical
result store together. Do not combine it with the separate result/provider flags
or run another console against the same stores. Nothing starts listening for
peers merely because the console opens.

The private configuration uses this shape (replace every example path/origin):

```json
{
  "schema": "cannabis.operator-service.v1",
  "resources": "/var/lib/cannabis/operator-boundary.json",
  "profile": "/var/lib/cannabis/host-profile.json",
  "catalog": "/var/lib/cannabis/provider-catalog.json",
  "approvals": "/var/lib/cannabis/operator-state/mount/state/approvals",
  "spool": "/var/lib/cannabis/result-volume/mount/spool",
  "dispatch": "/var/lib/cannabis/operator-state/mount/state/dispatch.sqlite",
  "peer": {
    "origin": "https://peer.example:4443",
    "listenHost": "0.0.0.0",
    "cert": "/var/lib/cannabis/tls/cert.pem",
    "key": "/var/lib/cannabis/tls/key.pem"
  },
  "relay": {
    "origin": "https://results.example",
    "port": 4210,
    "orders": "/var/lib/cannabis/operator-state/mount/state/orders.sqlite",
    "results": "/var/lib/cannabis/operator-state/mount/state/results.sqlite"
  }
}
```

All paths must already exist, be absolute and have root-owned parents without
symlinks or group/world write access. Configuration, profile, TLS key and databases
are private files. The console does not create/reset databases, obtain certificates,
change DNS or provision servers. Prepare their existing schemas through the
corresponding deployment tools and retain their recovery state. The catalog's peer
origins must match the selected TLS listener. Both local ports are explicit,
distinct and above 1023. An independently configured TLS reverse proxy must route
the selected result origin to the loopback relay; the peer port uses TLS directly.
No founder endpoint is required.

After retaining provider launch approval, choose **Start booked listener**.
The service first checks the pinned host profile, actual SNP device/QEMU support
and result volume. It selects only approved, unexpired, unused assignments and
allows one connection/session at a time. Actual peer authentication and fresh
funding checks still precede durable dispatch. The provider approves the live
connection in the wallet panel. Guest handoff, VM startup, encrypted relay and
local shutdown then appear as separate session stages.

**Stop intake and sessions** aborts peer connections and waits for owned cleanup.
The relay remains available for retained encrypted results until the console
server shuts down. Closing a browser or pausing monitoring does not stop the
service. A missing cleanup report or outstanding handler blocks restart in that
process. Preserve the VM slot, dispatch database and result volume for local
reconciliation; never erase them to force another attempt. Dispatch tombstones
survive restarts and are never reopened by a GUI action.

Local session completion means transport and local process shutdown only. It is
not vendor attestation, protected-key erasure, accepted useful work or payment.
The status report excludes local paths, TLS keys, signatures, result grants and
customer content. It includes selected origins, assignment identifiers, session
times and cleanup state. The report can contain scheduling metadata.

### Prepare the operator resource boundary

Install the reviewed source and pinned Node runtime beneath root-owned paths.
Select a private empty directory on ext4 for the operator's metadata volume. This
is separate from the retained ciphertext volume. The following commands create
new local state only; they do not provision hardware or start a service:

```sh
sudo python3 -I -B scripts/operator-state-volume.py create /var/lib/cannabis/operator-state
sudo /path/to/pinned/node scripts/prepare-operator-state.mjs /var/lib/cannabis/operator-state https://results.example
```

The default preallocated metadata image is 1 GiB with a finite inode allocation.
Half of that image is a protected recovery reserve, leaving the other half,
less filesystem overhead, for normal metadata. This spare space permits SQLite
to replay committed WAL data after the ordinary writable area fills.
`--bytes` and `--inodes` select explicit initial limits. It contains approvals,
dispatch, work/relay databases, SQLite sidecars and temporary files. Existing or
partially initialized state is refused rather than reset. Retain its manifest and
backing image. `mount`, `inspect` and `unmount` act only on that selected image;
unmount preserves all stored state. The image cannot grow as the filesystem fills.

Choose a unit name such as `cannabis-operator-primary.service`. The SNP profile's
`cgroupParent` must be `/sys/fs/cgroup/system.slice/cannabis-operator-primary.service/vm`.
After writing the operator configuration above, prepare new resource and unit files:

```sh
sudo python3 -I -B scripts/prepare-operator-boundary.py \
  --configuration /var/lib/cannabis/operator.json \
  --node /path/to/pinned/node \
  --state-volume /var/lib/cannabis/operator-state \
  --unit cannabis-operator-primary.service \
  --output /var/lib/cannabis/operator-boundary.json \
  --unit-output /var/lib/cannabis/cannabis-operator-primary.service
```

Review the generated profile/unit and installation before enabling it. Preparation
does not install, start or enable the unit. The profile pins the configuration and
Node executable, reserves control-plane capacity in addition to the selected VM
limits, and fixes the console port. The default extra reservation is one CPU,
1 GiB RAM and 128 tasks. It is an explicit ceiling, not evidence of purchased
capacity, useful utilization or billable work.

The bootstrap configures a control leaf and one VM pool beneath the unit's finite
aggregate CPU, memory and PID ceilings, with swap disabled. Node, Python supervisors,
guardians and VM descendants remain within that aggregate. Kernel accounting
covers charges made to the tree, including its charged page cache; shared pages
already charged elsewhere are not independent billing evidence. PID 1 supervises
the unit from outside this tree. Automatic restart is disabled. Main-process death
or shutdown invokes whole-group termination, with a 45-second stop ceiling.

The unit permits filesystem writes only in the two selected volume mounts and its
delegated cgroup subtree. SQLite temporary files use the bounded metadata volume;
core dumps and application stdout/stderr logging are disabled. The runtime checks
actual manager identity, executable, mount/cgroup objects and limits at startup,
before intake and before session handoff. A five-second monitor requests shutdown
if those observations fail or metadata headroom is exhausted. A session also needs
additional free metadata space before VM startup. Changing kernel limits or replacing
the mounted volume cannot silently renew the original observation.

The generated unit explicitly lists the installation's read-only mount points;
an ancestor setting alone does not cover every nested mount. Its device policy
allows the selected SNP/KVM devices and read-only observation of the two selected
loop devices, read-only clock access and standard pseudo devices. Startup verifies that opening those
loop devices for raw writes is denied without writing any data. If a remount changes
loop-device numbers, prepare and review the unit again before starting it.

A full metadata volume refuses further writes; it does not authorize deletion of
dispatch history, approvals or unacknowledged ciphertext. Relay failure still leaves
the separate local result spool available for recovery. These controls bound local
resources; they do not guarantee available throughput or delivery under every disk
failure, and they cannot constrain a malicious privileged host. Requester attestation
and protected execution remain mandatory. Actual SNP operation, its device access
under the selected service restrictions and genuine paid acceptance still require
hardware verification.

For metadata disk-full recovery, stop the exact selected unit and preserve all
database and WAL files. The explicit administrative commands are:

```sh
sudo python3 -I -B scripts/operator-state-volume.py release-reserve /var/lib/cannabis/operator-state --profile /var/lib/cannabis/operator-boundary.json
# Reopen and verify the retained databases with the pinned SQLite runtime.
# Reconcile permitted expired relay data and other owned temporary metadata.
sudo python3 -I -B scripts/operator-state-volume.py restore-reserve /var/lib/cannabis/operator-state --profile /var/lib/cannabis/operator-boundary.json
```

Release changes only the zero-content reserve file. The command verifies the
selected unit is stopped and requires an exclusive reserve lock. The fixed
bootstrap passes a shared lock to the actual Node owner, excluding concurrent
recovery. Startup is refused while the reserve is released; restore must fully
preallocate it again. No browser control releases this space, deletes databases
or resets dispatch history. Stop/recovery never establishes output acceptance.

The boundary follows [systemd resource delegation](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html),
[unit shutdown semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html)
and the [Linux cgroup v2 model](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## Before a paid worker can start

The Start paid worker control remains disabled in this release. The separate booked-listener controls do not establish paid admission. Admission needs a fresh vendor-verified hardware report bound to the approved guest and assignment, a measured isolated launcher, protected storage/devices/networking, cleanup and key retirement, reviewed payment contracts and provider terms, and a real end-to-end acceptance run. See [worker deployment](worker-deployment.md) and [confidential computation](confidential-compute.md).

Ordinary desktop hardware and the website hosting servers are not automatically eligible. A remotely operated confidential worker could later be controlled from a desktop GUI, provided the attestation and key-release path is validated. No plaintext fallback is permitted.

The console listens only on loopback, serves an explicit asset list and refuses foreign hosts/origins. Result, approval and lifecycle actions require same-origin bounded JSON and a process-local control token. The selected service's peer listener is separate and accepts only retained booked routes. Browser requests cannot add paths, commands, assignments or arbitrary signing messages. There is no plaintext customer-content, wallet-key custody or payment interface. Do not publish or reverse-proxy the console port.

## Computing and issuance

Cannabis uses Ethereum proof-of-stake settlement. Workers are paid for accepted computing services; they do not mine new tokens. The fixed cap, community claims and vested founder allocation remain as described in the [terms](tokenomics.md). Local observations and a running GUI do not establish a mainnet launch. Canonical release information belongs in the [mainnet release guide](mainnet-release.md).
