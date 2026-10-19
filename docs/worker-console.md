# Your worker console

The Cannabis worker console shows actual CPU activity, memory use and local hardware inventory in a browser window. It is available in the [project source](https://github.com/peter-ch/Cannabis). With an existing result volume selected, it also shows retained attempts and provides encrypted-result recovery and deliberate replacement delivery. The compute review branch additionally contains provider-controlled wallet approvals for retained assignments and direct peer connections. It cannot accept customer jobs or earn payments yet. These controls remain under integration; the older published tools do not include them.

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
subsequent execution handler still consumes its one-use capability. This adapter
does not itself start a listener, launch a guest or supply hardware admission.

There are at most four pending requests and a bounded recent history. Reviews
expire within 60 seconds; peer requests retain the shorter remaining handshake
deadline. Decline, expiry, account/network changes, disconnection and console
shutdown discard pending responses. The wallet may keep its own prompt open;
dismiss it rather than signing a stale request. Browser closure does not revoke
an already saved consent, and no pending approval is restored after restart.
Readiness reports include public assignment addresses and commitments, but never
signatures, wallet keys or local paths. Review them before sharing.

## Before a paid worker can start

The Start paid worker control remains disabled in this release. There is no hidden start endpoint or setting that enables paid work. Admission needs a fresh vendor-verified hardware report bound to the approved guest and assignment, a measured isolated launcher, protected storage/devices/networking, cleanup and key retirement, reviewed payment contracts and provider terms, and a real end-to-end acceptance run. See [worker deployment](worker-deployment.md) and [confidential computation](confidential-compute.md).

Ordinary desktop hardware and the website hosting servers are not automatically eligible. A remotely operated confidential worker could later be controlled from a desktop GUI, provided the attestation and key-release path is validated. No plaintext fallback is permitted.

The process listens only on loopback, serves an explicit asset list and refuses foreign hosts/origins. Result and approval actions require same-origin bounded JSON and a process-local control token. The optional result adapter only opens the startup-selected store and uploads retained ciphertext to startup-selected relay origins. Provider approvals use only startup-selected assignments. There is no job submission, arbitrary command/path/signing, plaintext customer-content, wallet-key custody or payment interface. Do not publish or reverse-proxy its port.

## Computing and issuance

Cannabis uses Ethereum proof-of-stake settlement. Workers are paid for accepted computing services; they do not mine new tokens. The fixed cap, community claims and vested founder allocation remain as described in the [terms](tokenomics.md). Local observations and a running GUI do not establish a mainnet launch. Canonical release information belongs in the [mainnet release guide](mainnet-release.md).
