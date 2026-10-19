# Your worker console

The Cannabis worker console shows actual CPU activity, memory use and local hardware inventory in a browser window. It is available in the [project source](https://github.com/peter-ch/Cannabis). With an existing result volume selected, it also shows retained attempts and provides encrypted-result recovery and deliberate replacement delivery. It cannot accept customer jobs or earn payments yet. The result controls are under integration in the compute review branch.

## Open the console

On Windows, use the pinned Node.js 24.22.0 tools (or the reviewed Node.js 22.23.3 runtime), download the project source and double-click `Start-Cannabis-Worker.cmd`. Chrome opens the console when installed; otherwise Windows opens the default browser. Keep the command window open. Press Ctrl+C there to stop the local server.

From the project source directory on another platform, run:

~~~sh
npm run worker:console
~~~

Open `http://127.0.0.1:4201/`. Machine observation uses Node's built-in modules. Selecting a result store additionally requires the pinned project dependencies and the supported Linux volume adapter. The older Windows participant kit is a separate release and does not contain this console.

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

## Before a paid worker can start

The Start paid worker control remains disabled in this release. There is no hidden start endpoint or setting that enables paid work. Admission needs a fresh vendor-verified hardware report bound to the approved guest and assignment, a measured isolated launcher, protected storage/devices/networking, cleanup and key retirement, reviewed payment contracts and provider terms, and a real end-to-end acceptance run. See [worker deployment](worker-deployment.md) and [confidential computation](confidential-compute.md).

Ordinary desktop hardware and the website hosting servers are not automatically eligible. A remotely operated confidential worker could later be controlled from a desktop GUI, provided the attestation and key-release path is validated. No plaintext fallback is permitted.

The process listens only on loopback, serves an explicit asset list and refuses foreign hosts/origins. Result actions require same-origin bounded JSON and a process-local control token. The optional result adapter only opens the startup-selected store and uploads retained ciphertext to startup-selected relay origins. It has no job submission, arbitrary command/path, plaintext customer-content, custody or payment interface. Do not publish or reverse-proxy its port.

## Computing and issuance

Cannabis uses Ethereum proof-of-stake settlement. Workers are paid for accepted computing services; they do not mine new tokens. The fixed cap, community claims and vested founder allocation remain as described in the [terms](tokenomics.md). Local observations and a running GUI do not establish a mainnet launch. Canonical release information belongs in the [mainnet release guide](mainnet-release.md).
