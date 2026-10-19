# Website orders and results

Open [Your work](../work.html) to select a direct market, prepare an order, recover its transaction history or decrypt result archives on your device. Registration is optional. No public mainnet deployment is selected by default. The optional order service saves **preparations**; it does not accept deposits, queue execution or advertise available provider capacity.

The review branch connects the browser to the [decentralized market](decentralized-compute.md) without the preparation service. Website accounts and hosted storage are optional conveniences and cannot approve workers or decide shared capacity. Public operation still requires a reviewed live release, confidential worker admission and verified paid acceptance.

## Direct market ordering

Obtain a reviewed deployment configuration independently and select it under **Your work. Your agreements.** It uses the same `cannabis.market-console.v1` schema and runtime pins as the [worker console](worker-console.md#direct-market-controls). Review the chain, genesis, contract addresses, runtime hashes and finite transaction fee limits before opening it. The selected RPC must allow browser requests from this website origin. Compressed replies must expose their content-encoding header through CORS; both declared and decoded reply sizes are bounded. Its canonical and finalized responses are an explicit trust dependency; this browser does not verify consensus itself. A website operator must permit the selected HTTPS RPC through its Content Security Policy. The client sends public chain queries without credentials or referrers; the RPC still sees your connection and query metadata.

Open saved history, explicitly start new history, or restore your latest recovery file. An exclusive Web Lock prevents two pages on the same browser origin from controlling this deployment simultaneously. IndexedDB must be available: the browser commits a transaction handoff before opening the wallet. There is no memory-only payment mode. Storage, locks and recovery are local to this browser origin, not synchronized across devices or websites. Clearing or eviction of browser storage loses that history; an old recovery file cannot reveal transactions made later elsewhere. Keep the latest file and reconcile wallet activity before another action.

Search a bounded finalized block range and import the providers' corresponding manifests or shared offer plans. The browser checks each manifest against its on-chain commitment, deployment, provider and offer. These declarations do not prove available hardware. Select every provider needed for the complete job, the agreed booking interval and units, and a public `cannabis.compute.order.v2` job exported from your compute client. Code, arguments, data, keys and private workload files do not belong in this form. Its exact committed budget must equal the gross booking total. Review the delivery manager, adjudicator and deadlines before retaining a plan. Plans with more complex intervals can be imported as typed market plans.

Share the retained plan with providers and import their signed holds. Each signature is checked against the selected contracts. Use the wallet controls to reserve the complete group, approve the exact allowance when paying Cannabis, fund the escrow, obtain every provider's acceptance and activate the group. Each step has its own fresh state check, simulation and maximum fee review. Intermediate inclusion may be reorganized; protected execution requires finalized activation and separate confidential admission. Neither a booking nor payment releases customer keys automatically.

Recovery downloads contain public plans, provider hold signatures and transaction payloads, never wallet secrets or workload keys. They can reveal and link your activity; share them deliberately. A download is requested before each transaction prompt; verify that your browser saved it and save a newer copy after receiving the hash. Cancelling a prompt or closing a page cannot revoke a submission. An uncertain handoff blocks further transactions from that account until its exact hash and canonical receipt can be reconciled. Restoring a backup imports transaction claims, discards old receipt observations and requires fresh checks; it cannot overwrite newer local history with an older confirmed claim. The browser bounds retained history to 32 plans, 256 actions and 8 MiB per deployment, with 16 deployments. Use the desktop client for larger histories rather than resetting unresolved activity.

## Guest ordering

Choose Cannabis or ETH and an exact maximum budget. You may attach a `cannabis.compute.order.v2` manifest from the [compute client](compute-payments.md). Only the opaque job identifier, requester address and encrypted package, policy and acceptance commitments are sent. Private workload instructions, code, inputs and content keys stay on your device.

Create and save the preparation recovery file, then reopen that file to verify your copy before the preparation is stored online. Its random 256-bit access key controls access to that preparation. Keep it private and backed up. The service stores a SHA-256 digest of the access key, never the key itself. Recovery secrets travel in authorization headers, never links, URL fragments or analytics. These access keys are not persisted in browser storage. This file is separate from direct-market transaction recovery.

Preparations expire after 30 days and can be deleted earlier from the dashboard. Losing a guest recovery file loses access unless you explicitly linked the preparation to your account. The recovery file is **not** a cryptocurrency wallet and contains no result-decryption identity. An expired or deleted preparation does not cancel an independently created blockchain transaction.

## Optional accounts

Choose **Sign in / register** and sign the displayed wallet message. The first valid sign-in creates an account. No email, password or identity documents are requested. This uses a domain-bound, chain-bound, five-minute, single-use [Sign-In with Ethereum message](https://eips.ethereum.org/EIPS/eip-4361) and a browser-bound challenge cookie. Sign-in does not authorize transfers or token allowances.

Only ordinary Ethereum signing accounts are supported by this version. ERC-1271 smart-contract wallet verification is not enabled. Sessions expire after 12 hours and use HttpOnly, Secure, SameSite=Strict cookies. Signing out revokes the session. Save-to-account is an explicit choice for each preparation; existing guest preparations are not silently attached to a wallet. Account history contains only explicitly linked orders.

Guest means no registration. Public payment addresses, blockchain transactions, timing and network metadata can still identify or link activity. The web host necessarily receives connection information. The application does not log request bodies, access credentials, wallet signatures or private files; no analytics scripts or third-party scripts are loaded on the work page. The account service stores the wallet address used to sign in.

## Payments and the founder fee

The implemented settlement contract supports separate immutable escrows for Cannabis and native ETH. The ETH escrow uses the zero token address and requires an exact `msg.value`; no wrapping or token allowance is needed. The Cannabis escrow requires an exact token deposit and rejects attached ETH. Neither is deployed for public use yet.

Each accepted gross payment allocates **99% to workers and 1% to the founder recipient** `0xe02Ad92413aD0a3Aac8263eE3C2Bd9410955F89b`. The fee is included in the budget, never added on top. Refunded portions incur no fee. Fees accrue as withdrawable credits for that wallet; they are not transferred to the wallet after every tiny job. Network transaction costs are separate. Every positive funded budget or award must be a multiple of 100 base units, making the fee exact even for tiny payments.

The website does not instruct customers to send a job budget directly to the founder wallet. Payment must fund the reviewed escrow for the exact agreed workers, workload, deadlines and dispute terms. Account sign-in and recovery possession do not replace the requester's wallet signature. A future quote must include the chain, asset, escrow and runtime pins, provider availability, total charge, expiry, network fees and refund/dispute terms. The present API refuses quotes with `PAYMENT_NOT_OPEN`; there is no configuration switch that turns a preparation into paid or completed work.

See [job payments](compute-payments.md) for acceptance, disputes and refunds, including the review-window deadline. The minimum atomic amount is a precision limit, not a promise that an on-chain transaction is economical. [Small jobs](microjobs.md) covers aggregated fees and low-cost settlement requirements.

## Other cryptocurrencies

Conversion is not enabled. Routing services can supply swap or bridge quotes and unsigned transactions; for example, the [LI.FI quote API](https://docs.li.fi/li.fi-api/li.fi-api/requesting-a-quote) exposes destination estimates, minimum amounts and a transaction request. This is a researched integration option, not a selected, endorsed or connected payment provider.

A reviewed integration must bind the source and destination chains/assets, approved router and spender, requester-controlled destination, explicit slippage, fees, quote expiry and sufficient destination funds. The customer must approve conversion separately. A conversion receipt is not escrow funding; funding must be verified on the destination chain. Failed routes, refunds, provider terms and privacy require review. Cannabis liquidity and routes must actually exist before quoting conversion into Cannabis. No swaps or bridges have been initiated by the website.

## Decrypt and reconstruct results

The result panel works locally even without an account or live order service. First export the current authenticated receipts and encrypted result-key backups from your [requester inbox](key-delivery.md#requester-receipt-recovery-and-approved-attempts) with `export-browser`. Open that requester-held recovery file, review its job, requester address, chain, escrow and attempts, and select **Use these approved attempts**. The export includes public signed approvals and encrypted custody/receipts; it contains no identity secret or decrypted output. Use your own latest export, never a worker-provided selection file.

Then select the **original private workload**, its encrypted package SHA-256, corresponding `.age` archives, and the requester's age identity file. Never enter a wallet seed or wallet private key. Windows DPAPI identity vaults remain in the desktop client; the browser accepts a plain age result identity file already controlled by the requester.

The viewer uses [age-encryption](https://github.com/FiloSottile/typage), bundled with the site. It checks the encrypted file digest and size before decryption, authenticates the complete age stream, and verifies archive hashes, job/package/task/rank/recipient bindings, output inventory and assembly destinations. It rejects extra members, unsafe paths, duplicate or overlapping destinations and incomplete required results. No archive code is executed or rendered as HTML. Only files that pass these archive checks receive download links. Keep the original private terms and reviewed result commitments: hashes in an arbitrary supplied receipt alone do not prove who performed the work or whether the result is correct.

The browser verifies the requester EIP-712 signature, domain and complete version-2
approval, recovers the per-release receipt key from its age-encrypted backup, and
authenticates the private JWE receipt against that approval. It binds the receipt
to the original package, policy, task index, runtime, recipient, rank and attempt
before reconstructing outputs. Plaintext receipts alone are not accepted by the
website. These checks establish the supplied records' cryptographic bindings;
they do not independently attest the worker, prove output quality or approve payment.

Selected attempts, encrypted receipts and encrypted result-key backups are retained
in IndexedDB on this browser origin. Identity secrets, original workload contents
and plaintext results are not persisted. Replacements require a higher signed
attempt with unchanged workload bindings; retired or superseded attempts cannot be
reselected. The browser checks the selection again after decryption and inside a
transaction when showing results or starting a download. A change in another tab
invalidates an older download. Conflicting receipts are refused once that approval's
results have been authenticated and checked. An unverified damaged import can be
replaced with the correct export without abandoning the signed attempt.

Browser storage is a local cache of your explicit selections, not a synchronized
global inbox. A desktop or another device can select a newer attempt without this
browser knowing. Re-export the current desktop state before relying on it. Clearing
or eviction of browser data removes its history; a new browser cannot determine
whether an old export was superseded elsewhere. Keep the requester database and
encrypted backups. Importing a recovery file never silently selects its attempts.
The local cache supports 16 jobs, 128 selected results per job and an 8 MiB recovery
export per job; larger workloads use the streaming requester client.

The browser supports result sets up to 64 MiB and 128 archives. Larger sets use the streaming desktop client. **Clear results & stop download** removes download links, private file inputs and in-memory downloaded ciphertext, and cancels an active transfer or opening; it preserves the encrypted recovery records in IndexedDB. **Retire selected attempts** removes the selected encrypted records while retaining the local history needed to refuse replay. It does not cancel remote execution or revoke previously disclosed keys. Downloaded plaintext remains on your device. Browser decryption is subject to the security of the delivered website and your browser; use a reviewed local client for stronger separation from the web host.

The result viewer opens requester-supplied encrypted files or retrieves an
encrypted delivery when the website reports that its optional relay is enabled.
Choose one delivery **read-access** file for every selected result. These must
match the current website origin and your selected approval digests. Before any
download, the browser opens your local encrypted key custody, authenticates each
receipt and verifies the original workload bindings. It then accepts only the
same encrypted receipt, archive hash and size from the relay. Your identity and
workload are not uploaded; read tokens are sent only in authorization headers.

Completed encrypted chunks remain in this page's memory after an interrupted
download. Retry with the same delivery files and reselect your identity file;
already received chunks are reused. A corrupt whole-archive hash discards that
archive's cache. Requests have bounded retries and time limits, and respect busy
or rate-limit responses. Closing or clearing the page discards these chunks.
They and the read tokens are not stored in IndexedDB. The browser checks that the
selected attempt is still current before and after network operations, then again
when publishing decrypted files or downloading them. A retrieval check cannot
mark an unfinished result verified. Another tab's retirement prevents publication.

The relay and retrieval controls are implemented in source but not enabled on the
public service. Production admitted-worker publication and requester acknowledgement,
reviewed live quotes and actual paid acceptance remain unfinished. Direct-market
wallet checkout and transaction reconciliation are available in the review branch.
Local verification or relay storage does not approve a payment.

## Operating the order service

`service/work-server.mjs` is a separate non-custodial Node service. Set `CANNABIS_WORK_DB` to a private SQLite path and `CANNABIS_WORK_ORIGIN` to the canonical HTTPS origin, then run `node service/work-server.mjs`. It listens only on `127.0.0.1:4210` by default. `CANNABIS_WORK_PORT` changes that loopback port. Only a configured Caddy proxy may use `CANNABIS_WORK_PROXY=caddy`; it must overwrite `X-Cannabis-Client-IP` and preserve the configured Host. Never expose this listener directly.

The service uses bounded JSON bodies, exact schemas, same-origin writes, request timeouts, per-connection-source/global request limits, persistent single-use challenges and bounded record counts. Store the SQLite database and its backups outside the static web root, with a dedicated unprivileged service identity and restricted permissions. Restarting the service preserves orders and invalidates no unexpired session unnecessarily. Do not upload custody vaults or workload keys. The website host is not a confidential compute worker.

The service checks its actual SQLite library version before opening the database,
refusing versions affected by the [concurrent WAL-reset bug](https://sqlite.org/wal.html#the_wal_reset_bug).
Use the pinned patched Node runtime and keep coherent database backups. The runtime
check prevents use of the known affected library; it is not a corruption repair.

## Encrypted result relay

The optional relay stores encrypted archives and encrypted receipts on an ordinary
host. It receives no identity, content key, private workload or plaintext output.
It can observe approval identifiers, network addresses, timing and ciphertext
sizes. The requester must authenticate the encrypted receipt against their own
selected signed approval, check the complete archive hash and reconstruct locally.
The relay's `complete` flag means its stored bytes match the supplied manifest;
it does not prove execution, protected hardware, output quality or payment.

Set `CANNABIS_RESULT_DB` to a separate private local SQLite file to enable the relay
in the order service. Keep it and coherent backups outside the web root. Deploying
this option still requires reviewed artifacts and host resource checks. It is not
currently enabled on the public service. Public callers cannot create reservations.
The operator provisions each approved delivery locally:

```sh
node scripts/reserve-result-storage.mjs private-relay-config.json reservation.json /absolute/private/new-access-directory
```

The standalone service artifact includes the same tool as `reserve.mjs`, together
with its dependency notices; use `node reserve.mjs` with the same arguments there.

The config contains `database` (the absolute private database path) and `origin`
(the canonical HTTPS website origin). The reservation contains `approvalDigest`,
`maxCiphertextBytes` and `expiresAt` (Unix milliseconds, at most seven days ahead).
The command creates a new directory containing separate `upload.json` and
`read.json` access files. Existing files are never overwritten. Distribute only
the corresponding role file through an authenticated private channel; these are
bearer credentials, not content-decryption keys. They are hashed in the relay
database and must never appear in URLs, logs or public files. A failed provisioning
attempt can leave partial files or a reservation until expiry; retain them for
operator recovery. Reserving space incurs no payment and grants no execution.

All routes use `/api/work/results/{id}` and the matching `Authorization: Bearer`
token. Writes require the configured `Origin`. The existing host, rate, request
timeout, no-cache and cross-origin restrictions also apply.
The reverse proxy must serve result responses without content encoding; disable
automatic compression on these routes. Keep exact byte lengths and allow the
documented manifest/chunk body limits only on their corresponding routes, while
retaining the smaller preparation-body limit elsewhere. The requester rejects
redirects, encoded responses, oversized bodies and unexpected media types.

| Method and suffix | Role | Behavior |
| --- | --- | --- |
| `POST /manifest` | Upload | Fix `{resultEnvelope, ciphertextSHA256, ciphertextBytes}` as JSON |
| `GET /status` | Upload | Return received chunk indices and completion state |
| `POST /chunks/{index}` | Upload | Store one uncompressed `application/octet-stream` chunk |
| `POST /finish` | Upload | Send `{}`; check every stored byte and the complete SHA-256 |
| `GET /manifest` | Read | Retrieve the encrypted receipt and archive metadata after completion |
| `GET /chunks/{index}` | Read | Retrieve one encrypted chunk after completion |
| `DELETE` | Read | Revoke access and remove the stored object and chunks |

Chunks are 65,536 bytes except the exact final remainder, indexed from zero.
Missing chunks can be uploaded in any order after restart. Exact retries are
idempotent; conflicting manifests or chunks cannot overwrite the chosen result.
If chosen bytes are wrong, create a new reservation. Partial objects cannot be
downloaded. Expiry is checked again during mutations and denies reads immediately;
periodic cleanup removes expired rows. Deletion does not erase prior copies or
backups or revoke content keys already disclosed elsewhere.

The default limits are 64 MiB per archive, 6 MiB per encrypted receipt, 128 slots
and 128 MiB of total reserved archive-plus-receipt capacity. Reservations count
their full allowances before upload. Limits are persisted and cannot be changed
on an existing database without reviewed migration. A database page ceiling is
additional protection; WAL, filesystem overhead and backups still need host disk
limits. Two concurrent body/large-response transfers are allowed, each with a
30-second total deadline. Existing per-source and global request limits also bound
chunk throughput; clients must resume later after a rate or busy response. No
automatic signing, payment, content-key release or admission follows a successful
upload. The website has bounded download/retry controls. An ordinary-host upload
tool is described below. A [hosted streaming handoff](key-delivery.md#hosted-streaming-handoff)
connects it to local requester storage and signature checks. Production session
composition and reviewed host deployment remain required before this can serve
admitted jobs.

## Uploading an encrypted result

The operator tool sends an already encrypted archive and encrypted receipt to an
existing reservation. It opens no identity, content key or wallet, and neither
runs customer code nor admits a worker. Keep the upload access and source files
private. Independently configure the expected HTTPS origin; do not take it from
an untrusted access file. HTTP is allowed only at `127.0.0.1` for local checks.

```sh
node scripts/upload-result.mjs private-upload-config.json upload.json encrypted-source.json
```

The standalone service artifact includes `upload.mjs` and its notices; run
`node upload.mjs` with the same arguments outside the source tree. The config
contains exactly `origin` and `timeoutMs` (a positive integer, at most 3,600,000).
An example timeout of 1,800,000 allows 30 minutes; the reservation expiry can end
the operation sooner. An upload timeout does not extend any signed job interval.
Rate limits can make a large transfer take minutes, so budget its full duration
before admitting execution.

The source JSON contains exactly these fields:

| Field | Value |
| --- | --- |
| `approvalDigest` | The approval already bound to the upload reservation |
| `resultEnvelope` | The unchanged compact encrypted result receipt |
| `ciphertextSHA256` | The expected lowercase SHA-256 of the complete encrypted archive |
| `ciphertextBytes` | Its exact byte length, at most 64 MiB |
| `ciphertext` | The absolute local path to that binary age archive |

The uploader checks the entire file's length and hash before making a request.
It checks the age prefix and the encrypted receipt's framing and approval header;
these format checks do not authenticate the receipt or prove that arbitrary
operator-supplied bytes protect a real workload. Only the requester can authenticate
the private receipt and decrypt/reconstruct their result. The operator must receive
these encrypted artifacts through the reviewed guest handoff. The result-phase
bridge is implemented; production session admission and composition remain
unfinished.

The tool retains the original file and rechecks each chunk against its initial
scan, refusing source changes. It sends the fixed manifest and only missing chunks.
Each request has a 15-second deadline and at most three attempts; busy or rate
responses have bounded waits within the operation deadline. Redirects, encoded or
oversized responses and mismatched acknowledgements fail closed. After interruption,
rerun with the same config, access and source files before expiry. Previously stored
immutable chunks are reused. A changed manifest or archive requires separate review
and a new reservation, not an overwrite. Stop signals cancel the active request.

The JSON report says `relayReportedComplete: true` only when the relay reports a
complete matching upload. Remote durability and honesty remain unproven by this
response. `requesterAcknowledgedStorage`, `outputVerified`, `qualityAccepted` and
`paymentAuthorized` all remain false. Preserve the encrypted source until the
requester's authenticated storage acknowledgement and the applicable retention
policy permit removal. Never turn a relay response into the requester's signature.
