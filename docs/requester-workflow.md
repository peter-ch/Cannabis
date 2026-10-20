# Run a booked workflow

Cannabis's requester client schedules your complete reviewed plan from your own
device. It connects directly to the selected providers, prepares encrypted
dependency inputs, asks your wallet for each approval and retains results for
recovery. There is no mandatory founder scheduler or account.

**Preparing mainnet launch.** The implementation has software integration checks.
Actual confidential hardware admission, current release images, independent
review and genuine paid acceptance remain required before production operation.
The client never submits payment or treats a stored result as accepted quality.

## Prepare the complete plan

First prepare the [workload and execution plan](universal-compute.md), complete
its [on-chain bookings](decentralized-compute.md), and obtain the exact bilateral
launch consent and initialization for every booking. Review each provider's
runtime, confidential-execution policy, Trustee endpoint and result-hosting origin.

Native Linux x86-64 CPU tasks support one rank per booking, including encrypted
dependencies and private native step graphs. The new
[protected group adapter](protected-groups.md) adds whole-group dispatch and
encrypted rank networking; its full runtime/release integration remains underway.
It requires an explicit entrypoint and per-rank output for every rank. Incomplete
plans and unsupported rank/runtime combinations are refused before dispatch.

Keep configuration, the private workload, encrypted input, custody backups and
the workflow directory on your requester device. Use absolute paths. A private
configuration has this shape; replace every example path and public commitment:

```json
{
  "schema": "cannabis.requester-workflow.v1",
  "proofFile": "C:/Cannabis/private/job/lease.json",
  "descriptorFile": "C:/Cannabis/private/job/descriptor.json",
  "manifestFile": "C:/Cannabis/private/job/workload.json",
  "ciphertextFile": "C:/Cannabis/private/job/workload.age",
  "directory": "C:/Cannabis/private/workflow-state",
  "keySource": {
    "python": "C:/Python/python.exe",
    "age": "C:/Cannabis/tools/age.exe",
    "identity": "C:/Cannabis/private/requester-identity.json",
    "capsule": "C:/Cannabis/private/job/job-key.age",
    "descriptor": "C:/Cannabis/private/job/descriptor.json"
  },
  "reconstruction": {
    "python": "C:/Python/python.exe",
    "age": "C:/Cannabis/tools/age.exe",
    "identity": "C:/Cannabis/private/requester-identity.json"
  },
  "resultRecipient": "YOUR_REQUESTER_AGE_PUBLIC_RECIPIENT",
  "maxParallel": 2,
  "maxStoredBytes": 134217728,
  "assignments": [
    {
      "reservationId": "FULL_ON_CHAIN_BOOKING_DIGEST",
      "origin": "https://provider.example",
      "resultOrigin": "https://results.example",
      "consentFile": "C:/Cannabis/private/job/consent.json",
      "initializationFile": "C:/Cannabis/private/job/initialization.json",
      "trusteeEndpoint": "https://your-reviewed-verifier.example/attestation"
    }
  ]
}
```

Include every assignment once. `reservationId` is the full booking digest, not
the requester's reservation nonce. Optional `caFile` selects a reviewed TLS trust
certificate file; it never disables certificate verification. The input and result
identities remain separate. `age-keygen` must be beside the selected age executable.
Use the supported [requester identity custody format](job-key-custody.md).

`maxParallel` is 1–64 and counts rank bookings. It must accommodate the largest
group as a whole. Group assignments also require their reviewed `groupEndpoint`.
`maxStoredBytes` must cover all declared result and dependency ciphertext limits,
per-booking metadata and group authorization allowances. This is a planning
bound; your requester filesystem still needs adequate storage. It is not a disk
quota. Hosted results currently support up to 64 MiB per booking.

## Start and approve

From the public source checkout:

```text
node scripts/compute-workflow.mjs create ABSOLUTE_CONFIG_PATH
node scripts/compute-workflow.mjs run ABSOLUTE_CONFIG_PATH
```

Creation is explicit and refuses an existing workflow directory. It retains the
complete plan, consent, public descriptor and private workload, with a durable
per-booking journal. Protect and back up this directory together with its files
and SQLite WAL files; do not delete a journal to bypass an uncertain launch.

Open the private loopback URL printed by `run` in a browser with your wallet
extension. Connect the intended account, then select **Start reviewed workflow**.
The screen shows each booking and its pending requests. Review and approve each:

1. A connection signature binds the booked provider and the particular TLS session.
2. A dependency signature, when needed, binds authenticated upstream selections
   and the exact encrypted input for the dependent booking.
3. A key-release signature authorizes the attested guest channel for that task.
   Current funding and the pinned attestation policy are checked before wrapping.
4. A storage signature acknowledges that encrypted output was received. It does
   not accept output quality or approve payment.

Coordinated groups also require approval of the complete attested peer roster
and a common start after authenticated readiness. These signatures precede key
release and do not authorize payment.

The wallet must report the selected chain and genesis block. Changing accounts
or networks invalidates pending approval. No wallet keys enter this client, and
there is no generic message-signing or transaction fallback. A cancelled approval
cannot dismiss an already open wallet prompt; late answers are discarded.

Keep the client and wallet ready during reserved windows. Independent tasks may
run concurrently up to your bound. Dependent tasks wait for current authenticated
source results and their own booking window. A missed window or interrupted
launch never silently changes the plan or starts a replacement booking.

## Recover and reconstruct

Press Ctrl+C to stop. Preserve the entire workflow directory. Inspect or recover
using its retained configuration:

```text
node scripts/compute-workflow.mjs status ABSOLUTE_WORKFLOW_DIRECTORY/config.json
node scripts/compute-workflow.mjs recover ABSOLUTE_WORKFLOW_DIRECTORY/config.json BOOKING_DIGEST
node scripts/compute-workflow.mjs assemble ABSOLUTE_WORKFLOW_DIRECTORY/config.json NEW_OUTPUT_DIRECTORY
```

An interrupted booking remains consumed. Recovery authenticates retained receipts
and ciphertext. If the ciphertext copy is missing but its retained result header
and read grant remain valid, recovery downloads it again without reconnecting to
the execution peer or releasing another key. The recovery storage signature stays
local; the client does not claim that the provider received it. Expired grants or
missing receipt/custody material require reconciliation with the provider's
retained output. Recovery never substitutes another approval or repeats execution.

After recovery, `run` can continue untouched queued bookings whose windows are
still available. It skips completed and uncertain bookings. Reconstruction uses
the retained private manifest, current inbox selections and requester identity,
and publishes only verified outputs into a new directory. It does not need the
original encrypted input file, and it never executes returned software or unpickles
model data. The application's output quality still needs your review before the
separate [payment acceptance](compute-payments.md) flow.
