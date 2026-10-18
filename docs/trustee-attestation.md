# Attestation before access

Cannabis's requester-side attestation component verifies signed results from an independently trusted Confidential Containers Trustee service. It connects an encrypted workload, paid lease and particular execution rank to fresh measured evidence and a guest-generated public key. This is one step toward keeping customer jobs private from worker operators.

The implementation is in `compute/attestation.mjs`, with a CLI in `scripts/compute-attestation.mjs`. It targets the EAR format and REST API in [Trustee v0.22.0, revision 512fed65642015b849f38fb13bfdec7806639987](https://github.com/confidential-containers/trustee/tree/512fed65642015b849f38fb13bfdec7806639987). It consumes **SNP and TDX CPU appraisals only**. Accelerator jobs remain unavailable through this component until CPU, device and interconnect evidence can be verified together. The integration does not itself implement vendor quote verification, dispatch a workload, authorize execution or release a key.

## Trust and measured configuration

Run Trustee in an environment trusted by the requester, separately from an untrusted worker's host. Provision the service's P-256 signing **public** key through an authenticated administrative channel. The client verifies ES256 signatures against that pinned key. A token's embedded JWK or certificate chain never supplies trust; remote key URLs are rejected.

The private policy file must contain exactly these fields:

| Field | Required value |
| --- | --- |
| `schema` | `cannabis.attestation.trustee-policy.v1` |
| `issuer` | The configured AS issuer |
| `signingJwk` | Public JWK with exactly `kty: EC`, `crv: P-256`, `x`, `y`; no private coordinate |
| `verifierBuild` | The configured EAR verifier build string |
| `appraisalPolicyId` | The approved base policy ID; Trustee selects its `_cpu` policy |
| `maxTokenAgeSeconds` | 1–300 seconds |
| `maxTokenLifetimeSeconds` | 1–300 seconds; Trustee's default lifetime is five minutes |
| `challengeTTLSeconds` | 1–120 seconds |
| `tee` | `snp` or `tdx` |
| `measurements` | Exact approved measurements and minimum versions, described below |

For SNP, `measurements` contains `launch` (48-byte lowercase hex), `initData` (32-byte lowercase hex), and `minimumTCB` with integer `bootloader`, `tee`, `snp`, `microcode` fields. The client rejects debug access, migration-agent access, an unapproved launch measurement, mismatched init data and versions below these thresholds.

For TDX, `measurements` contains `launch`, `initData`, `rtmr0`, `rtmr1`, `rtmr2`, `rtmr3`, each 48-byte lowercase hex. All registers must match. Debug must be disabled, collateral must be unexpired, and both launch-time and reported current TCB status must be `UpToDate`. Zeroes are accepted only for explicitly pinned runtime registers.

Measurement values must come from the reviewed guest image and measured boot configuration. The configuration must restrict the guest agent, command execution, secret export, storage, diagnostics and networking. A hash copied from an unknown worker is not an approved configuration. A matching build string or appraisal policy name does not prove the service's binary, policy contents or reference-value database: those belong to the trusted, change-controlled Trustee deployment. Vendor roots, certificate validation, current collateral/revocation and platform security advisories remain its responsibility.

The result must have one `cpu0` submodule, an affirmative appraisal and the supported explicit hardware/executable/configuration trust-vector values. A zero/no-assertion value is never accepted for those three required dimensions. The other five dimensions must be zero in this narrowly supported profile; this does not claim they were independently assessed. Unexpected devices, sample evidence, unknown profiles and missing claims are rejected.

## Challenge and binding

Keep the SQLite challenge ledger on trusted local storage. Each challenge contains a random 256-bit nonce, issue time, expiry and SHA-256 of the canonical private policy. It also binds:

- Chain ID, escrow address, order ID, signed lease digest and reservation ID.
- The original encrypted package hash and agreed service-policy hash.
- Runtime and task commitments, attempt, rank and world size.
- The supported accelerator class, currently `cpu`.

`leaseAttestationBinding(...)` derives the financial fields from an existing funded-lease ledger. The remaining runtime/task/rank values must come from the requester's approved placement and workload contract. A historical lease is not a fresh check that the order remains funded and active. The service policy must approve the exact attestation-policy digest before any future key-release decision.

The protected guest generates a fresh P-256 channel key internally. `trusteeRuntimeData(...)` constructs structured report data containing the challenge, binding and public key. Its private half must never be available to the host. The SHA-384 hash of RFC 8785 canonical JSON, padded with 16 zero bytes, is bound to the CPU's 64-byte report-data field. This profile restricts the hashed data to fixed ASCII field names, ASCII strings and safe integers. The client independently recomputes the report-data digest.

`trusteeReportData(...)` produces those validated 64 raw bytes. The [guest-side session](guest-attestation.md) sends them to the pinned guest-components REST bridge and retains the corresponding non-extractable private key until opening or retirement.

`trusteeEvidenceRequest(...)` produces the pinned AS REST request: structured runtime data, SHA-384, the measured init-data digest, one CPU evidence item and one base policy ID. This is a **Cannabis guest adapter protocol for Trustee AS**, not an implementation of KBS's RCAR protocol. An ordinary guest that only implements RCAR needs an adapter for this structured data.

## CLI

Run from the public repository, with all operational inputs and the database kept outside it:

```sh
node scripts/compute-attestation.mjs policy-digest ../private/attestation-policy.json
node scripts/compute-attestation.mjs challenge ../private/attestation-policy.json ../private/binding.json ../private/challenges.sqlite
node scripts/compute-attestation.mjs request ../private/attestation-policy.json ../private/evidence.json ../private/challenges.sqlite
node scripts/compute-attestation.mjs attest ../private/attestation-policy.json ../private/evidence.json ../private/challenges.sqlite
```

`evidence.json` contains `nonce`, `channelJwk`, `evidence` (unpadded base64url of the actual hardware evidence), and, for `attest`, `endpoint`. The endpoint must be HTTPS with path `/attestation`; explicit HTTP loopback is available for a local AS. Credentials in URLs, query parameters and redirects are rejected. Use a trusted network or authenticated reverse proxy for the AS; this CLI does not implement client-certificate provisioning. TLS certificate verification remains enabled. Requests time out after 15 seconds, evidence is capped at 4 MiB encoded, and responses at 256 KiB. Every successful HTTP response still undergoes pinned-signature and appraisal checks.

Alternatively, `verify` accepts `{ "nonce": "...", "channelJwk": { ... }, "token": "..." }` for an EAR obtained separately. `cancel` takes `{ "nonce": "..." }`. Tokens must be issued after the challenge, never in the future, and within both age and lifetime limits. Expiry and cancellation are rechecked after asynchronous verification. SQLite `BEGIN IMMEDIATE` makes nonce consumption atomic across concurrent connections. Failed results do not consume a challenge. A successful result consumes it once; loss of the local result requires a fresh challenge. Trust rotation requires a new ledger and explicit retirement of outstanding challenges under the old policy. Do not restore an old ledger snapshot and reuse its challenges.

The database stores challenge bindings and a successful token hash, not hardware reports or job keys. These bindings still reveal scheduling/payment metadata; keep the ledger private. It is a single-host coordination mechanism, not a replicated global replay service. Do not put a live SQLite WAL database on a network filesystem or use cloud-file synchronization as a multi-writer coordination system.

## Key delivery and release work

Successful output reports `attestationVerified: true`, `challengeConsumed: true`, `executionAuthorized: false`, `keyReleaseAuthorized: false` and `fundingRecheckRequired: true`. The pure `verifyTrusteeResult(...)` helper checks a result without consuming a nonce and does not report `challengeConsumed`.

For the subsequent key-delivery transaction, `requestTrusteeResult(...)` calls the same bounded REST transport and validates its EAR, but leaves the challenge pending. Cancellation and expiry are rechecked after the request. Its returned token must still pass the complete `sealJobKeyDelivery(...)` checks. The key-delivery CLI's `appraise` action exposes this path.

The workload client creates fresh [per-job input identities and requester-encrypted key capsules](job-key-custody.md), keeping returned results on a separate requester identity. The [key-delivery integration](key-delivery.md) now combines requester-signed approvals, appraisal verification, finalized funding and latest-head checks to prepare a JWE envelope for the attested public key. It preserves the funded package hash and atomically consumes the challenge with the encrypted journal entry. It does not transmit the envelope or start execution. Every distributed rank and replacement still requires protected runtime admission, encrypted authenticated peer traffic and bounded execution. Those integrations and independent review remain required.

The automated suite signs synthetic EAR claims with disposable keys to check cryptographic validation, policy rejection, substitution, expiry, cancellation, replay, database races and REST transport. It does **not** establish real SNP/TDX execution or vendor-verifier correctness. No confidential hardware deployment or customer key release is claimed by those checks.

Upstream format references: [EAR claims](https://github.com/confidential-containers/trustee/blob/512fed65642015b849f38fb13bfdec7806639987/attestation-service/docs/attestation_token.md), [hardware claims](https://github.com/confidential-containers/trustee/blob/512fed65642015b849f38fb13bfdec7806639987/attestation-service/docs/tcb_claims.md), [REST implementation](https://github.com/confidential-containers/trustee/blob/512fed65642015b849f38fb13bfdec7806639987/attestation-service/src/bin/restful/mod.rs), [JOSE verification library](https://github.com/panva/jose/tree/v6.2.12).
