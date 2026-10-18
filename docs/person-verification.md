# Person-verification integration

Cannabis community enrollment is being built around non-biometric verification and client-held Semaphore identities. The BrightID integration checks signed eligibility records and records each bound application request once in an operator-private intake database. It is a provider integration component; Cannabis has not selected or opened a production enrollment service.

## What the checker verifies

`claims/brightid.mjs` follows the signed-record interfaces in BrightID Node [6.17.2](https://github.com/BrightID/BrightID-Node/tree/c8fa7006d30d39e926fc6e96bb08819de76906ba) and [6.18.0](https://github.com/BrightID/BrightID-Node/tree/c699663519334b7a5149a4e4e8f5622984a23691). The response-signing and encoding paths were compared at these exact source revisions. Each deployment policy pins one version; a node changing to another supported version still fails the check. This is source compatibility review, not independent security review or proof of the deployed node's code. The checker requires a separately trusted Ed25519/NaCl public key, exact app identifier and verification expression, and a reviewed deployment binding. A key returned alongside a credential cannot establish trust in itself.

The application user ID is SHA-256 of the following ASCII strings separated by a single NUL byte, without a final separator:

~~~text
Cannabis BrightID enrollment v1
canonical decimal chain ID
lowercase enrollment-controller address
canonical decimal Semaphore commitment
~~~

This binding prevents a copied signed record from being reassigned to another commitment, chain or enrollment controller. The identity secret and future receiving wallet are not sent to the provider. The application user ID is derivable from the public commitment and deployment; it is not an additional secret or an anonymity guarantee.

Before and after fetching a credential, the adapter reads the configured node's state and app settings. It requires the exact supported version and pinned key, development/testing disabled, blind credentials enabled, ordinary string IDs, one verification expression and no verification expiration period. It requests `signed=nacl`, `includeHash=true`, and `timestamp=seconds`. It checks the signature over the exact upstream comma-separated app, application user ID, verification-expression hash and timestamp. Record age is bounded to at most 300 seconds, with at most 30 seconds of configured future clock skew.

Requests use HTTPS, with literal loopback HTTP available for local integration checks. Redirects, URL credentials, extra query parameters, oversized responses and unsupported record fields are rejected. No user-profile, social graph, photo, identity-document or biometric endpoint is requested. The selected provider still sees the request identifier and network metadata.

## Run an intake check

Prepare a protected local configuration containing `policy`, `commitment` and an absolute `ledger` file path. Policy fields are:

| Field | Required value |
| --- | --- |
| `schema` | `cannabis.brightid-policy.v1` |
| `nodeUrl` | Trusted HTTPS base ending in `/brightid/v6/` |
| `nodeVersion` | Exactly `6.17.2` or `6.18.0`, matching the reviewed provider deployment |
| `app` | Independently registered and reviewed app ID |
| `verification` | One exact reviewed verification expression |
| `publicKey` | Independently authenticated 32-byte Ed25519 key in canonical padded Base64 |
| `chainId` | Canonical positive decimal string |
| `enrollment` | Verified Cannabis enrollment-controller address |
| `maxAgeSeconds` | Integer from 1 to 300 |
| `clockSkewSeconds` | Integer from 0 to 30 |

`commitment` is the participant's canonical decimal Semaphore commitment. `brightIDApplicationUserId(policy, commitment)` produces the application ID to register through the provider's reviewed blind-credential client. This tool does not create that registration or obtain blind credentials on the participant's behalf. No production keys or provider settings are supplied by default.

~~~sh
node scripts/check-person-verification.mjs --config /protected/intake-config.json --out /protected/intake-result.json
~~~

Keep the configuration, output, SQLite database, its WAL/journal and backups off public hosting. Use protected operator storage and access controls; SQLite does not encrypt these files. Logs omit request IDs, commitments and provider response bodies. Only hashes and commitments needed for the intake record are retained; raw signatures and profile data are not stored by the ledger.

Transactions and uniqueness constraints make repeated submissions idempotent, including simultaneous processes. Reopening the database with changed trust, app, network or verification settings fails. A policy change needs a reviewed migration preserving the duplicate registry. Do not create a fresh empty ledger to bypass that requirement. If an output write fails after intake commits, retry with a fresh output filename: the existing request remains recorded once.

## What remains before enrollment

The signed record proves that the pinned node signed the exact statement. It does **not** cryptographically prove one distinct person for a lifetime. In particular, the v6 signed response does not contain the underlying blind-credential UID or a permanent cross-alias human nullifier. Local application-ID deduplication cannot resolve duplicate identities or aliases issued by the provider.

Nonexpiring settings alone do not settle recovery, credential reissuance, registration races, node migration or changes to the meaning of a named verification expression. The signed hash covers the expression text; it does not attest the running node's code, underlying verification rules or database behavior. Node/app configuration is observed over the configured connection, not independently attested by the credential signature.

Production selection therefore still requires an independently reviewed lifetime-uniqueness and recovery policy, authenticated node keys, durable provider registration behavior, app registration and sponsorship/access terms, participant consent and custody flows, protected operations and an actual end-to-end enrollment. Multiple provider policies or nodes must not create additional allocations for the same person. The registrar must enforce that reviewed identity rule before calling `addVerifiedMembers`.

Successful checks explicitly return `eligibilitySignatureVerified: true`, `lifetimeUniquenessEstablished: false`, `enrollmentAuthorized: false` and `enrolled: false`. The tool does not sign transactions, add members, mint tokens or expose a public enrollment endpoint. The existing [community claim flow](community-claims.md) and [launch acceptance criteria](launch-plan.md) remain controlling.
