# Keep your claim identity on your device

The participant CLI creates an encrypted Semaphore identity, checks recovery, and generates a claim proof locally. It uses the pinned Semaphore 4.14.5 libraries and native age X25519 encryption. Only the commitment goes to the reviewed Cannabis ceremony intake. The public claim proof contains neither that commitment nor the secret. Semaphore's [identity guide](https://docs.semaphore.pse.dev/guides/identities) describes the underlying key and commitment format.

This is a local command-line component of the production claim flow. It does not enroll a person, establish a canonical deployment, sign a transaction or submit a claim. The Cannabis ceremony, reviewed release and participant interface remain launch work. No operational participant identities are included in this repository.

## Prepare custody

Use Node.js 22.22+, the locked npm dependencies, and a verified age 1.3.2 installation. The local `age` executable path must be absolute. Use an existing, separately protected native age X25519 identity and its matching public recipient. Keep the owner key on encrypted local storage under your control; do not place it beside a synced encrypted vault. The current CLI accepts one native age identity, without plugins or interactive passphrases. Other custody methods need their own reviewed integration.

Create a private directory outside the public source tree. The parent directory must already exist. Create a local configuration file containing only public values and paths, for example:

~~~json
{
  "age": "C:/trusted/age/age.exe",
  "recipient": "YOUR_AGE_PUBLIC_RECIPIENT",
  "vault": "C:/private/cannabis/participant.age"
}
~~~

~~~sh
node scripts/claim-identity.mjs create --config create-config.json --out commitment.json
~~~

The command creates a fresh random identity and encrypts its record directly through an anonymous pipe. It writes only ciphertext to the vault. `commitment.json` contains the public commitment, ciphertext digest and byte count. Its `enrolled` field is false: creating an identity does not complete person verification. Existing vaults and output files are never overwritten.

Make a recovery configuration using the same vault and the commitment you just recorded:

~~~json
{
  "age": "C:/trusted/age/age.exe",
  "vault": "C:/private/cannabis/participant.age",
  "identityFile": "C:/separate-protected-storage/owner.key",
  "commitment": "YOUR_RECORDED_DECIMAL_COMMITMENT"
}
~~~

~~~sh
node scripts/claim-identity.mjs inspect --config recovery-config.json --out recovery-check.json
~~~

`recoveryVerified: true` means that this owner key recovered the expected commitment from that vault. Keep a separate recoverable backup of the owner key and encrypted vault. Verify recovery before enrolling; losing the secret after append-only enrollment can prevent a claim. A provider must prevent recovery or re-enrollment from enabling a second allocation. Share the commitment only as required for enrollment; do not attach it to your public claim or publish it alongside your receiving wallet.

## Prepare an offline proof

Obtain the **complete, ordered** membership list for the canonical Cannabis deployment. Independently check the chain, token address, current root and enrolled count against that deployment. A snapshot source must not receive your identity secret or a request for only your member path. Fetching the entire list avoids a member-specific lookup; transport and timing can still expose metadata.

The [whole-group downloader](membership-snapshot.md) reconstructs this list from public events and checks finalized/current state against reviewed deployment pins. Its output can be supplied as an absolute `membershipFile` path in the proof configuration, replacing the embedded `context` and `snapshot` fields below. It trusts the selected RPC's chain view; it is not a light client.

The proof configuration extends the recovery configuration with:

~~~json
{
  "recipient": "YOUR_RECEIVING_WALLET_ADDRESS",
  "context": {
    "chainId": "CANONICAL_CHAIN_ID",
    "token": "VERIFIED_TOKEN_ADDRESS",
    "root": "CURRENT_DECIMAL_GROUP_ROOT",
    "memberCount": 128
  },
  "snapshot": {
    "schema": "cannabis.membership-snapshot.v1",
    "chainId": "CANONICAL_CHAIN_ID",
    "token": "VERIFIED_TOKEN_ADDRESS",
    "root": "CURRENT_DECIMAL_GROUP_ROOT",
    "commitments": ["COMPLETE_ORDERED_DECIMAL_COMMITMENTS"]
  },
  "artifacts": {
    "depth": 7,
    "wasm": { "path": "C:/reviewed/semaphore-7.wasm", "sha256": "REVIEWED_SHA256", "bytes": 123 },
    "zkey": { "path": "C:/reviewed/semaphore-7.zkey", "sha256": "REVIEWED_SHA256", "bytes": 456 }
  }
}
~~~

These are placeholders, not a deployment or artifact manifest. Replace the count, depth, byte sizes and hashes with the actual reviewed values. The depth must match the reconstructed full group (7 through 20). Hashes supplied by the same untrusted download do not establish provenance: get artifact pins through the reviewed release. The library's current default circuit version is 4.13.0, distinct from its 4.14.5 package version; production tooling always supplies explicit artifacts and never invokes the automatic downloader.

~~~sh
node scripts/claim-identity.mjs prove --config prove-config.json --out proof.json
~~~

The prover checks canonical integers, deployment context, a unique list of 128–990,000 commitments, reconstructed root, membership, and artifact byte counts and SHA-256 hashes. It uses the checked artifact bytes in memory, preventing a later path substitution from changing the proving inputs. It derives the exact contract scope from the chain ID and token address, binds the receiving wallet as the message, and verifies the generated proof before returning it. A count of commitments alone is not evidence of distinct humans; that remains the provider's responsibility. The [Semaphore proof guide](https://docs.semaphore.pse.dev/guides/proofs) explains proof messages and scopes.

Only `proof.json` belongs in the unsigned [claim preparation](community-claims.md) step. That step checks the deployed code and simulates the claim. The offline prover trusts the context you supply; it cannot establish that a root is currently canonical. Membership updates can require a new proof and simulation before signing.

## Privacy and operational limits

The CLI uses no RPC, web request, wallet key or broadcast. Recovery pipes the age owner key into the local age process; it creates only a temporary ciphertext copy. Secret values never appear in arguments, environment variables, returned reports or intentional log output. Errors are deliberately generic. Mutable secret buffers are cleared where possible, but JavaScript strings, BigInts, engine copies, operating-system swap and crash dumps cannot be guaranteed erased by this code. Use a trusted, protected client device. Do not expose these operations as a shared server endpoint.

The public proof includes its nullifier, recipient and group root. Ledger activity remains visible. A CLI recovery check is not an independent custody audit, and an offline proof is not evidence that enrollment or a mainnet claim has occurred. A reviewed graphical custody flow, authenticated snapshot distribution, provider recovery policy and production relayer remain release work.
