# Privacy and security by design

Cannabis uses [Semaphore](https://docs.semaphore.pse.dev/) zero-knowledge membership proofs. A valid claim proves membership without revealing which enrolled identity produced it. Semaphore publishes its audit history; the Cannabis integration still needs independent security and privacy review.

## What stays private

The identity secret stays with the participant. Cannabis ceremony witnesses receive a public commitment after verifying continuous in-person attendance; Cannabis must not receive identity documents or biometric records. Proof generation should run on the participant's device using a complete public membership snapshot, without asking a server for the participant's individual membership path.

The claim contains a receiving address, group root, project-scoped nullifier and proof. It does not contain the user's identity commitment, identity secret, document number or name. The cryptographic proof does not expose the link from an enrolled commitment to a receiving address.

## What remains visible

The chain exposes recipients, token balances, transfers, claims and nullifiers. Ceremony witnesses can recognize attendees and associate them with commitments; public venue batches also reveal grouping. Timing, IP addresses, RPC logs, reused wallets, attendance records and endpoint compromise can create correlations. Relaying avoids requiring the claim recipient to be the gas payer, but does not provide complete transaction anonymity.

## Contract defenses

- Fixed cap, immutable founder vesting, no privileged mint, upgrade, tax or blacklist.
- One claim per scope-bound nullifier and receiving wallet; message bound to recipient.
- Append-only group control. The registrar cannot remove members or transfer group administration through CannabisEnrollment.
- At least 128 distinct commitments before claims; only the current group root is accepted.
- View-only external proof verification and a token-owned nullifier registry prevent outsiders from consuming the Cannabis claim through Semaphore's public validation endpoint.

The threshold is a count of commitments. It does not establish 128 honest independent people: a malicious registrar could populate the group with identities it controls. The registrar, person-verification method and recovery policy therefore require review and explicit disclosure. The permanent registrar has no founder enrollment bypass. Recurring rounds require separate venue and registry quorums; neither can reset consumed tags or commitments. A colluding quorum or a returning person issued both a new tag and secret can still defeat human uniqueness. Durable cross-round person checks remain required. Recovery restores the same secret. See the [ceremony trust assumptions](person-verification.md#trust-and-release-requirements).

## Production requirements

Review ceremony privacy and accessibility, one-person enrollment and recovery, witness independence and key custody, metadata retention, dependency and proving-artifact integrity, relayer behavior, membership batching, incident response and end-to-end security. The current website has no analytics, advertising pixels, enrollment form or identity upload. Do not claim perfect anonymity, carbon neutrality or a completed audit.
