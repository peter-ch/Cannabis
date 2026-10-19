# Privacy and security by design

Cannabis uses [Semaphore](https://docs.semaphore.pse.dev/) zero-knowledge membership proofs. A valid claim proves membership without putting the identity commitment in the proof. This does not guarantee anonymity: a singleton group has only one possible claimant, and small groups or correlated metadata can identify people. Semaphore publishes its audit history; the Cannabis integration still needs independent security and privacy review.

## What stays private

The identity secret stays with the participant. Cannabis ceremony witnesses receive a public commitment after verifying continuous in-person attendance; Cannabis must not receive identity documents or biometric records. Proof generation should run on the participant's device using a complete public membership snapshot, without asking a server for the participant's individual membership path.

The claim contains a receiving address, group root, project-scoped nullifier and proof. It does not contain the user's identity commitment, identity secret, document number or name. The proof omits the commitment-to-recipient link, but the group size and surrounding information may make that link inferable.

## What remains visible

The chain exposes recipients, token balances, transfers, claims and nullifiers. Ceremony witnesses can recognize attendees and associate them with commitments; public venue batches also reveal grouping. Timing, IP addresses, RPC logs, reused wallets, attendance records and endpoint compromise can create correlations. Relaying avoids requiring the claim recipient to be the gas payer, but does not provide complete transaction anonymity.

## Contract defenses

- Fixed cap, immutable founder vesting, no privileged mint, upgrade, tax or blacklist.
- One claim per scope-bound nullifier and receiving wallet; message bound to recipient.
- Append-only group control. The registrar cannot remove members or transfer group administration through CannabisEnrollment.
- Claims require genuine enrollment and the current on-chain minimum, initially configurable with a default of one. Only the current group root is accepted.
- View-only external proof verification and a token-owned nullifier registry prevent outsiders from consuming the Cannabis claim through Semaphore's public validation endpoint.

A commitment count does not establish honest independent people: a malicious registrar could populate the group with identities it controls. Adding artificial cover identities would not create real membership privacy. With the default minimum of one, the first real member may claim after the public opening, or voluntarily wait for a larger group; no group size guarantees anonymity. The registrar, person-verification method and recovery policy therefore require review and explicit disclosure. The permanent registrar has no founder enrollment bypass. Recurring rounds require separate venue and registry quorums; neither can reset consumed tags or commitments. A colluding quorum or a returning person issued both a new tag and secret can still defeat human uniqueness. Durable cross-round person checks remain required. Recovery restores the same secret. See the [ceremony trust assumptions](person-verification.md#trust-and-release-requirements).

## Production requirements

Review ceremony privacy and accessibility, one-person enrollment and recovery, witness independence and key custody, metadata retention, dependency and proving-artifact integrity, relayer behavior, membership batching, incident response and end-to-end security. The current website has no analytics, advertising pixels, enrollment form or identity upload. Do not claim perfect anonymity, carbon neutrality or a completed audit.

The initial claim minimum is configurable and defaults to **1 verified member**. The founder wallet can later increase it only up to the number already enrolled. Increases are recorded on-chain, cannot be reversed, cannot block an already eligible group and do not revoke completed claims. The complete current membership root is always required; increasing the numeric minimum does not itself enlarge the anonymity set. See [claim minimum controls](community-claims.md#configurable-claim-minimum).
