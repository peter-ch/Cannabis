# Privacy and security by design

Cannabis uses [Semaphore](https://docs.semaphore.pse.dev/) zero-knowledge membership proofs. A valid claim proves membership without revealing which enrolled identity produced it. Semaphore publishes its audit history; the Cannabis integration still needs independent security and privacy review.

## What stays private

The identity secret stays with the participant. The production enrollment provider receives a public commitment after verifying the person; Cannabis must not receive identity documents. Proof generation should run on the participant's device using a complete public membership snapshot, without asking a server for the participant's individual membership path.

The claim contains a receiving address, group root, project-scoped nullifier and proof. It does not contain the user's identity commitment, identity secret, document number or name. The cryptographic proof does not expose the link from an enrolled commitment to a receiving address.

## What remains visible

The chain exposes recipients, token balances, transfers, claims and nullifiers. The enrollment provider can know who enrolled and which commitment they registered. Timing, IP addresses, RPC logs, reused wallets, provider records and endpoint compromise can create correlations. Relaying avoids requiring the claim recipient to be the gas payer, but does not provide complete transaction anonymity.

## Contract defenses

- Fixed cap, immutable founder vesting, no privileged mint, upgrade, tax or blacklist.
- One claim per scope-bound nullifier and receiving wallet; message bound to recipient.
- Append-only group control. The registrar cannot remove members or transfer group administration through CannabisEnrollment.
- At least 128 distinct commitments before claims; only the current group root is accepted.
- View-only external proof verification and a token-owned nullifier registry prevent outsiders from consuming the Cannabis claim through Semaphore's public validation endpoint.

The threshold is a count of commitments. It does not establish 128 honest independent people: a malicious registrar could populate the group with identities it controls. The registrar, person-verification method and recovery policy therefore require review and explicit disclosure. Reissuing a fresh identity to the same person could allow another claim and must be prevented by the provider.

## Production requirements

Review provider privacy and country access, one-person enrollment and recovery, registrar key custody, metadata retention, dependency and proving-artifact integrity, relayer behavior, membership batching, incident response and end-to-end security. The current website has no analytics, advertising pixels, enrollment form or identity upload. Do not claim perfect anonymity, carbon neutrality or a completed audit.
