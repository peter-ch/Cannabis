# Cannabis person verification

Cannabis is building its own non-biometric enrollment system using recurring synchronized in-person ceremonies and a permanent enrollment registry. Future newcomers can attend later rounds. No BrightID account, sponsorship or external person-verification service is required. Enrollment is not open yet; real operations, cross-round human uniqueness, independent review and mainnet deployment remain to be completed.

## One person, one place, one commitment

All venues in a round share the same continuous-presence interval. Participants arrive before it starts, remain at one venue throughout it, and register one client-held Semaphore identity commitment. At least three independently controlled witness keys are assigned to each venue, with at least two thirds required to approve its complete roster. Witnesses must actually attend their assigned venue. Different keys alone do not prove independent people.

Witnesses maintain an observable room boundary, prevent re-entry or substitution, and independently reconcile the physical headcount with one commitment per person. Remote attendance, recordings and a brief check-in are insufficient. Each round lasts one to four hours, with the same UTC start and end everywhere. Uncertain presence means no approval. Accessibility, admission and dispute arrangements must preserve the rule and be published before registration.

Cannabis does not collect identity documents, iris or face scans, photographs, legal names or birth dates. Witnesses see the people who attend. Attendance handling must minimize records and protect links between a person and commitment. Do not collect a receiving wallet during enrollment.

## Future newcomers and the permanent registry

The same registrar accepts later rounds without replacing its membership history. Each round needs approval from a separately controlled Cannabis registry-review quorum, at least seven days of on-chain notice, and a presence interval after the preceding round's submission deadline. Every round, including the first, may have capacity for a single participant. Independent witness and registry quorums still apply; there is no recruitment quota for deployment. The enrollment controller keeps the global 990,000-person ceiling; a new round does not create additional supply or reset claims.

Each admitted person has one opaque permanent registry tag paired with one Semaphore commitment. Tags must be assigned through the reviewed registry process, not accepted as a participant's assertion that they are new. Do not derive them by hashing names, email addresses, documents or other guessable personal data. A venue roster needs both its witness quorum and the independent registry quorum's approval of these exact bindings.

On-chain history permanently consumes both the person tag and commitment. Neither another venue, another round, a new commitment for an existing tag, nor a new tag for an existing commitment permits enrollment again. No founder, reviewer or witness can reset these records or replace an enrolled identity through the contract. Newcomers use the existing registry; they do not require a new currency or group.

**A new tag together with a new identity is not automatically detectable as the same human.** Registry reviewers must establish durable person continuity across venues and rounds through a reviewed human-verification process, check previous records, and refuse reissuance. That operating method and its adversarial validation are still unfinished. The software must not be described as having solved lifetime human uniqueness merely because it checks tags, keys or signatures. This remains a release requirement within Cannabis, not a dependency on an external provider.

## Recovery and missed rounds

Recovery restores the **same identity secret and commitment** from the participant's encrypted backup. Witnesses and registry reviewers do not receive the secret, issue replacement identities or authorize a second allocation. Losing every recoverable copy can permanently prevent claiming. The [Windows guide](windows-setup.md) requires an actual portable-backup recovery check before preparing an enrollment request.

Each venue submits one complete roster per round. Participants inspect their entry before witnesses sign, with disputes resolved before submission. A missed round or omitted entry can be considered in a later round under the permanent registry checks; it does not receive an automatic extra identity or entitlement. Unallocated community supply is not reassigned to the founder. Reviewer keys are fixed in the current contract, so independent custody, recovery and sufficient surviving quorum are operational requirements.

## Participant procedure

1. Create your private identity and verify its portable backup on your own device. Keep the secret and password private.
2. Check the canonical release, authorized round, UTC interval, venue and witness policy. Attend one approved venue for the full interval.
3. Provide your commitment through reviewed local intake. Cannabis registry reviewers check the permanent person binding; venue witnesses check attendance. Supply no receiving wallet, document or biometric record.
4. Confirm the exact commitment and permanent record in the final roster, keep your private receipt, and verify inclusion in the complete finalized membership snapshot after enrollment.
5. From the common public claim opening, generate the [Semaphore claim proof](community-claims.md) locally. With the default minimum of one, the first genuinely verified member can claim, preserving the 420-per-person allocation. A release may choose another initial minimum; any later increase is bounded by already enrolled membership. With one member, membership anonymity is impossible; small groups limit privacy. Participants may wait for a larger real group. Later newcomers can claim after their enrollment is finalized.

## What the software enforces

`contracts/CommunityRegistrar.sol` fixes the enrollment controller and three to nine registry-reviewer addresses with a quorum of at least two thirds. It has no owner, privileged enrollment call, history reset or identity replacement. Quorum-signed round definitions are sequential, cannot overlap submission windows, and cannot be overwritten or rescheduled. Each fixes a venue-policy Merkle root, shared presence interval and a submission deadline one to thirty days afterward.

Venues have opaque identifiers, capacity up to 256, three to nine witness addresses and a quorum of at least two thirds. The contract rejects registry-reviewer keys acting as venue witnesses. The complete-policy checker also rejects witness-key reuse across simultaneous venues. Reviewers must inspect that full policy before signing its root; a contract sees only the venue proof supplied with each roster.

Venue approvals use [EIP-712](https://eips.ethereum.org/EIPS/eip-712) typed messages binding chain, registrar, enrollment controller, round, exact schedule, venue policy, venue, sorted commitment list and matching permanent tags. Registry approvals use a separate typed message over that roster digest, so the two roles cannot reuse one signature. The contract uses pinned [OpenZeppelin ECDSA, EIP-712 and Merkle-proof implementations](https://docs.openzeppelin.com/contracts/5.x/api/utils/cryptography). It checks distinct approved signers, canonical commitments, permanent registry duplication, venue capacity and the submission window.

Any relay can submit a fully approved roster without changing its contents. All state updates revert if either approval or enrollment fails. A venue submits once per round, while permanent records persist through every round. EIP-712 alone does not prevent replay; the sequence, used-venue and permanent-consumption registries enforce it here. The token's nullifier and wallet rules separately prevent claiming twice from an enrolled identity.

## Prepare approvals locally

`claims/community-enrollment.mjs` exports policy normalization, constructor configuration, `prepareRoundPolicy`, `verifyRoundApprovals`, `prepareVenueRoster` and `verifyVenueApprovals`. These build typed review messages and unsigned calls without network access, provider accounts or private signing keys.

The private policy uses these exact fields:

| Field | Meaning |
| --- | --- |
| `schema` | `cannabis.ceremony-policy.v2` |
| `chainId` | Canonical decimal chain ID |
| `registrar`, `enrollment` | Verified or deterministically predicted contract addresses |
| `registryReviewers`, `registryQuorum` | The fixed registry reviewers and required threshold |
| `round` | Positive sequential round number |
| `startsAt`, `endsAt`, `submissionsCloseAt` | UTC Unix seconds for that round |
| `venues` | Objects with `id`, `capacity`, `quorum`, and `witnesses` |

A round-request configuration contains `kind: "round"` and `policy`. For a roster request, use `kind: "roster"`, `policy`, `venueId`, and `members`, an array of objects containing `personTag` and `commitment`. Tags and venue IDs are nonzero lowercase bytes32 values; commitments are canonical decimal strings.

~~~sh
node scripts/check-person-verification.mjs --config /protected/ceremony.json --out /protected/approval-request.json
~~~

Witnesses and registry reviewers independently inspect their evidence and sign their own typed messages with their own wallets. The script signs for nobody. Add `registrySignatures` to a round configuration, or both `witnessSignatures` and `registrySignatures` to a roster configuration, then rerun with a new output path. It checks signatures and timing and prepares a zero-value unsigned transaction.

Before submitting, independently verify deployed code, constructor values, round policy, current registry state, decoded call and gas. This offline checker does not query chain state, confirm human observations or replace release review. Registrar/token deployment preparation must bind the exact predicted enrollment address; verify it after deployment before authorizing rounds. Publish the initial common claim opening with at least seven days' notice, after the initial round's submission deadline.

Keep intake and receipt files on protected operator storage under an explicit retention policy. Output creation refuses an existing filename, and console messages omit member records and signatures. Permanent tags, commitments, opaque venue grouping, approvals and transaction timing become public on submission. Semaphore conceals which enrolled identity later claims; it does not erase enrollment metadata or public wallet activity.

## Trust and release requirements

Witness signatures cannot prove honest physical observation, and registry signatures cannot prove lifetime human uniqueness. Collusion, substitution, compromised keys or a returning person issued a new tag and secret can defeat the human policy. Independence, durable continuity checks, privacy-preserving evidence handling and adversarial tests require review before any production authorization.

The tooling reports cryptographic quorum checks separately from `humanUniquenessEstablished: false`, `enrolled: false` and `sent: false`. Synthetic local participants exercise recurring admission, permanent duplicate refusal and actual Semaphore proofs only. They do not count as real participants or establish human uniqueness. Venue organization, real witness/reviewer custody, cross-round human checks, participant consent, accessibility, complaints, independent review and deployment remain unfinished. See [launch acceptance](launch-plan.md).

The earlier BrightID adapter is retired from the release path. Historical source and regression checks do not make it a dependency. The current person-verification command performs only the offline Cannabis flow above.
