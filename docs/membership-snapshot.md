# Download and check the complete membership list

The membership downloader reconstructs the full Cannabis enrollment group from public Semaphore events. It checks the result against a finalized block and confirms that newer enrollment has not changed the root. Participants can then generate their claim proof locally without telling a snapshot server which enrolled member they are.

This component reads the chain. It receives no identity secret, participant commitment or receiving-wallet address, and never enrolls, signs or broadcasts. The reviewed Cannabis ceremony and deployed contracts remain launch requirements.

## Deployment configuration

Use the exact addresses, runtime-code hashes and deployment block from the reviewed release. The three hashes are Ethereum Keccak-256 hashes of the deployed runtime bytes, including immutables. They are not source-file hashes or creation-bytecode hashes. Do not obtain the expected hashes solely from the same RPC you are trying to check.

~~~json
{
  "rpc": "https://YOUR_TRUSTED_RPC",
  "release": {
    "chainId": "CANONICAL_CHAIN_ID",
    "token": "VERIFIED_TOKEN_ADDRESS",
    "tokenCodeHash": "VERIFIED_TOKEN_RUNTIME_KECCAK256",
    "enrollment": "VERIFIED_ENROLLMENT_ADDRESS",
    "enrollmentCodeHash": "VERIFIED_ENROLLMENT_RUNTIME_KECCAK256",
    "semaphore": "VERIFIED_SEMAPHORE_ADDRESS",
    "semaphoreCodeHash": "VERIFIED_SEMAPHORE_RUNTIME_KECCAK256",
    "fromBlock": 12345678
  },
  "pageSize": 2000,
  "maxPages": 10000,
  "maxDurationMs": 300000,
  "maxHeadAgeSeconds": 300
}
~~~

This is a template, not a deployment. Replace every placeholder and the example start block. Start at the Cannabis deployment block so the history includes its newly created group and every addition. Keep RPC access credentials in a private configuration file; the output deliberately excludes the endpoint. HTTPS is required except for literal loopback HTTP. Userinfo, fragments and redirects are rejected.

~~~sh
node scripts/snapshot-claims.mjs --config membership-source.json --out membership.json
~~~

The command requires support for the `finalized` tag, historical code/calls/logs and EIP-1898 canonical block-hash selectors. It fails if those capabilities are unavailable; it does not fall back to a moving latest block for historical reads. [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898) defines the block-hash and canonicality options used for consistent state reads.

## Checks before output

The downloader checks the chain ID and pins all three contracts at one finalized block. It checks their address relationships, group ID, claim scope, enrollment count, group size and enrollment-controller administration. It then downloads bounded event pages for that entire group, accepts only additions, and reconstructs every batch root in order. Missing indices, duplicate commitments/events, unexpected groups, removals, updates, oversized batches and root mismatches stop the download. A claim snapshot requires 1–990,000 real enrolled commitments and must meet the token's current `minimumClaimMembers` value, which defaults to one. The downloader reads that policy at the finalized anchor, returns it in `context.minimumClaimMembers`, and refuses a changed policy at the current head. An empty group has no claimant; it does not prevent contract deployment. The complete current group is still required, even when it has only one member. Small groups limit membership privacy; a singleton gives none.

After reconstruction, it checks that the finalized block remains canonical according to the RPC. It then checks a recent latest block, the three code hashes, root, count, size and group admin again. New membership after the finalized anchor causes a failure: wait for that enrollment to finalize and fetch again. A final block-hash and chain check catches changes during these reads. No partial result is returned by the library; the CLI creates the output only after these checks and never overwrites an existing file.

The output contains `snapshot` and `context` in the offline prover's format, plus `evidence` with the checked block hashes, release pins, group ID and event/page counts. It does not contain participant-specific data or RPC credentials. The complete list is public enrollment data; its size is not evidence that each member is a distinct person.

## Use it for a local proof

Add the absolute path to the downloaded bundle to the private [identity/proof configuration](claim-identity.md):

~~~json
{
  "membershipFile": "C:/private/cannabis/membership.json"
}
~~~

Keep the existing `age`, `vault`, `identityFile`, recorded `commitment`, receiving `recipient` and reviewed `artifacts` fields. Omit embedded `snapshot` and `context` when using `membershipFile`; mixed sources are rejected. The proof command reads this file locally, reconstructs its root again, and checks membership and artifact pins before proving. It does not contact the downloader or an RPC. Finish with [unsigned claim preparation and wallet review](community-claims.md), which checks deployment code and simulates the claim. Later enrollment can stale an otherwise valid proof.

## Trust and availability

This is a consistency checker for a selected RPC's chain view. It is **not** independent consensus verification, a light client or a cryptographic proof that an RPC response came from the real canonical chain. Use a trusted self-hosted or independently reviewed node and verified release pins. A malicious RPC can fabricate a mutually consistent view; runtime hashes and event replay do not remove that trust. Finality must also be assessed for the chosen network and its settlement model. Public transport still exposes IP addresses and timing to its operators.

Enrollment should use published batches and quiet claim windows: the contract accepts only its current root, and frequent additions can repeatedly invalidate proofs. Cannabis ceremony operators must define human continuity, same-secret recovery and cross-round duplicate prevention separately. Authenticated snapshot distribution, operational enrollment and relaying still need deployment and review.

Each RPC response is capped at 8 MiB and each request at 15 seconds. Event pages contain at most 8,192 logs; reduce `pageSize` if a dense range exceeds that limit. Page size is 1–10,000 blocks, the page budget is at most 10,000, and the overall deadline is at most one hour (five minutes by default). Large-group reconstruction uses local memory and CPU; these bounds are not a throughput claim. Keep the client clock accurate: a head more than 60 seconds ahead or older than the configured freshness bound is rejected.
