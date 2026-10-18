# Community claims

The proposed production rules reserve 99% of Cannabis for up to 990,000 eligible people: one claim of 420 Cannabis per verified person, starting at the common public opening. Production enrollment awaits the reviewed Cannabis ceremony and verified deployment.

The selected verification method is Cannabis-run synchronized in-person attendance, with independent venue witnesses and participant-held identities. No BrightID account, external identity provider, identity documents or biometric scans are required.

The [permanent registrar and local approval tooling](person-verification.md) support recurring rounds for future newcomers. Separate venue and registry quorums approve each roster; permanent person tags and commitments cannot be reused across rounds. Recovery restores the same secret. Durable cross-round human verification remains essential: a returning person using both a new tag and a new identity is not detected by cryptography alone.

1. Generate and securely back up a private Semaphore identity on your device. The [local identity and proof CLI](claim-identity.md) provides encrypted custody and a recovery check. The identity secret must never be sent to the enrollment service, Cannabis, a chat or a public repository.
2. Attend one approved Cannabis venue for the complete synchronized interval. Submit only the identity commitment and check the final roster before witnesses sign. Restore the same identity for recovery; do not create a replacement allocation.
3. Retrieve the complete public membership snapshot using the [checked whole-group downloader](membership-snapshot.md). Generate a Semaphore proof locally with the receiving wallet address as its message and the deployed token's claimScope as its scope. Use the matching pinned Semaphore libraries and reviewed proving artifacts. Do not include the identity commitment or secret in the public claim file.
4. Validate the proof against the canonical deployment and prepare an unsigned transaction:

~~~sh
node scripts/prepare-claim.mjs --rpc HTTPS_RPC_URL --chain-id CHAIN_ID --token VERIFIED_TOKEN_ADDRESS --recipient YOUR_RECEIVING_ADDRESS --code-hash VERIFIED_TOKEN_RUNTIME_HASH --proof proof.json --out claim-transaction.json
~~~

5. Review the chain, contract, recipient and decoded claim in your wallet. Simulate again immediately before signing. A relayer can submit the same proof for the same recipient; it cannot redirect the reward. Network fees apply.

The preparation tool reads no wallet key and broadcasts nothing. A group-root update can require regenerating a proof. A failed transaction can still consume gas. The 128-commitment threshold and proof cryptography do not replace trustworthy human verification.

See [privacy and security](privacy-security.md) for public-ledger and metadata limits. The enrollment portal, reviewed graphical identity flow, authenticated membership distribution and production relayer remain release work; the current website does not collect identity information or pretend to verify humans.
