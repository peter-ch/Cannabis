# Security and privacy

Cannabis is preparing mainnet launch. Its custom contracts and complete deployment have not received an independent security/privacy audit. Existing library audits and passing tests do not constitute an audit of Cannabis.

The design uses OpenZeppelin ERC-20 components and Semaphore zero-knowledge membership proofs. It has a fixed supply cap, immutable founder vesting, append-only enrollment, recipient-bound claims, network/contract-bound nullifiers, a 128-commitment threshold, and no upgrade, tax, blacklist or administrator mint function.

The enrollment registrar remains a trust dependency: it must admit distinct verified people exactly once, protect enrollment metadata and prevent identity-reset abuse. A compromised or dishonest registrar could admit fake identities and weaken distribution fairness and effective anonymity. This must be independently reviewed before launch.

For sensitive reports, use [GitHub private vulnerability reporting](https://github.com/peter-ch/Cannabis/security/advisories/new), enabled for this repository. Do not publish identity secrets, wallet keys, personal data or exploit details affecting live funds in public issues. Ordinary reproducible software bugs may be reported as issues. No bounty or guaranteed response time is offered.

Local contract verification uses isolated loopback nodes with synthetic identities and publicly known development keys. These are test fixtures only. Never expose those RPC ports or use their accounts for production custody.

See [privacy and security design](docs/privacy-security.md) for the threat model and release requirements.
