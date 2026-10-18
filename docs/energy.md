# Efficient participation

Cannabis removes proof-of-work issuance. Participants do not compete by repeatedly searching hashes, and running more mining hardware does not create more eligible identities.

The target is an EVM network using Ethereum proof-of-stake settlement. Ethereum's own [energy documentation](https://ethereum.org/energy-consumption/) describes its reduction in energy use after replacing proof-of-work. [Ethereum's rollup documentation](https://ethereum.org/developers/docs/scaling/optimistic-rollups/) explains how execution can be batched while settlement relies on Ethereum. The final chain and its actual security model must be verified before launch.

Each eligible participant creates a useful zero-knowledge membership proof and submits one successful community claim. Registration can be batched. Proof generation, verification, storage, networking and ordinary transactions still consume resources; Cannabis makes no zero-energy or carbon-neutral claim and has not measured a full lifecycle footprint.

The security suite measured 367,292 gas for a real Semaphore claim on a local EVM under the current compiler and dependency versions. Gas is a computation/accounting measure, not a direct measurement of electricity, emissions or a mainnet fee quote.

Campaign wording: **Efficient by design. Privacy at heart. No proof-of-work competition.** Any numerical environmental claim must be supported by a suitable published measurement and must identify its scope.

The [useful-compute roadmap](useful-compute.md) adds requester-funded neural-network training off-chain. Jobs have bounded resources, checkpoint reuse, early stopping and agreed deliverables. No repeated training contest or compute-based issuance is part of Cannabis.
