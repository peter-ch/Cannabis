# Mainnet dependency verification

The release preparer checks the Semaphore contract, its verifier and its Poseidon library before exporting deployment data. Reviewers supply the expected addresses, full runtime-code hashes and compiler-derived library-link offsets. The checker never learns trusted pins from whatever code an RPC happens to return.

Run the read-only check separately:

```sh
npm run check:dependencies -- --config config/base-dependencies.json --out ../private/dependency-observation.json
```

The configuration contains an HTTPS RPC endpoint and `dependencies`, with schema `cannabis.semaphore-dependencies.v1`, a decimal-string `chainId`, three named `{address, codeHash}` entries (`semaphore`, `verifier`, `poseidon`), and ordered `poseidonLinkOffsets`. Local verification fixtures may use literal loopback HTTP. Keep RPC credentials in a private configuration; they are omitted from observations and CLI diagnostics.

The checker requires finalized state and EIP-1898 block-hash reads with `requireCanonical`. At both the finalized anchor and a fresh current head it checks all three complete runtime hashes, Semaphore's actual verifier address and each reviewed Poseidon address embedded in Semaphore's executable code. It rechecks the canonical block hashes and chain ID. Stale state, reorganized blocks, unavailable historical state and inconsistent responses fail the check. There is no fallback to unbound or latest-only state.

Defaults allow a current head up to 300 seconds old, a finalized anchor up to 7,200 seconds old and a 60-second total deadline. `maxHeadAgeSeconds`, `maxFinalizedAgeSeconds` and `maxDurationMs` can be set within documented implementation bounds for a reviewed network. RPC response size is bounded. The command cannot sign or submit transactions and refuses to overwrite a report.

`prepare:launch` requires this configuration, checks that its chain and Semaphore pins match the constructor parameters, runs the live check, and includes the observation in the unsigned manifest. A saved observation is not accepted as a substitute for those fresh reads. Repeat checks immediately before any owner-controlled signing; chain observations are point-in-time evidence.

## Base source and proof observations

On 2026-10-18, the published [Semaphore v4 deployment addresses](https://docs.semaphore.pse.dev/deployed-contracts) were inspected on Base. Sources retrieved through the [Sourcify contract lookup API](https://docs.sourcify.dev/docs/api/) matched the pinned Semaphore 4.14.5 and LeanIMT 2.0.1 package sources and their metadata hashes. They were recompiled with Solidity 0.8.23, optimizer enabled with 200 runs, targeting Paris. The compiler download was checked against the SHA256 published in the [official compiler distribution](https://github.com/ethereum/solc-bin).

At finalized Base block 52,767,156 (`0x7693220eb2a48dca2c4d514b56adcfe630cf23d1f145deec0ddf2dd8215797b1`):

| Dependency | Source correspondence |
| --- | --- |
| Semaphore | Executable runtime matches, including six Poseidon links; the strictly parsed IPFS compiler-metadata hash differs |
| SemaphoreVerifier | Complete runtime matches |
| PoseidonT3 | Complete runtime matches after the standard library self-address call-protection substitution |

The supplied configuration pins the **complete observed on-chain runtime**, including Semaphore's metadata. Runtime checking does not strip metadata or tolerate executable differences.

At finalized block 52,767,345 (`0xd3e1faaeb48ad253729c861cec2a73d9785bc80bb17d5dcf496d0ad8ed432c34`), deterministic synthetic Merkle-path proofs exercised circuit depths 7 and 20 using the 4.13.0 proving artifacts selected by the pinned SDK. The deployed verifier accepted each valid proof and rejected individual changes to the root, nullifier, message and scope: ten read-only checks. These boundary checks do not claim that every intermediate circuit, a real enrollment group or a full Cannabis claim has been exercised on mainnet.

The Arbitrum endpoint inspected did not provide the required finalized historical state. No successful finalized-state comparison is claimed for it.

## Scope

These checks establish correspondence with caller-reviewed pins within the selected RPC operator's chain view. They do not implement independent consensus or state-proof verification. Source correspondence is not an independent security audit. Human verification, registrar control, wallet recovery, operating requirements, funding, confidential workers and public claim readiness remain separate launch requirements. No Cannabis mainnet deployment is announced by this report.
