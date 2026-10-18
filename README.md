# Cannabis

**A little wild. A lot of purpose.**

Cannabis is a production cryptocurrency project built around efficient community participation and privacy-preserving eligibility. **Status: preparing mainnet launch.** [Explore Cannabis](https://cannabis-coin.online/).

**Money for useful computing.** The economic objective is real service demand: people pay in Cannabis for accepted computing work, while providers publish capacity and enforceable redemption terms. Read the [compute economy and backing requirements](docs/compute-economy.md). Service backing becomes operational only when defined provider commitments can actually be redeemed and fulfilled.

![Cannabis — A little wild. A lot of purpose.](web/assets/campaign/purpose-landscape.png)

The contracts define a fixed supply cap and one-time verified-person community claims with a common public opening. Read the [allocation, vesting and service terms](docs/tokenomics.md) before participating.

There is **no proof-of-work**. The selected architecture uses Ethereum proof-of-stake settlement through an EVM network. Semaphore zero-knowledge proofs conceal which enrolled identity made a claim, while the recipient wallet and transaction remain public. Enrollment is append-only; claims require at least 128 commitments. A reviewed provider must enforce one identity per distinct person.

**Put compute to work.** The general-purpose client packages arbitrary software through extensible runtime adapters, compares node quotes, plans task graphs and coordinated groups, and reconstructs encrypted output shards on the requester. Python, VM checkpoints and distributed model training are examples of the broader format. Target hardware includes NVIDIA/CUDA, AMD/ROCm, CPU and other accelerators. Job quotes disclose the included service fee and total before payment; see the [service terms](docs/tokenomics.md). Work stays off-chain and does not mint tokens or decide consensus. See the [universal client](docs/universal-compute.md), [useful-compute design](docs/useful-compute.md) and [escrow payment rules](docs/compute-payments.md). The protected worker service and mainnet payments still require integration and review.

Customer jobs require encrypted code/data and attested confidential execution. Keys must stay out of worker operators' hands, with no fallback to unprotected hardware. See the [confidential-compute requirements](docs/confidential-compute.md). Runtime compatibility alone does not establish private execution; the protected worker and key-release service are release work.

## Run the website

Requires Node.js 22.22+ and npm.

~~~sh
npm ci
npm run dev
~~~

Open http://127.0.0.1:4200. This serves the public Cannabis website.

## Verify the contracts

~~~sh
npm test
~~~

The suite checks real zero-knowledge proofs, replay and recipient-substitution attacks, enrollment permissions, anonymity thresholds, fixed supply and founder vesting on isolated ephemeral chains. Compute integration checks also require Python 3.12+ and age 1.3.2 with age-keygen; put them on PATH or set `CANNABIS_PYTHON` and `CANNABIS_AGE` to their executable paths. CI installs and verifies these tools. Production releases require independent security and privacy review.

## Project material

- [Windows guided participant setup](docs/windows-setup.md)
- [Token rules and architecture](docs/technical-paper.md)
- [Privacy and security design](docs/privacy-security.md)
- [Efficient-network approach](docs/energy.md)
- [Community claim workflow](docs/community-claims.md)
- [Provider signature checks and private enrollment intake](docs/person-verification.md)
- [Encrypted participant identity and offline proofs](docs/claim-identity.md)
- [Complete membership download and chain-state checks](docs/membership-snapshot.md)
- [Mainnet release preparation](docs/mainnet-release.md)
- [Deployment fee estimates and budget scope](docs/deployment-fees.md)
- [Launch acceptance criteria](docs/launch-plan.md)
- [Participation risks](docs/risks.md)
- [Launch review](docs/launch-review.md)
- [Campaign copy](media/campaign.md)
- [Ready-to-share graphics](https://cannabis-coin.online/share.html)
- [English narrated films](media/README.md)
- [General-purpose workload packaging and result reconstruction](docs/universal-compute.md)
- [Compute escrow and transparent pricing](docs/compute-payments.md)
- [Small jobs, exact fees and reproducible integration checks](docs/microjobs.md)
- [Signed capacity commitments and reservation controls](docs/capacity-commitments.md)
- [Trustee attestation checks and single-use challenges](docs/trustee-attestation.md)
- [Per-job encryption keys and requester recovery](docs/job-key-custody.md)
- [Requester-approved encrypted key delivery](docs/key-delivery.md)
- [Guest-held channels and hardware-evidence integration](docs/guest-attestation.md)
- [Guest workload decoding and assignment verification](docs/guest-workload.md)

The person-verification provider, final network, independent review and deployment are release dependencies. Canonical addresses and the opening time will be published with the verified release. Cannabis is an independent project, unaffiliated with other cannabis-themed currencies.
