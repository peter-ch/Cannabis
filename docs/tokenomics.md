# Cannabis allocation and service terms

These are the published parameters of the current contract implementation. Mainnet launch is being prepared; a verified release, Cannabis ceremony and opening time have not yet been announced. Read these terms before participating, alongside the [release requirements](mainnet-release.md), [privacy design](privacy-security.md) and [risks](risks.md).

## Supply and allocation

| Term | Amount or rule |
| --- | --- |
| Maximum supply | 420,000,000 Cannabis |
| Community allocation | 99%: 415,800,000 Cannabis |
| Founder allocation | 1%: 4,200,000 Cannabis |
| Founder vesting | Locked at creation; released linearly over 24 calendar months from the common public opening |
| Community claim | 420 Cannabis once per eligible verified person |
| Maximum claimants | 990,000 |
| Initial claim group | At least 128 independently verified people |

There is no proof-of-work issuance. The founder allocation is separate from compute-service fees. Eligibility, duplicate prevention and the common opening are described in the [community claim rules](community-claims.md). The contract implementation has no administrator function to increase the supply cap.

## Compute-service fee

Each accepted paid job includes a **1% founder service fee** within the accepted gross payment. It is not added above the agreed gross budget. The remaining 99% goes to the worker pool under the agreed worker shares. For example, an accepted gross payment of 100 Cannabis distributes 99 to workers and 1 to the founder.

Refunded amounts incur no founder service fee. Network transaction fees are separate. Quotes and payment preparation must show the service fee, worker amount, total budget and applicable network charges before the requester commits funds. The fee and founder recipient are immutable in the current escrow implementation.

Read the [payment rules](compute-payments.md) for acceptance windows, automatic settlement after an undisputed delivery, disputes, cancellation, refunds and rounding. A completed job does not itself reserve future compute capacity; [service commitments](compute-economy.md) have separate availability and fulfillment requirements.

## Release information

The canonical contract addresses, chain, code hashes, enrollment controller and opening time will be published with the reviewed release. Independent security/privacy review and protected worker validation remain outstanding. This page describes project parameters and does not claim that an independent review or public launch has occurred.
