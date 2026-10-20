# Compute software

The compute components package arbitrary software into streaming encrypted archives, validate task graphs, compare compatible node quotes, reconstruct encrypted results on the requester, inspect runtime capabilities and prepare unsigned escrow transactions. Operational worker dispatch, customer-code execution and signing/sending payments remain release integrations. Start with the [general-purpose client](../docs/universal-compute.md); the smaller planner below remains available for the original job-manifest interface.

The [guest session](../docs/guest-attestation.md) now connects the local SNP/TDX attestation agent to the requester approval and encrypted key-envelope APIs. It retains a guest-generated channel key through evidence collection and one verified opening. Operational confidential execution still requires a reviewed measured launcher and compatible hardware.

The [protected group adapter](../docs/protected-groups.md) adds explicit coordinated
CPU ranks, authenticated encrypted peer networking, a shared signed start and
group-bound result recovery. Its combined Linux checkpoint connects retained
guest sessions, native execution, separate operators and isolated-chain settlement.
Refreshed measured images and actual hardware admission remain unfinished. See the
[requester workflow](../docs/requester-workflow.md) for dispatch and recovery.

## Commands

```sh
npm run compute:plan -- path/to/job.json path/to/workers.json
python scripts/compute-probe.py
```

The worker manifest is optional. An empty pool produces an unassigned plan. Probe using a Python environment that already contains the intended PyTorch build. The probe does not install drivers, run benchmarks, print host identifiers or establish confidential-execution support.

The [optional CPU PyTorch image recipe](../docs/guest-image-build.md#cpu-pytorch-runtime)
pins Torch, NumPy and their dependency closure for native single-process and
protected Gloo group jobs. Its 8 GiB VM profile and runtime digest are distinct
from the minimal Python image. Select an independently admitted matching provider
before offering or paying for this capability; a successful local probe or
training fixture does not establish live availability.

## Public job manifest

Use schema `cannabis.compute.job.v1`. The planner validates these exact fields and rejects extra execution fields that could leak private arguments.

| Field | Meaning |
| --- | --- |
| id | Opaque job identifier, up to 64 letters/digits/dots/hyphens/underscores |
| requester | Requester's EVM public address |
| kind | `torch-distributed` or `standalone` |
| runtime | `cpu`, `cuda`, `rocm`, `xpu`, `mps`, `tpu`, or `custom:adapter-id` |
| collectiveBackend | Distributed collective backend, or null for standalone work |
| execution.image | Digest-pinned protected runtime image, `repository@sha256:...` |
| confidentiality | `required: true`, policySHA256, encryptedBundleSHA256, `cipher: AES-256-GCM`, `keyRelease: attested-only` |
| resources | nodes, processesPerNode, cpusPerNode, memoryMiBPerNode, scratchMiBPerNode, acceleratorsPerNode, acceleratorMemoryMiB, wallSeconds |
| payment | Exact decimal totalBudget in Cannabis, `feeBasisPoints: 100`, founderRecipient from policy.json |
| acceptance.encryptedTermsSHA256 | Digest of encrypted acceptance terms |

The private bundle contains the actual program/entrypoint, arguments, dataset/model locators, credentials, acceptance instructions and output policy. None of these belong in the public manifest or host launch arguments. The protected launcher will decode and validate them only after attestation and authorized key release.

The published fee policy lives in [policy.json](policy.json). A 100 Cannabis job budget allocates 99 to the worker pool and 1 to the founder. All arithmetic uses 18-decimal token base units. Gross budgets and positive accepted awards must be multiples of 100 base units so the 1% service fee is exact, including on very small jobs. Nonrepresentable amounts are rejected. Fees apply to accepted paid work, not refunded amounts; network fees are separate. This is a quote, not an escrow or a payment record.

## Worker advertisements

A worker record declares id, runtime, os, imageDigests, isolation, confidentialCapabilities, collectiveBackends and capacity. Initial planning targets Linux confidential VMs. Capacity includes cpus, memoryMiB, scratchMiB, accelerators and acceleratorMemoryMiB. Confidential capability claims must cover both CPU and any requested accelerator.

The planner checks those claims against job requirements and assigns candidate ranks. It never treats advertisements as attestation, and always leaves execution and key release unauthorized. Actual hardware proof, patch policy, protected runtime, private networking, atomic leases and signatures are mandatory release work. The [escrow implementation](../docs/compute-payments.md) now covers fixed budgets, worker acceptance, delivery review, disputes and refunds; it still needs independent review and deployment.

## Private bundles

Import `newContentKey`, `sealBundle`, `openBundle` and `envelopeDigest` from `scripts/compute-crypto.mjs`. Supply buffers and a jobId/policySHA256 context. Keep keys in an encrypted owner-controlled keystore or reviewed key-release service, never in JSON job manifests or command-line arguments.

The AES-256-GCM primitive authenticates content and context. It is limited to 32 MiB instruction bundles; it does not encrypt a GPU's memory or implement confidential execution. See [confidential-compute requirements](../docs/confidential-compute.md).
