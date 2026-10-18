# Put compute to work

Cannabis is building a general-purpose compute service around **arbitrary software workloads**, with extensible runtime adapters, whole-job placement, task graphs and coordinated multi-node execution. PyTorch training, VM checkpoints, renderers and scripts are examples. Paid jobs produce agreed outputs and include an upfront 1% founder service fee. **Status: encrypted packaging, candidate placement, requester-side result reconstruction and fixed-budget escrow software are implemented; the protected paid job service is not yet operating.**

## Consensus, participation and jobs

| Function | Design |
| --- | --- |
| Network consensus | Ethereum proof-of-stake settlement through the selected EVM network |
| Community allocation | 99% of capped supply, one privacy-preserving claim per verified person |
| Founder allocation | 1%, vested over 24 calendar months |
| Useful work | Arbitrary requester-paid software through extensible runtime adapters, task graphs and coordinated groups |
| Payment | Existing Cannabis, split into worker payment and an upfront disclosed 1% founder fee |

The founder service fee is **1% of the accepted paid amount**, included in the requester budget and separate from the 1% vested token allocation. The requester sees the total budget, worker share and fee before accepting a job. The rate and recipient must be pinned in the accepted terms; changes apply only to new jobs. A rejected/refunded amount does not earn a service fee. Network transaction fees are quoted separately.

## Hardware and distributed execution

| Target hardware | Runtime and distributed route |
| --- | --- |
| NVIDIA GPUs | CUDA; NCCL for compatible distributed GPU groups |
| AMD GPUs | ROCm/HIP; RCCL through PyTorch's `nccl` backend where the build supports it |
| CPU | CPU PyTorch; Gloo for supported distributed builds |
| Intel GPUs | XPU and XCCL when supported by the installed build |
| Other accelerators | Approved runtime adapter declaring devices, operators, collective backend and isolation support |

The mappings follow [PyTorch distributed documentation](https://docs.pytorch.org/docs/stable/distributed), [PyTorch ROCm semantics](https://docs.pytorch.org/docs/main/notes/hip.html), and [AMD RCCL documentation](https://rocm.docs.amd.com/projects/rccl/en/latest/how-to/rccl-usage-tips.html). A support target is not a claim that every chip or operating-system build has been validated.

Workers advertise verified capabilities: runtime, driver/toolchain versions, device memory, CPU/RAM/storage, available collectives and network limits. Jobs match compatible resources. Initial distributed groups use a homogeneous runtime and compatible images; cross-vendor all-reduce is not assumed. Different accelerator types can process separate compatible jobs without mixing them into the same process group.

Launch distributed workloads with `torchrun` inside each worker's isolated environment. A job gets a private, authenticated network and a unique rendezvous identifier. Restrict the rendezvous and collective ports to its assigned workers; never expose an unauthenticated store publicly. Apply gang scheduling, rank assignment, checkpoint recovery, restart budgets and an all-ranks cancellation policy. See [torchrun](https://docs.pytorch.org/docs/main/elastic/run.html) for the underlying launch mechanism. Custom workloads must support their declared runtime; the scheduler does not automatically port CUDA kernels to other chips.

There is no hash race, training race, difficulty target, emissions-per-GPU scheme or new minting allowance. Training results never decide blockchain consensus. More GPUs do not produce more verified-person claims.

## First supported workflow

All customer jobs follow the [mandatory confidential-compute design](confidential-compute.md). Host operators receive encrypted workloads; code and data are decrypted only in verified protected execution. Runtime compatibility is necessary but does not establish confidentiality.

1. A requester defines a useful task and offers a budget: digest-pinned custom container/program, licensed inputs, output rights, compatible hardware, resource limits, deadline, acceptance metrics and founder fee.
2. A worker or a compatible distributed worker group accepts the assignment. The dispatcher grants an expiring lease to one assignment, avoiding unintended duplicate execution. Retries require a failed or expired lease and explicit remaining-budget checks.
3. Computation runs off-chain inside the attested confidential environment. Encrypt checkpoints and internal logs; use early stopping where appropriate. Data licensing and privacy policy are part of the accepted job terms.
4. The worker delivers weights in an approved non-executable tensor format, configuration, dataset/model digests, dependency versions, hardware information, resource usage and an evaluation report.
5. An isolated evaluator loads the agreed architecture and submitted tensors, then evaluates against the requester's held-out dataset. Artifact hashes establish identity, not training quality or proof that computation occurred. Acceptance includes agreed baseline improvements, input limits and artifact checks.
6. Acceptance releases the agreed payment in existing Cannabis. The [escrow implementation](compute-payments.md) specifies cancellation/refunds, deadlines, a delivery review window and dispute resolution. Requesters must monitor the review window: undisputed deliveries become payable when it expires. Independent review and deployment remain release requirements.

Users may supply custom Python and other programs in digest-pinned execution images. Workers explicitly opt in to custom-code execution; it runs only inside the reviewed workload sandbox. A planner accepting a manifest does not authorize execution. Deterministic settings and reproducible seeds help investigation, but different hardware can still change numerical results. Payment concerns accepted outputs, not unverifiable claims about GPU-hours.

## Security and privacy

Workers use dedicated isolated environments without wallet keys, personal directories, host credentials or unrestricted networking. Resource quotas, explicit input/output paths, pinned dependencies, dataset size limits, timeouts and cancellation are mandatory. An ordinary subprocess on the founder's personal computer is not sufficient isolation for untrusted jobs.

Treat custom code, model files and datasets as untrusted. PyTorch's [security policy](https://github.com/pytorch/pytorch/security/policy) explains why running untrusted models can be equivalent to running untrusted code. Never load arbitrary pickle checkpoints or enable remote model code in the host control plane. Job-specific executable dependencies remain confined to the isolated workload. Artifact evaluation also needs isolation.

An ordinary host can inspect unprotected running workloads, so customer data must never be dispatched there. Require validated confidential execution covering CPU, accelerator and peer communication. Federated learning alone does not make gradients private. Public-chain payments remain visible. Keep community identity credentials separate from job profiles, delivery records and payment metadata.

## Efficiency and acceptance evidence

The [general-purpose client guide](universal-compute.md) documents streaming workload packages, arbitrary adapter contracts, task graphs, quote-aware placement and per-rank result assembly on the requester. The [compute software guide](../compute/README.md) also documents the original planner, precise 1% fee arithmetic, hardware probe and bounded encryption primitives. These components do not execute customer jobs or release keys.

Only schedule jobs backed by an actual requester and a finite budget. Prefer appropriately sized models, mixed precision when compatible, checkpoint reuse and early stopping. Keep weights and data off-chain; use the network for settlement and minimal commitments where needed. Never repeat training merely to qualify for a reward.

Measure task completion, quality improvement, elapsed time and GPU utilization. Report electricity only when measured with a stated method; useful work still consumes energy and does not establish a carbon-neutral claim.

Public operation requires one real, authorized workload delivered and independently evaluated, enforced isolation/resource limits, reviewed payment and dispute handling, cancellation/retry recovery, and a published operating cost model. No buyers, payments or throughput figures are claimed before that evidence exists.
