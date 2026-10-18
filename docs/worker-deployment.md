# Deploying a confidential worker

Cannabis workers must prove which protected environment will receive a job's keys. Selecting a VM advertised as confidential is the beginning of provider integration. Admission also requires a measured boot chain, the approved runtime, protected storage and the exact initialization policy expected by the requester.

The current client integrates Trustee CPU appraisals for SNP and TDX. No provider deployment has yet completed the protected execution and settlement acceptance checks. CUDA, ROCm and other accelerators remain part of the network's scope; each device and interconnect path requires its own evidence.

## What the existing adapter expects

| Profile | Initialization binding | Other required measurements |
| --- | --- | --- |
| AMD SEV-SNP | The configured initialization digest matches the hardware report's `HOST_DATA` | Approved launch measurement, disabled debug and migration-agent access, and the minimum TCB versions in requester policy |
| Intel TDX | The configured initialization digest matches the hardware quote's `MRCONFIGID` | Approved `MRTD`, all four `RTMR` values, disabled debug, current TCB and valid collateral |

Both profiles also bind fresh challenge data, the guest-generated channel key and the approved job assignment. The current policy rejects an all-zero initialization digest. Do not change these fields or omit checks merely to make a provider's sample quote pass.

These bindings follow the pinned [guest-components SNP adapter](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attester/src/snp/mod.rs), [TDX adapter](https://github.com/confidential-containers/guest-components/blob/eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a/attestation-agent/attester/src/tdx/mod.rs), and [Trustee verifier](https://github.com/confidential-containers/trustee/tree/512fed65642015b849f38fb13bfdec7806639987/deps/verifier/src). The measured guest must consume and enforce that configuration; a matching digest supplied by an operator does not establish that the configuration was enforced.

## Check provider compatibility before provisioning

For the existing profiles, the deployment route must provide the launch fields above and a way to reproduce the expected firmware, kernel, initialization and runtime measurements. Obtain that evidence before treating an instance as an admitted worker.

Google Cloud illustrates why the details matter. Its documented Compute v1 `confidentialInstanceConfig` exposes the technology choice and enable flag. The inspected schema has no `HOST_DATA` or `MRCONFIGID` setter. This is a compatibility gap to resolve, not proof that every provider mechanism is incapable of supplying those fields. A standard confidential-instance creation request is not established as compatible with this adapter. [Compute API reference](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances)

Google distinguishes SNP hardware launch measurements from subsequent bootloader, kernel and userspace measurements held in its managed vTPM. Its TDX path records the boot chain in hardware measurement registers. Do not substitute a firmware-only measurement for evidence of the loaded Cannabis runtime. [Attestation architecture](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation-overview)

A provider-specific measured-boot profile can be added after its trust boundary, evidence format and enforcement are reviewed. Alternatively, a compatible bare-metal SNP/TDX deployment can expose the required launch controls. Neither route is authorized by an instance label or a runtime discovery report.

## Distributed and accelerator work

Validate every rank, replacement, device and communication path. Google currently documents that its confidential GPU VMs do not support multi-node clusters, so that offering alone cannot establish Cannabis's distributed GPU training capability. Another supported deployment route and encrypted collective networking remain necessary. [Supported configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations)

## Complete the worker acceptance run

Use the [hardware-validation milestone](https://github.com/peter-ch/Cannabis/issues/1) to record the measured guest, requester-controlled verifier, disposable job-key delivery, protected workload execution, enforced resource limits and requester-decrypted result. Verify rejection of changed measurements and assignments, debug access, replay, unprotected storage and unsupported devices. Keep raw hardware identifiers and secrets private.

The [guest evidence-service build](guest-service-build.md), [boot-image assembly](guest-image-build.md), [assignment initialization](guest-initialization.md), [guest session](guest-attestation.md) and [workload preparation](guest-workload.md) implement parts of this path. The boot-image entry point checks components and powers off without admitting workloads. Building or booting these components does not establish a measured confidential VM, and workload preparation does not launch a program. A provider is operational only after the protected launcher, transport and end-to-end payment and recovery behavior have been demonstrated and reviewed.

The [guest resource boundary](guest-image-build.md#resource-enforcement-inside-the-guest) now enforces kernel CPU, memory and process limits with deadline and cancellation cleanup. It is checked with actual bounded processes in the boot image. The isolated runtime must additionally protect the control plane, storage, devices and network, enforce loaded-adapter policy and dispose of the guest if its supervisor fails. Resource counters alone do not establish execution privacy or payment acceptance.
