# Deploying a confidential worker

Use the [local worker console](worker-console.md) to inspect this computer and its admission requirements. Its running GUI provides observations; paid execution remains unavailable until the deployment below has been validated.

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

The [guest resource boundary](guest-image-build.md#resource-enforcement-inside-the-guest) enforces kernel CPU, memory and process limits. Its [independent guardian](guest-image-build.md#independent-process-guardian) terminates job trees after supervisor death or a stopped supervisor's deadline, including detached descendants and a leaked control socket. The [native runtime boundary](guest-image-build.md#native-runtime-isolation) adds read-only roots/inputs, private namespaces, restricted syscalls, denied external networking/devices and one unswappable byte/inode budget for scratch and logs. The [encrypted native task path](guest-image-build.md#encrypted-native-task-execution) connects bounded decoding, approved native execution and requester-bound result encryption, with separate helper guardians, a protected staging quota and one deadline shared across stages. Late publication returns no successful result. These run actual owned-process checks in the boot image. The complete launcher must still connect this path to the initialized evidence session, admitted hardware, loaded-adapter policy and current funded assignment, integrate protected distributed transport, and retire keys and the guest on fatal failure. Resource counters alone do not establish execution privacy or payment acceptance.
