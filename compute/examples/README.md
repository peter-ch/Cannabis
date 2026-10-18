# Workload contracts

[workload.json](workload.json) demonstrates the universal structure. Replace the opaque ID, placeholder digests, artifact names, runtime and launch contract with your actual values. Only allowlisted regular files are packaged. Runtime and resource fields are public placement metadata; code, arguments and customer-specific settings belong in the encrypted launch contract.

The adapter's launch object can represent any executable environment. For example, a declared container adapter might use `{"argv":["python","main.py"],"environment":{...}}`; a VM adapter might use `{"disk":"disk.qcow2","savedState":"machine.state","hypervisorVersion":"..."}`. These examples describe contracts, not installed protected runtimes. A VM snapshot must be consistent and compatible before packaging.

For distributed execution, request multiple `resources.nodes`, declare the required `runtime.collectiveBackend`, and use `outputScope: "per-rank"` if each rank produces files. An assembly item with `"rank":"all"` and `"destination":"checkpoint/rank-{rank}.bin"` reconstructs one output for every rank on the requester. For distributed checkpoints, declare all shard/index files required by the actual framework; the client does not average weights or interpret executable checkpoints.

Task dependencies are explicit `dependsOn` arrays. A reducer can be a separate task depending on all upstream tasks. The runtime adapter must provide valid partitioning and reduction semantics. The generic scheduler does not rewrite arbitrary programs into parallel code.
