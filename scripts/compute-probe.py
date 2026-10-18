"""Inspect local PyTorch runtime capabilities; does not execute jobs or expose host identifiers."""
import json
import platform
import torch

def probe():
    dist = torch.distributed
    backends = [name for name in ("gloo", "nccl", "mpi", "xccl")
                if dist.is_available() and getattr(dist, "is_" + name + "_available", lambda: False)()]
    devices = []
    gpu_runtime = "rocm" if torch.version.hip else "cuda"
    if torch.cuda.is_available():
        for index in range(torch.cuda.device_count()):
            item = torch.cuda.get_device_properties(index)
            devices.append({"runtime": gpu_runtime, "index": index, "name": item.name,
                            "memoryMiB": item.total_memory // (1024 * 1024)})
    if hasattr(torch, "xpu") and torch.xpu.is_available():
        for index in range(torch.xpu.device_count()):
            item = torch.xpu.get_device_properties(index)
            devices.append({"runtime": "xpu", "index": index, "name": item.name,
                            "memoryMiB": item.total_memory // (1024 * 1024)})
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        devices.append({"runtime": "mps", "index": 0, "name": "Apple MPS", "memoryMiB": None})
    return {"schema": "cannabis.compute.probe.v1", "os": platform.system().lower(),
            "torchVersion": str(torch.__version__), "cpuAvailable": True,
            "hipVersion": torch.version.hip, "cudaVersion": torch.version.cuda,
            "accelerators": devices, "availableCollectiveBackends": backends,
            "distributedAvailable": dist.is_available(), "executionAuthorized": False,
            "note": "Runtime discovery only. Isolation, job compatibility and multi-node execution require separate validation."}

if __name__ == "__main__":
    print(json.dumps(probe(), indent=2))
