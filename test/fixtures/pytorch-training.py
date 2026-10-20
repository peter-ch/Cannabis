"""Owned numerical training input for isolated verification; never customer work."""
from datetime import timedelta
import json
import os
from pathlib import Path
import socket
import struct
import errno

import numpy as np
import torch
import torch.distributed as dist
from torch.nn.parallel import DistributedDataParallel

torch.set_num_threads(1)
torch.set_num_interop_threads(1)
torch.manual_seed(17)
rank = int(os.environ.get('RANK', '0'))
world = int(os.environ.get('WORLD_SIZE', '1'))
assert world in (1, 2) and rank < world
assert not torch.cuda.is_available() and torch.version.cuda is None
assert not os.path.exists('/dev/net/tun')
for family, kind, protocol in [(socket.AF_INET6, socket.SOCK_STREAM, 0), (socket.AF_INET, socket.SOCK_RAW, 0),
                              (socket.AF_NETLINK, socket.SOCK_RAW, 2), (socket.AF_NETLINK, socket.SOCK_RAW, 16),
                              (socket.AF_PACKET, socket.SOCK_RAW, 0), (socket.AF_VSOCK, socket.SOCK_STREAM, 0)]:
    try:
        socket.socket(family, kind, protocol)
    except PermissionError:
        pass
    else:
        raise AssertionError('Unapproved network socket')
if world > 1:
    assert {name for _, name in socket.if_nameindex()} == {'lo', 'cannabis0'}
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as query:
        query.settimeout(5)
        index = socket.if_nametoindex('cannabis0')
        # RTM_NEWLINK tries to clear IFF_UP. The owning namespace's kernel
        # capability check must refuse it, not silently alter the private link.
        body = struct.pack('=BBHiII', socket.AF_UNSPEC, 0, 0, index, 0, 1)
        query.sendto(struct.pack('=IHHII', 16 + len(body), 16, 1 | 4, 91, 0) + body, (0, 0))
        response = query.recv(4096)
        assert struct.unpack_from('=IHHII', response)[1:4:2] == (2, 91)
        assert struct.unpack_from('=i', response, 16)[0] == -errno.EPERM
else:
    try:
        socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    except PermissionError:
        pass
    else:
        raise AssertionError('Standalone task acquired route query access')
data = json.loads(Path('/input/training.json').read_text())
assert type(data['collectiveTimeoutSeconds']) is int and data['collectiveTimeoutSeconds'] in (60, 300)
x = torch.from_numpy(np.array(data['x'][rank::world], dtype=np.float32)).reshape(-1, 1)
y = torch.from_numpy(np.array(data['y'][rank::world], dtype=np.float32)).reshape(-1, 1)
model = torch.nn.Linear(1, 1)
if world > 1:
    assert os.environ['GLOO_SOCKET_IFNAME'] == 'cannabis0'
    dist.init_process_group('gloo', init_method='env://', timeout=timedelta(seconds=data['collectiveTimeoutSeconds']))
    model = DistributedDataParallel(model)
optimizer = torch.optim.SGD(model.parameters(), lr=0.1)
initial = float(torch.nn.functional.mse_loss(model(x), y).detach())
for _ in range(80):
    optimizer.zero_grad()
    loss = torch.nn.functional.mse_loss(model(x), y)
    loss.backward()
    optimizer.step()
trained = model.module if world > 1 else model
final = float(torch.nn.functional.mse_loss(trained(x), y).detach())
assert final < 1e-8 and initial > 1
# The requester validates bounded numeric JSON, never an untrusted pickle.
checkpoint = {key: value.detach().tolist() for key, value in trained.state_dict().items()}
Path('/output/checkpoint.json').write_text(json.dumps(checkpoint))
restored = torch.nn.Linear(1, 1)
restored.load_state_dict({key: torch.tensor(value) for key, value in
                         json.loads(Path('/output/checkpoint.json').read_text()).items()})
assert torch.allclose(restored(x), trained(x))
Path('/output/result.json').write_text(json.dumps({
    'rank': rank, 'worldSize': world, 'initialLoss': initial, 'finalLoss': final,
    'steps': 80, 'torch': torch.__version__, 'checkpointRestored': True}))
if world > 1:
    dist.barrier()
    dist.destroy_process_group()
print('Owned CPU training completed')
