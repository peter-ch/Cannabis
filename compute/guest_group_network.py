"""One owned workload network namespace; packets leave only through protected TLS.

The measured Node controller owns peer admission/crypto. Its anonymous packet
pipes stay inside this protected VM. This helper never opens an Internet socket,
holds peer keys, chooses a peer or establishes hardware/funding authorization.
"""
import array
import ctypes
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import select
import selectors
import signal
import socket
import stat
import struct
import time

from .guest_deadline import ExecutionDeadline
from .guest_sandbox import enter_private_mount_namespace

MTU = 1280
CLONE_NEWNET = 0x40000000
NETWORK = ipaddress.IPv4Network('10.211.0.0/24')
_CONSTRUCTION = object()


def _check(value):
    if not value:
        raise RuntimeError('Protected group network failed; retire the group attempt')


def validate_packet(packet, source, target, world_size):
    _check(20 <= len(packet) <= MTU and packet[0] == 0x45
           and struct.unpack_from('!H', packet, 2)[0] == len(packet)
           and struct.unpack_from('!H', packet, 6)[0] & 0xbfff == 0
           and packet[8] > 0 and packet[9] in (6, 17)
           and 2 <= world_size <= 64 and 0 <= source < world_size and 0 <= target < world_size and source != target)
    _check(packet[12:16] == bytes((10, 211, 0, source + 1)) and packet[16:20] == bytes((10, 211, 0, target + 1)))
    if packet[9] == 6:
        _check(len(packet) >= 40 and packet[32] >> 4 >= 5 and 20 + (packet[32] >> 4) * 4 <= len(packet))
    else:
        _check(len(packet) >= 28 and struct.unpack_from('!H', packet, 24)[0] == len(packet) - 20)


def _ifreq(name):
    value = bytearray(40)
    encoded = name.encode('ascii')
    _check(len(encoded) < 16)
    value[:len(encoded)] = encoded
    return value


def _address(control, name, operation, address):
    value = _ifreq(name)
    struct.pack_into('H', value, 16, socket.AF_INET)
    value[20:24] = socket.inet_aton(address)
    fcntl.ioctl(control, operation, value)


def _up(control, name):
    value = _ifreq(name)
    fcntl.ioctl(control, 0x8913, value, True)  # SIOCGIFFLAGS
    struct.pack_into('H', value, 16, struct.unpack_from('H', value, 16)[0] | 1)
    fcntl.ioctl(control, 0x8914, value)  # SIOCSIFFLAGS


def _namespace_child(channel, rank, parent_pid):
    descriptors = []
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        _check(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent_pid)
        _check(libc.unshare(CLONE_NEWNET) == 0)
        for name in ('all', 'default'):
            path = Path('/proc/sys/net/ipv6/conf') / name / 'disable_ipv6'
            if path.exists():
                path.write_text('1')
        info = os.stat('/dev/net/tun', follow_symlinks=False)
        _check(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (10, 200))
        tun = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
        descriptors.append(tun)
        value = _ifreq('cannabis0')
        struct.pack_into('H', value, 16, 0x0001 | 0x1000)  # IFF_TUN | IFF_NO_PI; no offload header.
        fcntl.ioctl(tun, 0x400454ca, value, True)
        _check(bytes(value[:16]).rstrip(b'\0') == b'cannabis0')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
            _address(control, 'cannabis0', 0x8916, f'10.211.0.{rank + 1}')  # SIOCSIFADDR
            _address(control, 'cannabis0', 0x891c, '255.255.255.0')  # SIOCSIFNETMASK
            value = _ifreq('cannabis0'); struct.pack_into('i', value, 16, MTU)
            fcntl.ioctl(control, 0x8922, value)  # SIOCSIFMTU
            value = _ifreq('cannabis0'); struct.pack_into('i', value, 16, 64)
            fcntl.ioctl(control, 0x8943, value)  # SIOCSIFTXQLEN
            _up(control, 'lo'); _up(control, 'cannabis0')
        routes = [line.split() for line in Path('/proc/net/route').read_text().splitlines()[1:]]
        _check(len(routes) == 1 and routes[0][0] == 'cannabis0' and routes[0][1] == '0000D30A'
               and routes[0][2] == '00000000' and routes[0][7] == '00FFFFFF')
        namespace = os.open('/proc/self/ns/net', os.O_RDONLY | os.O_CLOEXEC)
        descriptors.append(namespace)
        channel.sendmsg([b'ready'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [namespace, tun]))])
        return 0
    except BaseException:
        return 1
    finally:
        for fd in descriptors:
            os.close(fd)
        channel.close()


def _close_except(keep):
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd not in keep:
            try:
                os.close(fd)
            except OSError:
                pass


def _pump(tun, incoming, outgoing, monitor, owner, rank, world_size, max_buffered, end):
    """Bounded private IPC/TUN bridge. No customer packet is logged or persisted."""
    _close_except({tun, incoming, outgoing, monitor.fileno(), owner})
    for fd in (tun, incoming, outgoing, monitor.fileno()):
        os.set_blocking(fd, False)
    incoming_bytes = bytearray(); outgoing_bytes = bytearray(); packets = []; packet_bytes = 0
    last_heartbeat = 0
    try:
        monitor.send(b'R')
        while time.monotonic() < end:
            now = time.monotonic()
            if now - last_heartbeat >= 0.5:
                try:
                    monitor.send(struct.pack('!cd', b'A', now)); last_heartbeat = now
                except BlockingIOError:
                    pass
            with selectors.DefaultSelector() as poll:
                poll.register(owner, selectors.EVENT_READ, 'owner')
                poll.register(monitor, selectors.EVENT_READ, 'control')
                input_space = max_buffered - packet_bytes - len(incoming_bytes)
                if input_space > 0:
                    poll.register(incoming, selectors.EVENT_READ, 'input')
                if len(outgoing_bytes) + MTU + 4 <= max_buffered:
                    poll.register(tun, selectors.EVENT_READ | (selectors.EVENT_WRITE if packets else 0), 'tun')
                elif packets:
                    poll.register(tun, selectors.EVENT_WRITE, 'tun')
                if outgoing_bytes:
                    poll.register(outgoing, selectors.EVENT_WRITE, 'output')
                events = poll.select(min(0.2, max(0, end - time.monotonic())))
            for event, flags in events:
                if event.data == 'owner':
                    return 1
                if event.data == 'control':
                    command = monitor.recv(8)
                    _check(command == b'S')
                    return 0
                if event.data == 'input':
                    block = os.read(incoming, min(65536, max_buffered - packet_bytes - len(incoming_bytes)))
                    _check(block and packet_bytes + len(incoming_bytes) + len(block) <= max_buffered)
                    incoming_bytes.extend(block)
                    while len(incoming_bytes) >= 4:
                        length = struct.unpack_from('!I', incoming_bytes)[0]
                        _check(20 <= length <= MTU)
                        if len(incoming_bytes) < length + 4:
                            break
                        packet = bytes(incoming_bytes[4:length + 4]); del incoming_bytes[:length + 4]
                        validate_packet(packet, packet[15] - 1, rank, world_size)
                        _check(packet_bytes + len(packet) <= max_buffered)
                        packets.append(packet); packet_bytes += len(packet)
                if event.data == 'tun':
                    if flags & selectors.EVENT_READ:
                        packet = os.read(tun, MTU + 1)
                        validate_packet(packet, rank, packet[19] - 1 if len(packet) >= 20 else -1, world_size)
                        outgoing_bytes.extend(struct.pack('!I', len(packet))); outgoing_bytes.extend(packet)
                    if flags & selectors.EVENT_WRITE and packets:
                        packet = packets[0]
                        _check(os.write(tun, packet) == len(packet))
                        packet_bytes -= len(packet); packets.pop(0)
                if event.data == 'output':
                    count = os.write(outgoing, outgoing_bytes)
                    _check(count > 0); del outgoing_bytes[:count]
        return 1
    except BaseException:
        return 1
    finally:
        incoming_bytes[:] = b'\0' * len(incoming_bytes)
        outgoing_bytes[:] = b'\0' * len(outgoing_bytes)
        packets.clear()


class GuestGroupNetwork:
    def __init__(self, guard, group, deadline):
        _check(guard is _CONSTRUCTION)
        self.rank, self.world_size = group['rank'], group['worldSize']
        self.group_digest = group['groupDigest']
        self.deadline = deadline
        self.owner_pid = os.getpid()
        self.namespace_fd = self.tun_fd = self.pidfd = None
        self.pid = self.monitor = None
        self.last_heartbeat = time.monotonic()
        self.namespace_identity = None
        self.closed = False

    @classmethod
    def create(cls, group, deadline, incoming=3, outgoing=4):
        _check(isinstance(deadline, ExecutionDeadline) and isinstance(group, dict)
               and set(group) == {'schema', 'rank', 'worldSize', 'groupDigest', 'maxBufferedBytes'}
               and group['schema'] == 'cannabis.guest-group-network.v1'
               and type(group['rank']) is int and type(group['worldSize']) is int
               and 2 <= group['worldSize'] <= 64 and 0 <= group['rank'] < group['worldSize']
               and isinstance(group['groupDigest'], str) and len(group['groupDigest']) == 66
               and group['groupDigest'].startswith('0x')
               and all(c in '0123456789abcdef' for c in group['groupDigest'][2:])
               and type(group['maxBufferedBytes']) is int and 131072 <= group['maxBufferedBytes'] <= 8 * 1024**2)
        _check(os.geteuid() == 0 and len(os.listdir('/proc/self/task')) == 1 and incoming != outgoing)
        deadline.check()
        for fd in (incoming, outgoing):
            mode = os.fstat(fd).st_mode
            if stat.S_ISFIFO(mode) and os.readlink(f'/proc/self/fd/{fd}').startswith('pipe:['):
                continue
            _check(stat.S_ISSOCK(mode))
            with socket.socket(fileno=os.dup(fd)) as channel:
                _check(channel.family == socket.AF_UNIX and channel.type == socket.SOCK_STREAM
                       and channel.getsockname() in ('', b'') and channel.getpeername() in ('', b''))
        enter_private_mount_namespace()
        obj = cls(_CONSTRUCTION, group, deadline)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        child_pid = None
        fds = []
        try:
            child_pid = os.fork()
            if child_pid == 0:
                parent.close(); os._exit(_namespace_child(child, obj.rank, obj.owner_pid))
            child.close()
            parent.settimeout(5)
            message, ancillary, flags, _ = parent.recvmsg(16, socket.CMSG_SPACE(2 * array.array('i').itemsize))
            for level, kind, data in ancillary:
                _check(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS)
                values = array.array('i'); values.frombytes(data); fds.extend(values)
            _check(message == b'ready' and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and len(fds) == 2)
            _, status = os.waitpid(child_pid, 0); child_pid = None
            _check(os.waitstatus_to_exitcode(status) == 0)
            obj.namespace_fd, obj.tun_fd = fds; fds = []
            obj.namespace_identity = (os.fstat(obj.namespace_fd).st_dev, os.fstat(obj.namespace_fd).st_ino)
            _check(os.readlink(f'/proc/self/fd/{obj.namespace_fd}').startswith('net:['))
            current = os.stat('/proc/self/ns/net')
            _check(obj.namespace_identity != (current.st_dev, current.st_ino))
            monitor, pump_monitor = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            obj.monitor = monitor
            owner = None
            try:
                owner = os.pidfd_open(os.getpid())
                obj.pid = os.fork()
                if obj.pid == 0:
                    monitor.close()
                    os._exit(_pump(obj.tun_fd, incoming, outgoing, pump_monitor, owner, obj.rank, obj.world_size,
                                   group['maxBufferedBytes'], deadline.monotonic_end))
            finally:
                pump_monitor.close()
                if owner is not None:
                    os.close(owner)
            obj.pidfd = os.pidfd_open(obj.pid)
            monitor.settimeout(5); _check(monitor.recv(8) == b'R'); monitor.setblocking(False)
            obj.assert_alive(); return obj
        except BaseException:
            obj.close(failed=True)
            raise
        finally:
            parent.close(); child.close()
            for fd in fds:
                os.close(fd)
            if child_pid is not None:
                os.kill(child_pid, signal.SIGKILL); os.waitpid(child_pid, 0)

    def assert_alive(self):
        _check(not self.closed and os.getpid() == self.owner_pid and self.pidfd is not None)
        self.deadline.check()
        _check((os.fstat(self.namespace_fd).st_dev, os.fstat(self.namespace_fd).st_ino) == self.namespace_identity)
        _check(not select.select([self.pidfd], [], [], 0)[0])
        while True:
            try:
                message = self.monitor.recv(16)
                _check(len(message) == 9)
                kind, emitted = struct.unpack('!cd', message)
                _check(kind == b'A' and self.last_heartbeat <= emitted <= time.monotonic())
                # Queued old messages cannot make a stopped pump look fresh.
                self.last_heartbeat = emitted
            except BlockingIOError:
                break
        _check(time.monotonic() - self.last_heartbeat < 5)

    def is_set(self):
        try:
            self.assert_alive(); return False
        except (RuntimeError, OSError):
            return True

    def close(self, *, failed=False):
        if self.closed:
            return
        self.closed = True
        clean = self.pid is None
        try:
            if self.pid is not None:
                try:
                    self.monitor.send(b'S')
                except (OSError, AttributeError):
                    pass
                if self.pidfd is not None and select.select([self.pidfd], [], [], 5)[0]:
                    _, status = os.waitpid(self.pid, 0)
                    clean = os.waitstatus_to_exitcode(status) == 0
                else:
                    os.kill(self.pid, signal.SIGKILL); os.waitpid(self.pid, 0)
                self.pid = None
        finally:
            if self.monitor is not None:
                self.monitor.close()
            for fd in (self.pidfd, self.tun_fd, self.namespace_fd):
                if fd is not None:
                    os.close(fd)
            self.pidfd = self.tun_fd = self.namespace_fd = None
        if not failed:
            _check(clean)
