"""Signed, bounded ciphertext storage inside the protected guest.

This volume contains encrypted input/output only. It does not authorize a job,
attest hardware or replace the enclosing whole-VM capacity/disposal policy.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat

from .guest_resources import ResourceCleanupError
from .guest_sandbox import ScratchLimits, _call, _directory, _libc, enter_private_mount_namespace


@dataclass(frozen=True)
class CiphertextLimits:
    bytes: int
    inodes: int
    inputBytes: int
    outputBytes: int
    dependencyBytes: int = 0

    def __post_init__(self):
        ScratchLimits(self.bytes, self.inodes)
        for value in [self.inputBytes, self.outputBytes]:
            if type(value) is not int or not 1 <= value <= 1024**4:
                raise ValueError('Invalid ciphertext file bound')
        if type(self.dependencyBytes) is not int or not 0 <= self.dependencyBytes <= 1024**4:
            raise ValueError('Invalid dependency ciphertext bound')
        if sum((v+4095)//4096*4096 for v in [self.inputBytes,self.outputBytes,self.dependencyBytes]) > self.bytes:
            raise ValueError('Ciphertext storage cannot hold both bounded files')


def ciphertext_directory(source):
    incoming, outgoing = Path(source['ciphertext']), Path(source['destination'])
    if (not incoming.is_absolute() or '..' in incoming.parts or incoming.name != 'workload.age'
            or outgoing.parent != incoming.parent or outgoing.name != 'result.age'):
        raise ValueError('Require distinct fixed files in one private ciphertext directory')
    return incoming.parent


def verify_storage(path, limits):
    fd = _directory(path)
    try:
        info, space = os.fstat(fd), os.fstatvfs(fd)
        fields = dict(line.split(':',1) for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines() if ':' in line)
        mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
                  if line.split()[0] == fields.get('mnt_id','').strip()]
        parent = _directory(Path(path).parent, memory=False)
        try:
            if (info.st_dev == os.fstat(parent).st_dev or stat.S_IMODE(info.st_mode) != 0o700
                    or len(mounts) != 1 or not {'rw','nosuid','nodev','noexec'} <= set(mounts[0][5].split(','))
                    or space.f_blocks * space.f_frsize != limits.bytes or space.f_files != limits.inodes):
                raise ValueError('Ciphertext volume differs from the signed storage limits')
        finally:
            os.close(parent)
        return fd
    except BaseException:
        os.close(fd)
        raise


class GuestCiphertextStorage:
    def __init__(self, source, limits):
        if not isinstance(limits, CiphertextLimits):
            raise ValueError('Require signed ciphertext limits')
        self.path = ciphertext_directory(source)
        parent = _directory(self.path.parent, memory=False)
        os.close(parent)
        enter_private_mount_namespace()
        self.path.mkdir(mode=0o700)  # Never adopt or hide an existing directory.
        self._created = True
        self._mounted = False
        try:
            options = f'size={limits.bytes},nr_inodes={limits.inodes},mode=0700,noswap'.encode()
            _call(_libc().mount(b'tmpfs',os.fsencode(self.path),b'tmpfs',2|4|8,options))
            self._mounted = True
            os.close(verify_storage(self.path,limits))
        except BaseException:
            self.close()
            raise

    def close(self):
        if not self._created:return
        if self._mounted:
            try:
                _call(_libc().umount2(os.fsencode(self.path),0))
            except OSError as error:
                raise ResourceCleanupError('Ciphertext storage did not retire; dispose of the VM') from error
            self._mounted = False
        self.path.rmdir()
        self._created = False

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class CiphertextAdmission:
    """Retain the real volume and verified input before the key-ready frame."""
    def __init__(self, source, limits, expected, deadline, cancelled, dependency=None):
        if not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected):
            raise ValueError('Require the retained encrypted package commitment')
        self.path, self.limits = ciphertext_directory(source), limits
        self.deadline, self.cancelled = deadline, cancelled
        self.directory = self.file = self.dependency_file = None
        try:
            self.directory = verify_storage(self.path,limits)
            self.file, self.identity = self._admit('workload.age', expected, limits.inputBytes)
            if dependency is not None:
                if (not isinstance(dependency,dict) or set(dependency) != {'ciphertextSHA256','ciphertextBytes'}
                        or not isinstance(dependency['ciphertextSHA256'],str) or not re.fullmatch('[0-9a-f]{64}',dependency['ciphertextSHA256'])
                        or type(dependency['ciphertextBytes']) is not int or not 1 <= dependency['ciphertextBytes'] <= limits.dependencyBytes):
                    raise ValueError('Dependency ciphertext differs from the reserved input capacity')
                self.dependency_file, self.dependency_identity = self._admit('dependency.age', dependency['ciphertextSHA256'],
                    limits.dependencyBytes, dependency['ciphertextBytes'])
            self.verify()
        except BaseException:
            self.close()
            raise

    def _admit(self, name, expected, limit, exact_bytes=None):
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o400
                    or info.st_nlink != 1 or info.st_dev != os.fstat(self.directory).st_dev
                    or not 1 <= info.st_size <= limit or exact_bytes is not None and info.st_size != exact_bytes):
                raise ValueError('Unsafe or unbounded encrypted input')
            state, count = hashlib.sha256(), 0
            while True:
                self.deadline.check(self.cancelled)
                chunk = os.read(fd,min(1024*1024,info.st_size+1-count))
                if not chunk:break
                count += len(chunk);state.update(chunk)
                if count > info.st_size:raise ValueError('Encrypted input grew during inspection')
            if count != info.st_size or state.hexdigest() != expected:
                raise ValueError('Encrypted input differs from the retained assignment')
            return fd, self._identity(info)
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

    def verify(self):
        self.deadline.check(self.cancelled)
        current = verify_storage(self.path,self.limits)
        try:
            if ((os.fstat(current).st_dev,os.fstat(current).st_ino) !=
                    (os.fstat(self.directory).st_dev,os.fstat(self.directory).st_ino)
                    or self._identity(os.fstat(self.file)) != self.identity
                    or self._identity(os.stat('workload.age',dir_fd=current,follow_symlinks=False)) != self.identity):
                raise ValueError('Admitted ciphertext storage or input changed')
            if self.dependency_file is not None and (self._identity(os.fstat(self.dependency_file)) != self.dependency_identity
                    or self._identity(os.stat('dependency.age',dir_fd=current,follow_symlinks=False)) != self.dependency_identity):
                raise ValueError('Admitted dependency ciphertext changed')
        finally:
            os.close(current)

    def close(self):
        for name in ['file','dependency_file','directory']:
            fd = getattr(self,name,None)
            if fd is not None:os.close(fd);setattr(self,name,None)
