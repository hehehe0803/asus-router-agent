"""Local exact-byte custody only; never recovery authority or a secret-vault fallback.

The owner must supply an existing private directory outside a Git checkout.
Descriptor/path checks detect observed substitutions; they do not isolate a
process from another process running as the same user.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time

from .errors import RouterError

MAX_FILE = 16 * 1024 * 1024
_HEADER_LIMIT = 1024
_REF = re.compile(r'[0-9a-f]{32}\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_KIND = 'opaque_configuration'
_DOMAIN = b'router-agent:protected-file:v1\0'


def _error(code='protected_file_unavailable'):
    return RouterError(code, 'Protected file custody could not be confirmed.')


@dataclass(frozen=True, repr=False, slots=True)
class PrivateFileBinding:
    ref: str
    binding: str
    original_sha256: str
    original_bytes: int
    kind: str


class _Budget:
    def __init__(self, clock):
        self.clock, self.last = clock, None
        self.deadline = self.check() + 30

    def check(self):
        now = self.clock()
        if (type(now) not in (int, float) or not math.isfinite(now)
                or self.last is not None and now < self.last):
            raise _error('protected_file_clock')
        self.last = now
        if hasattr(self, 'deadline') and now >= self.deadline:
            raise _error('protected_file_deadline')
        return now


def _path(value):
    path = Path(value)
    if (not path.is_absolute() or '\0' in str(path) or '..' in path.parts
            or not 1 < len(path.parts) <= 64):
        raise _error('protected_file_unsafe')
    return path


def _directory_identity(info):
    # File creation changes directory times/size; bind its identity and authority.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink)


def _file_identity(info):
    return (*_directory_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise _error('protected_file_unsafe')


class _Directory:
    def __init__(self, path):
        self.path, self.fds, self.chain = _path(path), [], []

    def __enter__(self):
        try:
            root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fds.append(root)
            self._check_git(root)
            for index, name in enumerate(self.path.parts[1:]):
                parent = self.fds[-1]
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent)
                self.fds.append(fd)
                info = os.fstat(fd)
                mode = stat.S_IMODE(info.st_mode)
                shared_tmp = (index == 0 and name == 'tmp' and mode == 0o1777
                              and info.st_uid == 0)
                if ((info.st_uid not in (0, os.getuid()) or mode & 0o022)
                        and not shared_tmp):
                    raise _error('protected_file_unsafe')
                self.chain.append((parent, name, fd, _directory_identity(info)))
                self._check_git(fd)
            info = os.fstat(self.fds[-1])
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise _error('protected_file_unsafe')
            self.check()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    @staticmethod
    def _check_git(fd):
        try:
            os.stat('.git', dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise _error('protected_file_unsafe')
        # Bare repositories have no .git entry. Inspect structure only, never
        # repository content or environment-selected external Git directories.
        try:
            for name in ('HEAD', 'objects', 'refs'):
                os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise _error('protected_file_unsafe')

    @property
    def fd(self):
        return self.fds[-1]

    def check(self):
        for parent, name, fd, before in self.chain:
            if (_directory_identity(os.fstat(fd)) != before
                    or _directory_identity(os.stat(name, dir_fd=parent,
                                                   follow_symlinks=False)) != before):
                raise _error('protected_file_changed')
            self._check_git(fd)

    def __exit__(self, *args):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


@contextmanager
def _opened(directory, name, *, verify_exit=True):
    directory.check()
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=directory.fd)
    try:
        info = os.fstat(fd)
        _private_file(info)
        yield fd, info
        if verify_exit:
            _stable_file(directory, name, fd, info)
    finally:
        os.close(fd)


def _stable_file(directory, name, fd, before):
    directory.check()
    if (_file_identity(os.fstat(fd)) != _file_identity(before)
            or _file_identity(os.stat(name, dir_fd=directory.fd,
                                     follow_symlinks=False)) != _file_identity(before)):
        raise _error('protected_file_changed')


def _read(fd, before, maximum, budget):
    if not 0 < before.st_size <= maximum:
        raise _error('protected_file_size')
    chunks, count = [], 0
    while True:
        budget.check()
        chunk = os.read(fd, min(65536, maximum - count + 1))
        if not chunk:
            break
        count += len(chunk)
        if count > maximum:
            raise _error('protected_file_size')
        chunks.append(chunk)
    if count != before.st_size:
        raise _error('protected_file_changed')
    budget.check()
    return b''.join(chunks)


def _ref(value):
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise _error('protected_file_invalid')
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def _guarded(method):
    """Never expose a pathname or an exception supplied by a filesystem/clock."""
    def call(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except RouterError as exc:
            allowed = {'protected_file_unavailable', 'protected_file_unsafe',
                       'protected_file_changed', 'protected_file_invalid',
                       'protected_file_size', 'protected_file_clock',
                       'protected_file_deadline'}
            raise _error(exc.code if exc.code in allowed else 'protected_file_unavailable') from None
        except Exception:
            raise _error() from None
    return call


class ProtectedFileStore:
    @_guarded
    def __init__(self, directory, *, binding_key, clock=time.monotonic):
        if type(binding_key) is not bytes or len(binding_key) < 32 or not callable(clock):
            raise _error('protected_file_invalid')
        self._directory, self._key, self._clock = _path(directory), binding_key, clock
        with _Directory(self._directory):
            pass

    def _binding(self, metadata, payload):
        return hmac.new(self._key, _DOMAIN + _canonical(metadata) + b'\0' + payload,
                        hashlib.sha256).hexdigest()

    def _encode(self, ref, payload):
        metadata = {'version': 1, 'ref': ref, 'kind': _KIND, 'bytes': len(payload),
                    'sha256': hashlib.sha256(payload).hexdigest()}
        binding = self._binding(metadata, payload)
        return _canonical(dict(metadata, binding=binding)) + b'\n' + payload

    def _decode(self, ref, record):
        head, separator, payload = record.partition(b'\n')
        if not separator or len(head) > _HEADER_LIMIT or not 0 < len(payload) <= MAX_FILE:
            raise _error('protected_file_invalid')
        metadata = json.loads(head)
        if (type(metadata) is not dict or set(metadata) !=
                {'version', 'ref', 'kind', 'bytes', 'sha256', 'binding'}
                or _canonical(metadata) != head
                or type(metadata['version']) is not int or metadata['version'] != 1
                or metadata['ref'] != ref or metadata['kind'] != _KIND
                or type(metadata['bytes']) is not int or metadata['bytes'] != len(payload)
                or type(metadata['sha256']) is not str
                or _HASH.fullmatch(metadata['sha256']) is None
                or metadata['sha256'] != hashlib.sha256(payload).hexdigest()
                or type(metadata['binding']) is not str
                or _HASH.fullmatch(metadata['binding']) is None):
            raise _error('protected_file_invalid')
        signature = metadata.pop('binding')
        if not hmac.compare_digest(signature, self._binding(metadata, payload)):
            raise _error('protected_file_changed')
        return PrivateFileBinding(ref, signature, metadata['sha256'], len(payload), _KIND), payload

    def _load(self, directory, ref, budget):
        with _opened(directory, ref + '.artifact') as (fd, info):
            record = _read(fd, info, MAX_FILE + _HEADER_LIMIT + 1, budget)
            bound, payload = self._decode(ref, record)
            budget.check()
        return bound, payload

    def _create(self, directory, name, payload, budget):
        directory.check()
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory.fd)
        try:
            _private_file(os.fstat(fd))
            remaining = memoryview(payload)
            while remaining:
                budget.check()
                count = os.write(fd, remaining[:65536])
                if count <= 0:
                    raise _error()
                remaining = remaining[count:]
            os.fsync(fd)
            budget.check()
            before = os.fstat(fd)
            _private_file(before)
            if before.st_size != len(payload):
                raise _error('protected_file_changed')
            os.lseek(fd, 0, os.SEEK_SET)
            if _read(fd, before, len(payload), budget) != payload:
                raise _error('protected_file_changed')
            _stable_file(directory, name, fd, before)
            os.fsync(directory.fd)
            directory.check()
            _stable_file(directory, name, fd, before)
            budget.check()
        except BaseException:
            # Clean only our newly created inode, through the original parent FD.
            try:
                current = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                ours = os.fstat(fd)
                if (current.st_dev, current.st_ino) == (ours.st_dev, ours.st_ino):
                    os.unlink(name, dir_fd=directory.fd)
                    os.fsync(directory.fd)
            except OSError:
                pass
            raise
        finally:
            os.close(fd)

    @_guarded
    def ingest(self, source: Path, *, kind: str) -> PrivateFileBinding:
        if type(kind) is not str or kind != _KIND:
            raise _error('protected_file_invalid')
        source, budget = _path(source), _Budget(self._clock)
        with _Directory(source.parent) as directory:
            with _opened(directory, source.name) as (fd, info):
                payload = _read(fd, info, MAX_FILE, budget)
        ref = secrets.token_hex(16)
        record = self._encode(ref, payload)
        with _Directory(self._directory) as directory:
            self._create(directory, ref + '.artifact', record, budget)
        return self._decode(ref, record)[0]

    @_guarded
    def describe(self, ref: str) -> dict:
        ref, budget = _ref(ref), _Budget(self._clock)
        with _Directory(self._directory) as directory:
            try:
                bound, _ = self._load(directory, ref, budget)
            except FileNotFoundError:
                directory.check()
                return {'ref': ref, 'kind': _KIND, 'available': False}
        return {'ref': bound.ref, 'kind': bound.kind, 'available': True}

    @_guarded
    def read_bound(self, bound: PrivateFileBinding) -> bytes:
        if (type(bound) is not PrivateFileBinding
                or type(bound.binding) is not str or _HASH.fullmatch(bound.binding) is None
                or type(bound.original_sha256) is not str
                or _HASH.fullmatch(bound.original_sha256) is None
                or type(bound.original_bytes) is not int
                or not 0 < bound.original_bytes <= MAX_FILE
                or type(bound.kind) is not str or bound.kind != _KIND):
            raise _error('protected_file_invalid')
        ref, budget = _ref(bound.ref), _Budget(self._clock)
        with _Directory(self._directory) as directory:
            actual, payload = self._load(directory, ref, budget)
        if actual != bound:
            raise _error('protected_file_changed')
        return payload

    @_guarded
    def export_bound(self, bound: PrivateFileBinding, destination: Path) -> dict:
        # Revalidate privately before creating any destination file.
        budget = _Budget(self._clock)
        payload = self.read_bound(bound)
        budget.check()
        destination = _path(destination)
        with _Directory(destination.parent) as directory:
            self._create(directory, destination.name, payload, budget)
        return {'ref': bound.ref, 'exported': True}

    @_guarded
    def delete(self, ref: str) -> None:
        ref, budget = _ref(ref), _Budget(self._clock)
        with _Directory(self._directory) as directory:
            try:
                with _opened(directory, ref + '.artifact', verify_exit=False) as (fd, info):
                    record = _read(fd, info, MAX_FILE + _HEADER_LIMIT + 1, budget)
                    self._decode(ref, record)
                    _stable_file(directory, ref + '.artifact', fd, info)
                    budget.check()
                    os.unlink(ref + '.artifact', dir_fd=directory.fd)
                    os.fsync(directory.fd)
                    directory.check()
                    budget.check()
            except FileNotFoundError:
                directory.check()
                return
