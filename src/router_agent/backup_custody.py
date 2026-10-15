"""Read-only bounded artifact observations; never a production backup provider."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

ROLES = ('original', 'roundtrip', 'encrypted')
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 48 * 1024 * 1024


class CustodyError(ValueError):
    pass


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_pinned(path):
    """Pin every ancestor; O_NONBLOCK prevents FIFO open from blocking."""
    path = Path(path)
    if not path.is_absolute() or '\x00' in str(path) or '..' in path.parts or len(path.parts) > 64:
        raise CustodyError('unsafe_path')
    chain = []
    root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fds = [root]
    try:
        for name in path.parts[1:-1]:
            parent = fds[-1]
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(fd)
            info = os.fstat(fd)
            mode = stat.S_IMODE(info.st_mode)
            safe_shared = (parent == root and name == 'tmp' and mode == 0o1777
                           and info.st_uid == 0)
            if (info.st_uid not in (0, os.getuid()) or mode & 0o022) and not safe_shared:
                raise CustodyError('unsafe_ancestor')
            chain.append((parent, name, fd, _identity(info)))
        directory = os.fstat(fds[-1])
        if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) != 0o700:
            raise CustodyError('unsafe_directory')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        fds.append(fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise CustodyError('unsafe_file')
        chain.append((fds[-2], path.name, fd, _identity(info)))
        return fd, info, chain, fds
    except BaseException:
        for fd in reversed(fds):os.close(fd)
        raise


def _stable(chain):
    for parent, name, fd, before in chain:
        if (_identity(os.fstat(fd)) != before or
                _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before):
            raise CustodyError('changed_during_read')


def _read(path, *, maximum, deadline, clock, read_chunk, total):
    fd, info, chain, fds = _open_pinned(path)
    try:
        if info.st_size == 0:raise CustodyError('empty_file')
        if info.st_size > maximum:raise CustodyError('oversize')
        digest, count = hashlib.sha256(), 0
        while True:
            if clock() >= deadline:raise CustodyError('deadline')
            chunk = read_chunk(fd, min(65536, maximum - count + 1))
            if not chunk:break
            count += len(chunk);total[0] += len(chunk)
            if count > maximum or total[0] > MAX_TOTAL:raise CustodyError('oversize')
            digest.update(chunk)
        if count != info.st_size:raise CustodyError('changed_during_read')
        _stable(chain)
        if clock() >= deadline:raise CustodyError('deadline')
        return digest.hexdigest()
    finally:
        for opened in reversed(fds):os.close(opened)


def load_private_manifest(path):
    """Read a small explicit private manifest, without searching or repairing."""
    fd, info, chain, fds = _open_pinned(path)
    try:
        if info.st_size > 32768:raise CustodyError('invalid_manifest')
        data = os.read(fd, 32769)
        if len(data) != info.st_size:raise CustodyError('invalid_manifest')
        _stable(chain)
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise CustodyError('invalid_manifest') from None
    finally:
        for opened in reversed(fds):os.close(opened)


def inspect_custody(manifest, *, clock=time.monotonic, read_chunk=os.read):
    """Manifest is {role: {'path': absolute, 'expected_sha256': optional}}.

    Expected hashes and manifests are private observations, not origin authority.
    """
    result = {'mode': 'custody_observation', 'production_admission_verified': False,
              'authenticated_origin_verified': False, 'roles': []}
    if (not isinstance(manifest, dict) or not 1 <= len(manifest) <= 3
            or not set(manifest) <= set(ROLES)):
        return dict(result, outcome='failed', reason='invalid_manifest')
    for entry in manifest.values():
        if (not isinstance(entry, dict) or not set(entry) <= {'path', 'expected_sha256'}
                or not isinstance(entry.get('path'), str)
                or ('expected_sha256' in entry and not isinstance(entry['expected_sha256'], str))
                or ('expected_sha256' in entry and re.fullmatch('[a-f0-9]{64}', entry['expected_sha256']) is None)):
            return dict(result, outcome='failed', reason='invalid_manifest')
    last = [None]
    def checked_clock():
        now = clock()
        if type(now) not in (int,float) or not math.isfinite(now) or last[0] is not None and now < last[0]:
            raise CustodyError('clock_failure')
        last[0] = now
        return now
    try:deadline = checked_clock() + 30
    except Exception:return dict(result,outcome='failed',reason='clock_failure')
    total, digests = [0], {}
    for role in ROLES:
        if role not in manifest:continue
        entry = manifest[role]
        row = {'role': role, 'available': False, 'stable_integrity_observed': False,
               'expected_digest_supplied': 'expected_sha256' in entry, 'expected_digest_matches': None}
        try:
            digest = _read(entry['path'], maximum=MAX_FILE, deadline=deadline,
                           clock=checked_clock, read_chunk=read_chunk, total=total)
            digests[role] = digest
            row.update(available=True, stable_integrity_observed=True, outcome='passed', reason='stable_read')
            if 'expected_sha256' in entry:
                row['expected_digest_matches'] = digest == entry['expected_sha256']
                if not row['expected_digest_matches']:row.update(outcome='failed', reason='digest_mismatch')
        except CustodyError as exc:
            row.update(outcome='failed', reason=str(exc))
        except FileNotFoundError:
            row.update(outcome='unavailable_target', reason='missing')
        except (OSError,ValueError):
            row.update(outcome='failed', reason='unsafe_or_unreadable')
        except Exception:
            row.update(outcome='failed', reason='read_failure')
        result['roles'].append(row)
    result['original_roundtrip_equal'] = digests['original']==digests['roundtrip'] if {'original','roundtrip'} <= digests.keys() else None
    result['outcome'] = 'passed' if all(r['outcome'] == 'passed' for r in result['roles']) else 'failed'
    return result
