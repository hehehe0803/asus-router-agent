"""Read user-admin issued grants; this module never creates approval authority.

The fixed root-owned directory is the trust anchor. The agent must run without
root privileges or unrestricted sudo access. Plan hashes provide integrity,
not authority; only a separately issued protected grant authorizes its scope.
"""
import json
import math
import os
import re
import stat
import time

from .catalog import canonical
from .errors import RouterError
from .operations import ApprovedScope

AUTHORITY_DIRECTORY = '/etc/asus-router-agent/approvals'
GRANT_KEYS = {'schema_version', 'plan_hash', 'device', 'operation', 'after_json', 'issued_at', 'expires_at'}


def approval_request(plan):
    """Public request for an administrator to inspect; never an approval."""
    data = plan.data
    return {'schema_version': 1, 'plan_hash': plan.id, 'device': data['device'],
            'operation': data['operation'], 'after_json': canonical(data['after']),
            'issued_at': data['created_at'], 'expires_at': data['expires_at']}


def _unsafe():
    return RouterError('approval_authority_unsafe', 'Approval authority must be protected and owned by a separate root administrator.')


def _check_owner(info, *, directory):
    if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise _unsafe()
    if not directory and (info.st_nlink != 1 or not 0 < info.st_size <= 16384):
        raise _unsafe()


def _read_grant(window_id):
    if os.geteuid() == 0:
        raise _unsafe()
    descriptor = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open('/', flags)
        _check_owner(os.fstat(descriptor), directory=True)
        for component in AUTHORITY_DIRECTORY.strip('/').split('/'):
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            _check_owner(os.fstat(descriptor), directory=True)
        leaf = os.open(window_id + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            _check_owner(os.fstat(leaf), directory=False)
            raw = os.read(leaf, 16385)
            if len(raw) > 16384:
                raise _unsafe()
            return json.loads(raw)
        finally:
            os.close(leaf)
    except FileNotFoundError:
        raise RouterError('approval_window_required', 'A separately issued administrator approval window is required.') from None
    except (OSError, UnicodeError, ValueError):
        raise _unsafe() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def validate_window(plan, window_id, *, clock=time.time):
    if not isinstance(window_id, str) or not re.fullmatch('[0-9a-f]{64}', window_id) or window_id != plan.id:
        raise RouterError('approval_window_required', 'Provide the exact plan-bound approval window reference.')
    grant = _read_grant(window_id)
    request = approval_request(plan)
    if not isinstance(grant, dict) or set(grant) != GRANT_KEYS or type(grant['schema_version']) is not int or grant['schema_version'] != 1:
        raise _unsafe()
    if any(grant[key] != request[key] for key in ('plan_hash', 'device', 'operation', 'after_json')):
        raise RouterError('approval_scope_mismatch', 'Administrator approval does not match the exact plan scope.')
    if any(type(grant[key]) not in (int, float) or not math.isfinite(grant[key]) for key in ('issued_at', 'expires_at')):
        raise _unsafe()
    now = clock()
    if not plan.data['created_at'] <= grant['issued_at'] <= now < grant['expires_at'] <= plan.data['expires_at']:
        raise RouterError('approval_window_expired', 'Administrator approval window is expired or not yet valid.')
    return ApprovedScope(plan.id, grant['device'], grant['operation'], grant['after_json'], grant['expires_at'], window_id)
