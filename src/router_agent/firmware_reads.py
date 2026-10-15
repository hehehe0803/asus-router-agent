"""Existing firmware status from pinned native Endpoint.FIRMWARE.

Source: data_finder.py:213; endpoint/firmware.py read/process. A bounded
POST /detect_firmware.asp has no payload; active check/upgrade are separate
AsusSystem actions. Router-side effects/applicability still need live evidence.
"""
from __future__ import annotations

from contextvars import ContextVar
import json
import logging
import re
from typing import Any

from .errors import RouterError

FIRMWARE_PATH = '/detect_firmware.asp'
_MAX_BYTES = 65536
_CODES = {'webs_state_update': 'update_code', 'webs_state_upgrade': 'upgrade_code',
          'webs_state_error': 'error_code', 'webs_state_flag': 'flag_code', 'webs_state_level': 'level_code'}
_VERSIONS = {'webs_state_info': 'reported_stable_version', 'webs_state_info_beta': 'reported_beta_version',
             'webs_state_REQinfo': 'reported_required_version'}
_SUPPRESS = ContextVar('firmware_suppress_native_reader', default=False)


class _ReaderFilter(logging.Filter):
    def filter(self, record):
        return not _SUPPRESS.get()


def _bad():
    return RouterError('malformed_response', 'Native existing firmware status is missing or malformed.')


def _auth(raw):
    if not isinstance(raw, dict) or 'error_status' not in raw:
        return
    value = raw['error_status']
    if type(value) not in (int, str) or isinstance(value, str) and not re.fullmatch(r'[0-9]{1,3}', value):
        raise _bad()
    code = int(value)
    if code in {2, 3, 7, 9, 10, 11}:
        raise RouterError(f'auth_{code}', 'Router authentication stopped; local intervention is required.')
    if code not in {0, 200}:
        raise RouterError('native_status_failed', 'The router returned an unsuccessful native status.')


def read_firmware_text(text: str) -> dict[str, Any]:
    """Unchanged native assignment reader, guarded before vendor retries."""
    from asusrouter.modules.endpoint.firmware import read
    if (not isinstance(text, str) or not text.strip() or len(text.encode('utf-8')) > _MAX_BYTES
            or re.search(r'<\s*(?:!doctype|/?(?:html|head|body|form|script)\b)', text, re.I)):
        raise _bad()
    try:
        possible_error = json.loads(text)
    except ValueError:
        possible_error = None
    _auth(possible_error)
    if possible_error is not None:
        raise _bad()  # Successful JSON is not this endpoint's native wire format.
    logger = logging.getLogger('asusrouter.tools.readers')
    if not any(isinstance(f, _ReaderFilter) for f in logger.filters):
        logger.addFilter(_ReaderFilter())
    token = _SUPPRESS.set(True)
    try:
        raw = read(text)
    except Exception:
        raise _bad() from None
    finally:
        _SUPPRESS.reset(token)
    _auth(raw)
    validate_firmware_shape(raw)
    return raw


def _code(value):
    if value is None or value == '':
        return None
    if type(value) is int:
        number = value
    elif type(value) is str and re.fullmatch(r'-?[0-9]{1,10}', value):
        number = int(value)
    else:
        raise _bad()
    if not -(2**31) <= number < 2**31:
        raise _bad()
    return number


def _version(value):
    if value is None or value in ('', '__', '___'):
        return None
    # Positive finite version syntax, never free text or URLs. No freshness or
    # availability comparison is inferred from a stored reported version.
    if (type(value) is not str or len(value) > 80
            or not re.fullmatch(r'[39][0-9._-]*[0-9][A-Za-z0-9._-]*', value)):
        raise _bad()
    return value


def validate_firmware_shape(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or len(raw) > 128 or not any(k in raw for k in (*_CODES, *_VERSIONS)):
        raise _bad()
    _auth(raw)
    selected = {out: _code(raw.get(key)) for key, out in _CODES.items()}
    selected.update({out: _version(raw.get(key)) for key, out in _VERSIONS.items()})
    return selected


def normalize_firmware(raw: Any) -> dict[str, Any]:
    selected = validate_firmware_shape(raw)
    gaps = ['stored_firmware_status_is_not_a_new_update_check', 'status_observation_time_unavailable',
            'endpoint_applicability_and_server_side_effects_unverified', 'no_upgrade_or_recovery_authorization']
    if any(v is None for v in selected.values()):
        gaps.append('selected_firmware_fields_missing_or_unknown')
    return {'scope': 'existing_firmware_status_only', **selected, 'gaps': gaps}
