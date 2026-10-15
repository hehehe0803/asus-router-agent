"""Native existing Ookla result/state read; never initiate a test.

data_finder.py:79-81/241-249; hook.py:421-486 selects the penultimate result
step (not history), converts bandwidth bytes/s to bits/s. No source evidence
establishes latency units or diagnostic-job initiation here.
"""
from __future__ import annotations

from datetime import UTC
import json
import math
import re
from typing import Any

from .errors import RouterError

SPEEDTEST_HOOK = 'nvram_get(ookla_state);ookla_speedtest_get_result();'
SPEEDTEST_CAPABILITY_HOOK = 'nvram_get(rc_support);nvram_get(ss_support);'
_MAX_BYTES = 262144


def _bad():
    return RouterError('malformed_response', 'Native existing speedtest result is missing or malformed.')


def normalize_speedtest_capability(raw: Any) -> dict[str, bool]:
    """Exact native identity rc_support -> services -> ookla membership.

    identity.py:52/206-208; no endpoint discovery and no raw services output.
    """
    from asusrouter.tools.converters import safe_list_from_string
    if not isinstance(raw, dict) or not {'rc_support', 'ss_support'} <= set(raw):
        raise _bad()
    tokens = []
    for key in ('rc_support', 'ss_support'):
        value = raw[key]
        if type(value) is not str or len(value) > 4096 or not value.isascii():
            raise _bad()
        selected_tokens = [token for token in safe_list_from_string(value) if token]
        if len(selected_tokens) > 512 or any(not re.fullmatch(r'[A-Za-z0-9_.+-]{1,80}', token) for token in selected_tokens):
            raise _bad()
        tokens.extend(selected_tokens)
    return {'ookla_supported': 'ookla' in tokens}


def _state(value):
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


def _bandwidth(section):
    if section is None:
        return None
    if not isinstance(section, dict):
        raise _bad()
    value = section.get('bandwidth')
    if value is None:
        return None
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= (2**53 - 1) / 8:
        raise _bad()
    return value * 8


def _timestamp(value, gaps):
    from asusrouter.tools.converters import safe_datetime
    if value is None or value == '':
        return None, None
    if type(value) is not str or len(value) > 80:
        raise _bad()
    timestamp = safe_datetime(value)
    if timestamp is None:
        raise _bad()
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        gaps.append('result_timestamp_timezone_unavailable')
        return None, timestamp.isoformat()
    return timestamp.astimezone(UTC).isoformat(), timestamp.isoformat()


def normalize_speedtest(raw: Any) -> dict[str, Any]:
    from asusrouter.modules.endpoint.hook import process_speedtest_last_step
    if not isinstance(raw, dict) or not any(k in raw for k in ('ookla_state', 'ookla_speedtest_get_result')):
        raise _bad()
    try:
        if len(json.dumps(raw).encode('utf-8')) > _MAX_BYTES:
            raise _bad()
    except (TypeError, ValueError):
        raise _bad() from None
    state = _state(raw.get('ookla_state'))
    result = raw.get('ookla_speedtest_get_result')
    if result is None:
        result = []
    if not isinstance(result, list) or len(result) > 64 or any(not isinstance(row, dict) for row in result):
        raise _bad()
    # Unchanged native selector: only [-2] with type == result is completed.
    step = process_speedtest_last_step(result)
    gaps = ['ookla_capability_not_discovered', 'existing_result_is_not_history_or_a_new_test',
            'result_does_not_verify_current_egress', 'latency_field_and_unit_contract_unverified',
            'server_ip_location_and_identifiers_not_collected']
    download = _bandwidth(step.get('download'))
    upload = _bandwidth(step.get('upload'))
    timestamp, native_timestamp = _timestamp(step.get('timestamp'), gaps)
    if not step:
        gaps.append('no_native_completed_result_returned')
    if state is None or download is None or upload is None or timestamp is None:
        gaps.append('selected_speedtest_fields_missing_or_unknown')
    return {'scope': 'existing_speedtest_state_and_result_only', 'state_code': state,
            'native_completed_result': bool(step), 'download_bps': download, 'upload_bps': upload,
            'result_timestamp_utc': timestamp, 'result_timestamp_native': native_timestamp, 'gaps': gaps}
