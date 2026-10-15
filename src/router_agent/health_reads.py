"""Selected health values via unchanged asusrouter 1.21.3 readers.

DEVICEMAP: native XML reader and read_uptime_string; router clock is discarded.
TEMPERATURE: native temperature reader, with optimistic rescaling disabled.
No native data-discovery, boot-time history, reboot flag or LED keep-state calls.
"""
from __future__ import annotations

import json
import math
import re
from typing import Any

from .errors import RouterError

UPTIME_PATH = '/ajax_status.xml'
TEMPERATURE_PATH = '/ajax_coretmp.asp'
_MAX_BYTES = 131072
_TEMP_KEYS = frozenset(['curr_cpuTemp', 'curr_coreTmp_cpu'] +
                      [f'curr_coreTmp_{part}_raw' for part in ('2', '5', '52', '0', '1', '3', 'wl0', 'wl1', 'wl2', 'wl3')])


def _bad() -> RouterError:
    return RouterError('malformed_response', 'Native selected health data is missing or malformed.')


def _auth(raw: Any) -> None:
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


def _text(text: str) -> None:
    if (not isinstance(text, str) or not text.strip() or len(text.encode()) > _MAX_BYTES
            or re.search(r'<\s*(?:!doctype|!entity|/?(?:html|head|body|form|script)\b)', text, re.I)):
        raise _bad()
    try:
        _auth(json.loads(text))
    except (ValueError, TypeError):
        pass


def read_uptime_text(text: str) -> dict[str, Any]:
    import xmltodict
    from asusrouter.modules.endpoint.devicemap import read
    _text(text)
    try:
        tree = xmltodict.parse(text, disable_entities=True)
    except Exception:
        raise _bad() from None
    if not isinstance(tree, dict) or set(tree) != {'devicemap'} or not isinstance(tree['devicemap'], dict):
        raise _bad()
    root = tree['devicemap']
    _auth(root)
    if len(root) > 128:
        raise _bad()
    count = 0
    for value in root.values():
        items = value if isinstance(value, list) else [value]
        count += len(items)
        if count > 1024 or any(item is not None and not isinstance(item, str) for item in items):
            raise _bad()
    selected = root.get('sys')
    entries = selected if isinstance(selected, list) else [selected]
    if sum(isinstance(item, str) and item.startswith('uptimeStr=') for item in entries) != 1:
        raise _bad()
    try:
        raw = read(text)
        normalize_uptime(raw)
    except RouterError:
        raise
    except Exception:
        raise _bad() from None
    return raw


def normalize_uptime(raw: Any) -> dict[str, Any]:
    from asusrouter.modules.endpoint.devicemap import read_uptime_string
    if not isinstance(raw, dict) or not isinstance(raw.get('sys'), dict):
        raise _bad()
    value = raw['sys'].get('uptimeStr')
    # Validate the selected scalar's literal seconds unit before using the
    # maintained converter; do not substitute the router's clock for freshness.
    if not isinstance(value, str) or not re.fullmatch(r'[^()\r\n]{1,96}\([0-9]{1,10} secs since boot\)', value):
        raise _bad()
    try:
        _, seconds = read_uptime_string(value)
    except Exception:
        raise _bad() from None
    if type(seconds) is not int or not 0 <= seconds <= 2**32 - 1:
        raise _bad()
    return {'uptime_seconds': seconds, 'gaps': ['router_clock_not_used_for_source_freshness', 'uptime_does_not_establish_router_or_network_health']}


def read_temperature_text(text: str) -> dict[str, Any]:
    from asusrouter.config import ARConfigKey, ARInstanceConfig
    from asusrouter.modules.endpoint.temperature import read
    from asusrouter.tools.readers import read_js_variables
    _text(text)
    try:
        variables = read_js_variables(text)
    except Exception:
        raise _bad() from None
    _auth(variables)
    selected = _TEMP_KEYS.intersection(variables)
    if not selected:
        raise _bad()
    if any(type(variables[key]) is not str or len(variables[key]) > 80 for key in selected):
        raise _bad()
    # Missing/disabled are unknown. Other unparseable selected values are
    # malformed, rather than accepting native safe_float's silent None fallback.
    for key in selected:
        value = variables[key]
        if value == '' or 'disabled' in value:
            continue
        if not re.fullmatch(r'-?[0-9]{1,6}(?:\.[0-9]{1,9})?(?:&deg;C)?', value):
            raise _bad()
    config = ARInstanceConfig(defaults={ARConfigKey.OPTIMISTIC_TEMPERATURE: False})
    try:
        raw = read(text, config=config)
        normalize_temperature(raw)
    except RouterError:
        raise
    except Exception:
        raise _bad() from None
    return raw


def normalize_temperature(raw: Any) -> dict[str, Any]:
    from asusrouter.modules.endpoint.temperature import EXPECTED_TEMPERATURE_MIN, EXPECTED_TEMPERATURE_MAX
    from asusrouter.modules.wlan import Wlan
    if not isinstance(raw, dict):
        raise _bad()
    allowed = {Wlan.FREQ_2G: '2ghz', Wlan.FREQ_5G: '5ghz', Wlan.FREQ_5G2: '5ghz2', Wlan.FREQ_6G: '6ghz', 'cpu': 'cpu'}
    sensors = []
    gaps = ['temperature_is_not_thermal_health_verification', 'missing_sensor_does_not_establish_hardware_absence', 'optimistic_temperature_scaling_disabled']
    for key, label in allowed.items():
        if key not in raw:
            continue
        value = raw[key]
        if value is not None and (type(value) not in (int, float) or not math.isfinite(value)):
            raise _bad()
        if value is None or not EXPECTED_TEMPERATURE_MIN <= value <= EXPECTED_TEMPERATURE_MAX:
            value = None
            gaps.append('native_sensor_value_missing_or_outside_expected_range')
        sensors.append({'sensor': label, 'celsius': value})
    if not sensors:
        gaps.append('no_numeric_sensors_returned')
    return {'sensors': sensors, 'gaps': sorted(set(gaps))}
