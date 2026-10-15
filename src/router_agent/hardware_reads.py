"""Passive Aura read contracts from asusrouter 1.21.3; explicit DSL gap.

identity.MAP_IDENTITY detects Aura only through ledg_rgb1 + safe_exists.
Aura state keys are a selected subset of data_finder.ASUSDATA_NVRAM['aura'].
Never touch EndpointTools.AURA/set_ledg.cgi or any Aura mutation method.

DSL identity detection uses HTTP availability of ajax_AdslStatus.asp, but this
release supplies no endpoint/dsl.py reader. The separate data hook strips rate
units and substitutes zero on missing values. No DSL response adapter, hardware
absence claim or rate-unit guess is introduced here.
"""
from __future__ import annotations

import re
from typing import Any

from .errors import RouterError

AURA_CAPABILITY_HOOK = 'nvram_get(ledg_rgb1);'
AURA_HOOK = 'nvram_get(AllLED);nvram_get(ledg_night_mode);nvram_get(ledg_scheme);nvram_get(ledg_scheme_old);'
DSL_NATIVE_GAP = 'native_dsl_endpoint_reader_missing_and_rate_units_unverified'


def _bad() -> RouterError:
    return RouterError('malformed_response', 'Native Aura selected settings or capability flag are malformed.')


def normalize_aura_capability(raw: Any) -> dict[str, bool | None]:
    from asusrouter.tools.converters import safe_exists
    if not isinstance(raw, dict):
        raise _bad()
    if 'ledg_rgb1' not in raw:
        return {'aura_flag_present': None}
    value = raw['ledg_rgb1']
    if value is not None and (type(value) is not str or len(value) > 4096 or not value.isascii()):
        raise _bad()
    return {'aura_flag_present': safe_exists(value)}


def _flag(value: Any) -> bool | None:
    if value is None or value in ('', '-999', -999):
        return None
    if type(value) not in (str, int) or value not in ('0', '1', 0, 1):
        raise _bad()
    return bool(int(value))


def _code(value: Any) -> int | None:
    if value is None or value == '':
        return None
    if type(value) is int:
        result = value
    elif type(value) is str and re.fullmatch(r'-?[0-9]{1,10}', value):
        result = int(value)
    else:
        raise _bad()
    if not -(2**31) <= result < 2**31:
        raise _bad()
    return None if result == -999 else result


def normalize_aura(raw: Any) -> dict[str, Any]:
    from asusrouter.modules.aura import AsusAura, process_aura
    keys = ('AllLED', 'ledg_night_mode', 'ledg_scheme', 'ledg_scheme_old')
    if not isinstance(raw, dict) or not any(key in raw for key in keys):
        raise _bad()
    all_led = _flag(raw.get('AllLED'))
    night = _flag(raw.get('ledg_night_mode'))
    scheme = _code(raw.get('ledg_scheme'))
    previous = _code(raw.get('ledg_scheme_old'))
    # Supply only selected scalar settings to the unchanged native processor;
    # never parse RGB effects, expose its unrestricted objects or derive colors.
    native = process_aura({key: raw[key] for key in keys if key in raw})
    enabled = native['state'] if all_led is not None or scheme == 0 else None
    gaps = ['aura_marker_is_not_physical_hardware_verification', 'rgb_effects_colors_and_zones_not_collected',
            'settings_are_not_runtime_light_verification', 'no_aura_write_authorization']
    if any(value is None for value in (all_led, night, scheme, previous)):
        gaps.append('selected_aura_fields_missing_or_unknown')
    known = {state.value for state in AsusAura}
    if any(value is not None and value not in known for value in (scheme, previous)):
        gaps.append('native_scheme_code_unrecognised')
    return {'scope': 'existing_aura_settings_only', 'enabled': enabled, 'all_led_enabled': all_led,
            'night_mode_enabled': night, 'scheme_code': scheme, 'previous_scheme_code': previous,
            'gaps': sorted(set(gaps))}
