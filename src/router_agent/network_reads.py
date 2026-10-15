"""Selected netdev(appobj) cumulative counters from asusrouter 1.21.3.

hook.py process_network_usage reads fixed hook_const.MAP_NETWORK names with
safe_int(base=16). No private/Linux interface names, timing-derived rates or
identity-discovery processing are used. uint64 is our explicit output bound;
upstream's Python conversion does not establish a firmware counter bit width.
"""
from __future__ import annotations

import re
from typing import Any

from asusrouter.modules.endpoint.hook_const import MAP_NETWORK

from .errors import RouterError

NETWORK_HOOK = 'netdev(appobj);'
_HEX = re.compile(r'(?:0[xX])?[0-9A-Fa-f]{1,16}\Z')
_MAX_COUNTER = 2**64 - 1


def _bad() -> RouterError:
    return RouterError('malformed_response', 'Native interface counters are missing or malformed.')


def _counter(value: Any) -> int | None:
    if value is None or value == '':
        return None
    if type(value) is int:
        number = value
    elif type(value) is str and _HEX.fullmatch(value):
        number = int(value, 16)
    else:
        raise _bad()
    if not 0 <= number <= _MAX_COUNTER:
        raise _bad()
    return number


def normalize_network(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get('netdev'), dict):
        raise _bad()
    counters = raw['netdev']
    rows = []
    gaps = ['cumulative_counters_are_not_rates', 'effective_egress_not_verified',
            'missing_groups_do_not_establish_hardware_absence',
            'native_groups_do_not_establish_device_routing']
    for native, label in MAP_NETWORK.items():
        rx_key, tx_key = f'{native}_rx', f'{native}_tx'
        if rx_key not in counters and tx_key not in counters:
            continue
        rx, tx = _counter(counters.get(rx_key)), _counter(counters.get(tx_key))
        if rx is None or tx is None:
            gaps.append('selected_counter_missing_or_unknown')
        rows.append({'interface': label, 'rx_bytes': rx, 'tx_bytes': tx})
    if not rows:
        gaps.append('no_named_counters_returned')
    return {'scope': 'native_cumulative_byte_counters', 'interfaces': rows, 'gaps': sorted(set(gaps))}
