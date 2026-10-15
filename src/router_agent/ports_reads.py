"""Selected port status fields from pristine asusrouter 1.21.3.

Public async_api_load(Endpoint.PORT_STATUS) appends node_mac=all and uses GET.
Wire/source contracts: data_finder.ASUSDATA_ENDPOINT_APPEND,
endpoint.ENDPOINT_FORCE_REQUEST, endpoint/port_status.py, modules/ports.py.
Do not use the upstream processing defaults: absent rates become zero there.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from .errors import RouterError

MAC = re.compile(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z')
PORT = re.compile(r'[A-Z][0-9]{1,2}\Z')
_MAX_NODES = 32
_MAX_PER_NODE = 64
_MAX_PORTS = 256


def _bad() -> RouterError:
    return RouterError('malformed_response', 'Native port status is missing or malformed.')


def _integer(value: Any, maximum: int) -> int | None:
    if value is None or value == '' or value == -999 or value == '-999':
        return None
    if type(value) not in (str, int) or isinstance(value, str) and not re.fullmatch(r'[0-9]{1,10}', value):
        raise _bad()
    number = int(value)
    if not 0 <= number <= maximum:
        raise _bad()
    return number


def _enabled(value: Any) -> bool | None:
    if value is None or value == '' or value == -999 or value == '-999':
        return None
    if type(value) is bool:
        return value
    if type(value) in (str, int) and value in ('0', '1', 0, 1):
        return str(value) == '1'
    raise _bad()


def normalize_ports(raw: Any, fingerprint_key: bytes) -> dict[str, Any]:
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise RouterError('identity_key_required', 'A private identity key of at least 32 bytes is required.')
    if not isinstance(raw, dict):
        raise _bad()
    info = raw.get('port_info')
    gaps = ['physical_port_state_is_not_end_to_end_connectivity', 'attached_device_details_not_collected']
    if info is None or info == {}:
        return {'ports': [], 'gaps': gaps + ['port_data_unavailable_or_unsupported']}
    if not isinstance(info, dict) or len(info) > _MAX_NODES:
        raise _bad()
    rows = []
    aliases = set()
    for mac, ports in info.items():
        if not isinstance(mac, str) or not MAC.fullmatch(mac) or not isinstance(ports, dict) or len(ports) > _MAX_PER_NODE:
            raise _bad()
        alias = 'node-' + hmac.new(fingerprint_key, b'node:' + mac.upper().encode(), hashlib.sha256).hexdigest()[:16]
        if alias in aliases:
            raise _bad()
        aliases.add(alias)
        if not ports:
            gaps.append('node_port_data_unavailable')
        for port, values in ports.items():
            if not isinstance(port, str) or not PORT.fullmatch(port) or not isinstance(values, dict):
                raise _bad()
            row = {'node_alias': alias, 'port': port, 'link_enabled': _enabled(values.get('is_on')),
                   'cap': _integer(values.get('cap'), 2**32 - 1),
                   'link_rate': _integer(values.get('link_rate'), 1_000_000),
                   'max_rate': _integer(values.get('max_rate'), 1_000_000)}
            # Upstream documents USB is_on as modem-only and consults devices
            # for other attachments. Without that private inventory, false is
            # not proof the physical USB port has no connected device.
            if row['cap'] is None:
                row['link_enabled'] = None
                gaps.append('port_type_unknown')
            elif row['cap'] & (1 << 7):
                row['link_enabled'] = None
                gaps.append('usb_presence_not_collected')
            if any(row[k] is None for k in ('link_enabled', 'cap', 'link_rate', 'max_rate')):
                gaps.append('selected_port_fields_missing_or_unknown')
            rows.append(row)
            if len(rows) > _MAX_PORTS:
                raise _bad()
    return {'ports': sorted(rows, key=lambda r: (r['node_alias'], r['port'])), 'gaps': sorted(set(gaps))}
