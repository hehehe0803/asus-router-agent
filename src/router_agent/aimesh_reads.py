"""AiMesh node selection from upstream onboarding.py's maintained JS reader.

No custom JavaScript parser or evaluation. The public endpoint's complete
response can contain client/configuration details; they never leave this module.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from .errors import RouterError

_MAX_RESPONSE_BYTES = 262144
_MAX_NODES = 32
_MAC = re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z')


def _bad() -> RouterError:
    return RouterError('malformed_response', 'Native AiMesh node data is missing or malformed.')


def read_onboarding_text(text: str) -> dict[str, Any]:
    """Use the exact upstream endpoint reader without changing its semantics."""
    from asusrouter.modules.endpoint.onboarding import read
    if (not isinstance(text, str) or len(text.encode('utf-8')) > _MAX_RESPONSE_BYTES
            or re.search(r'<\s*(?:!doctype|/?(?:html|head|body|form|script)\b)', text, re.I)):
        raise _bad()
    try:
        result = read(text)
    except Exception:
        raise _bad() from None
    if not isinstance(result, dict) or not result:
        raise _bad()
    return result


def validate_aimesh_shape(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, dict) or 'get_cfg_clientlist' not in raw:
        raise _bad()
    outer = raw['get_cfg_clientlist']
    # read_js_variables removes [0] suffix without evaluating JavaScript;
    # get_cfg_clientlist=[[node,...]][0] becomes a one-element outer list.
    if not isinstance(outer, list) or len(outer) != 1 or not isinstance(outer[0], list):
        raise _bad()
    nodes = outer[0]
    if len(nodes) > _MAX_NODES or any(not isinstance(n, dict) for n in nodes):
        raise _bad()
    return nodes


def _text(value: Any, firmware=False) -> str | None:
    if value is None or value == '':
        return None
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}' if firmware else r'[A-Za-z0-9_-]{1,40}', value):
        raise _bad()
    return value


def _integer(value: Any, low: int, high: int) -> int | None:
    if value is None or value == '' or value == '-999' or value == -999:
        return None
    if type(value) not in (int, str) or isinstance(value, str) and not re.fullmatch(r'-?[0-9]{1,5}', value):
        raise _bad()
    number = int(value)
    if not low <= number <= high:
        raise _bad()
    return number


def _online(value: Any) -> bool | None:
    if type(value) is bool:
        return value
    number = _integer(value, 0, 1)
    return None if number is None else bool(number)


def normalize_aimesh(raw: Any, fingerprint_key: bytes) -> dict[str, Any]:
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise RouterError('identity_key_required', 'A private identity key of at least 32 bytes is required.')
    records = validate_aimesh_shape(raw)
    gaps = ['node_state_is_not_backhaul_or_client_connectivity', 'client_inventory_and_configuration_not_collected', 'returned_record_count_is_not_satellite_count']
    nodes = []
    seen = set()
    for record in records:
        mac = record.get('mac')
        if not isinstance(mac, str) or not _MAC.fullmatch(mac) or mac.upper() in seen:
            raise _bad()
        seen.add(mac.upper())
        model = _text(record.get('ui_model_name', record.get('model_name')))
        firmware = _text(record.get('fwver'), firmware=True)
        online = _online(record.get('online'))
        level = _integer(record.get('level'), 0, 32)
        if any(value is None for value in (model, firmware, online, level)):
            gaps.append('selected_node_fields_missing_or_unknown')
        parent_connection = signal = None
        for suffix, connection in (('2g', '2ghz'), ('5g', '5ghz'), ('6g', '6ghz')):
            parent = record.get('pap' + suffix)
            if parent is None or parent == '':
                continue
            if not isinstance(parent, str) or not _MAC.fullmatch(parent):
                raise _bad()
            if parent.upper() in {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}:
                gaps.append('parent_association_unknown')
                break
            parent_connection = connection
            signal = _integer(record.get('rssi' + suffix), -150, 0)
            break
        nodes.append({'node_alias': 'node-' + hmac.new(fingerprint_key, b'node:' + mac.upper().encode(), hashlib.sha256).hexdigest()[:16],
                      'model': model, 'firmware': firmware, 'online': online, 'level': level,
                      'type': 'unknown' if level is None else ('router' if level == 0 else 'node'),
                      'parent_connection': parent_connection, 'signal_dbm': signal})
    if not records:
        gaps.append('zero_returned_nodes_does_not_establish_topology')
    return {'scope': 'returned_cfg_clientlist_records', 'nodes': sorted(nodes, key=lambda n: n['node_alias']), 'count': len(nodes), 'gaps': sorted(set(gaps))}
