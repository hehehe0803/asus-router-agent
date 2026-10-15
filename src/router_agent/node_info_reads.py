"""Minimal fixture-proven native NODE_INFO selection.

port_status.py:67-75 only passes node_info through. Pristine
rt_ax88u_merlin_388/port_status_001.content proves cd_good_to_go only; its
meaning is not documented. Never interpret the code as readiness/health.
"""
import hashlib
import hmac
import re
from typing import Any

from .errors import RouterError

NODE_INFO_PATH = '/get_port_status.cgi'


def _bad():
    return RouterError('malformed_response', 'Native selected node information is missing or malformed.')


def normalize_node_info(raw: Any, fingerprint_key: bytes):
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise RouterError('identity_key_required', 'A private identity key of at least 32 bytes is required.')
    if not isinstance(raw, dict):
        raise _bad()
    gaps = ['cd_good_to_go_semantics_unverified', 'node_info_is_not_node_or_network_health']
    if 'node_info' not in raw:
        return {'nodes': [], 'count': 0, 'gaps': [*gaps, 'node_info_not_returned']}
    info = raw['node_info']
    if not isinstance(info, dict) or len(info) > 32:
        raise _bad()
    nodes = []
    seen = set()
    for mac, fields in info.items():
        if (type(mac) is not str or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac)
                or mac.upper() in seen or not isinstance(fields, dict) or len(fields) > 128):
            raise _bad()
        mac = mac.upper(); seen.add(mac)
        value = fields.get('cd_good_to_go')
        if value is None or value == '':
            code = None
            gaps.append('cd_good_to_go_not_returned_in_some_nodes')
        elif type(value) is int:
            code = value
        elif type(value) is str and re.fullmatch(r'-?[0-9]{1,10}', value):
            code = int(value)
        else:
            raise _bad()
        if code is not None and not -(2**31) <= code < 2**31:
            raise _bad()
        if mac in {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}:
            gaps.append('native_node_identifier_is_a_placeholder')
        alias = 'node-' + hmac.new(fingerprint_key, b'node:' + mac.encode(), hashlib.sha256).hexdigest()[:16]
        nodes.append({'node_alias': alias, 'cd_good_to_go_code': code})
    if not nodes:
        gaps.append('zero_returned_records_does_not_establish_node_absence')
    return {'nodes': sorted(nodes, key=lambda row: row['node_alias']), 'count': len(nodes), 'gaps': sorted(set(gaps))}
