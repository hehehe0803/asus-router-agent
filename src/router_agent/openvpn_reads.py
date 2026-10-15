"""Nonsecret legacy aggregate slots; no profile/status association claims.

Stock source: devicemap.process_ovpn. Merlin source: vpn.read. Native
availability of SYSINFO is the identity.py Merlin signal; no suffix inference.
"""
import json
from enum import IntEnum
import re
from .errors import RouterError
from .health_reads import _auth, _text

VPN_PATH = '/ajax_vpn_status.asp'


def read_openvpn_text(text):
    from asusrouter.modules.endpoint.vpn import read
    from asusrouter.tools.readers import read_js_variables
    _text(text)
    try:
        _auth(json.loads(text))
    except ValueError:
        pass
    values = read_js_variables(text)
    _auth(values)
    for key, value in values.items():
        if re.fullmatch(r'vpn_(?:client|server)[0-9]+_status', key):
            if not isinstance(value, str) or len(value) > 8192:
                raise RouterError('malformed_response', 'Native OpenVPN aggregate status is malformed.')
    try:
        return read(text)
    except Exception:
        raise RouterError('malformed_response', 'Native OpenVPN aggregate status is malformed.') from None


def normalize_openvpn(raw, *, flavor):
    if flavor not in {'stock', 'merlin'} or not isinstance(raw, dict) or len(raw) > 128:
        raise RouterError('malformed_response', 'Native OpenVPN aggregate status is malformed.')
    _auth(raw)
    rows = []
    gaps = ['slot_is_not_fusion_profile_identity', 'native_status_is_not_daemon_or_egress_verification', 'source_observation_time_unavailable']
    if flavor == 'stock':
        vpn = raw.get('vpn', {})
        if not isinstance(vpn, dict) or len(vpn) > 128:
            raise RouterError('malformed_response', 'Native OpenVPN aggregate status is malformed.')
        source = {party: {i: {'state': vpn.get(f'{party}{i}_state'), 'errno': vpn.get(f'{party}{i}_errno')} for i in range(1, limit + 1) if f'{party}{i}_state' in vpn} for party, limit in [('client', 5), ('server', 2)]}
    else:
        source = raw
    for party, limit in [('client', 10 if flavor == 'merlin' else 5), ('server', 10 if flavor == 'merlin' else 2)]:
        slots = source.get(party, {})
        if slots is None:
            slots = {}
        if not isinstance(slots, dict) or len(slots) > limit:
            raise RouterError('malformed_response', 'Native OpenVPN aggregate status is malformed.')
        for slot, record in slots.items():
            if type(slot) is not int or not 1 <= slot <= limit or not isinstance(record, dict):
                raise RouterError('malformed_response', 'Native OpenVPN aggregate status is malformed.')
            state, error = record.get('state'), record.get('errno')
            if state in (None, '', '-999', -999):
                state = None
            elif type(state) not in (str, int) and not isinstance(state, IntEnum) or str(state) not in {'-1', '0', '1', '2'}:
                raise RouterError('malformed_response', 'Native OpenVPN aggregate status is malformed.')
            else:
                state = int(state)
            if error in (None, ''):
                error = None
            elif type(error) not in (str, int) or not re.fullmatch(r'-?[0-9]{1,6}', str(error)):
                raise RouterError('malformed_response', 'Native OpenVPN aggregate status is malformed.')
            else:
                error = int(error)
            rows.append({'party': party, 'slot': slot, 'state_code': state, 'error_code': error if party == 'client' else None})
    if not rows:
        gaps.append('aggregate_slots_missing_or_empty')
    if any(row['state_code'] is None for row in rows):
        gaps.append('native_state_missing_or_unknown')
    return {'source_flavor': flavor, 'slots': rows, 'gaps': gaps}
