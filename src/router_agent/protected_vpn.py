"""Transient Fusion selectors and lossless, maintained-native compilation.

Private snapshots and prepared commands contain credentials. Never emit them,
log them, or persist them outside the application's vetted credential vault.
"""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
from typing import Any

from asusrouter.modules.data import AsusData, AsusDataState
from asusrouter.modules import vpnc
from asusrouter.modules.endpoint.hook import process_vpnc
from asusrouter.modules.openvpn import AsusOVPNClient
from asusrouter.modules.wireguard import AsusWireGuardClient
from .errors import RouterError

VPN_HOOK = 'nvram_get(vpnc_clientlist);nvram_get(vpnc_unit);get_vpnc_status();'
SUPPORTED_MODEL = 'RT-AX86U'
SUPPORTED_FIRMWARE = '3.0.0.4.388_24436-ge7c0b5e'
PROTOCOLS = {'OpenVPN': 'openvpn', 'WireGuard': 'wireguard', 'L2TP': 'l2tp', 'PPTP': 'pptp', 'Surfshark': 'surfshark'}


def _error(code='malformed_response'):
    return RouterError(code, 'The protected VPN configuration cannot be safely represented or recovered.')


def validate_identity(identity):
    if (not isinstance(identity, dict) or set(identity) != {'model', 'firmware', 'device_fingerprint'}
            or any(type(v) is not str or not v for v in identity.values())):
        raise _error('invalid_operation')
    if identity['model'] != SUPPORTED_MODEL or identity['firmware'] != SUPPORTED_FIRMWARE:
        raise _error('unsupported_vpn_target')


def _key(key):
    if type(key) is not bytes or len(key) < 32:
        raise _error('identity_key_required')


def _digest(key, domain, value):
    return hmac.new(key, domain + json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode(), hashlib.sha256).hexdigest()


def config_snapshot(operation, raw):
    """Configuration only: runtime tunnel status must not invalidate recovery."""
    if not isinstance(raw, dict) or type(raw.get('vpnc_clientlist')) is not str:
        raise _error()
    unit = raw.get('vpnc_unit')
    if unit is not None and (type(unit) is not str or len(unit) > 32 or any(ord(c) < 32 for c in unit)):
        raise _error()
    return {'vpnc_clientlist': raw['vpnc_clientlist'], 'vpnc_unit': unit}


def _native_representation(original):
    """Return native list plus a read-domain encoder for a narrow bijection.

    ej_nvram_get emits delimiter entities without semicolons. The maintained
    processor decodes only those two entities; encoded ampersands, quotes and
    application backslash handling have no proven lossless native contract.
    """
    encoded = '&#60' in original or '&#62' in original
    if encoded:
        if '<' in original or '>' in original or '&#60;' in original or '&#62;' in original:
            raise _error('native_serializer_loss')
        decoded = original.replace('&#62', '>').replace('&#60', '<')
    else:
        decoded = original
    if any(ord(c) < 32 or ord(c) > 126 or c in '&"\\' for c in decoded):
        raise _error('native_serializer_loss')
    def encode(value):
        return value.replace('<', '&#60').replace('>', '&#62') if encoded else value
    if encode(decoded) != original:
        raise _error('native_serializer_loss')
    return decoded, encode


@dataclass(frozen=True, repr=False)
class FusionSnapshot:
    raw_config: dict = field(repr=False)
    profiles: tuple = field(repr=False)
    fingerprint: str


def parse_snapshot(raw, key, identity):
    _key(key)
    validate_identity(identity)
    config = config_snapshot(None, raw)
    original = config['vpnc_clientlist']
    if len(original.encode()) > 32768 or any(ord(c) < 32 for c in original):
        raise _error()
    # Decode only for association, never overwrite the original representation.
    decoded = original.replace('&#62', '>').replace('&#60', '<')
    records = decoded.split('<')
    if len(records) > 129:
        raise _error()
    profiles, seen_ids, seen_pairs = [], set(), set()
    compact_index = 0
    for index, record in enumerate(records):
        if not record:
            continue
        columns = record.split('>')
        if len(columns) < 7 or len(columns) > 64 or not re.fullmatch(r'[0-9]{1,5}', columns[2]) or not re.fullmatch(r'[0-9]{1,5}', columns[6]):
            raise _error()
        protocol = PROTOCOLS.get(columns[1], 'unknown')
        native_id, fusion_id = int(columns[2]), int(columns[6])
        if native_id < 1 or fusion_id < 1 or fusion_id in seen_ids or (columns[1], native_id) in seen_pairs:
            raise _error('ambiguous_vpn_profile')
        seen_ids.add(fusion_id)
        seen_pairs.add((columns[1], native_id))
        ref = 'vpn-' + _digest(key, b'vpn-profile:', [identity, columns[1], native_id, fusion_id])[:24]
        profiles.append({'profile_ref': ref, 'protocol': protocol, 'enabled': {'0': False, '1': True}.get(columns[5]),
                         'status_code': None, 'error_code': None, 'association': 'unambiguous',
                         '_index': index, '_unit': compact_index, '_id': native_id, '_fusion_id': fusion_id})
        compact_index += 1
    status = raw.get('get_vpnc_status')
    if status not in (None, ''):
        if type(status) is not str or len(status) > 8192:
            raise _error()
        seen_status = set()
        by_id = {p['_fusion_id']: p for p in profiles}
        for record in status.split('<'):
            if not record:
                continue
            columns = record.split('>')
            if len(columns) != 3 or any(not re.fullmatch(r'-?[0-9]{1,6}', c) for c in columns):
                raise _error()
            state, error, fid = map(int, columns)
            if fid not in by_id or fid in seen_status:
                raise _error('ambiguous_vpn_profile')
            seen_status.add(fid)
            by_id[fid]['status_code'], by_id[fid]['error_code'] = state, error
    return FusionSnapshot(config, tuple(profiles), _digest(key, b'vpn-config:', [identity, config]))


def select_profiles(snapshot, protocol=None):
    if protocol not in (None, 'openvpn', 'wireguard'):
        raise _error('invalid_arguments')
    return {'profiles': [{k: v for k, v in profile.items() if not k.startswith('_')}
                         for profile in snapshot.profiles if protocol is None or profile['protocol'] == protocol],
            'association': 'unambiguous', 'status_scope': 'native_observation_only'}


async def prepare(raw, intent, key, identity):
    snapshot = parse_snapshot(raw, key, identity)
    if (not isinstance(intent, dict) or set(intent) != {'kind', 'profile_ref', 'enabled'}
            or intent['kind'] not in {'vpnc', 'openvpn_client', 'wireguard_client'}
            or type(intent['enabled']) is not bool or type(intent['profile_ref']) is not str
            or not re.fullmatch(r'vpn-[0-9a-f]{24}', intent['profile_ref'])):
        raise _error('invalid_operation')
    matches = [p for p in snapshot.profiles if p['profile_ref'] == intent['profile_ref']]
    if len(matches) != 1:
        raise _error('unknown_vpn_profile')
    selected = matches[0]
    expected_protocol = {'openvpn_client': 'openvpn', 'wireguard_client': 'wireguard'}.get(intent['kind'])
    if (selected['protocol'] == 'unknown' or expected_protocol and selected['protocol'] != expected_protocol
            or selected['enabled'] is None):
        raise _error('unsupported_vpn_profile')
    if selected['_index'] != selected['_unit']:
        raise _error('unsafe_vpn_unit')
    if snapshot.raw_config['vpnc_unit'] != str(selected['_unit']):
        raise _error('exact_recovery_unavailable')
    original = snapshot.raw_config['vpnc_clientlist']
    native_before, encode_read = _native_representation(original)
    records = native_before.split('<')
    columns = records[selected['_index']].split('>')
    columns[5] = str(int(intent['enabled']))
    records[selected['_index']] = '>'.join(columns)
    native_after = '<'.join(records)
    after = {**snapshot.raw_config, 'vpnc_clientlist': encode_read(native_after)}
    # Supplying the complete validated snapshot avoids private router-state edits.
    from .transport import _SUPPRESS_VENDOR
    suppression = _SUPPRESS_VENDOR.set(True)
    try:
        native_profiles, native_list = process_vpnc(snapshot.raw_config)
        if native_list != native_before:
            raise _error('native_serializer_loss')
        router_state = {AsusData.VPNC: AsusDataState(data=native_profiles), AsusData.VPNC_CLIENTLIST: AsusDataState(data=native_list)}
        state_type = {'vpnc': vpnc.AsusVPNC, 'openvpn_client': AsusOVPNClient, 'wireguard_client': AsusWireGuardClient}[intent['kind']]
        state = state_type.ON if intent['enabled'] else state_type.OFF
        kwargs = {'vpnc_unit': selected['_unit']} if intent['kind'] == 'vpnc' else {'id': selected['_id']}
        commands = []
        async def capture(**command):
            commands.append(command)
            return True
        success = await vpnc.set_state(capture, state, router_state=router_state, **kwargs)
    except Exception:
        raise _error('native_serializer_loss') from None
    finally:
        _SUPPRESS_VENDOR.reset(suppression)
    service = 'restart_vpnc' if intent['enabled'] else 'stop_vpnc'
    expected = {'service': service, 'arguments': {'vpnc_unit': selected['_unit'], 'vpnc_clientlist': native_after}, 'apply': True, 'expect_modify': False}
    if success is not True or commands != [expected]:
        raise _error('native_serializer_loss')
    before_public = {'profile_ref': selected['profile_ref'], 'enabled': selected['enabled']}
    after_public = {**before_public, 'enabled': intent['enabled']}
    return {'before_raw': deepcopy(snapshot.raw_config), 'after_raw': after, 'review': {'before': before_public, 'after': after_public},
            'intent': deepcopy(intent), 'side_effects': ['vpn_client_restart_or_stop', 'routing_and_lan_access_may_change'],
            'commands': commands, 'noop': snapshot.raw_config == after, 'native_state': state,
            'router_state': router_state, 'native_kwargs': kwargs}
