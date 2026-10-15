"""Typed native diagnostic traffic reads with fresh private alias resolution.

Source: traffic.py:35-46/58-64/230-268, native test_traffic.py:457-482.
Private endpoint/query generation delegates to maintained typed get_state;
unknown raw translated fields never enter selected output.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import re
from typing import Any

from .aimesh_reads import validate_aimesh_shape
from .errors import RouterError

_METRICS = {'data_rx':'rx_bps', 'data_tx':'tx_bps', 'data_avg_rx':'rx_avg_bps',
            'data_avg_tx':'tx_avg_bps', 'phy_rx':'phy_rx_bps', 'phy_tx':'phy_tx_bps'}
_NATIVE_OUTPUT = {'data_rx':'rx_speed', 'data_tx':'tx_speed', 'data_avg_rx':'rx_speed_avg',
                  'data_avg_tx':'tx_speed_avg', 'phy_rx':'phy_rx', 'phy_tx':'phy_tx'}
_ALIAS = re.compile(r'node-[0-9a-f]{16}\Z')
_MAC = re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z')


@dataclass(frozen=True)
class PreparedTrafficRead:
    kind: str
    node_alias: str
    peer_alias: str | None
    band: str | None
    backhaul: bool
    endpoint: Any = field(repr=False)
    request: str = field(repr=False)


def _bad():
    return RouterError('malformed_response', 'Native selected traffic rates are missing or malformed.')


def _target_error():
    return RouterError('traffic_target_unavailable', 'The requested native traffic alias or band is unavailable in the fresh node inventory.')


def _mac(value):
    if type(value) is not str or not _MAC.fullmatch(value) or value.upper() in {'00:00:00:00:00:00','FF:FF:FF:FF:FF:FF'}:
        raise _target_error()
    return value.upper()


async def prepare_traffic_request(kind: str, node_alias: str, raw_onboarding: Any,
                                  fingerprint_key: bytes, *, peer_alias=None, band=None, backhaul=False):
    """Prepare exact native request without network calls or raw MAC arguments."""
    from asusrouter.modules.traffic import ARTrafficSourceEthernet, ARTrafficSourceWiFi, ARTrafficSourceBackhaul, get_state
    # Public alias grammar is distinct from all vendor wire identifiers.
    if (kind not in {'ethernet','wifi','backhaul'} or type(node_alias) is not str or not _ALIAS.fullmatch(node_alias)
            or type(backhaul) is not bool):
        raise _target_error()
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise RouterError('identity_key_required', 'A private identity key of at least 32 bytes is required.')
    records = validate_aimesh_shape(raw_onboarding)
    by_alias = {}
    seen = set()
    for record in records:
        raw_mac = record.get('mac')
        if type(raw_mac) is not str or not _MAC.fullmatch(raw_mac) or raw_mac.upper() in seen:
            raise _target_error()
        seen.add(raw_mac.upper())
        alias = 'node-' + hmac.new(fingerprint_key, b'node:' + raw_mac.upper().encode(), hashlib.sha256).hexdigest()[:16]
        by_alias[alias] = record
    if node_alias not in by_alias:
        raise _target_error()
    record = by_alias[node_alias]
    target = _mac(record.get('mac'))
    if kind == 'ethernet':
        if peer_alias is not None or band is not None:
            raise _target_error()
        source = ARTrafficSourceEthernet(target, bh_flag=backhaul)
    elif kind == 'wifi':
        if peer_alias is not None or backhaul or band not in {'2ghz','5ghz','5ghz2','6ghz'}:
            raise _target_error()
        # Exact upstream onboarding.CONST_AP mapping and source fixture fields.
        field_name = {'2ghz':'ap2g','5ghz':'ap5g','5ghz2':'ap5g1','6ghz':'ap6g'}[band]
        source = ARTrafficSourceWiFi(target, towards=_mac(record.get(field_name)))
    else:
        if band is not None or backhaul or type(peer_alias) is not str or not _ALIAS.fullmatch(peer_alias) or peer_alias == node_alias or peer_alias not in by_alias:
            raise _target_error()
        # Caller selects two observed node aliases; adjacency is not inferred.
        source = ARTrafficSourceBackhaul(target, towards=_mac(by_alias[peer_alias].get('mac')))
    captured = []
    async def capture(*, endpoint, request):
        captured.append((endpoint, request))
        return None
    await get_state(capture, source)
    if len(captured) != 1:
        raise _target_error()
    endpoint, request = captured[0]
    return PreparedTrafficRead(kind, node_alias, peer_alias, band, backhaul, endpoint, request)


def _bound(raw, depth=0, count=None):
    if count is None:
        count = [0]
    if not isinstance(raw, dict) or depth > 4 or len(raw) > 128:
        raise _bad()
    for value in raw.values():
        count[0] += 1
        if count[0] > 512:
            raise _bad()
        if isinstance(value, dict):
            _bound(value, depth+1, count)


def _number(value):
    if value is None or value == '':
        return None
    if type(value) not in (int,float,str):
        raise _bad()
    if type(value) is str and (len(value)>48 or not re.fullmatch(r'(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?',value)):
        raise _bad()
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= 1e12:
        raise _bad()
    return number


def normalize_traffic(raw: Any, prepared: PreparedTrafficRead):
    from asusrouter.modules.traffic import translate_state
    from asusrouter.tools.converters import flatten_dict
    if not isinstance(prepared, PreparedTrafficRead):
        raise _bad()
    _bound(raw)
    if any(key in raw and isinstance(raw[key], (dict,list)) for key in _METRICS):
        raise _bad()
    try:
        if len(json.dumps(raw).encode()) > 65536:
            raise _bad()
    except (TypeError,ValueError):
        raise _bad() from None
    flat = flatten_dict(raw) or {}
    selected = {}
    missing = set()
    for native in _METRICS:
        number = _number(flat.get(native))
        if number is None:
            missing.add(native)
        else:
            selected[native] = number
    value = flat.get('error_status')
    if value is None:
        status_code = None
    elif type(value) in (int,str) and (type(value) is int or re.fullmatch(r'[0-9]{1,3}',value)):
        status_code = int(value)
        if status_code in {2,3,7,9,10,11}:
            raise RouterError(f'auth_{status_code}', 'Router authentication stopped; local intervention is required.')
        if status_code not in {0,200}:
            raise RouterError('native_status_failed','The router returned an unsuccessful native status.')
    else:
        raise _bad()
    translated = translate_state(selected)
    output = {out: None if native in missing else translated[_NATIVE_OUTPUT[native]] for native,out in _METRICS.items()}
    gaps = ['native_rates_are_not_throughput_or_egress_verification','observation_window_and_source_time_unavailable',
            'target_pair_does_not_establish_mesh_adjacency','unrecognised_vendor_fields_not_collected']
    if missing:
        gaps.append('selected_rate_fields_missing_or_unknown')
    if status_code is None:
        gaps.append('native_status_code_not_returned')
    return {'scope':'selected_native_diagnostic_rates','kind':prepared.kind,'node_alias':prepared.node_alias,
            'peer_alias':prepared.peer_alias,'band':prepared.band,'backhaul':prepared.backhaul,
            'status_code':status_code,**output,'gaps':gaps}
