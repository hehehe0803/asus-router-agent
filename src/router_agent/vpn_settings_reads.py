"""Exact selected VPN enable settings from pristine asusrouter 1.21.3.

Stock >388 routing: asusrouter.py async_get_identity lines 298-326.
OpenVPN setting: endpoint/hook_const.py MAP_OVPN_SERVER_388.
WG server/client settings: MAP_WIREGUARD_SERVER/MAP_VPNC_WIREGUARD and
fixed client indices 1..5 in data_finder.py. No profile/key/name/address reads.
These settings do not establish daemon state, profile association or egress.
"""
from typing import Any
from .errors import RouterError

SUPPORTED_MODEL = 'RT-AX86U'
SUPPORTED_FIRMWARE = '3.0.0.4.388_24436-ge7c0b5e'
VPN_SETTINGS_GROUPS = ('openvpn_server','wireguard_server','wireguard_clients')
OPENVPN_SERVER_HOOK = 'nvram_get(VPNServer_enable);'
WIREGUARD_SERVER_HOOK = 'nvram_get(wgs_enable);'
WIREGUARD_CLIENT_KEYS = tuple(f'wgc{index}_enable' for index in range(1,6))
WIREGUARD_CLIENTS_HOOK = ''.join(f'nvram_get({key});' for key in WIREGUARD_CLIENT_KEYS)


def validate_vpn_settings_identity(identity: Any):
    """Call before the selected hooks as well as normalization; no route guessing."""
    if (not isinstance(identity,dict) or identity.get('model')!=SUPPORTED_MODEL
            or identity.get('firmware')!=SUPPORTED_FIRMWARE):
        raise RouterError('unsupported_vpn_settings_target','Selected native VPN settings are bound to the reviewed model and firmware; other target applicability is unknown.')


def _bad():
    return RouterError('malformed_response','Native selected VPN enable settings are malformed.')


def _flag(value):
    if value is None or value in ('','-999',-999):return None
    if type(value) not in (int,str) or value not in ('0','1',0,1):raise _bad()
    return bool(int(value))


def _base(raw,identity):
    validate_vpn_settings_identity(identity)
    if not isinstance(raw,dict) or len(raw)>128:raise _bad()


def _gaps():
    return ['enable_setting_does_not_establish_running_state','profile_identity_and_peer_configuration_not_collected','route_policy_and_egress_not_verified','source_observation_time_unavailable']


def normalize_openvpn_server(raw:Any,identity:dict):
    from asusrouter.modules.endpoint.hook import process_openvpn_server
    _base(raw,identity)
    enabled=_flag(raw.get('VPNServer_enable'))
    if enabled is not None:
        # Strings preserve the upstream processor's handling of disabled zero.
        native=process_openvpn_server({'VPNServer_enable':str(int(enabled))})
        enabled=bool(int(native[1]['state']))
    gaps=_gaps()+['aggregate_openvpn_and_client_settings_not_collected']
    if enabled is None:gaps.append('enable_setting_missing_or_unknown')
    return {'scope':'selected_openvpn_server_enable_only','enabled':enabled,'gaps':gaps}


def normalize_wireguard_server(raw:Any,identity:dict):
    from asusrouter.modules.endpoint.hook import process_wireguard_server
    _base(raw,identity)
    enabled=_flag(raw.get('wgs_enable'))
    if enabled is not None:
        native=process_wireguard_server({'wgs_enable':str(int(enabled))})
        enabled=bool(int(native[1]['state']))
    gaps=_gaps()
    if enabled is None:gaps.append('enable_setting_missing_or_unknown')
    return {'scope':'selected_wireguard_server_enable_only','enabled':enabled,'gaps':gaps}


def normalize_wireguard_clients(raw:Any,identity:dict):
    from asusrouter.modules.endpoint.hook import process_vpnc_wireguard
    _base(raw,identity)
    flags={index:_flag(raw.get(key)) for index,key in enumerate(WIREGUARD_CLIENT_KEYS,1)}
    selected={WIREGUARD_CLIENT_KEYS[index-1]:str(int(flag)) for index,flag in flags.items() if flag is not None}
    native=process_vpnc_wireguard(selected)
    slots=[{'client_slot':index,'enabled':native[index]['state'] if flag is not None else None} for index,flag in flags.items()]
    gaps=_gaps()+['client_slot_is_not_fusion_profile_identity','aggregate_vpnc_and_credential_profile_lists_not_collected']
    if any(flag is None for flag in flags.values()):gaps.append('enable_setting_missing_or_unknown')
    return {'scope':'selected_wireguard_client_enable_slots_only','slots':slots,'gaps':gaps}
