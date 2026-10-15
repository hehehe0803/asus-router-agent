import pytest
from router_agent.errors import RouterError
from router_agent.vpn_settings_reads import (SUPPORTED_MODEL,SUPPORTED_FIRMWARE,OPENVPN_SERVER_HOOK,WIREGUARD_SERVER_HOOK,WIREGUARD_CLIENTS_HOOK,WIREGUARD_CLIENT_KEYS,normalize_openvpn_server,normalize_wireguard_server,normalize_wireguard_clients,validate_vpn_settings_identity)

IDENTITY={'model':SUPPORTED_MODEL,'firmware':SUPPORTED_FIRMWARE,'device_fingerprint':'synthetic-fingerprint'}


def test_selected_hooks_match_native_mapping_and_never_request_credentials():
    from asusrouter.modules.data_finder import ASUSDATA_NVRAM
    from asusrouter.modules.endpoint.hook_const import MAP_OVPN_SERVER_388,MAP_WIREGUARD_SERVER,MAP_VPNC_WIREGUARD
    from asusrouter.tools.converters import safe_unpack_keys
    assert OPENVPN_SERVER_HOOK=='nvram_get(VPNServer_enable);'
    assert WIREGUARD_SERVER_HOOK=='nvram_get(wgs_enable);'
    assert WIREGUARD_CLIENTS_HOOK==''.join(f'nvram_get(wgc{i}_enable);' for i in range(1,6))
    assert 'VPNServer_enable' in {safe_unpack_keys(value)[0] for value in MAP_OVPN_SERVER_388}
    assert 'VPNServer_enable' in ASUSDATA_NVRAM['openvpn_server_388']
    assert 'wgs_enable' in {safe_unpack_keys(value)[0] for value in MAP_WIREGUARD_SERVER}
    assert 'wgs_enable' in ASUSDATA_NVRAM['wireguard_server']
    assert 'enable' in {safe_unpack_keys(value)[0] for value in MAP_VPNC_WIREGUARD}
    assert set(WIREGUARD_CLIENT_KEYS)<=set(ASUSDATA_NVRAM['vpnc'])
    combined=OPENVPN_SERVER_HOOK+WIREGUARD_SERVER_HOOK+WIREGUARD_CLIENTS_HOOK
    for private in ('priv','pub','psk','addr','clientlist','name','dns','rc_service','get_vpnc_status'):
        assert private not in combined


@pytest.mark.parametrize('value,expected',[('0',False),('1',True),(0,False),(1,True),('',None),('-999',None),(None,None)])
def test_native_enable_flags_preserve_disabled_and_unknown(value,expected):
    for fn,key in ((normalize_openvpn_server,'VPNServer_enable'),(normalize_wireguard_server,'wgs_enable')):
        result=fn({key:value},IDENTITY)
        assert result['enabled'] is expected
        assert 'enable_setting_does_not_establish_running_state' in result['gaps']
    clients=normalize_wireguard_clients({'wgc1_enable':value},IDENTITY)
    assert clients['slots'][0]=={'client_slot':1,'enabled':expected}
    assert all(slot['enabled'] is None for slot in clients['slots'][1:])


def test_missing_settings_are_unknown_not_discovery_or_health():
    for fn in (normalize_openvpn_server,normalize_wireguard_server):
        result=fn({},IDENTITY)
        assert result['enabled'] is None
        assert 'enable_setting_missing_or_unknown' in result['gaps']
    clients=normalize_wireguard_clients({},IDENTITY)
    assert len(clients['slots'])==5 and all(slot['enabled'] is None for slot in clients['slots'])
    assert 'client_slot_is_not_fusion_profile_identity' in clients['gaps']


def test_positive_selection_omits_keys_addresses_names_peers_and_running_state():
    raw={'VPNServer_enable':'1','wgs_enable':'0',**{f'wgc{i}_enable':str(i%2) for i in range(1,6)},'vpn_serverx_clientlist':'private-user-password','wgs_priv':'synthetic-private-key','wgs_pub':'synthetic-public-key','wgc1_addr':'192.0.2.1','wgc1_name':'private-profile-name','get_wgsc_status':{'connected':'private-peer'},'get_vpnc_status':'private-slot-state','vpnc_clientlist':'private-login-password'}
    outputs=[fn(raw,IDENTITY) for fn in (normalize_openvpn_server,normalize_wireguard_server,normalize_wireguard_clients)]
    for private in ('private-user-password','synthetic-private-key','synthetic-public-key','192.0.2.1','private-profile-name','private-peer','private-slot-state','private-login-password'):
        assert private not in str(outputs)
    assert 'aggregate_openvpn_and_client_settings_not_collected' in outputs[0]['gaps']
    assert 'aggregate_vpnc_and_credential_profile_lists_not_collected' in outputs[2]['gaps']
    assert [slot['enabled'] for slot in outputs[2]['slots']]==[True,False,True,False,True]


@pytest.mark.parametrize('identity',[{},None,{**IDENTITY,'model':'OTHER'},{**IDENTITY,'firmware':'3.0.0.4.388_24436'},{**IDENTITY,'firmware':'388.7_Merlin'},{**IDENTITY,'firmware':'3.0.0.4.386_1'}])
def test_conditional_routes_require_exact_reviewed_stock_target(identity):
    with pytest.raises(RouterError) as error:validate_vpn_settings_identity(identity)
    assert error.value.code=='unsupported_vpn_settings_target'
    for fn in (normalize_openvpn_server,normalize_wireguard_server,normalize_wireguard_clients):
        with pytest.raises(RouterError):fn({},identity)


@pytest.mark.parametrize('value',[True,False,'2',2,'on','secret-password',{},[],1.0])
def test_malformed_flag_values_are_sanitized(value):
    for fn,key in ((normalize_openvpn_server,'VPNServer_enable'),(normalize_wireguard_server,'wgs_enable'),(normalize_wireguard_clients,'wgc1_enable')):
        with pytest.raises(RouterError) as error:fn({key:value},IDENTITY)
        assert error.value.code=='malformed_response'
        assert 'secret-password' not in str(error.value)


def test_bad_structure_and_field_bounds_are_rejected():
    for fn in (normalize_openvpn_server,normalize_wireguard_server,normalize_wireguard_clients):
        with pytest.raises(RouterError):fn([],IDENTITY)
        with pytest.raises(RouterError):fn({f'private-{i}':None for i in range(129)},IDENTITY)
