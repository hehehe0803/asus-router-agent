import asyncio
import inspect
from copy import deepcopy

import pytest

from router_agent.errors import RouterError
from router_agent.finite_controls import OPERATIONS, compile_native, prepare, required_keys, validate_intent

IDENTITY = {'model':'RT-AX86U', 'firmware':'3.0.0.4.388_24436-ge7c0b5e', 'device_fingerprint':'synthetic'}
CASES = [('state.port_forwarding', {'enabled':True}, 'vts_enable_x'), ('state.openvpn_server', {'enabled':True}, 'VPNServer_enable'), ('state.wireguard_server', {'enabled':True}, 'wgs_enable'), ('state.wlan', {'target':'radio0','enabled':True}, 'wl0_radio'), ('state.wlan', {'target':'radio1','enabled':True}, 'wl1_radio'), ('state.wlan', {'target':'guest0.1','enabled':True}, 'wl0.1_bss_enabled'), ('state.wlan', {'target':'guest1.3','enabled':True}, 'wl1.3_bss_enabled')]


def fixture(operation, intent):
    raw = dict.fromkeys(required_keys(operation, intent), '')
    for key in raw:
        if key.endswith(('_radio', '_bss_enabled', '_expire', '_expire_tmp')) or key in {'vts_enable_x','VPNServer_enable','wgs_enable'}:
            raw[key] = '0'
    if operation == 'state.openvpn_server':raw['vpn_server_unit'] = '1'
    if operation == 'state.wireguard_server':raw['wgs_unit'] = '1'
    if operation == 'state.port_forwarding':raw['vts_rulelist'] = '&#60private-name&#62unknown&#62future&#62columns'
    raw['future_setting'] = 'private-preserved-sentinel'
    return raw


@pytest.mark.parametrize('operation,intent,flag', CASES)
def test_compilers_and_exact_inverse(operation, intent, flag):
    raw = fixture(operation, intent)
    before = deepcopy(raw)
    result = asyncio.run(prepare(operation, raw, intent, identity=IDENTITY))
    assert result.before == before and raw == before
    assert result.after == {**before, flag:'1'}
    assert 'private-preserved' not in str(result.review)
    assert 'private-preserved' not in repr(result)
    reverse = asyncio.run(prepare(operation, result.after, {**intent,'enabled':False}, identity=IDENTITY))
    assert reverse.after == before
    assert asyncio.run(prepare(operation, before, {**intent,'enabled':False})).noop


@pytest.mark.parametrize('operation,intent,service,args', [
    ('state.port_forwarding', {'enabled':True}, 'restart_firewall', {'vts_enable_x':1}),
    ('state.openvpn_server', {'enabled':True}, 'restart_openvpnd;restart_chpass;restart_samba;restart_dnsmasq;', {'id':1,'VPNServer_enable':'1'}),
    ('state.openvpn_server', {'enabled':False}, 'stop_openvpnd;restart_samba;restart_dnsmasq;', {'id':1,'VPNServer_enable':'0'}),
    ('state.wireguard_server', {'enabled':True}, 'restart_wgs;restart_dnsmasq', {'id':1,'wgs_enable':1,'wgs_unit':1}),
    ('state.wireguard_server', {'enabled':False}, 'restart_wgs;restart_dnsmasq', {'id':1,'wgs_enable':0,'wgs_unit':1}),
    ('state.wlan', {'target':'guest0.1','enabled':True}, 'restart_wireless;restart_firewall', {'wl0.1_bss_enabled':1,'wl0.1_expire':0}),
    ('state.wlan', {'target':'guest0.1','enabled':False}, 'restart_wireless;restart_firewall', {'wl0.1_bss_enabled':0}),
])
def test_exact_maintained_command(operation,intent,service,args):
    result = asyncio.run(prepare(operation,fixture(operation,intent),intent))
    assert result.service == service and result.arguments == args


@pytest.mark.parametrize('enabled',[True,False])
@pytest.mark.parametrize('key',['wl0.1_expire','wl0.1_expire_tmp'])
@pytest.mark.parametrize('expiry',['3600','','unknown'])
def test_guest_rejects_both_inverse_directions(enabled,key,expiry):
    intent = {'target':'guest0.1','enabled':enabled}
    raw = fixture('state.wlan',intent);raw[key] = expiry
    with pytest.raises(RouterError, match='expiry'):
        asyncio.run(prepare('state.wlan',raw,intent))


def test_unknown_and_missing_settings_rejected():
    for operation,intent,flag in CASES:
        raw = fixture(operation,intent);raw[flag] = ''
        with pytest.raises(RouterError):asyncio.run(prepare(operation,raw,intent))
        del raw[flag]
        with pytest.raises(RouterError):asyncio.run(prepare(operation,raw,intent))


@pytest.mark.parametrize('intent',[{'target':'radio2','enabled':True},{'target':'guest0.4','enabled':False},{'target':'radio0','enabled':1},{'enabled':True,'id':2}])
def test_finite_intents(intent):
    with pytest.raises(RouterError):validate_intent('state.wlan',intent)


def test_aura_missing_auxiliary_inputs_keeps_unproven_recovery_gated():
    from asusrouter.modules import aura
    source = inspect.getsource(aura.set_state)
    assert '"ledg_scheme"' in source and '"ledg_rgb"' in source
    assert 'ledg_scheme_old' not in source and 'ledg_night_mode' not in source
    raw = fixture('state.aura',None)
    raw.update({'ledg_scheme':'2','ledg_scheme_old':'3','ledg_rgb2':'1,2,3'})
    for intent in [{'effect':'off'},{'effect':'static','color':[1,2,3],'brightness':50,'zone':0}]:
        with pytest.raises(RouterError) as exc:asyncio.run(prepare('state.aura',raw,intent))
        assert exc.value.code == 'exact_recovery_unavailable'


@pytest.mark.parametrize('enabled',[True,False])
@pytest.mark.parametrize('unit',['','0','2','unknown'])
def test_wireguard_auxiliary_unit_must_already_be_exact_server_one(enabled,unit):
    intent={'enabled':enabled}
    raw=fixture('state.wireguard_server',intent);raw['wgs_unit']=unit
    with pytest.raises(RouterError) as exc:
        asyncio.run(prepare('state.wireguard_server',raw,intent))
    assert exc.value.code=='unsupported_operation'


def test_wireguard_unit_is_source_backed_bound_and_preserved():
    from asusrouter.modules import wireguard
    from router_agent.finite_controls import settings_hook
    source=inspect.getsource(wireguard.set_state)
    assert 'f"{wg_unit}_unit": wlan_id' in source
    assert settings_hook('state.wireguard_server').endswith('nvram_get(wgs_unit);')
    raw=fixture('state.wireguard_server',{'enabled':True})
    result=asyncio.run(prepare('state.wireguard_server',raw,{'enabled':True}))
    assert result.before['wgs_unit']==result.after['wgs_unit']=='1'
    del raw['wgs_unit']
    with pytest.raises(RouterError):asyncio.run(prepare('state.wireguard_server',raw,{'enabled':True}))
