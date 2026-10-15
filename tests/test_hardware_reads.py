import asyncio
import importlib.util
import json
import logging
import socket
from urllib.parse import unquote

from aiohttp import web
import pytest

from router_agent.errors import RouterError
from router_agent.hardware_reads import AURA_HOOK, AURA_CAPABILITY_HOOK, DSL_NATIVE_GAP, normalize_aura, normalize_aura_capability
from router_agent.transport import HOOKS, TransportConfig, collect_native
from router_agent.vpn_settings_reads import OPENVPN_SERVER_HOOK, WIREGUARD_SERVER_HOOK, WIREGUARD_CLIENTS_HOOK

AURA = {'AllLED': '1', 'ledg_night_mode': '0', 'ledg_scheme': '2', 'ledg_scheme_old': '3', 'ledg_rgb2': 'synthetic-secret', 'password': 'synthetic-secret'}
IDENTITY = {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436-ge7c0b5e', 'label_mac': 'AA:BB:CC:DD:EE:FF'}


def test_aura_gate_matches_exact_native_identity_marker_without_claiming_hardware():
    from asusrouter.tools.converters import safe_exists
    for value in ('', None, '0', '20,0,128'):
        assert normalize_aura_capability({'ledg_rgb1': value})['aura_flag_present'] == safe_exists(value)
    assert normalize_aura_capability({})['aura_flag_present'] is None


def test_selected_aura_settings_no_rgb_or_vendor_objects():
    result = normalize_aura(AURA)
    assert result['enabled'] is True and result['all_led_enabled'] is True
    assert result['night_mode_enabled'] is False and result['scheme_code'] == 2 and result['previous_scheme_code'] == 3
    assert 'synthetic-secret' not in json.dumps(result)
    assert 'rgb_effects_colors_and_zones_not_collected' in result['gaps']
    result = normalize_aura({**AURA, 'ledg_scheme': '0'})
    assert result['enabled'] is False and result['all_led_enabled'] is True


def test_unknown_aura_settings_or_future_codes_are_not_healthy():
    result = normalize_aura({'AllLED': '', 'ledg_scheme': '-999'})
    assert result['enabled'] is None and result['scheme_code'] is None
    result = normalize_aura({**AURA, 'ledg_scheme': '42'})
    assert result['scheme_code'] == 42 and 'native_scheme_code_unrecognised' in result['gaps']


@pytest.mark.parametrize('raw', [None, {}, {'AllLED': 'secret'}, {'ledg_night_mode': True}, {'ledg_scheme': 2**31}, {'ledg_scheme': 'synthetic-secret'}])
def test_malformed_aura_selected_settings_fail(raw):
    with pytest.raises(RouterError) as caught:
        normalize_aura(raw)
    assert caught.value.code == 'malformed_response'


def test_dsl_contract_gap_is_native_reader_absence_no_adapter_or_units_guess():
    from asusrouter.modules.endpoint import Endpoint, read
    assert importlib.util.find_spec('asusrouter.modules.endpoint.dsl') is None
    assert read(Endpoint.DSL, 'dsllog_dataratedown="1234 Kbps";') == {}
    assert DSL_NATIVE_GAP == 'native_dsl_endpoint_reader_missing_and_rate_units_unverified'


async def scenario(groups=('aura',), *, capability=None, identity=None, calls=None, overrides=None, budget=None):
    calls = [] if calls is None else calls
    raw = {
        'hook=' + AURA_CAPABILITY_HOOK: {'ledg_rgb1': '20,0,128'} if capability is None else capability,
        'hook=' + AURA_HOOK: AURA,
        'hook=' + OPENVPN_SERVER_HOOK: {'VPNServer_enable': '0', 'vpn_server1_password': 'synthetic-secret'},
        'hook=' + WIREGUARD_SERVER_HOOK: {'wgs_enable': '0', 'wgs1_priv': 'synthetic-secret'},
        'hook=' + WIREGUARD_CLIENTS_HOOK: {'wgc1_enable': '1', 'wgc2_enable': '0', 'wgc3_enable': '', 'wgc4_enable': '0', 'wgc5_enable': '0', 'wgc1_priv': 'synthetic-secret'},
        **(overrides or {}),
    }
    async def handle(request):
        payload = unquote(await request.text())
        calls.append((request.method, request.path, payload))
        if request.path == '/login.cgi':
            return web.json_response({'asus_token': 'synthetic-token'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            if payload == 'hook=' + HOOKS['identity']:
                return web.json_response(identity or IDENTITY)
            return web.json_response(raw[payload])
        raise AssertionError('control or unreviewed endpoint emitted')
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    await web.SockSite(runner, sock).start()
    cfg = TransportConfig('127.0.0.1', 'synthetic-admin', use_ssl=False, allow_plain_http=True, port=port, **({'max_requests': budget} if budget is not None else {}))
    try:
        return await collect_native(cfg, 'synthetic-password', groups, fingerprint_key=b'k' * 32), calls
    finally:
        await runner.cleanup()


def test_pristine_upstream_aura_only_passive_gate_and_selected_state():
    result, calls = asyncio.run(scenario(budget=5))
    assert [path for _, path, _ in calls] == ['/login.cgi', '/appGet.cgi', '/appGet.cgi', '/appGet.cgi', '/Logout.asp']
    assert calls[2][2] == 'hook=' + AURA_CAPABILITY_HOOK and calls[3][2] == 'hook=' + AURA_HOOK
    assert result['sources']['aura']['freshness'] == 'unknown'
    assert result['data']['aura']['scheme_code'] == 2
    assert 'synthetic-secret' not in json.dumps(result)
    assert all('set_ledg' not in path for _, path, _ in calls)


@pytest.mark.parametrize('capability,code', [({}, 'capability_unknown'), ({'ledg_rgb1': ''}, 'unsupported_capability'), ({'ledg_rgb1': []}, 'malformed_response'), ({'error_status': 10}, 'auth_10')])
def test_aura_unknown_or_absent_marker_skips_settings(capability, code):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(capability=capability, calls=calls))
    assert caught.value.code == code
    assert all(payload != 'hook=' + AURA_HOOK for _, _, payload in calls)
    assert sum(path == '/login.cgi' for _, path, _ in calls) == 1


def test_aura_extra_gate_budget_fails_before_any_login():
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(budget=4, calls=calls))
    assert caught.value.code == 'request_budget' and calls == []


def test_selected_vpn_enable_settings_exact_pristine_hooks_no_private_keys():
    groups = ('openvpn_server', 'wireguard_server', 'wireguard_clients')
    result, calls = asyncio.run(scenario(groups))
    assert [payload for _, path, payload in calls if path == '/appGet.cgi'] == ['hook=' + HOOKS['identity'], 'hook=' + OPENVPN_SERVER_HOOK, 'hook=' + WIREGUARD_SERVER_HOOK, 'hook=' + WIREGUARD_CLIENTS_HOOK]
    assert result['data']['openvpn_server']['enabled'] is False
    assert result['data']['wireguard_server']['enabled'] is False
    assert result['data']['wireguard_clients']['slots'][0]['enabled'] is True
    assert result['data']['wireguard_clients']['slots'][2]['enabled'] is None
    assert 'synthetic-secret' not in json.dumps(result)
    assert all('_priv' not in payload and 'password' not in payload for _, _, payload in calls)


@pytest.mark.parametrize('group', ['openvpn_server', 'wireguard_server', 'wireguard_clients'])
def test_unreviewed_vpn_firmware_skips_settings_hook(group):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario((group,), identity={**IDENTITY, 'extendno': 'other'}, calls=calls))
    assert caught.value.code == 'unsupported_vpn_settings_target'
    assert [path for _, path, _ in calls] == ['/login.cgi', '/appGet.cgi', '/Logout.asp']


def test_aura_auth_error_stops_before_retry_and_suppresses_logs(caplog):
    calls = []
    caplog.set_level(logging.DEBUG)
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(calls=calls, overrides={'hook=' + AURA_HOOK: {'error_status': 2, 'password': 'synthetic-secret'}}))
    assert caught.value.code == 'auth_2'
    assert sum(payload == 'hook=' + AURA_HOOK for _, _, payload in calls) == 1
    assert 'synthetic-secret' not in caplog.text
