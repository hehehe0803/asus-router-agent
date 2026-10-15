import asyncio
import json
import logging
import socket
from types import SimpleNamespace

from aiohttp import web
import pytest

from router_agent.errors import RouterError
from router_agent.firmware_reads import FIRMWARE_PATH
from router_agent.policy_reads import PARENTAL_HOOK, FORWARDING_HOOK
from router_agent.speedtest_reads import SPEEDTEST_HOOK, SPEEDTEST_CAPABILITY_HOOK
from urllib.parse import unquote
from router_agent.health_reads import (UPTIME_PATH, TEMPERATURE_PATH, normalize_uptime, normalize_temperature, read_uptime_text, read_temperature_text)
from router_agent.transport import GROUPS, HOOKS, RequestGuard, TransportConfig, collect_native

XML = '<devicemap><sys>uptimeStr=Sun, 19 Nov 2023 15:51:06 +0100(509356 secs since boot)</sys><wan>wan0_ipaddr=192.0.2.1</wan><vpn>password=synthetic-secret</vpn></devicemap>'
JS = 'curr_coreTmp_wl0_raw = "44&deg;C";\ncurr_coreTmp_wl1_raw = "45&deg;C";\ncurr_coreTmp_wl2_raw = "<i>disabled</i>";\ncurr_cpuTemp = "65.514";\npassword = "synthetic-secret";'


def test_native_uptime_seconds_only_no_clock_or_private_fields():
    result = normalize_uptime(read_uptime_text(XML))
    assert result['uptime_seconds'] == 509356
    assert 'router_clock_not_used_for_source_freshness' in result['gaps']
    assert 'Sun' not in json.dumps(result) and '192.0.2.1' not in json.dumps(result) and 'synthetic-secret' not in json.dumps(result)


def test_native_temperature_sensors_unchanged_reader_and_no_disabled_default():
    result = normalize_temperature(read_temperature_text(JS))
    assert result['sensors'] == [{'sensor': '2ghz', 'celsius': 44.0}, {'sensor': '5ghz', 'celsius': 45.0}, {'sensor': 'cpu', 'celsius': 65.514}]
    assert 'synthetic-secret' not in json.dumps(result)
    result = normalize_temperature(read_temperature_text('curr_cpuTemp = "0.65";'))
    assert result['sensors'] == [{'sensor': 'cpu', 'celsius': None}]
    assert 'native_sensor_value_missing_or_outside_expected_range' in result['gaps']


@pytest.mark.parametrize('text', ['<html>synthetic-secret</html>', '<!DOCTYPE devicemap [<!ENTITY x "secret">]><devicemap><sys>&x;</sys></devicemap>', '<devicemap><sys>uptimeStr=not-valid</sys></devicemap>', '<devicemap><sys>other=1</sys></devicemap>', '<devicemap><sys>uptimeStr=clock(1 secs since boot)</sys><sys>uptimeStr=clock(2 secs since boot)</sys></devicemap>', '<devicemap><sys>uptimeStr=clock(9999999999 secs since boot)</sys></devicemap>', '<devicemap><sys><nested>uptimeStr=clock(1 secs since boot)</nested></sys></devicemap>', '<devicemap>', '<wrong/>'])
def test_xml_dtd_shape_uptime_malformed_fail_closed(text):
    with pytest.raises(RouterError) as caught:
        read_uptime_text(text)
    assert caught.value.code == 'malformed_response'


@pytest.mark.parametrize('text', ['<html>secret</html>', 'curr_cpuTemp = "garbage";', 'curr_cpuTemp = "NaN";', 'curr_cpuTemp = "Infinity";', 'curr_cpuTemp = 65;', 'password = "synthetic-secret";', 'curr_cpuTemp = ', 'x' * 131073])
def test_temperature_html_missing_malformed_nonfinite_and_oversized_fail(text):
    with pytest.raises(RouterError) as caught:
        read_temperature_text(text)
    assert caught.value.code == 'malformed_response'


def test_disabled_or_empty_temperature_is_unknown_not_healthy():
    for text in ('curr_cpuTemp = "disabled";', 'curr_cpuTemp = "";'):
        result = normalize_temperature(read_temperature_text(text))
        assert result['sensors'] == []
        assert 'no_numeric_sensors_returned' in result['gaps']


async def scenario(groups=('uptime', 'temperature'), *, overrides=None, calls=None, budget=None, factory=None, hook_raw=None):
    calls = [] if calls is None else calls
    bodies = {UPTIME_PATH: XML, TEMPERATURE_PATH: JS, **(overrides or {})}
    async def handle(request):
        calls.append((request.method, request.path, request.query_string, await request.text()))
        if request.path == '/login.cgi':
            return web.json_response({'asus_token': 'synthetic-token'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            selected_hook = unquote(calls[-1][3])
            if selected_hook != 'hook=' + HOOKS['identity']:
                return web.json_response((hook_raw or {})[selected_hook])
            return web.json_response({'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436', 'label_mac': 'AA:BB:CC:DD:EE:FF'})
        if request.path in bodies:
            if bodies[request.path] == 'redirect':
                raise web.HTTPFound('http://example.invalid/secret')
            return web.Response(text=bodies[request.path])
        raise AssertionError('unreviewed endpoint')
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
        return await collect_native(cfg, 'synthetic-password', groups, fingerprint_key=b'k' * 32, router_factory=factory), calls
    finally:
        await runner.cleanup()


def test_pristine_upstream_health_exact_post_sequence_no_discovery_and_budget():
    result, calls = asyncio.run(scenario(budget=5))
    assert [(m, p, q) for m, p, q, _ in calls] == [('POST', '/login.cgi', ''), ('POST', '/appGet.cgi', ''), ('POST', UPTIME_PATH, ''), ('POST', TEMPERATURE_PATH, ''), ('POST', '/Logout.asp', '')]
    assert calls[2][3] == calls[3][3] == ''
    assert result['data']['uptime']['uptime_seconds'] == 509356
    assert result['sources']['temperature']['freshness'] == 'unknown'
    assert result['sources']['uptime']['observed_at'] is None
    assert 'synthetic-secret' not in json.dumps(result)


def test_lower_budget_rejects_before_any_login_or_partial_read():
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(budget=4, calls=calls))
    assert caught.value.code == 'request_budget'
    assert calls == []
    assert TransportConfig('example.test', 'synthetic').max_requests >= len(GROUPS) + 2


def test_global_optimistic_scaling_cannot_change_guard_or_public_parse(caplog):
    from asusrouter.config import ARConfig, ARConfigKey
    previous = ARConfig.get(ARConfigKey.OPTIMISTIC_TEMPERATURE)
    ARConfig.set(ARConfigKey.OPTIMISTIC_TEMPERATURE, True)
    caplog.set_level(logging.DEBUG)
    try:
        raw = read_temperature_text('curr_cpuTemp="0.65";')
        assert raw['cpu'] == .65
        result, _ = asyncio.run(scenario(('temperature',), overrides={TEMPERATURE_PATH: 'curr_cpuTemp="0.65";'}))
        assert result['data']['temperature']['sensors'] == [{'sensor': 'cpu', 'celsius': None}]
        assert 'rescaled' not in caplog.text
    finally:
        ARConfig.set(ARConfigKey.OPTIMISTIC_TEMPERATURE, previous)


@pytest.mark.parametrize('path,group', [(UPTIME_PATH, 'uptime'), (TEMPERATURE_PATH, 'temperature')])
@pytest.mark.parametrize('content,code', [('{"error_status":2,"password":"synthetic-secret"}', 'auth_2'), ('<html>synthetic-secret</html>', 'malformed_response'), ('redirect', 'redirect_blocked')])
def test_health_auth_html_redirect_stop_without_retry(path, group, content, code, caplog):
    calls = []
    caplog.set_level(logging.DEBUG)
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario((group,), overrides={path: content}, calls=calls))
    assert caught.value.code == code
    assert sum(p == path for _, p, _, _ in calls) == 1
    assert sum(p == '/login.cgi' for _, p, _, _ in calls) == 1
    assert 'synthetic-secret' not in caplog.text


def test_temperature_js_auth_error_checked_before_other_sensor_data():
    with pytest.raises(RouterError) as caught:
        read_temperature_text('error_status=7; curr_cpuTemp="65";')
    assert caught.value.code == 'auth_7'


@pytest.mark.parametrize('group,path', [('uptime', UPTIME_PATH), ('temperature', TEMPERATURE_PATH)])
def test_endpoint_auth_query_method_once_and_body_boundaries(group, path):
    async def run():
        cfg = TransportConfig('example.test', 'synthetic')
        params = SimpleNamespace(url='https://example.test' + path, method='POST')
        with pytest.raises(RouterError):
            await RequestGuard(cfg).start(None, None, params)
        guard = RequestGuard(cfg, **{'allow_' + group: True})
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, params)
        assert caught.value.code == 'auth_required'
        guard.authenticated = True
        for method, query in [('GET', ''), ('POST', '?x=1')]:
            with pytest.raises(RouterError):
                await guard.start(None, None, SimpleNamespace(url=params.url + query, method=method))
        await guard.start(None, None, params)
        with pytest.raises(RouterError):
            await guard.start(None, None, params)
    asyncio.run(run())


def test_health_nonempty_body_rejected_before_server():
    from asusrouter import AsusRouter
    class BodyRouter(AsusRouter):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.test_session = kwargs['session']
            self.test_url = f"http://{kwargs['hostname']}:{kwargs['port']}{UPTIME_PATH}"
        async def async_api_load(self, endpoint, request='', retry=0):
            if endpoint.value == UPTIME_PATH.lstrip('/'):
                return await self.test_session.post(self.test_url, data='forbidden')
            return await super().async_api_load(endpoint, request, retry)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(('uptime',), calls=calls, factory=BodyRouter))
    assert caught.value.code == 'read_boundary'
    assert all(path != UPTIME_PATH for _, path, _, _ in calls)


def expansion_fixture():
    return {
        'hook=' + PARENTAL_HOOK: {'MULTIFILTER_ALL': '0', 'MULTIFILTER_BLOCK_ALL': '0', 'MULTIFILTER_MAC': '', 'MULTIFILTER_MACFILTER_DAYTIME_V2': '', 'MULTIFILTER_ENABLE': ''},
        'hook=' + FORWARDING_HOOK: {'vts_enable_x': '0', 'vts_rulelist': ''},
        'hook=' + SPEEDTEST_CAPABILITY_HOOK: {'rc_support': '2.4G 5G ookla', 'ss_support': ''},
        'hook=' + SPEEDTEST_HOOK: {'ookla_state': '2', 'ookla_speedtest_get_result': [{'type': 'ping'}, {'type': 'result', 'timestamp': '2026-10-12T12:00:00+07:00', 'download': {'bandwidth': 100}, 'upload': {'bandwidth': 25.5}}, {'type': 'log'}]},
    }


def test_pristine_upstream_policy_firmware_speedtest_exact_reads_and_extra_gate_budget():
    groups = ('parental', 'forwarding', 'firmware', 'speedtest')
    firmware = 'webs_state_update="1"; webs_state_error="0"; webs_state_info="3004_388_4_0"; password="synthetic-secret";'
    result, calls = asyncio.run(scenario(groups, overrides={FIRMWARE_PATH: firmware}, hook_raw=expansion_fixture(), budget=8))
    assert [path for _, path, _, _ in calls] == ['/login.cgi', '/appGet.cgi', '/appGet.cgi', '/appGet.cgi', FIRMWARE_PATH, '/appGet.cgi', '/appGet.cgi', '/Logout.asp']
    assert [unquote(payload) for _, path, _, payload in calls if path == '/appGet.cgi'] == ['hook=' + HOOKS['identity'], 'hook=' + PARENTAL_HOOK, 'hook=' + FORWARDING_HOOK, 'hook=' + SPEEDTEST_CAPABILITY_HOOK, 'hook=' + SPEEDTEST_HOOK]
    assert calls[4][3] == ''
    assert result['data']['speedtest']['download_bps'] == 800
    assert result['data']['speedtest']['upload_bps'] == 204.0
    assert 'ookla_capability_not_discovered' not in result['data']['speedtest']['gaps']
    assert 'ookla_capability_flag_is_not_job_authorization' in result['data']['speedtest']['gaps']
    assert result['data']['parental']['enabled'] is False
    assert result['data']['forwarding']['enabled'] is False
    assert 'synthetic-secret' not in json.dumps(result)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(groups, budget=7, calls=calls))
    assert caught.value.code == 'request_budget' and calls == []


@pytest.mark.parametrize('capability,code', [({'rc_support': '2.4G 5G', 'ss_support': ''}, 'unsupported_capability'), ({'rc_support': 'ookla'}, 'malformed_response'), ({'error_status': 2}, 'auth_2')])
def test_speedtest_missing_ookla_capability_never_reads_result(capability, code):
    raw = expansion_fixture()
    raw['hook=' + SPEEDTEST_CAPABILITY_HOOK] = capability
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(('speedtest',), hook_raw=raw, calls=calls))
    assert caught.value.code == code
    assert all(unquote(payload) != 'hook=' + SPEEDTEST_HOOK for _, _, _, payload in calls)
    assert sum(path == '/login.cgi' for _, path, _, _ in calls) == 1


@pytest.mark.parametrize('text,code', [('{"error_status":10,"password":"synthetic-secret"}', 'auth_10'), ('error_status=2;webs_state_update="1";', 'auth_2'), ('<html>synthetic-secret</html>', 'malformed_response'), ('redirect', 'redirect_blocked')])
def test_firmware_guard_handles_auth_html_redirect_without_native_retry(text, code):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(('firmware',), overrides={FIRMWARE_PATH: text}, calls=calls))
    assert caught.value.code == code
    assert sum(path == FIRMWARE_PATH for _, path, _, _ in calls) == 1
    assert sum(path == '/login.cgi' for _, path, _, _ in calls) == 1


def test_firmware_endpoint_wrong_method_query_body_repeat_rejected():
    async def run():
        cfg = TransportConfig('example.test', 'synthetic')
        guard = RequestGuard(cfg, allow_firmware=True)
        guard.authenticated = True
        for method, query in [('GET', ''), ('POST', '?run=upgrade')]:
            with pytest.raises(RouterError):
                await guard.start(None, None, SimpleNamespace(url='https://example.test' + FIRMWARE_PATH + query, method=method))
        params = SimpleNamespace(url='https://example.test' + FIRMWARE_PATH, method='POST')
        await guard.start(None, None, params)
        with pytest.raises(RouterError):
            await guard.start(None, None, params)
    asyncio.run(run())
