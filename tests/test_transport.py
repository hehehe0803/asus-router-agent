import asyncio
import json
import logging
from types import SimpleNamespace
from urllib.parse import unquote

import aiohttp
from aiohttp import web
import pytest

from router_agent.errors import RouterError
from router_agent.speedtest_reads import SPEEDTEST_CAPABILITY_HOOK
from router_agent.hardware_reads import AURA_CAPABILITY_HOOK
from router_agent.transport import GROUPS, HOOKS, RequestGuard, TransportConfig, collect_native, probe_auth

KEY = b'k' * 32
RAW = {
    'dsl': {'dsllog_dataratedown': '0 kbps', 'dsllog_datarateup': None},
    'firmware_note': {'release_note': 'Synthetic release note.', 'release_note_raw': 'synthetic-secret'},
    'aura': {'AllLED': '1', 'ledg_night_mode': '0', 'ledg_scheme': '2', 'ledg_scheme_old': '3'},
    'openvpn_server': {'VPNServer_enable': '0'},
    'wireguard_server': {'wgs_enable': '0'},
    'wireguard_clients': {f'wgc{i}_enable': '0' for i in range(1, 6)},
    'uptime': {'sys': {'uptimeStr': 'Sun, 19 Nov 2023 15:51:06 +0100(509356 secs since boot)'}},
    'temperature': {'cpu': 65.5},
    'parental': {'MULTIFILTER_ALL': '0', 'MULTIFILTER_BLOCK_ALL': '0', 'MULTIFILTER_MAC': '', 'MULTIFILTER_MACFILTER_DAYTIME_V2': '', 'MULTIFILTER_ENABLE': ''},
    'forwarding': {'vts_enable_x': '0', 'vts_rulelist': ''},
    'firmware': {'webs_state_update': '1', 'webs_state_error': '0', 'webs_state_info': '3004_388_4_0', 'webs_state_flag': '1'},
    'speedtest': {'ookla_state': '2', 'ookla_speedtest_get_result': [{'type': 'ping'}, {'type': 'result', 'timestamp': '2026-10-12T12:00:00+07:00', 'download': {'bandwidth': 100}, 'upload': {'bandwidth': 25.5}}, {'type': 'log'}]},
    'sysinfo': {'conn_stats_arr': ['3', '2'], 'cpu_stats_arr': ['0.1', '0.2', '0.3']},
    'network': {'netdev': {'INTERNET_rx': '0x10', 'INTERNET_tx': '0x20'}},
    'aimesh': {'get_cfg_clientlist': [[]]},
    'ports': {'port_info': {'AA:BB:CC:DD:EE:FF': {'L1': {'cap': '2', 'is_on': '1', 'link_rate': '1000', 'max_rate': '1000'}}}},
    'led': {'led_val': '1', 'secret': 'synthetic-secret'},
    'wlan': {'wl0_radio': '1', 'wl1_radio': '1', 'wl0_wpa_psk': 'synthetic-secret'},
    'guest': {**{f'wl{i}.{g}_bss_enabled': '0' for i in (0,1) for g in (1,2,3)}, 'wl0.1_wpa_psk': 'synthetic-secret'},
    'ddns': {'ddns_enable_x': '0', 'ddns_updated': '0', 'ddns_return_code_chk': '', 'ddns_hostname_x': 'synthetic-secret'},
    'vpn': {'get_vpnc_status': '<2>0>7<777>999>8', 'vpnc_clientlist': 'synthetic-secret', 'wgc1_priv': 'synthetic-secret'},
    'identity': {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436-ge7c0b5e', 'label_mac': 'AA:BB:CC:DD:EE:FF', 'password': 'synthetic-secret'},
    'wan': {'get_wan_unit': '0', 'link_internet': '2', 'wan_pppoe_passwd': 'synthetic-secret'},
    'cpu': {'cpu_usage': {'cpu1_total': '100', 'cpu1_usage': '20', 'secret': 'synthetic-secret'}},
    'ram': {'memory_usage': {'mem_total': '100', 'mem_used': '20', 'mem_free': '80', 'secret': 'synthetic-secret'}},
    'clients': {'get_clientlist': {'maclist': ['AA:BB:CC:DD:EE:FF'], 'AA:BB:CC:DD:EE:FF': {'isOnline': '1', 'isWL': '1', 'rssi': '-42', 'name': 'synthetic-secret', 'ip': '192.0.2.1'}}},
}


class FakeRouter:
    instances = []
    fail = None
    cleanup_hangs = False

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls = []
        self.instances.append(self)

    async def async_init_connection(self):
        self.calls.append('init')

    async def async_api_hook(self, hook):
        self.calls.append(hook)
        if self.fail:
            raise self.fail
        if hook == AURA_CAPABILITY_HOOK:
            return {'ledg_rgb1': '20,0,128'}
        if hook == SPEEDTEST_CAPABILITY_HOOK:
            return {'rc_support': '2.4G 5G ookla', 'ss_support': ''}
        return RAW[next(k for k, v in HOOKS.items() if hook == v)]

    async def async_api_load(self, endpoint):
        groups = {'get_port_status.cgi': 'ports', 'ajax_onboarding.asp': 'aimesh', 'ajax_sysinfo.asp': 'sysinfo', 'ajax_status.xml': 'uptime', 'ajax_coretmp.asp': 'temperature', 'detect_firmware.asp': 'firmware', 'release_note0.asp': 'firmware_note'}
        assert endpoint.value in groups
        group = groups[endpoint.value]
        self.calls.append(group)
        return RAW[group]

    async def async_api_query(self, endpoint, payload=None):
        assert endpoint.value == 'ajax_AdslStatus.asp' and payload is None
        self.calls.append('dsl_probe')
        return 200, {}, 'dsl_state="up";'

    async def async_disconnect(self):
        self.calls.append('logout')
        if self.cleanup_hangs:
            await asyncio.sleep(1)


@pytest.fixture(autouse=True)
def reset_fake():
    FakeRouter.instances = []
    FakeRouter.fail = None
    FakeRouter.cleanup_hangs = False


def config(**kw):
    return TransportConfig('router.example', 'admin', **kw)


def test_http_requires_explicit_selection_and_ssl_is_strict():
    with pytest.raises(RouterError, match='HTTP requires'):
        config(use_ssl=False)
    cfg = TransportConfig.from_auth(SimpleNamespace(origin='http://router.example:80', username='admin', allow_plain_http=True))
    assert not cfg.use_ssl and cfg.allow_plain_http
    result = asyncio.run(collect_native(config(), 'synthetic-password', router_factory=FakeRouter, fingerprint_key=KEY))
    opts = FakeRouter.instances[0].kwargs['connection_config']
    assert {k.value: v for k, v in opts.items()} == {'allow_fallback': False, 'allow_multiple_fallbacks': False, 'allow_upgrade_http_to_https': False, 'strict_ssl': True, 'verify_ssl': True}
    assert result['freshness'] == 'unknown' and result['observed_at'] is None


def test_positive_fields_no_raw_secrets_and_no_broad_connect():
    result = asyncio.run(collect_native(config(), 'synthetic-password', router_factory=FakeRouter, fingerprint_key=KEY))
    serialized = json.dumps(result)
    for secret in ('synthetic-secret', 'AA:BB:CC:DD:EE:FF', '192.0.2.1', 'synthetic-password'):
        assert secret not in serialized
    assert result['sources']['clients']['reason'] == 'router_cached'
    assert result['data']['vpn']['scope'] == 'fusion_slot_status_only' and result['capability_gaps']
    assert result['data']['vpn']['slots'][1]['state_code'] == 777
    expected_calls = ['init']
    for group in GROUPS:
        if group in {'node_info', 'flags', 'openvpn'}:
            continue  # Reuses the already fetched PORT_STATUS response.
        if group == 'speedtest':
            expected_calls.append(SPEEDTEST_CAPABILITY_HOOK)
        if group == 'aura':
            expected_calls.append(AURA_CAPABILITY_HOOK)
        if group == 'dsl':
            expected_calls.append('dsl_probe')
        expected_calls.append(HOOKS[group] if group in HOOKS else group)
    expected_calls.append('logout')
    assert FakeRouter.instances[0].calls == expected_calls


def test_repeated_same_vendor_object_never_stamped_fresh():
    first = asyncio.run(collect_native(config(), 'p', ('ram',), router_factory=FakeRouter, fingerprint_key=KEY))
    second = asyncio.run(collect_native(config(), 'p', ('ram',), router_factory=FakeRouter, fingerprint_key=KEY))
    from router_agent.snapshots import semantic
    assert semantic(first) == semantic(second)
    assert first["fetched_at"] != second["fetched_at"]
    assert len(FakeRouter.instances) == 2
    assert first['sources']['ram']['observed_at'] is None
    FakeRouter.fail = RuntimeError('synthetic-secret')
    with pytest.raises(RouterError) as caught:
        asyncio.run(collect_native(config(), 'p', ('ram',), router_factory=FakeRouter, fingerprint_key=KEY))
    assert caught.value.code == 'native_read_failed'
    assert 'synthetic-secret' not in str(caught.value)


def test_cleanup_deadline_and_session_closed():
    FakeRouter.cleanup_hangs = True
    result = asyncio.run(collect_native(config(cleanup_timeout=.01), 'p', ('ram',), router_factory=FakeRouter, fingerprint_key=KEY))
    assert result['warnings'] == ['logout_unconfirmed']
    assert FakeRouter.instances[0].kwargs['session'].closed


def test_malformed_response_is_not_health(monkeypatch):
    monkeypatch.setitem(RAW, 'ram', {'memory_usage': {'mem_total': 'NaN', 'mem_used': 'secret', 'mem_free': '80'}})
    with pytest.raises(RouterError) as caught:
        asyncio.run(collect_native(config(), 'p', ('ram',), router_factory=FakeRouter, fingerprint_key=KEY))
    assert caught.value.code == 'malformed_response'


def test_unknown_group_and_weak_fingerprint_are_rejected():
    for groups, key in [(('wifi',), KEY), (('ram',), b'short')]:
        with pytest.raises(RouterError):
            asyncio.run(collect_native(config(), 'p', groups, router_factory=FakeRouter, fingerprint_key=key))
    assert not FakeRouter.instances


async def _server_scenario(mode, native=True, calls=None, pending=None, groups=('ram',)):
    calls = [] if calls is None else calls
    async def route(request):
        calls.append((request.method, request.path, unquote(await request.text())))
        if request.path == '/login.cgi':
            if mode == 'redirect':
                raise web.HTTPFound('http://example.invalid/collect')
            if mode == 'missing_token':
                return web.json_response({'password': 'synthetic-secret'})
            if mode == 'malformed':
                return web.Response(text='synthetic-secret bad-json')
            if isinstance(mode, int):
                return web.json_response({'error_status': mode, 'password': 'synthetic-secret'})
            if mode == 'timeout':
                await asyncio.sleep(.2)
            return web.json_response({'asus_token': 'synthetic-token'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            if mode == 'unknown_status':
                return web.json_response({'error_status': 999, **RAW['identity']})
            if mode == 'expired':
                return web.json_response({'error_status': 2, 'password': 'synthetic-secret'})
            hook = calls[-1][2]
            return web.json_response(RAW[next(group for group, selected in HOOKS.items() if hook == 'hook=' + selected)])
        return web.Response(status=500)
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', route)
    runner = web.AppRunner(app)
    await runner.setup()
    # An ephemeral local synthetic server, never the real router.
    import socket
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    site = web.SockSite(runner, sock)
    await site.start()
    cfg = TransportConfig('127.0.0.1', 'synthetic-admin', use_ssl=False, allow_plain_http=True, port=port, timeout=.05 if mode == 'timeout' else 1)
    try:
        if native:
            outcome = await collect_native(cfg, 'synthetic-password', groups, fingerprint_key=KEY)
        else:
            outcome = await probe_auth(cfg, 'synthetic-password')
        return outcome, calls
    except RouterError:
        if pending is not None:
            pending.extend(t for t in asyncio.all_tasks() if t is not asyncio.current_task() and hasattr(t.get_coro(), 'cr_code') and '/asusrouter/' in t.get_coro().cr_code.co_filename)
        raise
    finally:
        await runner.cleanup()


def test_actual_upstream_native_network_trace_has_only_selected_reads():
    result, calls = asyncio.run(_server_scenario('ok'))
    assert [c[1] for c in calls] == ['/login.cgi', '/appGet.cgi', '/appGet.cgi', '/Logout.asp']
    assert calls[1][2] == 'hook=' + HOOKS['identity']
    assert calls[2][2] == 'hook=' + HOOKS['ram']
    assert result['data']['ram']['total_kib'] == 100


def test_actual_upstream_limited_auth_probe():
    result, calls = asyncio.run(_server_scenario('ok', native=False))
    assert result['authenticated']
    assert [c[1] for c in calls] == ['/login.cgi', '/Logout.asp']


@pytest.mark.parametrize('mode,code', [(2, 'auth_2'), (3, 'auth_3'), (7, 'auth_7'), (9, 'auth_9'), (10, 'auth_10'), ('expired', 'auth_2'), ('redirect', 'redirect_blocked'), ('malformed', 'malformed_response'), ('missing_token', 'auth_failed'), ('unknown_status', 'native_status_failed')])
def test_actual_upstream_stops_auth_redirect_malformed_and_scrubs_logs(mode, code, caplog):
    caplog.set_level(logging.DEBUG)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(_server_scenario(mode, calls=calls))
    assert caught.value.code == code
    assert sum(path == '/login.cgi' for _, path, _ in calls) == 1
    assert all(path in {'/login.cgi', '/appGet.cgi', '/Logout.asp'} for _, path, _ in calls)
    assert 'synthetic-secret' not in caplog.text
    assert 'synthetic-password' not in caplog.text
    assert 'synthetic-token' not in caplog.text


def test_guard_origin_control_retry_budget_and_hook_payload():
    async def run():
        guard = RequestGuard(config(max_requests=3), (HOOKS['ram'],))
        for url in ('https://evil.example/login.cgi', 'http://router.example/login.cgi', 'https://router.example/apply.cgi', 'https://router.example/appGet.cgi?hook=evil'):
            with pytest.raises(RouterError) as caught:
                await guard.start(None, None, SimpleNamespace(url=url, method='POST'))
            assert caught.value.code == 'read_boundary'
        login = SimpleNamespace(url='https://router.example/login.cgi', method='POST')
        await guard.start(None, None, login)
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, login)
        assert caught.value.code == 'login_budget'
        for payload in (b'hook=nvram_set(secret);', b'hook=nvram_get(wgc1_priv);', b'\xff'):
            with pytest.raises(RouterError):
                await guard.chunk(None, None, SimpleNamespace(url='https://router.example/appGet.cgi', chunk=payload))
        await guard.start(None, None, SimpleNamespace(url='https://router.example/Logout.asp', method='POST'))
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, SimpleNamespace(url='https://router.example/Logout.asp', method='POST'))
        assert caught.value.code == 'request_budget'
    asyncio.run(run())


def test_actual_upstream_timeout_stays_bounded_and_sanitized():
    pending = []
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(_server_scenario('timeout', native=False, calls=calls, pending=pending))
    assert caught.value.code == 'timeout'
    assert not pending
    assert sum(path == '/login.cgi' for _, path, _ in calls) == 1


def test_vendor_exception_logs_are_suppressed(caplog):
    class LoggingRouter(FakeRouter):
        async def async_api_hook(self, hook):
            logging.getLogger('asusrouter.connection').error('synthetic-secret')
            raise RuntimeError('synthetic-secret')
    caplog.set_level(logging.DEBUG)
    with pytest.raises(RouterError):
        asyncio.run(collect_native(config(), 'p', ('ram',), router_factory=LoggingRouter, fingerprint_key=KEY))
    assert 'synthetic-secret' not in caplog.text


def test_tiny_login_deadline_never_leaves_untraced_child_requests():
    from router_agent.transport import RequestGuard
    async def run():
        cfg = config(timeout=.001)
        guard = RequestGuard(cfg)
        async def queued_login():
            await guard.start(None, None, SimpleNamespace(url='https://router.example/login.cgi', method='POST'))
        task = asyncio.create_task(queued_login())
        guard.stopped = True
        await asyncio.sleep(0)
        with pytest.raises(RouterError) as caught:
            await task
        assert caught.value.code == 'auth_stopped'
        assert task in guard.request_tasks
    asyncio.run(run())


def test_mutation_attempt_via_injected_router_is_blocked_before_network():
    class MutationRouter(FakeRouter):
        async def async_api_hook(self, hook):
            async with self.kwargs['session'].post('https://router.example/apply.cgi', data='action_mode=apply'):
                raise AssertionError('mutation reached network')
    with pytest.raises(RouterError) as caught:
        asyncio.run(collect_native(config(), 'p', ('ram',), router_factory=MutationRouter, fingerprint_key=KEY))
    assert caught.value.code == 'read_boundary'


def test_http_auth_config_cannot_bypass_explicit_choice():
    with pytest.raises(RouterError) as caught:
        TransportConfig.from_auth(SimpleNamespace(origin='http://router.example', username='admin', allow_plain_http=False))
    assert caught.value.code == 'http_not_selected'


def test_guard_requires_authenticated_before_read():
    async def run():
        guard = RequestGuard(config(), (HOOKS['ram'],))
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, SimpleNamespace(url='https://router.example/appGet.cgi', method='POST'))
        assert caught.value.code == 'auth_required'
        assert guard.requests == 0
    asyncio.run(run())


@pytest.mark.parametrize('ssl,port,url', [(False, None, 'http://192.168.123.1:80/login.cgi'), (False, 80, 'http://192.168.123.1/login.cgi'), (True, None, 'https://192.168.123.1:443/login.cgi'), (True, 443, 'https://192.168.123.1/login.cgi'), (True, 8443, 'https://192.168.123.1:8443/login.cgi')])
def test_origin_effective_default_and_custom_ports(ssl, port, url):
    cfg = TransportConfig('192.168.123.1', 'synthetic', use_ssl=ssl, allow_plain_http=not ssl, port=port)
    asyncio.run(RequestGuard(cfg).start(None, None, SimpleNamespace(url=url, method='POST')))


@pytest.mark.parametrize('url', ['http://192.168.123.1:81/login.cgi', 'https://192.168.123.1:80/login.cgi', 'http://192.168.123.2:80/login.cgi', 'http://admin@192.168.123.1:80/login.cgi'])
def test_origin_rejects_actual_port_protocol_host_or_userinfo_change(url):
    cfg = TransportConfig('192.168.123.1', 'synthetic', use_ssl=False, allow_plain_http=True)
    with pytest.raises(RouterError) as caught:
        asyncio.run(RequestGuard(cfg).start(None, None, SimpleNamespace(url=url, method='POST')))
    assert caught.value.code == 'read_boundary'


def test_clients_skip_only_documented_metadata(monkeypatch):
    clients = dict(RAW['clients']['get_clientlist'])
    clients['ClientAPILevel'] = '1'
    monkeypatch.setitem(RAW, 'clients', {'get_clientlist': clients})
    result = asyncio.run(collect_native(config(), 'p', ('clients',), router_factory=FakeRouter, fingerprint_key=KEY))
    assert len(result['data']['clients']) == 1
    clients['unexpectedMetadata'] = '1'
    with pytest.raises(RouterError) as caught:
        asyncio.run(collect_native(config(), 'p', ('clients',), router_factory=FakeRouter, fingerprint_key=KEY))
    assert caught.value.code == 'malformed_response'


@pytest.mark.parametrize('metadata,value', [('maclist', 'bad'), ('ClientAPILevel', ['bad'])])
def test_client_metadata_wrong_types_fail_closed(metadata, value, monkeypatch):
    clients = dict(RAW['clients']['get_clientlist'])
    clients[metadata] = value
    monkeypatch.setitem(RAW, 'clients', {'get_clientlist': clients})
    with pytest.raises(RouterError) as caught:
        asyncio.run(collect_native(config(), 'p', ('clients',), router_factory=FakeRouter, fingerprint_key=KEY))
    assert caught.value.code == 'malformed_response'


def test_actual_native_vpn_wire_reads_only_status_without_clientlist():
    from router_agent.output import safe_data
    result, calls = asyncio.run(_server_scenario('ok', groups=('vpn',)))
    assert [path for _, path, _ in calls] == ['/login.cgi', '/appGet.cgi', '/appGet.cgi', '/Logout.asp']
    assert calls[2][2] == 'hook=get_vpnc_status();'
    assert all('vpnc_clientlist' not in payload and 'wgc1_priv' not in payload for _, _, payload in calls)
    vpn = result['data']['vpn']
    assert vpn['slots'] == [{'vpnc_id': 7, 'state_code': 2, 'error_code': 0, 'protocol': 'unknown'}, {'vpnc_id': 8, 'state_code': 777, 'error_code': 999, 'protocol': 'unknown'}]
    assert vpn['egress_verified'] is False
    assert result['sources']['vpn']['freshness'] == 'unknown'
    assert all(gap['group'] == 'vpn' for gap in result['capability_gaps'])
    assert safe_data(result) == result
    assert 'synthetic-secret' not in json.dumps(result)


def test_wired_client_has_no_wireless_signal(monkeypatch):
    clients = {'AA:BB:CC:DD:EE:FF': {'isOnline': '1', 'isWL': '0', 'rssi': '0'}}
    monkeypatch.setitem(RAW, 'clients', {'get_clientlist': clients})
    result = asyncio.run(collect_native(config(), 'p', ('clients',), router_factory=FakeRouter, fingerprint_key=KEY))
    assert result['data']['clients'][0]['connection'] == 'wired'
    assert result['data']['clients'][0]['signal_dbm'] is None


@pytest.mark.parametrize('group', ['led', 'wlan', 'guest', 'ddns'])
def test_actual_native_selected_state_hooks_and_safe_snapshot_fields(group):
    from router_agent.output import safe_data
    result, calls = asyncio.run(_server_scenario('ok', groups=(group,)))
    assert [path for _, path, _ in calls] == ['/login.cgi', '/appGet.cgi', '/appGet.cgi', '/Logout.asp']
    assert calls[2][2] == 'hook=' + HOOKS[group]
    assert all('wpa_psk' not in payload and 'ddns_hostname' not in payload for _, _, payload in calls)
    assert result['sources'][group]['freshness'] == 'unknown'
    assert result['capability_gaps'] and all(gap['group'] == group for gap in result['capability_gaps'])
    assert safe_data(result) == result
    assert 'synthetic-secret' not in json.dumps(result)


@pytest.mark.parametrize('group', ['wlan', 'guest'])
def test_target_radio_contract_rejects_other_model_before_radio_hook(group, monkeypatch):
    monkeypatch.setitem(RAW, 'identity', {**RAW['identity'], 'productid': 'OTHER-MODEL'})
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(_server_scenario('ok', groups=(group,), calls=calls))
    assert caught.value.code == 'unsupported_model'
    assert [path for _, path, _ in calls] == ['/login.cgi', '/appGet.cgi', '/Logout.asp']
    assert all(payload != 'hook=' + HOOKS[group] for _, _, payload in calls)


def test_fetch_time_does_not_claim_source_observation_or_freshness():
    from datetime import datetime, timezone
    before = datetime.now(timezone.utc)
    result = asyncio.run(collect_native(config(), 'p', ('ram',), router_factory=FakeRouter, fingerprint_key=KEY))
    after = datetime.now(timezone.utc)
    assert before <= datetime.fromisoformat(result['fetched_at']) <= after
    assert result['observed_at'] is None and result['freshness'] == 'unknown'
    for group in ('identity','ram'):
        source = result['sources'][group]
        assert before <= datetime.fromisoformat(source['fetched_at']) <= after
        assert source['observed_at'] is None and source['freshness'] == 'unknown'


def test_latest_fetch_time_survives_late_cached_endpoint_reuse():
    class CachedRouter(FakeRouter):
        async def async_api_load(self, endpoint):
            assert endpoint.value == 'get_port_status.cgi'
            self.calls.append('shared-ports')
            return RAW['ports']
    result = asyncio.run(collect_native(config(), 'p', ('ports','wan','node_info'), router_factory=CachedRouter, fingerprint_key=KEY))
    assert FakeRouter.instances[0].calls.count('shared-ports') == 1
    assert result['sources']['ports']['fetched_at'] == result['sources']['node_info']['fetched_at']
    assert result['sources']['ports']['fetched_at'] <= result['sources']['wan']['fetched_at']
    assert result['fetched_at'] == result['sources']['wan']['fetched_at']
