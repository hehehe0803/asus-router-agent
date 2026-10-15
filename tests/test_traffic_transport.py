import asyncio
from dataclasses import replace
import hashlib
import hmac
import json
import logging
import socket
from types import SimpleNamespace
from urllib.parse import unquote

from aiohttp import web
import pytest

from router_agent.errors import RouterError
from router_agent.traffic_reads import prepare_traffic_request
from router_agent.transport import HOOKS, TrafficGuard, TransportConfig, collect_traffic, RequestGuard

KEY = b't' * 32
MAC = 'AA:BB:CC:DD:EE:FF'
PEER = 'AA:BB:CC:DD:EE:01'
BAND = 'AA:BB:CC:DD:EE:02'

def alias(mac):
    return 'node-' + hmac.new(KEY, b'node:' + mac.encode(), hashlib.sha256).hexdigest()[:16]

INVENTORY = {'get_cfg_clientlist': [[{'mac': MAC, 'ui_model_name': 'RT-AX86U', 'fwver': '3.0.0.4.388_24436', 'online': '1', 'level': '0', 'ap5g': BAND, 'alias': 'synthetic-secret', 'ip': '192.0.2.1'}, {'mac': PEER, 'online': '1', 'level': '1'}]]}
RATES = {'data': {'rx': '1.5', 'tx': '2', 'avg_rx': '3', 'avg_tx': '4'}, 'phy': {'rx': '5.5', 'tx': '6'}, 'error_status': '200', 'private': {'name': 'synthetic-secret', 'ip': '192.0.2.1'}}
PATHS = {'ethernet': '/get_diag_eth_traffic.cgi', 'wifi': '/get_diag_wifi_traffic.cgi', 'backhaul': '/get_diag_sta_traffic.cgi'}


async def scenario(kind='ethernet', *, mode='ok', calls=None, factory=None, inventory=INVENTORY, budget=5, raw=RATES, **options):
    calls = [] if calls is None else calls
    async def handle(request):
        calls.append((request.method, request.path, request.query_string, await request.text()))
        if request.path == '/login.cgi':
            return web.json_response({'asus_token': 'synthetic-token'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            assert unquote(calls[-1][3]) == 'hook=' + HOOKS['identity']
            return web.json_response({'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436', 'label_mac': MAC})
        if request.path == '/ajax_onboarding.asp':
            return web.Response(text='get_cfg_clientlist = ' + json.dumps(inventory['get_cfg_clientlist']) + '[0];')
        if request.path in PATHS.values():
            if mode == 'redirect':
                raise web.HTTPFound('http://example.invalid/secret')
            if mode == 'html':
                return web.Response(text='<html>synthetic-secret</html>')
            if mode == 'timeout':
                await asyncio.sleep(.2)
            return web.json_response(raw)
        raise AssertionError('unexpected endpoint')
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handle)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    await web.SockSite(runner, sock).start()
    cfg = TransportConfig('127.0.0.1', 'synthetic-admin', use_ssl=False, allow_plain_http=True, port=port, max_requests=budget, timeout=.05 if mode == 'timeout' else 1)
    try:
        return await collect_traffic(cfg, 'synthetic-password', kind, alias(MAC), fingerprint_key=KEY, router_factory=factory, **options), calls
    finally:
        await runner.cleanup()


@pytest.mark.parametrize('kind,options,query', [('ethernet', {}, f'node_mac={MAC}&is_bh=0'), ('ethernet', {'backhaul': True}, f'node_mac={MAC}&is_bh=1'), ('wifi', {'band': '5ghz'}, f'node_mac={MAC}&band_mac={BAND}'), ('backhaul', {'peer_alias': alias(PEER)}, f'node_mac={MAC}&sta_mac={PEER}')])
def test_pristine_upstream_typed_traffic_exact_same_session_read_sequence(kind, options, query, caplog):
    caplog.set_level(logging.DEBUG)
    result, calls = asyncio.run(scenario(kind, **options))
    assert [(m, p) for m, p, _, _ in calls] == [('POST', '/login.cgi'), ('POST', '/appGet.cgi'), ('POST', '/ajax_onboarding.asp'), ('GET', PATHS[kind]), ('POST', '/Logout.asp')]
    assert calls[3][2] == query and calls[3][3] == ''
    assert result['data']['traffic']['rx_bps'] == 1536.0
    assert result['data']['traffic']['phy_rx_bps'] == 5.5 * 1024**2
    assert result['data']['traffic']['node_alias'] == alias(MAC)
    assert result['freshness'] == 'unknown' and result['sources']['traffic']['observed_at'] is None
    output = json.dumps(result)
    for secret in (MAC, PEER, BAND, 'synthetic-secret', '192.0.2.1', 'synthetic-password', 'synthetic-token'):
        assert secret not in output and secret not in caplog.text


@pytest.mark.parametrize('raw,code', [({'data': {'error_status': '2'}, 'error_status': '200'}, 'auth_2'), ({'private': {'nested': {'error_status': '7'}}, 'error_status': '200'}, 'auth_7'), ({'error_status': '10'}, 'auth_10'), ({'private': {'error_status': '999'}, 'error_status': '200'}, 'native_status_failed'), ({'error_status': True}, 'malformed_response'), ({'data': {'rx': 'synthetic-secret'}, 'error_status': '200'}, 'malformed_response')])
def test_nested_errors_and_malformed_fields_stop_before_native_retry(raw, code):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(raw=raw, calls=calls))
    assert caught.value.code == code
    assert sum(path == '/login.cgi' for _, path, _, _ in calls) == 1
    assert sum(path in PATHS.values() for _, path, _, _ in calls) == 1


@pytest.mark.parametrize('mode,code', [('redirect', 'redirect_blocked'), ('html', 'malformed_response'), ('timeout', 'timeout')])
def test_traffic_redirect_html_timeout_no_retry(mode, code):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(mode=mode, calls=calls))
    assert caught.value.code == code
    assert sum(path in PATHS.values() for _, path, _, _ in calls) == 1


def test_fresh_inventory_missing_target_never_sends_traffic():
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(inventory={'get_cfg_clientlist': [[{'mac': PEER}]]}, calls=calls))
    assert caught.value.code == 'traffic_target_unavailable'
    assert all(path not in PATHS.values() for _, path, _, _ in calls)


@pytest.mark.parametrize('kind,node,options', [('ethernet', MAC, {}), ('wifi', alias(MAC), {'band': 'unknown'}), ('ethernet', alias(MAC), {'peer_alias': alias(PEER)}), ('backhaul', alias(MAC), {'peer_alias': alias(MAC)}), ('wifi', alias(MAC), {'band': '5ghz', 'backhaul': True})])
def test_invalid_typed_args_fail_without_session_or_credentials(kind, node, options):
    with pytest.raises(RouterError) as caught:
        asyncio.run(collect_traffic(TransportConfig('example.test', 'synthetic'), 'p', kind, node, fingerprint_key=KEY, **options))
    assert caught.value.code == 'invalid_arguments'


def test_low_budget_fails_before_login():
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(budget=4, calls=calls))
    assert caught.value.code == 'request_budget' and calls == []


def test_traffic_guard_cannot_be_armed_with_control_or_extra_query_and_static_reads_remain_closed():
    async def run():
        from asusrouter.modules.endpoint import EndpointControl
        cfg = TransportConfig('example.test', 'synthetic')
        prepared = await prepare_traffic_request('ethernet', alias(MAC), INVENTORY, KEY)
        for candidate in (replace(prepared, endpoint=EndpointControl.COMMAND), replace(prepared, request=prepared.request + '&action_mode=apply'), replace(prepared, request=prepared.request.replace('is_bh=0', 'is_bh=2'))):
            with pytest.raises(RouterError):
                TrafficGuard(cfg).arm(candidate)
        static = RequestGuard(cfg)
        static.authenticated = True
        with pytest.raises(RouterError):
            await static.start(None, None, SimpleNamespace(url='https://example.test' + PATHS['ethernet'] + '?node_mac=x', method='GET'))
    asyncio.run(run())


def test_guard_exact_bound_endpoint_query_origin_auth_and_single_read():
    async def run():
        cfg = TransportConfig('example.test', 'synthetic')
        prepared = await prepare_traffic_request('ethernet', alias(MAC), INVENTORY, KEY)
        guard = TrafficGuard(cfg)
        guard.arm(prepared)
        with pytest.raises(RouterError):
            await guard.start(None, None, SimpleNamespace(url=guard.traffic_url, method='GET'))
        guard.authenticated = True
        for url, method in [(str(guard.traffic_url) + '&extra=1', 'GET'), (str(guard.traffic_url).replace('example.test', 'evil.test'), 'GET'), (guard.traffic_url, 'POST')]:
            with pytest.raises(RouterError):
                await guard.start(None, None, SimpleNamespace(url=url, method=method))
        await guard.start(None, None, SimpleNamespace(url=guard.traffic_url, method='GET'))
        with pytest.raises(RouterError):
            await guard.start(None, None, SimpleNamespace(url=guard.traffic_url, method='GET'))
    asyncio.run(run())


def test_nonempty_traffic_body_rejected_before_server():
    from asusrouter import AsusRouter
    class BodyRouter(AsusRouter):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.test_session = kwargs['session']
            self.test_origin = f"http://{kwargs['hostname']}:{kwargs['port']}"
        async def async_api_load(self, endpoint, request='', retry=0):
            if endpoint.value == PATHS['ethernet'][1:]:
                return await self.test_session.get(self.test_origin + PATHS['ethernet'] + '?' + request, data='forbidden')
            return await super().async_api_load(endpoint, request, retry)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(factory=BodyRouter, calls=calls))
    assert caught.value.code == 'read_boundary'
    assert all(path not in PATHS.values() for _, path, _, _ in calls)


def test_no_transient_raw_identifiers_are_persisted_or_added_to_output():
    result, _ = asyncio.run(scenario())
    assert set(result['data']) == {'identity', 'traffic'}
    assert 'get_cfg_clientlist' not in json.dumps(result)
    assert 'request' not in result and 'endpoint' not in result


def test_fresh_missing_band_skips_traffic_request():
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario('wifi', band='5ghz', inventory={'get_cfg_clientlist': [[{'mac': MAC}]]}, calls=calls))
    assert caught.value.code == 'traffic_target_unavailable'
    assert all(path not in PATHS.values() for _, path, _, _ in calls)


def test_native_double_read_blocked_before_second_wire_request_and_cleanup_still_fits_ceiling():
    from asusrouter import AsusRouter
    class Twice(AsusRouter):
        async def async_api_load(self, endpoint, request='', retry=0):
            raw = await super().async_api_load(endpoint, request, retry)
            if endpoint.value == PATHS['ethernet'][1:]:
                return await super().async_api_load(endpoint, request, retry)
            return raw
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(factory=Twice, calls=calls))
    assert caught.value.code == 'read_boundary'
    assert len(calls) == 5
    assert sum(path in PATHS.values() for _, path, _, _ in calls) == 1
    assert calls[-1][1] == '/Logout.asp'


def test_timeout_closes_external_session_and_leaves_no_native_tasks():
    from asusrouter import AsusRouter
    sessions = []
    class CaptureSession(AsusRouter):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            sessions.append(kwargs['session'])
    async def run():
        with pytest.raises(RouterError) as caught:
            await scenario(mode='timeout', factory=CaptureSession)
        assert caught.value.code == 'timeout'
        assert sessions and sessions[0].closed
        native_tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task() and hasattr(task.get_coro(), 'cr_code') and '/asusrouter/' in task.get_coro().cr_code.co_filename]
        assert native_tasks == []
    asyncio.run(run())


@pytest.mark.parametrize('kind,options', [([], {}), ('wifi', {'band': []})])
def test_unhashable_typed_arguments_are_sanitized_before_transport(kind, options):
    with pytest.raises(RouterError) as caught:
        asyncio.run(collect_traffic(TransportConfig('example.test', 'synthetic'), 'p', kind, alias(MAC), fingerprint_key=KEY, **options))
    assert caught.value.code == 'invalid_arguments'
