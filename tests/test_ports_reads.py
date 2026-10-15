import asyncio
import json
import socket
from types import SimpleNamespace
from urllib.parse import unquote

import aiohttp
from aiohttp import web
import pytest

from router_agent.errors import RouterError
from router_agent.ports_reads import normalize_ports
from router_agent.transport import HOOKS, RequestGuard, TransportConfig, collect_native

KEY = b'p' * 32
MAC = 'AA:BB:CC:DD:EE:FF'
RAW = {'node_info': {MAC: {'name': 'synthetic-secret', 'ip': '192.0.2.1'}}, 'port_info': {MAC: {'W0': {'is_on': '1', 'cap': '1073741825', 'link_rate': '2500', 'max_rate': '2500', 'devices': 'synthetic-secret'}, 'L1': {'is_on': '0', 'cap': '2', 'link_rate': '0', 'max_rate': '1000'}}}}


def test_selected_port_fields_aliases_sorted_and_secret_free():
    result = normalize_ports(RAW, KEY)
    assert [row['port'] for row in result['ports']] == ['L1', 'W0']
    assert result['ports'][0]['link_enabled'] is False and result['ports'][0]['link_rate'] == 0
    assert result['ports'][1]['link_enabled'] is True and result['ports'][1]['cap'] == 1073741825
    encoded = json.dumps(result)
    assert MAC not in encoded and 'synthetic-secret' not in encoded and '192.0.2.1' not in encoded
    assert result == normalize_ports(RAW, KEY)
    assert result != normalize_ports(RAW, b'q' * 32)


def test_missing_unknown_never_defaults_down():
    result = normalize_ports({'port_info': {MAC: {'L1': {'link_rate': '-999'}}}}, KEY)
    assert all(result['ports'][0][k] is None for k in ('cap', 'link_rate', 'max_rate', 'link_enabled'))
    assert 'selected_port_fields_missing_or_unknown' in result['gaps']
    for raw in ({}, {'port_info': {}}, {'port_info': None}):
        assert normalize_ports(raw, KEY)['ports'] == []
        assert 'port_data_unavailable_or_unsupported' in normalize_ports(raw, KEY)['gaps']


@pytest.mark.parametrize('raw', [None, [], {'port_info': []}, {'port_info': {'bad': {}}}, {'port_info': {MAC: {'named-secret': {}}}}, {'port_info': {MAC: {'L1': {'cap': 'secret'}}}}, {'port_info': {MAC: {'L1': {'is_on': '2'}}}}, {'port_info': {MAC: {'L1': {'link_rate': True}}}}, {'port_info': {MAC: {'L1': {'max_rate': 1_000_001}}}}, {'port_info': {MAC: {'L1': {'cap': 2**32}}}}])
def test_malformed_selected_fields_fail_closed(raw):
    with pytest.raises(RouterError) as caught:
        normalize_ports(raw, KEY)
    assert caught.value.code == 'malformed_response'


def test_node_port_and_total_bounds():
    for info in ({f'00:00:00:00:00:{i:02X}': {} for i in range(33)}, {MAC: {f'L{i}': {} for i in range(65)}}, {f'00:00:00:00:00:{i:02X}': {f'L{j}': {} for j in range(64)} for i in range(5)}):
        with pytest.raises(RouterError):
            normalize_ports({'port_info': info}, KEY)


async def scenario(mode='ok', factory=None, calls=None):
    calls = [] if calls is None else calls
    identity = {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436', 'label_mac': MAC}
    async def handle(request):
        calls.append((request.method, request.path, request.query_string, await request.text()))
        if request.path == '/login.cgi':
            return web.json_response({'asus_token': 'synthetic-token'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            assert unquote(calls[-1][3]) == 'hook=' + HOOKS['identity']
            return web.json_response(identity)
        if request.path == '/get_port_status.cgi':
            if mode == 'redirect':
                raise web.HTTPFound('http://example.invalid/secret')
            if mode == 'auth':
                return web.json_response({'error_status': 2, 'password': 'synthetic-secret'})
            return web.json_response(RAW)
        raise AssertionError('unreviewed endpoint')
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    await web.SockSite(runner, sock).start()
    config = TransportConfig('127.0.0.1', 'synthetic-admin', use_ssl=False, allow_plain_http=True, port=port)
    try:
        result = await collect_native(config, 'synthetic-password', ('ports',), fingerprint_key=KEY, router_factory=factory)
        return result, calls
    finally:
        await runner.cleanup()


def test_pristine_upstream_port_read_exact_get_query_no_body_no_scan():
    from router_agent.output import safe_data
    result, calls = asyncio.run(scenario())
    assert [(m, p, q) for m, p, q, _ in calls] == [('POST', '/login.cgi', ''), ('POST', '/appGet.cgi', ''), ('GET', '/get_port_status.cgi', 'node_mac=all'), ('POST', '/Logout.asp', '')]
    assert calls[2][3] == ''
    assert result['data']['ports']['ports']
    assert result['sources']['ports']['freshness'] == 'unknown'
    assert all(gap['group'] == 'ports' for gap in result['capability_gaps'])
    assert safe_data(result) == result
    assert 'synthetic-secret' not in json.dumps(result)


@pytest.mark.parametrize('mode,code', [('redirect', 'redirect_blocked'), ('auth', 'auth_2')])
def test_port_read_redirect_auth_stops_without_retry(mode, code, caplog):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(mode, calls=calls))
    assert caught.value.code == code
    assert sum(path == '/login.cgi' for _, path, _, _ in calls) == 1
    assert sum(path == '/get_port_status.cgi' for _, path, _, _ in calls) == 1
    assert 'synthetic-secret' not in caplog.text


@pytest.mark.parametrize('method,query', [('POST', 'node_mac=all'), ('GET', 'node_mac=other'), ('GET', 'node_mac=all&other=x'), ('GET', ''), ('GET', 'node_mac=all%26other=x')])
def test_guard_rejects_wrong_port_method_or_query(method, query):
    async def run():
        config = TransportConfig('router.example', 'synthetic')
        guard = RequestGuard(config, allow_ports=True)
        guard.authenticated = True
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, SimpleNamespace(url='https://router.example/get_port_status.cgi?' + query, method=method))
        assert caught.value.code == 'read_boundary'
    asyncio.run(run())


def test_guard_ports_requires_selected_group_auth_and_one_call():
    async def run():
        config = TransportConfig('router.example', 'synthetic')
        params = SimpleNamespace(url='https://router.example/get_port_status.cgi?node_mac=all', method='GET')
        disabled = RequestGuard(config)
        with pytest.raises(RouterError):
            await disabled.start(None, None, params)
        guard = RequestGuard(config, allow_ports=True)
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, params)
        assert caught.value.code == 'auth_required'
        guard.authenticated = True
        await guard.start(None, None, params)
        with pytest.raises(RouterError):
            await guard.start(None, None, params)
    asyncio.run(run())


def test_get_body_rejected_before_server_receives_port_request():
    from asusrouter import AsusRouter
    class BodyRouter(AsusRouter):
        async def async_api_load(self, endpoint, request='', retry=0):
            if endpoint.value == 'get_port_status.cgi':
                url = self._test_url
                return await self._test_session.get(url, data='forbidden')
            return await super().async_api_load(endpoint, request, retry)
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self._test_session = kwargs['session']
            self._test_url = f"http://{kwargs['hostname']}:{kwargs['port']}/get_port_status.cgi?node_mac=all"
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(factory=BodyRouter, calls=calls))
    assert caught.value.code == 'read_boundary'
    assert all(path != '/get_port_status.cgi' for _, path, _, _ in calls)


def test_usb_modem_false_does_not_claim_no_attached_device():
    result = normalize_ports({'port_info': {MAC: {'U1': {'is_on': '0', 'cap': '128', 'devices': {'name': 'synthetic-secret'}}}}}, KEY)
    assert result['ports'][0]['link_enabled'] is None
    assert 'usb_presence_not_collected' in result['gaps']
    assert 'synthetic-secret' not in json.dumps(result)


def test_missing_cap_does_not_claim_disconnected_with_unknown_port_semantics():
    result = normalize_ports({'port_info': {MAC: {'L1': {'is_on': '0', 'devices': {'name': 'synthetic-secret'}}}}}, KEY)
    assert result['ports'][0]['link_enabled'] is None
    assert 'port_type_unknown' in result['gaps']
    assert 'synthetic-secret' not in json.dumps(result)
