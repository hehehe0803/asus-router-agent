import asyncio
import json
import socket
from types import SimpleNamespace
from urllib.parse import unquote
from aiohttp import web
from yarl import URL
import pytest

from router_agent.dsl_reads import DSL_PATH, DSL_HOOK
from router_agent.health_reads import UPTIME_PATH
from router_agent.errors import RouterError
from router_agent.transport import TransportConfig, collect_native, RequestGuard

XML = '<devicemap><sys>uptimeStr=2026-10-15T01:00:00+00:00(1000 secs since boot)</sys><vpn>vpn_client1_state=2</vpn><vpn>vpn_client1_errno=0</vpn><vpn>vpn_server1_state=0</vpn><vpn>password=sentinel</vpn></devicemap>'


async def scenario(groups, *, probe='dsl_status = "up";', status=200, identity=None, calls=None, state_dir=None, budget=8):
    calls = [] if calls is None else calls
    async def handle(request):
        body = await request.text()
        calls.append((request.method, request.path, request.query_string, unquote(body)))
        if request.path == '/login.cgi':
            return web.json_response({'asus_token': 'synthetic'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            if 'dsllog_' in unquote(body):
                return web.json_response({'dsllog_dataratedown': '0 kbps', 'dsllog_datarateup': None})
            return web.json_response(identity or {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436-ge7c0b5e', 'label_mac': 'AA:BB:CC:DD:EE:FF'})
        if request.path == DSL_PATH:
            return web.Response(text=probe, status=status)
        if request.path == UPTIME_PATH:
            return web.Response(text=XML)
        raise AssertionError('unreviewed route')
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    await web.SockSite(runner, sock).start()
    try:
        config = TransportConfig('127.0.0.1', 'synthetic', use_ssl=False, allow_plain_http=True, port=port, max_requests=budget)
        return await collect_native(config, 'synthetic-password', groups, fingerprint_key=b'x'*32, state_dir=state_dir), calls
    finally:
        await runner.cleanup()


def test_dsl_exact_native_probe_before_selected_rate_hook():
    result, calls = asyncio.run(scenario(('dsl',), budget=5))
    assert [path for _, path, _, _ in calls] == ['/login.cgi', '/appGet.cgi', DSL_PATH, '/appGet.cgi', '/Logout.asp']
    assert calls[2] == ('POST', DSL_PATH, '', '')
    assert calls[3][3] == 'hook=' + DSL_HOOK
    assert result['data']['dsl']['rates']['down'] == {'value': 0, 'unit': 'kbps'}
    assert result['data']['dsl']['rates']['up']['value'] is None


@pytest.mark.parametrize('probe,status,code', [('not found', 404, 'unsupported_capability'), ('{}', 200, 'capability_unknown'), ('{"error_status":2}', 200, 'auth_2'), ('<html>sentinel</html>', 200, 'malformed_response')])
def test_dsl_failed_gate_zero_rate_calls_no_retry(probe, status, code, caplog):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(('dsl',), probe=probe, status=status, calls=calls))
    assert caught.value.code == code
    assert sum(path == DSL_PATH for _, path, _, _ in calls) == 1
    assert not any('dsllog_' in body for _, _, _, body in calls)
    assert 'sentinel' not in caplog.text


@pytest.mark.parametrize('groups', [('flags', 'openvpn', 'uptime'), ('openvpn', 'uptime', 'flags'), ('uptime', 'flags', 'openvpn')])
def test_flags_openvpn_uptime_share_one_bounded_native_endpoint(tmp_path, groups):
    result, calls = asyncio.run(scenario(groups, state_dir=tmp_path, budget=4))
    assert [path for _, path, _, _ in calls] == ['/login.cgi', '/appGet.cgi', UPTIME_PATH, '/Logout.asp']
    assert result['data']['flags']['reboot'] is None
    assert result['data']['openvpn']['source_flavor'] == 'stock'
    assert result['data']['openvpn']['slots'][0]['state_code'] == 2
    assert result['sources']['openvpn']['fetched_at'] == result['sources']['uptime']['fetched_at']
    assert 'sentinel' not in json.dumps(result)


def test_openvpn_unknown_firmware_rejected_before_status():
    calls = []
    identity = {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '99999-merlin', 'label_mac': 'AA:BB:CC:DD:EE:FF'}
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(('openvpn',), identity=identity, calls=calls))
    assert caught.value.code == 'unsupported_vpn_settings_target'
    assert all(path != UPTIME_PATH for _, path, _, _ in calls)


def test_dsl_guard_exact_method_auth_query_once_and_no_jobs():
    async def run():
        guard = RequestGuard(TransportConfig('example.test', 'synthetic'), allow_dsl=True)
        p = SimpleNamespace(url='https://example.test' + DSL_PATH, method='POST')
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, p)
        assert caught.value.code == 'auth_required'
        guard.authenticated = True
        for url, method in [(p.url, 'GET'), (p.url + '?a=1', 'POST'), ('https://example.test/netool.cgi', 'POST')]:
            with pytest.raises(RouterError):
                await guard.start(None, None, SimpleNamespace(url=url, method=method))
        await guard.start(None, None, p)
        with pytest.raises(RouterError):
            await guard.start(None, None, p)
    asyncio.run(run())


def test_dsl_nonempty_body_blocked_before_transmission():
    # Exercise middleware without using any live router.
    async def run():
        guard = RequestGuard(TransportConfig('example.test', 'synthetic'), allow_dsl=True)
        sent = False
        async def handler(request):
            nonlocal sent
            sent = True
        with pytest.raises(RouterError) as caught:
            await guard.middleware(SimpleNamespace(url=URL('https://example.test' + DSL_PATH), body=b'forbidden'), handler)
        assert caught.value.code == 'read_boundary' and not sent
    asyncio.run(run())
