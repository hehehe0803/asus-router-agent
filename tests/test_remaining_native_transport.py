import asyncio
import json
import socket
from types import SimpleNamespace

from aiohttp import web
import pytest

from router_agent.errors import RouterError
from router_agent.firmware_note_reads import FIRMWARE_NOTE_PATH
from router_agent.transport import RequestGuard, TransportConfig, collect_native

KEY = b'n' * 32
MAC = 'AA:BB:CC:DD:EE:FF'
NOTE = 'Synthetic release notes\nChanges for this example.\nNo active update check.'


async def scenario(groups=('node_info',), *, note=NOTE, calls=None, offset=0, limit=2048, budget=None, factory=None):
    calls = [] if calls is None else calls
    async def handle(request):
        calls.append((request.method, request.path, request.query_string, await request.text()))
        if request.path == '/login.cgi':
            return web.json_response({'asus_token': 'synthetic-token'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            return web.json_response({'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436', 'label_mac': MAC})
        if request.path == '/get_port_status.cgi':
            return web.json_response({'node_info': {MAC: {'cd_good_to_go': '1', 'name': 'synthetic-secret', 'ip': '192.0.2.1'}}, 'port_info': {MAC: {'L1': {'cap': '2', 'is_on': '1', 'link_rate': '1000', 'max_rate': '1000'}}}})
        if request.path == FIRMWARE_NOTE_PATH:
            if note == 'redirect':
                raise web.HTTPFound('http://example.invalid/secret')
            return web.Response(text=note)
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
        return await collect_native(cfg, 'synthetic-password', groups, fingerprint_key=KEY, note_offset=offset, note_limit=limit, router_factory=factory), calls
    finally:
        await runner.cleanup()


@pytest.mark.parametrize('groups', [('node_info',), ('ports', 'node_info'), ('node_info', 'ports')])
def test_node_info_and_ports_share_one_actual_native_endpoint(groups):
    result, calls = asyncio.run(scenario(groups, budget=4))
    assert [(m, p, q) for m, p, q, _ in calls] == [('POST', '/login.cgi', ''), ('POST', '/appGet.cgi', ''), ('GET', '/get_port_status.cgi', 'node_mac=all'), ('POST', '/Logout.asp', '')]
    assert result['data']['node_info']['nodes'][0]['cd_good_to_go_code'] == 1
    assert result['sources']['node_info']['freshness'] == 'unknown'
    if 'ports' in groups:
        assert result['data']['ports']['ports'][0]['node_alias'] == result['data']['node_info']['nodes'][0]['node_alias']
    assert MAC not in json.dumps(result) and 'synthetic-secret' not in json.dumps(result)
    assert '192.0.2.1' not in json.dumps(result)


def test_native_release_note_post_pagination_and_fingerprint():
    from router_agent.firmware_note_reads import normalize_firmware_note, read_firmware_note_text
    expected = normalize_firmware_note(read_firmware_note_text(NOTE), offset=3, limit=12)
    result, calls = asyncio.run(scenario(('firmware_note',), offset=3, limit=12, budget=4))
    assert [(m, p, q) for m, p, q, _ in calls] == [('POST', '/login.cgi', ''), ('POST', '/appGet.cgi', ''), ('POST', FIRMWARE_NOTE_PATH, ''), ('POST', '/Logout.asp', '')]
    assert calls[2][3] == ''
    assert result['data']['firmware_note'] == expected
    assert result['data']['firmware_note']['pagination']['next_offset'] == 15
    assert 'release_note_raw' not in json.dumps(result)
    assert result['sources']['firmware_note']['freshness'] == 'unknown'
    next_page, _ = asyncio.run(scenario(('firmware_note',), offset=15, limit=12))
    assert next_page['data']['firmware_note']['content_fingerprint'] == expected['content_fingerprint']
    changed, _ = asyncio.run(scenario(('firmware_note',), note=NOTE + ' Changed.', offset=15, limit=12))
    assert changed['data']['firmware_note']['content_fingerprint'] != expected['content_fingerprint']


@pytest.mark.parametrize('offset,limit,groups', [(-1, 10, ('firmware_note',)), (0, 4097, ('firmware_note',)), (131073, 10, ('firmware_note',)), (1, 2048, ('node_info',)), (0, 10, ('node_info',))])
def test_invalid_note_pagination_fails_before_any_request(offset, limit, groups):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(groups, offset=offset, limit=limit, calls=calls))
    assert caught.value.code == 'invalid_arguments' and calls == []


@pytest.mark.parametrize('note,code', [('{"error_status":2,"password":"synthetic-secret"}', 'auth_2'), ('error_status=10;', 'auth_10'), ('<html>synthetic-secret</html>', 'malformed_response'), ('redirect', 'redirect_blocked'), ('x' * 131073, 'malformed_response')])
def test_release_note_auth_html_redirect_size_stops_without_retry(note, code, caplog):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(('firmware_note',), note=note, calls=calls))
    assert caught.value.code == code
    assert sum(path == FIRMWARE_NOTE_PATH for _, path, _, _ in calls) == 1
    assert sum(path == '/login.cgi' for _, path, _, _ in calls) == 1
    assert 'synthetic-secret' not in caplog.text


def test_release_note_exact_method_query_auth_once_guard():
    async def run():
        cfg = TransportConfig('example.test', 'synthetic')
        guard = RequestGuard(cfg, allow_firmware_note=True)
        params = SimpleNamespace(url='https://example.test' + FIRMWARE_NOTE_PATH, method='POST')
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, params)
        assert caught.value.code == 'auth_required'
        guard.authenticated = True
        for method, query in [('GET', ''), ('POST', '?check=1')]:
            with pytest.raises(RouterError):
                await guard.start(None, None, SimpleNamespace(url=params.url + query, method=method))
        await guard.start(None, None, params)
        with pytest.raises(RouterError):
            await guard.start(None, None, params)
    asyncio.run(run())


def test_release_note_nonempty_body_rejected_before_endpoint():
    from asusrouter import AsusRouter
    class BodyRouter(AsusRouter):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.test_session = kwargs['session']
            self.test_url = f"http://{kwargs['hostname']}:{kwargs['port']}{FIRMWARE_NOTE_PATH}"
        async def async_api_load(self, endpoint, request='', retry=0):
            if endpoint.value == FIRMWARE_NOTE_PATH[1:]:
                return await self.test_session.post(self.test_url, data='forbidden')
            return await super().async_api_load(endpoint, request, retry)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(('firmware_note',), factory=BodyRouter, calls=calls))
    assert caught.value.code == 'read_boundary'
    assert all(path != FIRMWARE_NOTE_PATH for _, path, _, _ in calls)
