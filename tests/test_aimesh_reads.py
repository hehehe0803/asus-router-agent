import asyncio
import json
import logging
import socket
from types import SimpleNamespace

from aiohttp import web
import pytest

from router_agent.aimesh_reads import normalize_aimesh, read_onboarding_text
from router_agent.errors import RouterError
from router_agent.ports_reads import normalize_ports
from router_agent.transport import RequestGuard, TransportConfig, collect_native

KEY = b'a' * 32
MAC = 'AA:BB:CC:DD:EE:FF'
NODE = {'mac': MAC, 'ui_model_name': 'RT-AX86U', 'fwver': '3.0.0.4.388_24436', 'online': '1', 'level': '0', 'alias': 'synthetic-secret', 'ip': '192.0.2.1', 'config': {'password': 'synthetic-secret'}, 'pap5g': 'AA:BB:CC:DD:EE:01', 'rssi5g': '-42', 'pap5g_ssid': 'synthetic-secret'}


def js(nodes):
    return 'get_cfg_clientlist = ' + json.dumps([nodes]) + '[0];\nget_allclientlist = [{"password":"synthetic-secret"}][0];'


def test_maintained_reader_selected_fields_and_alias_shared_with_ports():
    result = normalize_aimesh(read_onboarding_text(js([NODE])), KEY)
    node = result['nodes'][0]
    assert node['online'] is True and node['level'] == 0 and node['type'] == 'router'
    assert result['scope'] == 'returned_cfg_clientlist_records'
    assert 'returned_record_count_is_not_satellite_count' in result['gaps']
    assert node['parent_connection'] == '5ghz' and node['signal_dbm'] == -42
    port = normalize_ports({'port_info': {MAC: {'L1': {}}}}, KEY)['ports'][0]
    assert node['node_alias'] == port['node_alias']
    output = json.dumps(result)
    assert MAC not in output and 'synthetic-secret' not in output and '192.0.2.1' not in output


def test_missing_online_level_model_firmware_remain_unknown():
    result = normalize_aimesh({'get_cfg_clientlist': [[{'mac': MAC}]]}, KEY)
    node = result['nodes'][0]
    assert node['online'] is None and node['level'] is None and node['type'] == 'unknown'
    assert node['model'] is None and node['firmware'] is None
    assert 'selected_node_fields_missing_or_unknown' in result['gaps']


def test_explicit_empty_nodes_count_only_returned_nodes():
    result = normalize_aimesh(read_onboarding_text(js([])), KEY)
    assert result['count'] == 0 and result['nodes'] == []
    assert 'zero_returned_nodes_does_not_establish_topology' in result['gaps']


@pytest.mark.parametrize('parent', ['00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'])
def test_parent_sentinel_cannot_create_association(parent):
    result = normalize_aimesh({'get_cfg_clientlist': [[{**NODE, 'pap5g': parent}]]}, KEY)
    assert result['nodes'][0]['parent_connection'] is None
    assert result['nodes'][0]['signal_dbm'] is None
    assert 'parent_association_unknown' in result['gaps']


@pytest.mark.parametrize('raw', [{}, {'get_cfg_clientlist': None}, {'get_cfg_clientlist': []}, {'get_cfg_clientlist': [None]}, {'get_cfg_clientlist': [[None]]}, {'get_cfg_clientlist': [[NODE, NODE]]}, {'get_cfg_clientlist': [[{**NODE, 'online': '2'}]]}, {'get_cfg_clientlist': [[{**NODE, 'level': 'secret'}]]}, {'get_cfg_clientlist': [[{**NODE, 'fwver': '<script>'}]]}, {'get_cfg_clientlist': [[{**NODE, 'pap5g': 'bad'}]]}, {'get_cfg_clientlist': [[{**NODE, 'rssi5g': -151}]]}, {'get_cfg_clientlist': [[{**NODE, 'mac': f'00:00:00:00:00:{i:02X}'} for i in range(33)]]}])
def test_malformed_missing_null_duplicate_or_oversized_records_fail(raw):
    with pytest.raises(RouterError) as caught:
        normalize_aimesh(raw, KEY)
    assert caught.value.code == 'malformed_response'


async def scenario(content=None, *, mode='ok', factory=None, calls=None):
    calls = [] if calls is None else calls
    identity = {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436', 'label_mac': MAC}
    async def handle(request):
        calls.append((request.method, request.path, request.query_string, await request.text()))
        if request.path == '/login.cgi':
            return web.json_response({'asus_token': 'synthetic-token'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            return web.json_response(identity)
        if request.path == '/ajax_onboarding.asp':
            if mode == 'redirect':
                raise web.HTTPFound('http://example.invalid/secret')
            return web.Response(text=js([NODE]) if content is None else content, content_type='application/javascript')
        raise AssertionError('unreviewed endpoint')
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    await web.SockSite(runner, sock).start()
    cfg = TransportConfig('127.0.0.1', 'synthetic-admin', use_ssl=False, allow_plain_http=True, port=port)
    try:
        return await collect_native(cfg, 'synthetic-password', ('aimesh',), fingerprint_key=KEY, router_factory=factory), calls
    finally:
        await runner.cleanup()


def test_pristine_upstream_aimesh_post_js_reader_no_body_or_scan():
    from router_agent.output import safe_data
    result, calls = asyncio.run(scenario())
    assert [(m, p, q) for m, p, q, _ in calls] == [('POST', '/login.cgi', ''), ('POST', '/appGet.cgi', ''), ('POST', '/ajax_onboarding.asp', ''), ('POST', '/Logout.asp', '')]
    assert calls[2][3] == ''
    assert result['data']['aimesh']['count'] == 1
    assert result['sources']['aimesh']['freshness'] == 'unknown'
    assert safe_data(result) == result
    assert 'synthetic-secret' not in json.dumps(result)


@pytest.mark.parametrize('content,code', [('{"error_status":2,"password":"synthetic-secret"}', 'auth_2'), ('error_status = 2;\n' + js([NODE]), 'auth_2'), ('error_status = 7;', 'auth_7'), ('error_status = 10;', 'auth_10'), ('error_status = 999;\n' + js([NODE]), 'native_status_failed'), ('<html><form>synthetic-secret</form></html>', 'malformed_response'), ('get_cfg_clientlist = [[', 'malformed_response'), ('get_cfg_clientlist = null;', 'malformed_response'), ('get_allclientlist = [{}][0];', 'malformed_response')])
def test_auth_html_malformed_missing_null_fail_closed_no_retry(content, code, caplog):
    caplog.set_level(logging.DEBUG)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(content, calls=calls))
    assert caught.value.code == code
    assert sum(path == '/login.cgi' for _, path, _, _ in calls) == 1
    assert sum(path == '/ajax_onboarding.asp' for _, path, _, _ in calls) == 1
    assert 'synthetic-secret' not in caplog.text


def test_aimesh_redirect_never_followed():
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(mode='redirect', calls=calls))
    assert caught.value.code == 'redirect_blocked'
    assert sum(path == '/ajax_onboarding.asp' for _, path, _, _ in calls) == 1


@pytest.mark.parametrize('method,query', [('GET', ''), ('POST', '?action=apply')])
def test_aimesh_guard_rejects_wrong_method_or_query(method, query):
    async def run():
        guard = RequestGuard(TransportConfig('router.example', 'synthetic'), allow_aimesh=True)
        guard.authenticated = True
        with pytest.raises(RouterError):
            await guard.start(None, None, SimpleNamespace(url='https://router.example/ajax_onboarding.asp' + query, method=method))
    asyncio.run(run())


def test_aimesh_guard_auth_selected_group_and_one_call():
    async def run():
        cfg = TransportConfig('router.example', 'synthetic')
        params = SimpleNamespace(url='https://router.example/ajax_onboarding.asp', method='POST')
        with pytest.raises(RouterError):
            await RequestGuard(cfg).start(None, None, params)
        guard = RequestGuard(cfg, allow_aimesh=True)
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, params)
        assert caught.value.code == 'auth_required'
        guard.authenticated = True
        await guard.start(None, None, params)
        with pytest.raises(RouterError):
            await guard.start(None, None, params)
    asyncio.run(run())


def test_nonempty_aimesh_body_rejected_before_server():
    from asusrouter import AsusRouter
    class BodyRouter(AsusRouter):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.test_session = kwargs['session']
            self.test_url = f"http://{kwargs['hostname']}:{kwargs['port']}/ajax_onboarding.asp"
        async def async_api_load(self, endpoint, request='', retry=0):
            if endpoint.value == 'ajax_onboarding.asp':
                return await self.test_session.post(self.test_url, data='forbidden')
            return await super().async_api_load(endpoint, request, retry)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(factory=BodyRouter, calls=calls))
    assert caught.value.code == 'read_boundary'
    assert all(path != '/ajax_onboarding.asp' for _, path, _, _ in calls)
