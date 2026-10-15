import asyncio
import json
import socket
from types import SimpleNamespace
from urllib.parse import unquote

from aiohttp import web
import pytest

from router_agent.errors import RouterError
from router_agent.network_reads import NETWORK_HOOK, normalize_network
from router_agent.transport import HOOKS, RequestGuard, TransportConfig, collect_native

RAW = {'netdev': {'INTERNET_rx': '0x10', 'INTERNET_tx': '0x20', 'WIRELESS0_rx': 'fF', 'WIRELESS0_tx': '10', 'eth-secret_rx': 'synthetic-secret', 'password': 'synthetic-secret'}, 'password': 'synthetic-secret'}


def test_selected_names_hex_encoding_and_privacy():
    result = normalize_network(RAW)
    assert result['interfaces'] == [{'interface': 'wan', 'rx_bytes': 16, 'tx_bytes': 32}, {'interface': '2ghz', 'rx_bytes': 255, 'tx_bytes': 16}]
    assert result['scope'] == 'native_cumulative_byte_counters'
    encoded = json.dumps(result)
    assert 'synthetic-secret' not in encoded and 'eth-secret' not in encoded
    assert 'speed' not in encoded and 'fresh' not in encoded
    assert 'effective_egress_not_verified' in result['gaps']


def test_null_missing_and_empty_do_not_become_zero():
    result = normalize_network({'netdev': {'WIRED_rx': None}})
    assert result['interfaces'] == [{'interface': 'wired', 'rx_bytes': None, 'tx_bytes': None}]
    assert 'selected_counter_missing_or_unknown' in result['gaps']
    result = normalize_network({'netdev': {}})
    assert result['interfaces'] == []
    assert 'no_named_counters_returned' in result['gaps']


def test_all_fixed_groups_are_bounded_and_zero_is_observed():
    from asusrouter.modules.endpoint.hook_const import MAP_NETWORK
    counters = {f'{native}_{direction}': '0x0' for native in MAP_NETWORK for direction in ('rx', 'tx')}
    result = normalize_network({'netdev': counters})
    assert len(result['interfaces']) == 10
    assert [r['interface'] for r in result['interfaces']] == list(MAP_NETWORK.values())
    assert all(row['rx_bytes'] == 0 and row['tx_bytes'] == 0 for row in result['interfaces'])


@pytest.mark.parametrize('value', ['-1', -1, True, 1.5, '1.5', '0xG', '0x10000000000000000', 2**64, 'synthetic-secret', '0x' + '0' * 1000, [], {}])
def test_malformed_negative_oversized_and_nonintegral_counters_fail(value):
    with pytest.raises(RouterError) as caught:
        normalize_network({'netdev': {'INTERNET_rx': value}})
    assert caught.value.code == 'malformed_response'


@pytest.mark.parametrize('raw', [None, [], {}, {'netdev': None}, {'netdev': []}, {'netdev': 'secret'}])
def test_malformed_source_fails(raw):
    with pytest.raises(RouterError):
        normalize_network(raw)


def test_uint64_boundary_and_public_native_integer_form():
    result = normalize_network({'netdev': {'INTERNET_rx': '0xffffffffffffffff', 'INTERNET_tx': 2**64 - 1}})
    assert result['interfaces'][0]['rx_bytes'] == result['interfaces'][0]['tx_bytes'] == 2**64 - 1


async def scenario(raw=RAW, calls=None):
    calls = [] if calls is None else calls
    async def handler(request):
        payload = unquote(await request.text())
        calls.append((request.method, request.path, payload))
        if request.path == '/login.cgi':
            return web.json_response({'asus_token': 'synthetic-token'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            if payload == 'hook=' + HOOKS['identity']:
                return web.json_response({'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436', 'label_mac': 'AA:BB:CC:DD:EE:FF'})
            assert payload == 'hook=' + NETWORK_HOOK
            return web.json_response(raw)
        raise AssertionError('unreviewed endpoint')
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    await web.SockSite(runner, sock).start()
    cfg = TransportConfig('127.0.0.1', 'synthetic-admin', use_ssl=False, allow_plain_http=True, port=port)
    try:
        return await collect_native(cfg, 'synthetic-password', ('network',), fingerprint_key=b'k' * 32), calls
    finally:
        await runner.cleanup()


def test_pristine_upstream_network_hook_exact_sequence_without_discovery():
    result, calls = asyncio.run(scenario())
    assert [(method, path) for method, path, _ in calls] == [('POST', '/login.cgi'), ('POST', '/appGet.cgi'), ('POST', '/appGet.cgi'), ('POST', '/Logout.asp')]
    assert calls[2][2] == 'hook=netdev(appobj);'
    assert result['sources']['network']['freshness'] == 'unknown'
    assert result['sources']['network']['observed_at'] is None
    assert result['data']['network']['interfaces'][0]['rx_bytes'] == 16
    assert 'synthetic-secret' not in json.dumps(result)


def test_actual_malformed_counter_does_not_return_healthy_snapshot():
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario({'netdev': {'INTERNET_rx': 'synthetic-secret'}}, calls))
    assert caught.value.code == 'malformed_response'
    assert sum(path == '/login.cgi' for _, path, _ in calls) == 1
    assert sum(payload == 'hook=' + NETWORK_HOOK for _, _, payload in calls) == 1


def test_guard_only_allows_exact_netdev_hook_not_arbitrary_interface():
    async def run():
        guard = RequestGuard(TransportConfig('router.example', 'synthetic'), (NETWORK_HOOK,))
        guard.authenticated = True
        await guard.chunk(None, None, SimpleNamespace(url='https://router.example/appGet.cgi', chunk=b'hook%3Dnetdev%28appobj%29%3B'))
        for payload in (b'hook=netdev(secret);', b'hook=netdev(appobj);nvram_get(password);'):
            with pytest.raises(RouterError):
                await guard.chunk(None, None, SimpleNamespace(url='https://router.example/appGet.cgi', chunk=payload))
    asyncio.run(run())
