"""Synthetic only: no real credential, endpoint, router, or keyring access."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import ssl
import sys

from aiohttp import web
import pytest
from tls_helpers import localhost_tls

from router_agent import home_observations as home

CANARY = 'private-household-canary.invalid'


def private(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


@pytest.fixture
def setup(tmp_path):
    credential = private(tmp_path / 'credential.json', {'token': 'private-token-canary'})
    config = {'source': 'home_assistant', 'origin': 'https://' + CANARY,
              'credential_file': str(credential),
              'sensors': [{'alias': 'metric_1', 'entity_id': 'sensor.private_household_canary', 'unit': 'ms'}]}
    path = private(tmp_path / 'config.json', config)
    return path, config, credential


def response(config, value='3', unit='ms', **extra):
    return {'entity_id': config['sensors'][0]['entity_id'], 'state': value,
            'last_updated': '2026-10-16T01:02:03+00:00',
            'last_changed': '2020-01-01T00:00:00Z',
            'attributes': {'unit_of_measurement': unit, 'friendly_name': CANARY, 'token': CANARY}, **extra}


class Transport:
    def __init__(self, *payloads):
        self.payloads = iter(payloads)
        self.calls = []

    def __call__(self, origin, path, headers, **limits):
        self.calls.append((origin, path, headers, limits))
        payload = next(self.payloads)
        if isinstance(payload, Exception):
            raise payload
        return payload if type(payload) is bytes else json.dumps(payload).encode()


def collect(setup, payload=None):
    path, config, _ = setup
    transport = Transport({'message': 'API running.'}, response(config) if payload is None else payload)
    return home.collect_home(path, transport=transport), transport


def test_preflight_missing_and_ready(setup, tmp_path, monkeypatch):
    path, _, _ = setup
    monkeypatch.setattr(home, 'default_config_path', lambda: tmp_path / 'absent')
    assert home.preflight()['status'] == 'blocked_access'
    assert home.preflight(path) == {'status': 'ready', 'source': 'home_assistant',
                                     'configured': True, 'credential_ready': True}
    assert home.collect_home()['request_count'] == 0


def test_ha_exact_paths_limits_units_privacy_and_no_monotonic_claim(setup):
    result, transport = collect(setup)
    assert result['status'] == 'passed'
    assert [c[1] for c in transport.calls] == ['/api/', '/api/states/sensor.private_household_canary']
    assert all(c[0] == 'https://' + CANARY and c[3] == {'timeout': 5., 'max_bytes': 1048576} for c in transport.calls)
    assert transport.calls[0][2]['Authorization'] == 'Bearer private-token-canary'
    assert result['metrics'][0]['value'] == 3
    assert result['metrics'][0]['unit'] == 'ms'
    assert result['provider_poll_freshness'] == 'unknown'
    assert result['source_version'] is None
    assert not result['credential_read_only_scope_verified']
    serialized = json.dumps(result)
    for secret in (CANARY, 'private-token-canary', 'sensor.', '2020-01-01', 'friendly_name', 'https:'):
        assert secret not in serialized


@pytest.mark.parametrize('state,status', [('unknown', 'unknown'), ('unavailable', 'unavailable'),
    ('NaN', 'non_numeric'), ('Infinity', 'non_numeric'), ('not-a-number', 'non_numeric'),
    (True, 'non_numeric'), (None, 'non_numeric'), ({'private': CANARY}, 'non_numeric'),
    ('1e999', 'non_numeric')])
def test_unknown_never_zero(setup, state, status):
    result, _ = collect(setup, response(setup[1], state))
    assert result['status'] == 'inconclusive'
    assert result['metrics'][0]['status'] == status
    assert result['metrics'][0]['value'] is None


@pytest.mark.parametrize('unit', ['s', CANARY, None, 3, {'private': CANARY}])
def test_unit_mismatch_excludes_raw_unit(setup, unit):
    result, _ = collect(setup, response(setup[1], unit=unit))
    assert result['metrics'][0]['status'] == 'unit_mismatch'
    assert result['metrics'][0]['value'] is None
    assert result['metrics'][0]['unit'] is None
    assert CANARY not in json.dumps(result)


@pytest.mark.parametrize('stamp', [CANARY, None, '2026-10-16', '2026-10-16T01:02:03', 123])
def test_invalid_source_timestamp_is_unknown(setup, stamp):
    result, _ = collect(setup, response(setup[1], last_updated=stamp))
    assert result['metrics'][0]['source_timestamp'] is None


@pytest.mark.parametrize('payload,error', [
    (b'{"state":1,"state":2}', 'malformed_json'), (b'{"value":NaN}', 'malformed_json'),
    (b'[]', 'malformed_response'), (b'not json', 'malformed_json'),
    pytest.param(b'x' * (home.MAX_RESPONSE + 1), 'response_limit', id='oversized'),
    ({'entity_id': 'sensor.wrong', 'attributes': {}}, 'malformed_response')])
def test_malformed_and_oversize_stop_without_leak(setup, payload, error):
    result, transport = collect(setup, payload)
    assert result['error'] == error
    assert result['request_count'] == len(transport.calls) == 2
    assert CANARY not in json.dumps(result)


@pytest.mark.parametrize('origin', ['http://example.invalid', 'https://user:secret@example.invalid',
    'https://example.invalid/path', 'https://example.invalid?secret=1', 'https://example.invalid#x',
    'https://example.invalid:99999', 'https://example.invalid\\@evil.invalid',
    'https://example.invalid%2Fevil', 'https://example.invalid\n', 'file:///tmp/credential'])
def test_bad_origins_never_reach_transport(setup, origin):
    path, config, _ = setup
    config['origin'] = origin
    private(path, config)
    assert home.collect_home(path, transport=lambda *a, **k: pytest.fail('request'))['status'] == 'blocked_access'


@pytest.mark.parametrize('change', [lambda c: c.update(source='both'), lambda c: c.update(history=True),
    lambda c: c.update(sensors=[]), lambda c: c['sensors'][0].update(alias=CANARY),
    lambda c: c['sensors'][0].update(entity_id='sensor.a/../../config'),
    lambda c: c['sensors'][0].update(unit=CANARY),
    lambda c: c.update(sensors=c['sensors'] * 9), lambda c: c.update(sensors=c['sensors'] * 2)])
def test_config_strict_allowlist(setup, change):
    path, config, _ = setup
    change(config)
    private(path, config)
    assert home.preflight(path)['status'] == 'blocked_access'


@pytest.mark.parametrize('error', [home.ObservationError('auth_denied'), home.ObservationError('http_error'),
    TimeoutError(CANARY), ssl.SSLError(CANARY), RuntimeError(CANARY), home.ObservationError(CANARY)])
def test_error_stops_source_no_retry(setup, error):
    transport = Transport(error, {'message': 'API running.'})
    result = home.collect_home(setup[0], transport=transport)
    assert result['status'] == 'inconclusive'
    assert result['request_count'] == len(transport.calls) == 1
    assert CANARY not in json.dumps(result)


def test_eight_sensors_nine_get_max(setup):
    path, config, _ = setup
    config['sensors'] = [{'alias': 'metric_' + str(i), 'entity_id': 'sensor.synthetic_' + str(i), 'unit': 'queries'} for i in range(1, 9)]
    private(path, config)
    payloads = [{'entity_id': s['entity_id'], 'state': '12', 'attributes': {'unit_of_measurement': 'queries'}} for s in config['sensors']]
    transport = Transport({'message': 'API running.'}, *payloads)
    result = home.collect_home(path, transport=transport)
    assert result['request_count'] == 9 and len(result['metrics']) == 8


@pytest.mark.parametrize('times,expected_count,error', [([0, 61], 0, 'budget_exhausted'),
    ([0, 0, 6], 1, 'timeout'), ([0, 0, -1], 1, 'timeout'),
    ([0, 0, 1, 60], 1, 'budget_exhausted')])
def test_deadline_and_clock_backwards(setup, times, expected_count, error):
    clock = iter(times)
    transport = Transport({'message': 'API running.'})
    result = home.collect_home(setup[0], transport=transport, clock=lambda: next(clock))
    assert result['request_count'] == expected_count
    assert result['error'] == error


def adguard(setup, schema='current'):
    path, _, credential = setup
    private(credential, {'username': 'synthetic-user', 'password': 'private-token-canary'})
    config = {'source': 'adguard', 'origin': 'https://' + CANARY, 'credential_file': str(credential), 'stats_schema': schema}
    private(path, config)
    return path


@pytest.mark.parametrize('schema,interval,unit,window_path', [('current', 86400000, 'ms', '/control/stats/config'),
    ('legacy', 1, 'days', '/control/stats_info')])
def test_adguard_aggregate_only_exact_schema_and_seconds(setup, schema, interval, unit, window_path):
    path = adguard(setup, schema)
    stats = {key: .003 if key == 'avg_processing_time' else 123 for key in home.TOTALS}
    stats.update(top_clients=[{'192.0.2.123': 4}], top_queried_domains=[{CANARY: 4}],
                 top_upstreams_responses=[{CANARY: 1}], rules=[CANARY], hosts=[CANARY])
    transport = Transport(stats, {'interval': interval, 'enabled': True, 'ignored': [CANARY]})
    result = home.collect_home(path, transport=transport)
    assert result['status'] == 'passed'
    assert [c[1] for c in transport.calls] == ['/control/stats', window_path]
    assert result['window']['unit'] == unit and result['window']['interval'] == interval
    assert result['metrics'][-1]['value'] == .003 and result['metrics'][-1]['unit'] == 's'
    for secret in (CANARY, '192.0.2.123', 'private-token-canary', 'synthetic-user', 'top_clients', 'rules', 'hosts'):
        assert secret not in json.dumps(result)


@pytest.mark.parametrize('value', [None, True, -1, 1.5, '12', 'unknown', {'private': CANARY}])
def test_adguard_missing_bad_counts_unknown(setup, value):
    path = adguard(setup)
    stats = {key: value for key in home.TOTALS}
    result = home.collect_home(path, transport=Transport(stats, {'enabled': True, 'interval': 60000}))
    assert result['status'] == 'inconclusive'
    assert result['metrics'][0]['value'] is None


def test_window_failure_never_falls_back(setup):
    path = adguard(setup)
    transport = Transport({}, home.ObservationError('http_error'), {'interval': 1})
    result = home.collect_home(path, transport=transport)
    assert result['request_count'] == 2 and result['window'] is None
    assert result['error'] == 'http_error'


def test_decreasing_counts_are_ambiguous_not_rate_or_reset(setup):
    path = adguard(setup)
    results = [home.collect_home(path, transport=Transport({k: v for k in home.TOTALS}, {'interval': 86400000, 'enabled': True})) for v in (100, 5)]
    assert [r['metrics'][0]['value'] for r in results] == [100, 5]
    assert all(r['counter_decrease_semantics'] == 'ambiguous_window_change_not_rate_or_reset_proof' for r in results)
    assert all(not r['benefit_proven'] for r in results)


@pytest.mark.parametrize('target', ['config', 'credential'])
@pytest.mark.parametrize('unsafe', ['mode', 'symlink', 'hardlink', 'fifo', 'oversize', 'directory'])
def test_unsafe_private_files(setup, tmp_path, target, unsafe):
    path, _, credential = setup
    selected = path if target == 'config' else credential
    if unsafe == 'mode':
        selected.chmod(0o644)
    elif unsafe == 'symlink':
        moved = tmp_path / 'moved'
        selected.rename(moved)
        selected.symlink_to(moved)
    elif unsafe == 'hardlink':
        os.link(selected, tmp_path / 'hard')
    elif unsafe == 'fifo':
        selected.unlink()
        os.mkfifo(selected, 0o600)
    elif unsafe == 'oversize':
        selected.write_bytes(b'x' * (home.MAX_PRIVATE + 1))
    else:
        selected.unlink()
        selected.mkdir(mode=0o600)
    assert home.preflight(path)['status'] == 'blocked_access'


def test_symlink_and_writable_ancestor(setup, tmp_path):
    path, config, credential = setup
    linked = tmp_path / 'linked'
    linked.symlink_to(tmp_path, target_is_directory=True)
    config['credential_file'] = str(linked / credential.name)
    private(path, config)
    assert home.preflight(path)['status'] == 'blocked_access'
    config['credential_file'] = str(credential)
    private(path, config)
    tmp_path.chmod(0o777)
    assert home.preflight(path)['status'] == 'blocked_access'


def test_duplicate_and_oversize_json_config(setup):
    path, _, _ = setup
    path.write_bytes(b'{"source":"home_assistant","source":"adguard"}')
    assert home.preflight(path)['status'] == 'blocked_access'


def test_private_receipt_exclusive_and_cli_stdout(setup, tmp_path, monkeypatch, capsys):
    path, _, _ = setup
    script = Path(__file__).resolve().parents[1] / 'scripts/observe_home.py'
    spec = importlib.util.spec_from_file_location('observe_home_test_cli', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / 'receipt.json'
    monkeypatch.setattr(sys, 'argv', [str(script), '--config', str(path), '--output', str(output)])
    assert module.main() == 0
    assert output.stat().st_mode & 0o777 == 0o600
    assert json.loads(output.read_text())['status'] == 'ready'
    assert CANARY not in capsys.readouterr().out
    assert module.main() == 2
    assert CANARY not in capsys.readouterr().out


@pytest.mark.parametrize('mode', ['trusted', 'untrusted', 'wrong_hostname', 'redirect', 'auth', 'oversize', 'malformed', 'encoding', 'disconnect'])
def test_synthetic_https_protocol_no_proxy_redirect_or_tls_bypass(mode, monkeypatch):
    async def run():
        seen, connections = [], []
        real_trace = home.aiohttp.TraceConfig
        def observed_trace():
            trace = real_trace()
            async def connected(session, context, params):
                connections.append(True)
            trace.on_connection_create_end.append(connected)
            return trace
        monkeypatch.setattr(home.aiohttp, 'TraceConfig', observed_trace)
        async def handle(request):
            seen.append((request.method, request.path, request.headers.get('Authorization')))
            if mode == 'disconnect':
                request.transport.close()
                return web.Response()
            if mode == 'redirect':
                return web.Response(status=302, headers={'Location': '/must-never-follow'})
            if mode == 'auth':
                return web.Response(status=401)
            if mode == 'oversize':
                return web.Response(body=b'x' * (home.MAX_RESPONSE + 1), content_type='application/json')
            if mode == 'malformed':
                return web.Response(text='private error', content_type='text/plain')
            if mode == 'encoding':
                return web.Response(body=b'encoded', headers={'Content-Encoding': 'gzip'}, content_type='application/json')
            return web.json_response({'message': 'API running.'})
        with localhost_tls(san='DNS:wrong.invalid' if mode == 'wrong_hostname' else 'IP:127.0.0.1,DNS:localhost') as (context, ca):
            if mode != 'untrusted':
                monkeypatch.setenv('SSL_CERT_FILE', ca)
            else:
                monkeypatch.delenv('SSL_CERT_FILE', raising=False)
            monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
            monkeypatch.setenv('https_proxy', 'http://127.0.0.1:1')
            monkeypatch.setenv('NO_PROXY', '')
            app = web.Application()
            app.router.add_route('*', '/{path:.*}', handle)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, '127.0.0.1', 0, ssl_context=context)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            try:
                call = home._https_get('https://127.0.0.1:' + str(port), '/api/',
                                       {'Authorization': 'Bearer synthetic-only'}, 2, home.MAX_RESPONSE)
                if mode == 'trusted':
                    assert json.loads(await call) == {'message': 'API running.'}
                else:
                    with pytest.raises(Exception) as caught:
                        await call
                    if mode == 'disconnect':
                        assert isinstance(caught.value, home.ObservationError)
                        assert str(caught.value) == 'retry_rejected'
                assert len(connections) == (0 if mode in ('wrong_hostname', 'untrusted') else 1)
                assert seen == ([] if mode in ('wrong_hostname', 'untrusted') else [('GET', '/api/', 'Bearer synthetic-only')])
            finally:
                await runner.cleanup()
    asyncio.run(run())


@pytest.mark.parametrize('schema,window', [('current', {}), ('current', {'interval': '60000', 'enabled': True}),
    ('current', {'interval': 60000, 'enabled': 'true'}), ('current', {'interval': -1, 'enabled': True}),
    ('legacy', {'interval': 42}), ('legacy', {'interval': True})])
def test_unknown_window_never_becomes_success_or_zero(setup, schema, window):
    path = adguard(setup, schema)
    result = home.collect_home(path, transport=Transport({k: 1 for k in home.TOTALS}, window))
    assert result['status'] == 'inconclusive'
    assert result['window']['interval'] is None or result['window']['enabled'] is None


@pytest.mark.parametrize('change', ['mutation', 'replacement', 'owner'])
def test_private_read_detects_mutation_replacement_and_wrong_owner(setup, monkeypatch, change):
    path, _, _ = setup
    real_read, real_fstat = os.read, os.fstat
    if change == 'owner':
        def fake_fstat(fd):
            st = real_fstat(fd)
            values = list(st)
            if home.stat.S_ISREG(st.st_mode):
                values[4] = os.getuid() + 1
            return os.stat_result(values)
        monkeypatch.setattr(home.os, 'fstat', fake_fstat)
    else:
        once = False
        def fake_read(fd, size):
            nonlocal once
            data = real_read(fd, size)
            if not once:
                once = True
                if change == 'mutation':
                    with path.open('ab') as stream:
                        stream.write(b' ')
                else:
                    path.unlink()
                    private(path, {'private': CANARY})
            return data
        monkeypatch.setattr(home.os, 'read', fake_read)
    assert home.preflight(path)['status'] == 'blocked_access'


@pytest.mark.parametrize('bad', [{'token': 'secret\r\nInjected: yes'}, {'token': ''}, {'token': 23},
    {'token': 'valid', 'source': CANARY}, {'password': 'private'}])
def test_credential_shape_and_header_injection_fail_closed(setup, bad):
    path, _, credential = setup
    private(credential, bad)
    assert home.collect_home(path, transport=lambda *a, **k: pytest.fail('request'))['status'] == 'blocked_access'


def test_api_probe_shape_failure_stops_sensor_calls(setup):
    transport = Transport({'message': CANARY}, {})
    result = home.collect_home(setup[0], transport=transport)
    assert result['status'] == 'inconclusive' and result['request_count'] == 1
    assert result['error'] == 'malformed_response'
    assert CANARY not in json.dumps(result)


def test_remaining_overall_deadline_caps_request_timeout(setup):
    times = iter([0, 58, 59, 59.5, 59.9])
    transport = Transport({'message': 'API running.'}, response(setup[1]))
    result = home.collect_home(setup[0], transport=transport, clock=lambda: next(times))
    assert result['status'] == 'passed'
    assert [c[3]['timeout'] for c in transport.calls] == [2, .5]


def test_synthetic_https_slow_body_obeys_total_timeout(monkeypatch):
    async def run():
        seen = []
        async def handle(request):
            seen.append(request.path)
            response = web.StreamResponse(headers={'Content-Type': 'application/json'})
            await response.prepare(request)
            await response.write(b'{')
            await asyncio.sleep(.15)
            return response
        with localhost_tls() as (context, ca):
            monkeypatch.setenv('SSL_CERT_FILE', ca)
            app = web.Application()
            app.router.add_route('GET', '/api/', handle)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, '127.0.0.1', 0, ssl_context=context)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            try:
                with pytest.raises(TimeoutError):
                    await home._https_get('https://127.0.0.1:' + str(port), '/api/', {}, .05, home.MAX_RESPONSE)
                assert seen == ['/api/']
            finally:
                await runner.cleanup()
    asyncio.run(run())


@pytest.mark.parametrize('unit,value,status', [('queries', '-1', 'invalid_value'),
    ('requests', '2.5', 'invalid_value'), ('count', '-3', 'invalid_value'),
    ('rules', '1.2', 'invalid_value'), ('ms', '-1', 'invalid_value'),
    ('s', '-1', 'invalid_value'), ('MiB', '-1', 'invalid_value'),
    ('%', '100.1', 'invalid_value'), ('%', '-.1', 'invalid_value'),
    ('°C', '-12', 'ok'), ('queries', '0', 'ok'), ('rules', '2', 'ok'), ('%', '100', 'ok')])
def test_ha_unit_aware_numeric_bounds(setup, unit, value, status):
    path, config, _ = setup
    config['sensors'][0]['unit'] = unit
    private(path, config)
    result, _ = collect(setup, response(config, value=value, unit=unit))
    assert result['metrics'][0]['status'] == status
    assert (result['metrics'][0]['value'] is None) == (status != 'ok')
