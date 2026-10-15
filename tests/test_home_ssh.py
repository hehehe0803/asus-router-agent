"""Synthetic SSH runners / standard-library HTTP fixtures; never actual SSH."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import urllib.error
import urllib.request

import pytest
from router_agent import home_ssh as home
from router_agent.home_observations import write_observation

SECRET = 'TokenSentinelPrivate'
CANARY = 'private-household-canary.invalid'


def private(path, content, mode=0o600):
    path.write_text(content)
    path.chmod(mode)
    return path


@pytest.fixture
def setup(tmp_path):
    key = private(tmp_path / 'key', 'synthetic-key-not-real')
    hosts = private(tmp_path / 'knownhosts', 'synthetic-not-real', 0o644)
    env = private(tmp_path / 'env', 'OTHER_VALUE=not-a-token\nexport HASS_TOKEN="' + SECRET + '" # note\n')
    config = {'host': 'ha.example.invalid', 'user': 'synthetic', 'keyfile': str(key),
              'knownhostsfile': str(hosts), 'hass_env_file': str(env),
              'sensors': [{'alias': 'metric_1', 'entity_id': 'sensor.private_canary', 'unit': 'queries'}]}
    path = private(tmp_path / 'config', json.dumps(config))
    return path, config


def remote_reply(config, **updates):
    states = [{'entity_id': s['entity_id'], 'state': '12', 'attributes': {'unit_of_measurement': s['unit']},
               'last_updated': '2026-10-16T01:02:03Z'} for s in config['sensors']]
    result = {'protocol': 1, 'authenticated_api': True, 'request_count': len(states) + 1, 'states': states, 'error': None}
    result.update(updates)
    return result


class Runner:
    def __init__(self, payload):
        self.payload, self.calls = payload, []

    def __call__(self, argv, request, **limits):
        self.calls.append((argv, request, limits))
        return {'status': 'completed', 'returncode': 0,
                'stdout': self.payload if type(self.payload) is bytes else json.dumps(self.payload).encode()}


def test_exact_ssh_argv_no_token_shell_proxy_or_hooks(setup):
    path, config = setup
    runner = Runner(remote_reply(config))
    result = home.collect_home_ssh(path, runner=runner)
    assert result['status'] == 'passed'
    assert len(runner.calls) == 1
    argv, request, limits = runner.calls[0]
    assert argv[:3] == ['/usr/bin/ssh', '-F', '/dev/null']
    assert argv[-8:] == ['-i', config['keyfile'], '-a', '-x', '-T', '--', 'synthetic@ha.example.invalid', home.REMOTE_COMMAND]
    options = [argv[i + 1] for i, arg in enumerate(argv) if arg == '-o']
    assert options == ['UpdateHostKeys=no', 'ControlMaster=no', 'ControlPath=none',
        'GlobalKnownHostsFile=/dev/null', 'UserKnownHostsFile=' + config['knownhostsfile'],
        'StrictHostKeyChecking=yes', 'BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none',
        'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no', 'ProxyCommand=none',
        'ProxyJump=none', 'PermitLocalCommand=no', 'ClearAllForwardings=yes', 'ConnectionAttempts=1', 'ConnectTimeout=5']
    assert SECRET not in repr(argv) and config['sensors'][0]['entity_id'] not in repr(argv)
    assert json.loads(request) == {'token': SECRET, 'entities': ['sensor.private_canary']}
    assert 0 < limits['timeout'] <= 70 and limits['max_output'] == 65536
    assert result['provider_poll_freshness'] == 'unknown'
    assert not result['credential_read_only_scope_verified'] and not result['benefit_proven']
    for private_value in (SECRET, 'sensor.', CANARY, config['host'], config['keyfile'], 'stderr'):
        assert private_value not in json.dumps(result)


@pytest.mark.parametrize('field,value', [('host', '-oProxyCommand=evil'), ('host', 'a;touch /tmp/x'),
    ('host', 'user@host'), ('host', 'a\nb'), ('host', '::'), ('host', '224.0.0.1'),
    ('user', '-root'), ('user', 'a@host'), ('user', 'a;echo'), ('keyfile', '-i bad'),
    ('knownhostsfile', '/tmp/../etc/hosts'), ('knownhostsfile', '/tmp/a otherfile'),
    ('knownhostsfile', '/tmp/%h'), ('knownhostsfile', '/tmp/quote"file'), ('hass_env_file', '/tmp/has\nnewline')])
def test_config_injection_rejected_without_runner(setup, field, value):
    path, config = setup
    config[field] = value
    private(path, json.dumps(config))
    assert home.collect_home_ssh(path, runner=lambda *a, **k: pytest.fail('runner'))['status'] == 'blocked_access'


@pytest.mark.parametrize('change', [lambda c: c.update(source='ha'), lambda c: c.update(command='evil'),
    lambda c: c.update(sensors=[]), lambda c: c.update(sensors=c['sensors'] * 9),
    lambda c: c['sensors'][0].update(alias=CANARY), lambda c: c['sensors'][0].update(unit=CANARY),
    lambda c: c['sensors'][0].update(entity_id='sensor.a/../config')])
def test_config_exact_fields_sensor_budget(setup, change):
    path, config = setup
    change(config)
    private(path, json.dumps(config))
    assert home.preflight(path)['status'] == 'blocked_access'


@pytest.mark.parametrize('field', ['keyfile', 'knownhostsfile', 'hass_env_file'])
@pytest.mark.parametrize('unsafe', ['symlink', 'hardlink', 'fifo', 'mode', 'oversize', 'directory'])
def test_unsafe_selected_files(setup, tmp_path, field, unsafe):
    path, config = setup
    selected = Path(config[field])
    if unsafe == 'symlink':
        moved = tmp_path / 'moved'
        selected.rename(moved)
        selected.symlink_to(moved)
    elif unsafe == 'hardlink':
        os.link(selected, tmp_path / 'hard')
    elif unsafe == 'mode':
        selected.chmod(0o666)
    elif unsafe == 'fifo':
        selected.unlink()
        os.mkfifo(selected, 0o600)
    elif unsafe == 'directory':
        selected.unlink()
        selected.mkdir()
    else:
        selected.write_bytes(b'x' * 1048577)
    assert home.preflight(path)['status'] == 'blocked_access'


def test_missing_config_and_writable_ancestor(setup, tmp_path, monkeypatch):
    monkeypatch.setattr(home, 'default_config_path', lambda: tmp_path / 'absent')
    assert home.preflight()['status'] == 'blocked_access'
    assert home.preflight(setup[0])['status'] == 'ready'
    tmp_path.chmod(0o777)
    assert home.preflight(setup[0])['status'] == 'blocked_access'


@pytest.mark.parametrize('text', ['HASS_TOKEN=one\nHASS_TOKEN=two', 'OTHER_TOKEN=secret',
    'HASS_TOKEN=$(touch /tmp/must-not-exist)', 'echo HASS_TOKEN=secret', 'HASS_TOKEN=""',
    'HASS_TOKEN="bad token"', 'HASS_TOKEN=good extra', 'HASS_TOKEN="unterminated'])
def test_token_parsing_never_executes_or_expands(text):
    with pytest.raises(home.ObservationError, match='invalid_credentials'):
        home._token(text.encode())


@pytest.mark.parametrize('text', ['HASS_TOKEN=synthetic_token', 'export HASS_TOKEN="synthetic_token" # ignored',
    "OTHER='ignored value'\nHASS_TOKEN='synthetic_token'\n"])
def test_token_shlex_selected_assignment_only(text):
    assert home._token(text.encode()) == 'synthetic_token'


@pytest.mark.parametrize('updates', [{'protocol': True}, {'protocol': 2}, {'states': []}, {'request_count': 10},
    {'request_count': True}, {'authenticated_api': False}, {'error': CANARY}, {'extra': CANARY}])
def test_protocol_invalid_cardinality_no_leak(setup, updates):
    runner = Runner(remote_reply(setup[1], **updates))
    result = home.collect_home_ssh(setup[0], runner=runner)
    assert result['status'] == 'inconclusive' and result['error'] == 'malformed_response'
    assert len(runner.calls) == 1 and SECRET not in json.dumps(result) and CANARY not in json.dumps(result)


@pytest.mark.parametrize('raw,error', [(b'{"value":NaN}', 'malformed_json'),
    (b'{"a":1,"a":2}', 'malformed_json'), (b'not json', 'malformed_json'),
    pytest.param(b'x' * 65537, 'output_limit', id='oversized')])
def test_malformed_and_output_bound(setup, raw, error):
    result = home.collect_home_ssh(setup[0], runner=Runner(raw))
    assert result['status'] == 'inconclusive' and result['error'] == error


@pytest.mark.parametrize('state,unit,status', [('unknown', 'queries', 'unknown'),
    ('unavailable', 'queries', 'unavailable'), ('-1', 'queries', 'invalid_value'),
    ('1.5', 'queries', 'invalid_value'), ('NaN', 'queries', 'non_numeric'),
    ('1', 'ms', 'unit_mismatch')])
def test_units_and_unknown_never_zero(setup, state, unit, status):
    data = remote_reply(setup[1])
    data['states'][0].update(state=state, attributes={'unit_of_measurement': unit})
    result = home.collect_home_ssh(setup[0], runner=Runner(data))
    assert result['metrics'][0]['status'] == status
    assert result['metrics'][0]['value'] is None


def test_unexpected_raw_attributes_or_entity_fail_closed(setup):
    for mutate in (lambda s: s['attributes'].update(friendly_name=CANARY),
                   lambda s: s.update(entity_id='sensor.other')):
        data = remote_reply(setup[1])
        mutate(data['states'][0])
        result = home.collect_home_ssh(setup[0], runner=Runner(data))
        assert result['error'] == 'malformed_response'
        assert CANARY not in json.dumps(result)


@pytest.mark.parametrize('error', sorted(home.ERRORS))
def test_remote_error_stops_one_session_no_retry(setup, error):
    runner = Runner(remote_reply(setup[1], states=[], request_count=1, authenticated_api=False, error=error))
    result = home.collect_home_ssh(setup[0], runner=runner)
    assert result['status'] == 'inconclusive' and result['error'] == error
    assert len(runner.calls) == 1


@pytest.mark.parametrize('times,count,error', [([0, 71], 0, 'budget_exhausted'),
    ([0, 0, 71], 1, 'timeout'), ([0, 0, -1], 1, 'timeout')])
def test_local_total_deadline(setup, times, count, error):
    clock = iter(times)
    runner = Runner(remote_reply(setup[1]))
    result = home.collect_home_ssh(setup[0], runner=runner, clock=lambda: next(clock))
    assert result['error'] == error and len(runner.calls) == count


@pytest.mark.parametrize('mode', ['ok', 'timeout', 'overflow', 'stderr_overflow', 'nonzero'])
def test_actual_synthetic_child_executor_limits_env_stdin_and_reaping(mode, monkeypatch):
    real_popen, children, calls = subprocess.Popen, [], []
    def launch(argv, **kwargs):
        calls.append(kwargs)
        child = real_popen(argv, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(home.subprocess, 'Popen', launch)
    monkeypatch.setenv('HASS_TOKEN', SECRET)
    commands = {
        'ok': 'import sys,os,json; data=sys.stdin.buffer.read(); print(json.dumps({"input":len(data),"env":dict(os.environ)}))',
        'timeout': 'import time; time.sleep(30)',
        'overflow': 'import sys,time; sys.stdout.write("x"*100000); sys.stdout.flush(); time.sleep(30)',
        'stderr_overflow': 'import sys,time; sys.stderr.write("x"*100000); sys.stderr.flush(); time.sleep(30)',
        'nonzero': 'import sys; sys.stdin.buffer.read(); sys.exit(7)'}
    result = home.execute_ssh([sys.executable, '-c', commands[mode]], SECRET.encode(),
                              timeout=.15 if mode == 'timeout' else 2, max_output=4096)
    assert len(children) == 1 and children[0].poll() is not None
    assert calls[0]['env'] == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    assert not calls[0]['shell'] and calls[0]['start_new_session']
    assert SECRET not in json.dumps({k: v for k, v in result.items() if k != 'stdout'})
    if mode == 'ok':
        output = json.loads(result['stdout'])
        assert output['input'] == len(SECRET) and 'HASS_TOKEN' not in output['env']
    elif mode == 'nonzero':
        assert result['returncode'] == 7
    else:
        assert result['status'] == ('timeout' if mode == 'timeout' else 'output_limit')
        assert result['stdout'] == b'' and children[0].returncode == -signal.SIGKILL


def test_cli_preflight_receipt_and_sanitized_stdout(setup, tmp_path, monkeypatch, capsys):
    script = Path(__file__).resolve().parents[1] / 'scripts/observe_home_ssh.py'
    spec = importlib.util.spec_from_file_location('home_ssh_cli_test', script)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    receipt = tmp_path / 'receipt'
    monkeypatch.setattr(sys, 'argv', [str(script), '--config', str(setup[0]), '--output', str(receipt)])
    assert cli.main() == 0
    assert receipt.stat().st_mode & 0o777 == 0o600
    assert SECRET not in receipt.read_text() + capsys.readouterr().out
    assert cli.main() == 2


@pytest.mark.parametrize('mode', ['success', 'auth', 'redirect', 'oversize', 'malformed', 'wrong_entity', 'transport'])
def test_constant_remote_program_get_only_loopback_sanitizes_and_stops(setup, mode, monkeypatch):
    calls, timers, handlers = [], [], []
    class Reply(io.BytesIO):
        status = 200
        def __init__(self, payload):
            super().__init__(payload)
            from email.message import Message
            self.headers = Message()
            self.headers['Content-Type'] = 'application/json'
    class Opener:
        def open(self, request, timeout):
            calls.append((request, timeout))
            assert request.get_method() == 'GET'
            assert request.full_url in ('http://127.0.0.1:8123/api/', 'http://127.0.0.1:8123/api/states/sensor.private_canary')
            assert request.headers['Authorization'] == 'Bearer ' + SECRET
            if mode == 'auth':
                raise urllib.error.HTTPError(request.full_url, 401, SECRET, {}, None)
            if mode == 'transport':
                raise RuntimeError(SECRET)
            if mode == 'redirect':
                handlers[1].redirect_request(request, None, 302, SECRET, {}, 'http://evil.invalid')
            if mode == 'oversize':
                return Reply(b'x' * 1048577)
            if mode == 'malformed':
                return Reply(b'{"value":NaN}')
            if len(calls) == 1:
                return Reply(b'{"message":"API running."}')
            state = {'entity_id': 'sensor.private_canary' if mode != 'wrong_entity' else 'sensor.other',
                     'state': '4', 'last_updated': '2026-10-16T01:02:03Z',
                     'attributes': {'unit_of_measurement': 'queries', 'friendly_name': CANARY, 'token': SECRET, 'private_ip': '192.0.2.123'}}
            return Reply(json.dumps(state).encode())
    def build(*args):
        handlers.extend(args)
        return Opener()
    monkeypatch.setattr(urllib.request, 'build_opener', build)
    monkeypatch.setattr(signal, 'signal', lambda *a: None)
    monkeypatch.setattr(signal, 'setitimer', lambda *a: timers.append(a))
    request = json.dumps({'token': SECRET, 'entities': ['sensor.private_canary']}).encode()
    monkeypatch.setattr(sys, 'stdin', type('In', (), {'buffer': io.BytesIO(request)})())
    out = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', out)
    exec(compile(home.REMOTE_PROGRAM, '<fixed-remote-test>', 'exec'), {})
    data = json.loads(out.getvalue())
    assert handlers[0].proxies == {}
    assert all(0 < timeout <= 5 for _, timeout in calls)
    assert all(0 <= timer[1] <= 5 for timer in timers)
    assert data['request_count'] == len(calls) <= 2
    assert SECRET not in out.getvalue() and CANARY not in out.getvalue() and '192.0.2.123' not in out.getvalue()
    if mode == 'success':
        assert data['error'] is None and len(data['states']) == 1
        assert set(data['states'][0]['attributes']) == {'unit_of_measurement'}
    else:
        assert data['error'] in home.ERRORS and not data['states']
        assert len(calls) == (2 if mode == 'wrong_entity' else 1)


def test_eight_selected_sensors_single_process_nine_get_budget(setup):
    path, config = setup
    config['sensors'] = [{'alias': 'metric_' + str(i), 'entity_id': 'sensor.synthetic_' + str(i), 'unit': 'queries'} for i in range(1, 9)]
    private(path, json.dumps(config))
    runner = Runner(remote_reply(config))
    result = home.collect_home_ssh(path, runner=runner)
    assert result['status'] == 'passed' and result['request_count'] == 9
    assert len(result['metrics']) == 8 and len(runner.calls) == 1


@pytest.mark.parametrize('status,code', [('timeout', 0), ('output_limit', 0), ('completed', 1), ('launch_failed', None)])
def test_subprocess_failures_are_fixed_and_never_keep_stderr(setup, status, code):
    def runner(*args, **kwargs):
        return {'status': status, 'returncode': code, 'stdout': SECRET.encode(), 'stderr': CANARY.encode()}
    result = home.collect_home_ssh(setup[0], runner=runner)
    assert result['status'] == 'inconclusive'
    assert SECRET not in json.dumps(result) and CANARY not in json.dumps(result)


@pytest.mark.parametrize('mode', ['timeout', 'budget', 'eight'])
def test_remote_absolute_timer_and_get_budget_synthetic(mode, monkeypatch):
    from email.message import Message
    get_count, alarms = [], []
    class Reply(io.BytesIO):
        status = 200
        def __init__(self, data):
            super().__init__(json.dumps(data).encode())
            self.headers = Message()
            self.headers['Content-Type'] = 'application/json'
    class Opener:
        def open(self, req, timeout):
            get_count.append(req.full_url)
            if mode == 'timeout':
                alarms[0](signal.SIGALRM, None)
            if req.full_url.endswith('/api/'):
                return Reply({'message': 'API running.'})
            entity = req.full_url.rsplit('/', 1)[1]
            return Reply({'entity_id': entity, 'state': '4', 'attributes': {'unit_of_measurement': 'queries'}})
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *args: Opener())
    monkeypatch.setattr(signal, 'signal', lambda sig, handler: alarms.append(handler))
    monkeypatch.setattr(signal, 'setitimer', lambda *args: None)
    # Freeze the remote monotonic clock to exhaust its deadline before first GET.
    if mode == 'budget':
        times = iter([0, 61])
        monkeypatch.setattr(home.time, 'monotonic', lambda: next(times))
    entities = ['sensor.synthetic_' + str(i) for i in range(1, 9)]
    request = json.dumps({'token': SECRET, 'entities': entities}).encode()
    monkeypatch.setattr(sys, 'stdin', type('In', (), {'buffer': io.BytesIO(request)})())
    out = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', out)
    exec(compile(home.REMOTE_PROGRAM, '<synthetic-fixed-remote>', 'exec'), {})
    result = json.loads(out.getvalue())
    assert SECRET not in out.getvalue()
    if mode == 'timeout':
        assert result['error'] == 'timeout' and len(get_count) == 1
    elif mode == 'budget':
        assert result['error'] == 'budget_exhausted' and not get_count
    else:
        assert result['error'] is None and len(get_count) == result['request_count'] == 9
        assert len(result['states']) == 8
