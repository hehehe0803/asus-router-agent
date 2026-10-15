"""Synthetic DNS-only fixtures. Never execute dig or read host resolver/private state."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess

import pytest

from router_agent import dns_baseline as dns
from router_agent.network_measurements import (MeasurementError, read_private_json,
    create_output_directory, write_private_result)


class Clock:
    def __init__(self):
        self.value = 10.0
        self.origin = datetime(2026, 10, 16, tzinfo=timezone.utc)

    def monotonic(self):
        return self.value

    def utc(self):
        return self.origin + timedelta(seconds=self.value - 10) if math.isfinite(self.value) else self.origin


def reply(rcode='NOERROR', latency=7):
    payload = (f';; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: 4\n'
        ';; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n'
        f';; Query time: {latency} msec\n').encode()
    return {'status': 'completed', 'returncode': 0, 'stdout': payload,
        'stderr': b'', 'output_bytes': len(payload)}


def run(executor=None, clock=None, **kwargs):
    clock = clock or Clock()
    if executor is None:
        def executor(argv, **_):
            clock.value += .01
            return reply('NXDOMAIN' if argv[4].startswith('m') else 'NOERROR')
    return dns.observe_baseline(dns.make_system_config(), resolv_conf_text='nameserver 127.0.0.53\n',
        execute=executor, monotonic=clock.monotonic, utc_clock=clock.utc,
        run_id='a' * 32, dig_path='/synthetic/dig', **kwargs)


def test_fixed_workload_single_attempt_and_sanitized_result():
    calls = []
    clock = Clock()
    def execute(argv, **options):
        calls.append((argv, options))
        clock.value += .01
        return reply('NXDOMAIN' if argv[4].startswith('m') else 'NOERROR')
    result = run(execute, clock)
    assert len(calls) == result['calls'] == 46
    assert len(set(call[0][4] for call in calls[:25])) == 25
    assert all(call[0][4].endswith('.example.com.') for call in calls[:25])
    assert all(call[0][4] == 'example.com.' for call in calls[25:])
    for argv, options in calls:
        assert argv[:4] == ['/synthetic/dig', '-r', '@127.0.0.53', '-q']
        assert argv[5:] == ['-t', 'A', '-c', 'IN', '+notcp', '+ignore', '+nosearch',
            '+tries=1', '+retry=0', '+nobadcookie', '+nocookie', '+time=5', '+noall', '+comments', '+stats']
        assert options == {'timeout': 6, 'max_output': 4096}
    assert result['resolver_kind'] == 'local_stub'
    assert result['path'] == result['upstream_identity'] == result['freshness'] == 'unknown'
    assert result['sampling_quality_passed'] is True
    assert result['overall_gain_established'] is False
    serialized = json.dumps(result)
    for private in ('127.0.0.53', 'example.com', 'a' * 32, 'HEADER', 'fingerprint', '"stage"', 'p95', 'p99'):
        assert private not in serialized
    assert result['workloads']['warm']['aggregate']['requested'] == 20
    assert result['workloads']['unique_negative']['aggregate']['requested'] == 25
    assert result['unit'] == 'ms'


@pytest.mark.parametrize('text,expected', [
    ('nameserver 127.0.0.53\nnameserver 127.0.0.53 # same\n', '127.0.0.53'),
    ('search secret.invalid\nnameserver ::1\n', '::1'),
    ('nameserver 192.168.1.1 ; comment\n', '192.168.1.1'),
    ('nameserver 2001:db8::1\n', '2001:db8::1')])
def test_resolver_parser(text, expected):
    assert dns.select_system_resolver(text) == expected


@pytest.mark.parametrize('text,code', [
    ('', 'system_resolver_unavailable'),
    ('nameserver 192.168.1.1\nnameserver 192.168.1.2', 'ambiguous_system_resolver'),
    ('nameserver host.invalid', 'invalid_system_resolver_configuration'),
    ('nameserver 0.0.0.0', 'invalid_system_resolver_configuration'),
    ('nameserver ff02::1', 'invalid_system_resolver_configuration'),
    ('nameserver fe80::1%wlan0', 'invalid_system_resolver_configuration'),
    ('nameserver 255.255.255.255', 'invalid_system_resolver_configuration'),
    ('nameserver 127.0.0.1 extra', 'invalid_system_resolver_configuration'),
    ('nameserver 127.0.0.1\nnameserver bad', 'invalid_system_resolver_configuration'),
    ('x' * 65537, 'invalid_system_resolver_configuration')])
def test_resolver_gates_without_fallback(text, code):
    with pytest.raises(MeasurementError, match=code):
        dns.make_system_config(text)


@pytest.mark.parametrize('patch', [{'stage': 'B'}, {'stages': {}},
    {'configuration_fingerprint': 'a' * 64}, {'resolver': '1.1.1.1'},
    {'transport': 'tcp'}, {'counts': {'warm': 1}}, {'schema_version': True},
    {'mode': 'A1'}])
def test_strict_baseline_config_rejects_bindings(patch):
    with pytest.raises(MeasurementError, match='invalid_baseline_config'):
        dns.validate_config(dns.make_system_config() | patch)


@pytest.mark.parametrize('failure,state', [
    ({'status': 'timeout', 'output_bytes': 0}, 'timeout'),
    ({'status': 'completed', 'returncode': 9, 'output_bytes': 0}, 'no_reply'),
    ({'status': 'completed', 'returncode': 1, 'output_bytes': 0}, 'process_failed'),
    ({'status': 'launch_failed', 'output_bytes': 0}, 'process_failed'),
    ({'status': 'completed', 'returncode': 0, 'stdout': b'private garbage', 'output_bytes': 15}, 'malformed'),
    (reply('SERVFAIL'), 'servfail'), (reply('REFUSED'), 'unexpected_rcode'),
    ({'status': 'output_limit', 'stdout': b'x' * 4096, 'output_bytes': 4097}, 'output_limit')])
def test_failed_slots_keep_denominator_and_no_retry(failure, state):
    result = run(lambda *_, **__: failure)
    negative = result['workloads']['unique_negative']['aggregate']
    assert negative['requested'] == negative['attempted'] == negative['failed_or_missing'] == 25
    assert negative['successful_median_ms'] is None
    assert negative['state_counts'][state] == 25
    assert result['calls'] == 46
    assert result['sampling_quality_passed'] is False
    assert 'private garbage' not in json.dumps(result)


def test_deadline_accounts_for_prime_and_unattempted_slots():
    clock = Clock()
    timeouts = []
    def execute(argv, **options):
        timeouts.append(options['timeout'])
        clock.value += 4.9
        return reply('NXDOMAIN')
    result = run(execute, clock)
    assert result['calls'] == 25
    assert timeouts[-1] == pytest.approx(2.4)
    assert result['workloads']['unique_negative']['samples'][-1]['state'] == 'timeout'
    assert result['prime']['state'] == 'not_attempted_deadline'
    aggregate = result['workloads']['warm']['aggregate']
    assert aggregate['requested'] == aggregate['failed_or_missing'] == 20
    assert aggregate['attempted'] == 0
    assert result['sampling_quality_passed'] is False


@pytest.mark.parametrize('exception,state', [(subprocess.TimeoutExpired('sentinel', 5), 'timeout'),
    (OSError('secret'), 'process_failed'), (subprocess.SubprocessError('secret'), 'process_failed')])
def test_executor_exceptions_are_sanitized(exception, state):
    def execute(*_, **__):
        raise exception
    result = run(execute)
    assert result['prime']['state'] == state
    assert result['calls'] == 46
    assert 'secret' not in json.dumps(result)


def test_median_retains_failed_response_and_zero_ms():
    index = 0
    def execute(*_, **__):
        nonlocal index
        index += 1
        if index == 1:
            return reply('NXDOMAIN', 0)
        if index == 2:
            return reply('NXDOMAIN', 10)
        return reply('SERVFAIL', 100)
    result = run(execute)
    aggregate = result['workloads']['unique_negative']['aggregate']
    assert aggregate['successful'] == 2
    assert aggregate['successful_median_ms'] == 5
    assert aggregate['observed_response_median_ms'] == 100
    assert aggregate['response_timing_count'] == 25
    assert result['sampling_quality_passed'] is False


@pytest.mark.parametrize('jump', [float('nan'), float('inf'), -1.0, 9.0])
def test_clock_failure_stops_queries_and_preserves_slots(jump):
    clock = Clock()
    def execute(*_, **__):
        clock.value = jump
        return reply('NXDOMAIN')
    result = run(execute, clock)
    assert result['calls'] == 1
    assert result['clock_consistent'] is False
    assert result['workloads']['unique_negative']['aggregate']['requested'] == 25
    assert result['workloads']['unique_negative']['aggregate']['attempted'] == 1
    assert result['workloads']['warm']['aggregate']['attempted'] == 0
    assert math.isfinite(result['elapsed_seconds'])
    json.dumps(result, allow_nan=False)


def test_utc_discontinuity_invalidates_quality():
    clock = Clock()
    calls = 0
    def utc():
        nonlocal calls
        calls += 1
        return clock.origin + timedelta(hours=calls)
    result = dns.observe_baseline(
        dns.make_system_config(), resolv_conf_text='nameserver ::1', execute=lambda *_, **__: reply(),
        monotonic=clock.monotonic, utc_clock=utc, dig_path='/fixture/dig')
    assert result['clock_consistent'] is False
    assert result['sampling_quality_passed'] is False


@pytest.mark.parametrize('output', [None, {}, {'output_bytes': True}, {'output_bytes': -1},
    {'output_bytes': 4098}, {'output_bytes': 0, 'stdout': b'secret'},
    {'output_bytes': 1, 'stdout': 'secret'}])
def test_executor_accounting_rejects_unbounded_or_malformed_output(output):
    with pytest.raises(MeasurementError, match='invalid_executor_result'):
        run(lambda *_, **__: output)


def cli_module():
    spec = importlib.util.spec_from_file_location('observe_dns_cli',
        Path(__file__).parents[1] / 'scripts' / 'observe_dns.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cli_private_config_output_and_redaction(tmp_path, monkeypatch, capsys):
    config = tmp_path / 'private.json'
    config.write_text(json.dumps(dns.make_system_config()))
    config.chmod(0o600)
    module = cli_module()
    monkeypatch.setattr(module, 'observe_baseline', lambda config: run())
    destination = tmp_path / 'evidence'
    assert module.main(['--config', str(config), '--output', str(destination)]) == 0
    summary = read_private_json(destination / 'summary.json')
    assert summary['kind'] == 'dns_baseline'
    assert (destination.stat().st_mode & 0o777) == 0o700
    assert ((destination / 'summary.json').stat().st_mode & 0o777) == 0o600
    stdout = capsys.readouterr().out
    assert str(tmp_path) not in stdout
    assert '127.0.0.53' not in stdout
    assert json.loads(stdout)['overall_gain_established'] is False


@pytest.mark.parametrize('unsafe', ['world', 'symlink', 'hardlink', 'fifo', 'duplicate', 'nan', 'oversize'])
def test_private_config_safety(tmp_path, unsafe, monkeypatch, capsys):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(dns.make_system_config()))
    path.chmod(0o600)
    if unsafe == 'world':
        path.chmod(0o644)
    elif unsafe == 'symlink':
        path.rename(tmp_path / 'real')
        path.symlink_to(tmp_path / 'real')
    elif unsafe == 'hardlink':
        os.link(path, tmp_path / 'link')
    elif unsafe == 'fifo':
        path.unlink()
        os.mkfifo(path, 0o600)
    elif unsafe == 'duplicate':
        path.write_text('{"mode":"baseline","mode":"B"}')
    elif unsafe == 'nan':
        path.write_text('{"number":NaN}')
    else:
        path.write_text('x' * 65537)
    module = cli_module()
    monkeypatch.setattr(module, 'observe_baseline', lambda _: pytest.fail('no execution on unsafe input'))
    assert module.main(['--config', str(path), '--output', str(tmp_path / 'out')]) == 1
    assert str(tmp_path) not in capsys.readouterr().out
    assert not (tmp_path / 'out').exists()


def test_output_is_exclusive_and_symlink_ancestor_rejected(tmp_path):
    result = run()
    fd = create_output_directory(tmp_path / 'evidence')
    try:
        write_private_result(fd, result)
        with pytest.raises(MeasurementError):
            write_private_result(fd, result)
    finally:
        os.close(fd)
    link = tmp_path / 'link'
    link.symlink_to(tmp_path / 'evidence', target_is_directory=True)
    with pytest.raises(MeasurementError, match='unsafe_output_directory'):
        create_output_directory(link / 'new')


def test_live_default_rereads_only_known_system_source(monkeypatch):
    # Replace source read rather than reading the real host's configuration.
    sources = iter(['nameserver 127.0.0.53', 'nameserver ::1'])
    monkeypatch.setattr(dns, '_system_resolver_text', lambda: next(sources))
    seen = []
    def execute(argv, **_):
        seen.append(argv[2])
        return reply('NXDOMAIN' if argv[4].startswith('m') else 'NOERROR')
    clock = Clock()
    config = dns.make_system_config()
    for _ in range(2):
        dns.observe_baseline(config, execute=execute, monotonic=clock.monotonic,
            utc_clock=clock.utc, dig_path='/fixture/dig')
    assert set(seen[:46]) == {'@127.0.0.53'}
    assert set(seen[46:]) == {'@::1'}


@pytest.mark.parametrize('lost_reply,state', [(True, 'no_reply'), (False, 'timeout')])
def test_single_lost_reply_or_outer_timeout_does_not_halt_run(lost_reply, state):
    clock = Clock()
    calls = []
    def execute(argv, **options):
        calls.append(options)
        if len(calls) == 3:
            clock.value += 5.02 if lost_reply else 6
            if lost_reply:
                return {'status': 'completed', 'returncode': 9, 'output_bytes': 0}
            raise subprocess.TimeoutExpired('fixture', 6)
        clock.value += .01
        return reply('NXDOMAIN' if argv[4].startswith('m') else 'NOERROR')
    result = run(execute, clock)
    assert result['calls'] == len(calls) == 46
    assert all(options['timeout'] == 6 for options in calls)
    aggregate = result['workloads']['unique_negative']['aggregate']
    assert aggregate['state_counts'][state] == 1
    assert aggregate['successful'] == 24
    assert aggregate['attempted'] == aggregate['requested'] == 25
    assert result['workloads']['warm']['aggregate']['successful'] == 20
    assert result['prime']['state'] == 'ok'
    assert result['sampling_quality_passed'] is False


@pytest.mark.parametrize('initial', [float('nan'), float('inf'), -1, True])
def test_invalid_initial_clock_prevents_execution(initial):
    with pytest.raises(MeasurementError, match='invalid_baseline_clock'):
        dns.observe_baseline(dns.make_system_config(), resolv_conf_text='nameserver ::1',
            monotonic=lambda: initial, utc_clock=lambda: Clock().origin,
            execute=lambda *_, **__: pytest.fail('no call'), dig_path='/fixture/dig')


def test_all_output_limit_results_remain_bounded_and_descriptive():
    result = run(lambda *_, **__: {'status': 'output_limit', 'output_bytes': 4097,
        'stdout': b'x' * 4096, 'stderr': b''})
    assert result['calls'] == 46
    assert result['output_bytes'] == 46 * 4097 < 256 * 1024
    assert result['prime']['state'] == 'output_limit'
    assert all(workload['aggregate']['successful'] == 0 for workload in result['workloads'].values())


def test_known_system_source_read_is_bounded(monkeypatch):
    import io
    seen = []
    def fake_open(path, mode):
        seen.append((path, mode))
        return io.BytesIO(b'nameserver 127.0.0.53\n')
    monkeypatch.setattr('builtins.open', fake_open)
    assert dns._system_resolver_text() == 'nameserver 127.0.0.53\n'
    assert seen == [('/etc/resolv.conf', 'rb')]


def test_cli_direct_opt_in_uses_same_fixed_config(tmp_path, monkeypatch, capsys):
    module = cli_module()
    def collect(config):
        assert config == dns.CONFIG
        return run()
    monkeypatch.setattr(module, 'observe_baseline', collect)
    assert module.main(['--system-resolver', '--output', str(tmp_path / 'out')]) == 0
    assert json.loads(capsys.readouterr().out)['kind'] == 'dns_baseline'


def answer_reply(records=(), rcode='NOERROR', latency=3):
    result = reply(rcode, latency)
    payload = result['stdout'].replace(b'ANSWER: 1,', f'ANSWER: {len(records)},'.encode())
    payload += b';; ANSWER SECTION:\n' + ('\n'.join(records) + ('\n' if records else '')).encode()
    result.update(stdout=payload, output_bytes=len(payload))
    return result


def diagnostic(executor=None, clock=None):
    clock = clock or Clock()
    return dns.observe_dns_diagnostic(dns.make_system_config(), resolv_conf_text='nameserver 127.0.0.53',
        execute=executor or (lambda *_, **__: answer_reply()), monotonic=clock.monotonic,
        utc_clock=clock.utc, run_id='a' * 32, dig_path='/fixture/dig')


@pytest.mark.parametrize('address,classification', [
    ('0.0.0.0', 'unspecified'), ('127.0.0.7', 'loopback'),
    ('198.18.0.1', 'benchmark'), ('198.19.255.254', 'benchmark'),
    ('100.64.0.1', 'shared'), ('100.127.255.254', 'shared'),
    ('10.4.5.6', 'private'), ('192.168.1.2', 'private'),
    ('240.1.2.3', 'private'), ('224.0.0.1', 'reserved'), ('8.8.8.8', 'public')])
def test_diagnostic_address_classes_and_redaction(address, classification):
    result = dns.parse_diagnostic_dig(answer_reply([
        f'secret-house.invalid. 90 IN A {address}',
        'secret-house.invalid. 91 IN CNAME private-target.invalid.',
        'private-target.invalid. 92 IN TXT "private-content"']))
    assert result['state'] == 'observed'
    assert result['answer_count'] == 3
    assert result['answer_types'] == {'A': 1, 'CNAME': 1, 'other': 1}
    assert result['address_classes'][classification] == 1
    assert sum(result['address_classes'].values()) == 1
    serialized = json.dumps(result)
    for sentinel in (address, 'secret-house', 'private-target', 'private-content', '90', '91', '92'):
        assert sentinel not in serialized


@pytest.mark.parametrize('records', [
    ['owner.invalid. x IN A 10.0.0.1'], ['owner.invalid. 99999999999 IN A 10.0.0.1'],
    ['owner.invalid. 60 CH A 10.0.0.1'], ['owner.invalid. 60 IN A invalid'],
    ['owner.invalid. 60 IN A ::1'], ['owner.invalid. 60 IN A 1.2.3.4 extra'],
    ['owner.invalid. 60 IN CNAME missing-dot'], ['owner.invalid. 60 IN CNAME target.invalid. extra'],
    ['bad-owner 60 IN A 1.2.3.4'], ['owner.invalid. 60 IN A'],
    ['owner.invalid. 60 IN badtype ignored']])
def test_diagnostic_malformed_answer_is_not_partially_retained(records):
    row = dns.parse_diagnostic_dig(answer_reply(records))
    assert row == dns._diagnostic_row('malformed')


def test_diagnostic_answer_limits_and_header_mismatch():
    records = [f'owner.invalid. 60 IN A 10.0.0.{index}' for index in range(1, 10)]
    assert dns.parse_diagnostic_dig(answer_reply(records))['state'] == 'output_limit'
    mismatch = answer_reply([])
    mismatch['stdout'] = mismatch['stdout'].replace(b'ANSWER: 0', b'ANSWER: 1')
    mismatch['output_bytes'] = len(mismatch['stdout'])
    assert dns.parse_diagnostic_dig(mismatch)['state'] == 'malformed'
    assert dns.parse_diagnostic_dig({'output_bytes': 4097, 'stdout': b'x' * 4097})['state'] == 'output_limit'
    assert dns.parse_diagnostic_dig({'output_bytes': 0, 'stdout': b'private'})['state'] == 'malformed'
    assert dns.parse_diagnostic_dig(None)['state'] == 'malformed'


def test_diagnostic_zero_answer_nxdomain_and_servfail_are_observations():
    for rcode in ('NXDOMAIN', 'SERVFAIL', 'REFUSED', 'NOERROR'):
        row = dns.parse_diagnostic_dig(answer_reply(rcode=rcode))
        assert row['state'] == 'observed'
        assert row['rcode'] == rcode
        assert row['answer_count'] == 0
        assert row['latency_ms'] == 3


def test_diagnostic_exact_workload_argv_caps_and_separate_evidence():
    calls = []
    def execute(argv, **options):
        calls.append((argv, options))
        return answer_reply(['secret.invalid. 60 IN A 198.18.1.1'])
    result = diagnostic(execute)
    assert len(calls) == result['calls'] == 4
    assert [argv[4] for argv, _ in calls] == ['example.com.', 'a' * 32 + '.example.com.',
        'example.invalid.', 'a' * 32 + '.invalid.']
    for argv, options in calls:
        assert argv[:4] == ['/fixture/dig', '-r', '@127.0.0.53', '-q']
        assert argv[5:] == ['-t', 'A', '-c', 'IN', '+notcp', '+ignore', '+nosearch',
            '+tries=1', '+retry=0', '+nobadcookie', '+nocookie', '+time=5', '+noall', '+comments', '+stats', '+answer']
        assert options == {'timeout': 6, 'max_output': 4096}
    assert result['kind'] == 'dns_diagnostic'
    assert result['aggregate'] == {'requested': 4, 'attempted': 4, 'observed': 4,
        'failed_or_missing': 0, 'state_counts': {'observed': 4}}
    assert [row['query_class'] for row in result['samples']] == list(dns.DIAGNOSTIC_CLASSES)
    for key in ('overall_gain_established', 'cause_established', 'malware_established',
        'filtering_established', 'routing_established', 'security_established'):
        assert result[key] is False
    serialized = json.dumps(result)
    for sentinel in ('198.18.1.1', 'secret.invalid', '127.0.0.53', 'a' * 32, 'example.com.', 'TTL', 'CNAMEtarget'):
        assert sentinel not in serialized


@pytest.mark.parametrize('failure,state', [
    ({'status': 'timeout', 'output_bytes': 0}, 'timeout'),
    ({'status': 'completed', 'returncode': 9, 'output_bytes': 0}, 'no_reply'),
    ({'status': 'launch_failed', 'output_bytes': 0}, 'process_failed'),
    ({'status': 'output_limit', 'output_bytes': 4097}, 'output_limit')])
def test_diagnostic_failures_do_not_retry_and_preserve_denominator(failure, state):
    result = diagnostic(lambda *_, **__: failure)
    assert result['calls'] == 4
    assert result['aggregate']['failed_or_missing'] == result['aggregate']['requested'] == 4
    assert result['aggregate']['state_counts'] == {state: 4}


@pytest.mark.parametrize('bad_result', [None, {}, {'output_bytes': -1}, {'output_bytes': 4098},
    {'output_bytes': True}, {'output_bytes': 0, 'stderr': b'private'}, {'output_bytes': 1, 'stdout': 'x'}])
def test_diagnostic_executor_guards(bad_result):
    with pytest.raises(MeasurementError, match='invalid_executor_result'):
        diagnostic(lambda *_, **__: bad_result)


def test_diagnostic_total_deadline_and_clock_stop():
    clock = Clock()
    def overdue(*_, **__):
        clock.value += 31
        return answer_reply()
    result = diagnostic(overdue, clock)
    assert result['calls'] == 1
    assert result['aggregate']['state_counts'] == {'timeout': 1, 'not_attempted_deadline': 3}
    clock = Clock()
    def backwards(*_, **__):
        clock.value = 9
        return answer_reply()
    result = diagnostic(backwards, clock)
    assert result['clock_consistent'] is False
    assert result['calls'] == 1
    assert result['aggregate']['requested'] == 4


def test_diagnostic_outer_timeout_one_slot_only():
    clock = Clock()
    calls = 0
    def execute(*_, **__):
        nonlocal calls
        calls += 1
        if calls == 2:
            clock.value += 6
            raise subprocess.TimeoutExpired('private', 6)
        return answer_reply()
    result = diagnostic(execute, clock)
    assert result['calls'] == 4
    assert result['aggregate']['observed'] == 3
    assert result['aggregate']['state_counts']['timeout'] == 1


def test_diagnostic_ambiguous_resolver_prevents_execution():
    with pytest.raises(MeasurementError, match='ambiguous_system_resolver'):
        dns.observe_dns_diagnostic(dns.make_system_config(),
            resolv_conf_text='nameserver 127.0.0.1\nnameserver ::1',
            execute=lambda *_, **__: pytest.fail('no execution'))


def test_diagnostic_cli_separate_private_receipt(tmp_path, monkeypatch, capsys):
    module = cli_module()
    monkeypatch.setattr(module, 'observe_dns_diagnostic', lambda config: diagnostic())
    monkeypatch.setattr(module, 'observe_baseline', lambda _: pytest.fail('baseline must stay separate'))
    output = tmp_path / 'diagnostic'
    assert module.main(['--system-resolver', '--diagnostic', '--output', str(output)]) == 0
    result = read_private_json(output / 'summary.json')
    assert result['kind'] == json.loads(capsys.readouterr().out)['kind'] == 'dns_diagnostic'


def test_diagnostic_exact_eight_answer_boundary():
    records = [f'private-owner.invalid. 60 IN A 10.0.0.{index}' for index in range(1, 9)]
    row = dns.parse_diagnostic_dig(answer_reply(records))
    assert row['state'] == 'observed'
    assert row['answer_count'] == row['answer_types']['A'] == 8
    assert row['address_classes']['private'] == 8


@pytest.mark.parametrize('payload', [b'\xffprivate', b'private malformed output'])
def test_diagnostic_nonascii_or_missing_header_is_malformed(payload):
    result = {'status': 'completed', 'returncode': 0, 'stdout': payload,
        'stderr': b'', 'output_bytes': len(payload)}
    assert dns.parse_diagnostic_dig(result) == dns._diagnostic_row('malformed')
