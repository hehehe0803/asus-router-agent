"""Synthetic executors and private temporary artifacts only; no live DNS/HA/router."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path

import pytest

from router_agent import network_measurements as nm

BASE = datetime(2026, 10, 15, 0, 0, tzinfo=timezone.utc)


def manifest():
    value = nm.manifest_template(resolver='192.0.2.53', client_role='client_a', path_id='wired_a',
        baseline_config='a'*64, candidate_config='b'*64, created_at=BASE,
        experiment_id='c'*32)
    value['counts'] = {'unique_negative': 2, 'warm': 2}
    value['total_timeout_seconds'] = 30
    return value


class Clock:
    def __init__(self, offset=100):
        self.value = float(offset)
    def monotonic(self):
        return self.value
    def utc(self):
        return BASE + timedelta(seconds=self.value)


def answer(rcode='NOERROR', milliseconds=10, *, flags='qr rd ra'):
    payload = f';; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: 123\n;; flags: {flags}; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n;; Query time: {milliseconds} msec\n;; SERVER: 192.0.2.53#53\n; sentinel-private-query.example\n'.encode()
    return {'status': 'completed', 'returncode': 0, 'stdout': payload,
        'stderr': b'sentinel-private-error', 'output_bytes': len(payload) + 22}


def collect(stage='A1', *, config=None, unique_ms=100, warm_ms=2, offset=100, mutation=None, run_id=None):
    value = manifest() if config is None else config
    clock, calls = Clock(offset), []
    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        clock.value += .1
        name = argv[argv.index('-q') + 1]
        output = answer('NOERROR' if name == value['warm_domain'].rstrip('.') + '.' else 'NXDOMAIN',
            warm_ms if name == value['warm_domain'].rstrip('.') + '.' else unique_ms)
        if mutation:
            result = mutation(len(calls), output, clock)
            if result is not None:
                output = result
        return output
    result = nm.sample_dns(value, stage, execute=execute, monotonic=clock.monotonic,
        utc_clock=clock.utc, run_id=run_id or {'A1': '1'*32, 'B': '2'*32, 'A2': '3'*32}[stage], dig_path='/usr/bin/dig')
    return result, calls


def trio():
    return (collect('A1', unique_ms=100, offset=100)[0], collect('B', unique_ms=60, offset=200)[0],
            collect('A2', unique_ms=102, offset=300)[0])


def test_exact_bounded_no_shell_workload_transport_and_private_output():
    value, calls = collect()
    assert value['sampling_quality_passed'] is True
    assert len(calls) == value['calls'] == 5
    assert len({argv[argv.index('-q') + 1] for argv, _ in calls[:2]}) == 2
    assert len({argv[argv.index('-q') + 1] for argv, _ in calls[2:]}) == 1
    for argv, options in calls:
        assert argv[:3] == ['/usr/bin/dig', '-r', '@192.0.2.53']
        assert '-q' in argv and argv[argv.index('-q') + 1].endswith('.')
        assert all(item in argv for item in ('+notcp', '+ignore', '+nosearch', '+tries=1', '+retry=0', '+nobadcookie', '+nocookie'))
        assert options['timeout'] <= 6 and options['max_output'] <= 4096
    aggregate = value['workloads']['unique_negative']['aggregate']
    assert aggregate['requested'] == aggregate['attempted'] == aggregate['completed'] == aggregate['successful'] == 2
    assert aggregate['successful_median_ms'] == 100
    serialized = json.dumps(value)
    for private in ('192.0.2.53', 'example.com', 'sentinel-private', '@', ';; SERVER'):
        assert private not in serialized
    assert value['unit'] == 'ms' and value['observed_at'] is None and value['freshness'] == 'unknown'
    assert nm.validate_artifact(value, manifest(), 'A1') == value


def test_tcp_is_separate_explicit_manifest_and_absolute_names():
    config = manifest()
    config['transport'] = 'tcp'
    value, calls = collect(config=config)
    assert value['transport'] == 'tcp'
    assert all('+tcp' in argv and '+notcp' not in argv for argv, _ in calls)


@pytest.mark.parametrize('change', [
    lambda m: m.update(total_timeout_seconds=10**300),
    lambda m: m.update(total_timeout_seconds=True),
    lambda m: m.update(query_timeout_seconds=0),
    lambda m: m.update(transport='https'),
    lambda m: m.update(counts={'unique_negative': 32, 'warm': 32}),
    lambda m: m.update(warm_domain='example.com;sentinel'),
    lambda m: m['stages']['A1'].update(resolver='resolver.example'),
    lambda m: m['stages']['A1'].update(resolver='224.0.0.1'),
    lambda m: m['stages']['A1'].update(resolver='0.0.0.0'),
    lambda m: m['stages']['A2'].update(configuration_fingerprint='c'*64),
    lambda m: m['stages']['B'].update(configuration_fingerprint='a'*64),
    lambda m: m['stages']['B'].update(resolver='192.0.2.54'),
    lambda m: m['thresholds'].update(improvement_fraction=float('nan')),
    lambda m: m['thresholds'].update(warm_absolute_allowance_ms=10**300),
    lambda m: m.update(extra='sentinel'),
])
def test_hostile_or_unbounded_manifest_rejected_before_execute(change):
    value = manifest()
    change(value)
    calls = []
    with pytest.raises(nm.MeasurementError):
        nm.sample_dns(value, 'A1', execute=lambda *a, **kw: calls.append(a), utc_clock=lambda: BASE + timedelta(seconds=1))
    assert calls == []


def test_explicit_resolver_experiment_only_changes_declared_variable():
    config = manifest()
    config['variable'] = 'resolver'
    config['stages']['B'].update(resolver='192.0.2.54', upstream_mode='load_balance')
    nm.validate_manifest(config)
    nm.validate_artifact(collect('B', config=config)[0], config, 'B')


@pytest.mark.parametrize('damage', ['unit', 'multiple_header', 'multiple_timing', 'bool', 'negative', 'huge', 'truncated', 'unknown_rcode', 'nonascii'])
def test_malformed_native_output_never_becomes_a_timing(damage):
    output = answer()
    if damage == 'unit': output['stdout'] = output['stdout'].replace(b'msec', b'seconds')
    elif damage == 'multiple_header': output['stdout'] += output['stdout']
    elif damage == 'multiple_timing': output['stdout'] += b';; Query time: 3 msec\n'
    elif damage == 'bool': output['stdout'] = output['stdout'].replace(b'10 msec', b'True msec')
    elif damage == 'negative': output['stdout'] = output['stdout'].replace(b'10 msec', b'-1 msec')
    elif damage == 'huge': output['stdout'] = output['stdout'].replace(b'10 msec', b'9999999 msec')
    elif damage == 'truncated': output = answer(flags='qr tc rd ra')
    elif damage == 'unknown_rcode': output = answer(rcode='PRIVATE')
    else: output['stdout'] = b'\xff'
    assert nm.parse_dig(output, 'NOERROR') == {'state': 'malformed', 'rcode': None, 'latency_ms': None}


@pytest.mark.parametrize('state', ['timeout', 'output_limit', 'no_reply', 'process_failed', 'servfail', 'unexpected_rcode', 'malformed'])
def test_failures_stay_in_denominator_and_disable_comparison_quality(state):
    def mutation(index, output, clock):
        if index != 1: return None
        if state == 'timeout': return dict(output, status='timeout')
        if state == 'output_limit': return dict(output, status='output_limit')
        if state == 'no_reply': return dict(output, returncode=9)
        if state == 'process_failed': return dict(output, returncode=10)
        if state == 'servfail': return answer(rcode='SERVFAIL')
        if state == 'unexpected_rcode': return answer(rcode='REFUSED')
        return dict(output, stdout=b'sentinel-malformed')
    value, calls = collect(mutation=mutation)
    aggregate = value['workloads']['unique_negative']['aggregate']
    assert len(calls) == 5 and aggregate['requested'] == 2 and aggregate['successful'] == 1
    assert aggregate['failed_or_missing'] == 1 and aggregate['state_counts'][state] == 1
    assert value['sampling_quality_passed'] is False
    report = nm.compare_dns(manifest(), value, trio()[1], trio()[2])
    assert report['quality_eligible'] is False and report['changes']['unique_negative_percent_vs_a1'] is None
    assert report['latency_criteria_met'] is False


def test_failed_priming_is_explicit_and_no_automatic_retry():
    value, calls = collect(mutation=lambda i, out, clock: dict(out, status='timeout') if i == 3 else None)
    assert value['prime']['state'] == 'timeout'
    assert len(calls) == 5 and value['sampling_quality_passed'] is False
    assert value['workloads']['warm']['aggregate']['successful'] == 2


def test_deadline_fills_missing_rows_and_has_finite_call_count():
    config = manifest()
    config['total_timeout_seconds'] = 1
    def slow(index, output, clock):
        clock.value += 1
    value, calls = collect(config=config, mutation=slow)
    assert len(calls) == 1 and value['sampling_quality_passed'] is False
    assert value['workloads']['unique_negative']['samples'][0]['state'] == 'timeout'
    assert value['workloads']['unique_negative']['samples'][1]['state'] == 'not_attempted_deadline'
    assert value['workloads']['warm']['aggregate']['requested'] == 2
    assert value['workloads']['warm']['aggregate']['attempted'] == 0


def test_clock_discontinuity_is_not_a_passing_series():
    value, _ = collect(mutation=lambda i, out, clock: setattr(clock, 'value', 90) if i == 1 else None)
    assert value['clock_consistent'] is False and value['sampling_quality_passed'] is False


def test_manifest_must_exist_before_sampling():
    config = manifest()
    config['created_at_utc'] = (BASE + timedelta(seconds=200)).isoformat()
    with pytest.raises(nm.MeasurementError, match='manifest_must_precede'):
        collect(config=config)


def test_comparison_quantitative_only_and_pending_independent_constraints():
    values = trio()
    report = nm.compare_dns(manifest(), *values)
    assert report['quality_eligible'] is True and report['latency_criteria_met'] is True
    assert report['changes']['unique_negative_percent_vs_a1'] == 40
    assert report['changes']['unique_negative_percent_vs_a2'] == pytest.approx(41.1765)
    assert report['overall_gain_established'] is False and report['security_established'] is False
    assert set(report['independent_checks'].values()) == {'pending'}
    assert report == nm.compare_dns(manifest(), *values)
    assert not any(secret in json.dumps(report) for secret in ('192.0.2.53', 'example.com', 'sentinel-private'))


@pytest.mark.parametrize('case', ['drift', 'no_gain', 'warm_regression', 'zero_baseline'])
def test_fixed_threshold_clauses_capture_regressions_and_zero(case):
    a1, b, a2 = trio()
    if case == 'drift': a2 = collect('A2', unique_ms=130, offset=300)[0]
    if case == 'no_gain': b = collect('B', unique_ms=99, offset=200)[0]
    if case == 'warm_regression': b = collect('B', unique_ms=60, warm_ms=8, offset=200)[0]
    if case == 'zero_baseline':
        a1, b, a2 = (collect(stage, unique_ms=0, offset=i*100)[0] for i, stage in enumerate(nm.STAGES, 1))
    report = nm.compare_dns(manifest(), a1, b, a2)
    assert report['quality_eligible'] is True and report['latency_criteria_met'] is False
    if case == 'zero_baseline': assert report['changes']['unique_negative_percent_vs_a1'] is None


@pytest.mark.parametrize('damage', ['aggregate', 'bool_timing', 'nonfinite_timing', 'huge_timing', 'wrong_rcode', 'quality', 'calls', 'output_bytes', 'units', 'source_age', 'config', 'client', 'transport', 'manifest', 'stage', 'duplicate', 'overlap', 'before_manifest', 'extra_private'])
def test_edited_mixed_or_duplicate_artifacts_are_rejected(damage):
    values = list(copy.deepcopy(trio()))
    target = values[1]
    if damage == 'aggregate': target['workloads']['warm']['aggregate']['successful_median_ms'] = 0
    elif damage == 'bool_timing': target['workloads']['warm']['samples'][0]['latency_ms'] = True
    elif damage == 'nonfinite_timing': target['workloads']['warm']['samples'][0]['latency_ms'] = float('nan')
    elif damage == 'huge_timing': target['elapsed_seconds'] = 10**300
    elif damage == 'wrong_rcode': target['workloads']['warm']['samples'][0]['rcode'] = 'NXDOMAIN'
    elif damage == 'quality': target['sampling_quality_passed'] = False
    elif damage == 'calls': target['calls'] = 100
    elif damage == 'output_bytes': target['output_bytes'] = 10**300
    elif damage == 'units': target['unit'] = 'seconds'
    elif damage == 'source_age': target['freshness'] = 'fresh'
    elif damage == 'config': target['configuration_fingerprint'] = 'a'*64
    elif damage == 'client': target['client_role'] = 'another_client'
    elif damage == 'transport': target['transport'] = 'tcp'
    elif damage == 'manifest': target['manifest_sha256'] = 'e'*64
    elif damage == 'stage': target['stage'] = 'A2'
    elif damage == 'duplicate': target['run_id'] = values[0]['run_id']
    elif damage == 'overlap': target['started_at_utc'] = values[0]['started_at_utc']; target['finished_at_utc'] = values[0]['finished_at_utc']
    elif damage == 'before_manifest': target['started_at_utc'] = BASE.isoformat()
    else: target['private'] = 'sentinel'
    with pytest.raises(nm.MeasurementError):
        nm.compare_dns(manifest(), *values)


def test_threshold_manifest_change_cannot_be_applied_after_sampling():
    config = manifest()
    config['thresholds']['improvement_fraction'] = .001
    with pytest.raises(nm.MeasurementError, match='binding_mismatch'):
        nm.compare_dns(config, *trio())


def test_unique_labels_use_entire_run_identity():
    _, first = collect(run_id='1'*32)
    _, second = collect(run_id='1'*31+'2')
    assert first[0][0][first[0][0].index('-q')+1] != second[0][0][second[0][0].index('-q')+1]


def test_private_files_new_directory_no_overwrite_and_public_cli(tmp_path, monkeypatch, capsys):
    directory = nm.create_output_directory(tmp_path/'run')
    try:
        nm.write_private_result(directory, manifest(), filename='manifest.json')
        with pytest.raises(nm.MeasurementError, match='result_write_failed'):
            nm.write_private_result(directory, manifest(), filename='manifest.json')
    finally: os.close(directory)
    path = tmp_path/'run'/'manifest.json'
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert nm.read_private_json(path) == manifest()
    with pytest.raises(nm.MeasurementError): nm.create_output_directory(path.parent)
    path.chmod(0o644)
    with pytest.raises(nm.MeasurementError): nm.read_private_json(path)


def test_private_reader_duplicate_keys_size_and_symlink(tmp_path):
    path = tmp_path/'manifest.json'
    path.write_text('{"x":1,"x":2}')
    path.chmod(0o600)
    with pytest.raises(nm.MeasurementError): nm.read_private_json(path)
    path.write_text('x'*(nm.MAX_FILE_BYTES+1))
    with pytest.raises(nm.MeasurementError): nm.read_private_json(path)
    link = tmp_path/'link'; link.symlink_to(path)
    with pytest.raises(nm.MeasurementError): nm.read_private_json(link)


def script_module():
    spec = importlib.util.spec_from_file_location('measure_dns', Path(__file__).resolve().parents[1]/'scripts/measure_dns.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_template_cli_is_usable_private_and_does_not_invoke_dig(tmp_path, monkeypatch, capsys):
    module = script_module()
    monkeypatch.setattr(nm.subprocess, 'Popen', lambda *a, **kw: pytest.fail('No process allowed'))
    code = module.main(['template', '--output', str(tmp_path/'proposal'), '--resolver', '192.0.2.53',
        '--client-role', 'client_a', '--path-id', 'wired_a', '--baseline-config', 'a'*64, '--candidate-config', 'b'*64])
    assert code == 0
    output = capsys.readouterr().out
    assert '192.0.2.53' not in output and str(tmp_path) not in output
    value = nm.validate_manifest(nm.read_private_json(tmp_path/'proposal'/'manifest.json'))
    assert value['counts'] == {'unique_negative': 25, 'warm': 20}


def test_cli_compare_offline_privacy_and_file_exclusivity(tmp_path, capsys):
    module = script_module()
    directory = nm.create_output_directory(tmp_path/'input')
    nm.write_private_result(directory, manifest(), filename='manifest.json')
    os.close(directory)
    args = ['compare', '--manifest', str(tmp_path/'input'/'manifest.json'), '--output', str(tmp_path/'comparison')]
    for stage, value in zip(('a1', 'b', 'a2'), trio()):
        descriptor = nm.create_output_directory(tmp_path/stage)
        nm.write_private_result(descriptor, value)
        os.close(descriptor)
        args += ['--'+stage, str(tmp_path/stage/'summary.json')]
    assert module.main(args) == 0
    text = capsys.readouterr().out
    assert '192.0.2.53' not in text and 'example.com' not in text and str(tmp_path) not in text
    assert module.main(args) == 1
    assert 'output_directory_must_be_new' in capsys.readouterr().out


def test_cli_private_invalid_input_yields_static_error_not_traceback(tmp_path, capsys):
    path = tmp_path/'private-192.0.2.53-password.json'
    value = manifest(); value['total_timeout_seconds'] = 10**300
    path.write_text(json.dumps(value)); path.chmod(0o600)
    module = script_module()
    assert module.main(['sample', '--manifest', str(path), '--stage', 'A1', '--output', str(tmp_path/'new')]) == 1
    result = capsys.readouterr()
    assert json.loads(result.out)['error']['code'] == 'invalid_query_budget'
    assert 'password' not in result.out and '192.0.2.53' not in result.out and result.err == ''
    assert not (tmp_path/'new').exists()


def test_output_budget_stops_queries_without_losing_missing_denominator(monkeypatch):
    monkeypatch.setattr(nm, 'MAX_TOTAL_OUTPUT', 100)
    def mutation(index, output, clock):
        return dict(output, status='output_limit', output_bytes=101)
    value, calls = collect(mutation=mutation)
    assert len(calls) == 1 and value['output_bytes'] == 101  # one overflow-detection byte
    assert calls[0][1]['max_output'] == 100
    assert value['workloads']['unique_negative']['aggregate']['state_counts']['not_attempted_output_budget'] == 1
    assert value['workloads']['warm']['aggregate']['failed_or_missing'] == 2
    assert value['sampling_quality_passed'] is False


@pytest.mark.parametrize('exception,state', [(OSError('sentinel-private-command'), 'process_failed'), (nm.subprocess.TimeoutExpired('sentinel-private-command', 1), 'timeout')])
def test_executor_exceptions_are_static_selected_failures(exception, state):
    clock = Clock()
    def execute(*args, **kwargs):
        clock.value += .1
        raise exception
    value = nm.sample_dns(manifest(), 'A1', execute=execute, monotonic=clock.monotonic,
        utc_clock=clock.utc, run_id='1'*32, dig_path='/usr/bin/dig')
    assert value['calls'] == 5
    assert all(row['state'] == state for row in value['workloads']['warm']['samples'])
    assert value['sampling_quality_passed'] is False
    assert 'sentinel-private-command' not in json.dumps(value)


def test_cli_sample_uses_injected_fixture_and_saves_selected_artifact(tmp_path, monkeypatch, capsys):
    module = script_module()
    descriptor = nm.create_output_directory(tmp_path/'input')
    nm.write_private_result(descriptor, manifest(), filename='manifest.json')
    os.close(descriptor)
    monkeypatch.setattr(module, 'sample_dns', lambda m, stage: collect(stage, config=m)[0])
    assert module.main(['sample', '--manifest', str(tmp_path/'input'/'manifest.json'), '--stage', 'A1', '--output', str(tmp_path/'sample')]) == 0
    result = nm.read_private_json(tmp_path/'sample'/'summary.json')
    nm.validate_artifact(result, manifest(), 'A1')
    output = capsys.readouterr()
    assert '192.0.2.53' not in output.out and str(tmp_path) not in output.out and output.err == ''


@pytest.mark.parametrize('scenario,expected', [('deadline', 'timeout'), ('overflow', 'output_limit')])
def test_process_wrapper_deadline_output_kills_group_without_real_process(monkeypatch, scenario, expected):
    import io
    from types import SimpleNamespace
    clock = {'value': 0}
    killed, launched = [], []
    class Process:
        pid = 987654321
        returncode = None
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        def poll(self): return self.returncode
        def wait(self, **kwargs):
            self.returncode = -9 if killed else 0
            return self.returncode
    process = Process()
    def popen(argv, **kwargs):
        launched.append((argv, kwargs))
        return process
    class Selector:
        def __init__(self): self.entries = {}
        def register(self, stream, events, name): self.entries[name] = stream
        def get_map(self): return self.entries
        def select(self, delay):
            if scenario == 'deadline':
                clock['value'] = 2
                return []
            return [(SimpleNamespace(fd=99, data='stdout'), None)]
        def close(self): pass
    monkeypatch.setattr(nm.subprocess, 'Popen', popen)
    monkeypatch.setattr(nm.selectors, 'DefaultSelector', Selector)
    monkeypatch.setattr(nm.time, 'monotonic', lambda: clock['value'])
    monkeypatch.setattr(nm.os, 'read', lambda fd, count: b'x'*count)
    monkeypatch.setattr(nm.os, 'killpg', lambda pid, sig: killed.append((pid, sig)))
    result = nm.execute_dig(['/usr/bin/dig', '-r'], timeout=1, max_output=10)
    assert result['status'] == expected and len(killed) == 1
    assert len(result['stdout']) + len(result['stderr']) <= 10
    assert result['output_bytes'] <= 11
    options = launched[0][1]
    assert options['shell'] is False and options['start_new_session'] is True
    assert options['stdin'] == nm.subprocess.DEVNULL
    assert options['env'] == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}


def test_network_no_reply_parent_timeout_and_local_process_failure_remain_distinct():
    def mixed(index, output, clock):
        if index == 1:
            return dict(output, returncode=9, stdout=b'sentinel-private-no-response')
        if index == 2:
            return dict(output, status='timeout', returncode=-9)
        if index == 4:
            return dict(output, returncode=10, stderr=b'sentinel-private-local-failure')
    value, calls = collect(mutation=mixed)
    assert len(calls) == 5
    negatives = value['workloads']['unique_negative']['aggregate']
    assert negatives['requested'] == negatives['attempted'] == 2
    assert negatives['successful'] == negatives['completed'] == 0
    assert negatives['failed_or_missing'] == 2
    assert negatives['state_counts']['no_reply'] == 1
    assert negatives['state_counts']['timeout'] == 1
    assert negatives['state_counts']['process_failed'] == 0
    warm = value['workloads']['warm']['aggregate']
    assert warm['requested'] == warm['attempted'] == 2
    assert warm['state_counts']['process_failed'] == 1
    assert warm['state_counts']['no_reply'] == warm['state_counts']['timeout'] == 0
    report = nm.compare_dns(manifest(), value, trio()[1], trio()[2])
    assert report['quality_eligible'] is False and report['latency_criteria_met'] is False
    assert report['overall_gain_established'] is False
    assert set(report['changes'].values()) == {None}
    assert 'sentinel-private' not in json.dumps(value) + json.dumps(report)
