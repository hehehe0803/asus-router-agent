"""Bounded client DNS observations and offline, manifest-bound comparisons.

No router/HA API, credentials, background collection or settings mutation.
Resolver/query strings remain in private input and transient subprocess memory.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import selectors
import secrets
import shutil
import signal
import stat
import statistics
import subprocess
import time

MAX_FILE_BYTES = 65536
MAX_QUERY_OUTPUT = 4096
MAX_TOTAL_OUTPUT = 262144
STAGES = ('A1', 'B', 'A2')
SAMPLE_STATES = frozenset({'ok', 'unexpected_rcode', 'servfail', 'timeout', 'no_reply', 'process_failed',
    'malformed', 'output_limit', 'not_attempted_deadline', 'not_attempted_output_budget'})
RCODES = frozenset({'NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED', 'FORMERR', 'NOTIMP', 'NOTAUTH', 'BADVERS'})
LIMITS = ['client_path_and_configuration_are_operator_declared_not_independently_verified',
    'unique_label_negative_queries_may_use_cached_negative_proofs',
    'source_observation_time_unavailable', 'small_fixed_sample_no_tail_percentile_claim',
    'filtering_ha_application_and_recovery_checks_pending', 'no_causal_or_security_success_claim', 'local_artifacts_are_unsigned_observations']


class MeasurementError(ValueError):
    """Fixed public code only; never include private input or subprocess text."""


def require(condition, code='invalid_measurement'):
    if not condition:
        raise MeasurementError(code)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError):
        raise MeasurementError('invalid_json_value') from None


def utc_now():
    return datetime.now(timezone.utc)


def _timestamp(value):
    require(type(value) is str and len(value) <= 40, 'invalid_timestamp')
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise MeasurementError('invalid_timestamp') from None
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None, 'invalid_timestamp')
    return parsed.astimezone(timezone.utc)


def _number(value, lower, upper):
    return type(value) in (int, float) and lower <= value <= upper and math.isfinite(value)


def _domain(value, maximum=253):
    require(type(value) is str and len(value) <= maximum and value == value.lower(), 'invalid_private_workload')
    labels = value.rstrip('.').split('.')
    require(len(labels) >= 2 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels), 'invalid_private_workload')


def validate_manifest(manifest):
    keys = {'schema_version', 'experiment_id', 'created_at_utc', 'client_role', 'path_id', 'transport',
        'counts', 'query_timeout_seconds', 'total_timeout_seconds', 'warm_domain', 'unique_suffix',
        'variable', 'stages', 'thresholds'}
    require(type(manifest) is dict and set(manifest) == keys and type(manifest['schema_version']) is int and manifest['schema_version'] == 1, 'invalid_manifest')
    require(type(manifest['experiment_id']) is str and re.fullmatch(r'[0-9a-f]{32}', manifest['experiment_id']), 'invalid_manifest')
    _timestamp(manifest['created_at_utc'])
    for key in ('client_role', 'path_id'):
        require(type(manifest[key]) is str and re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', manifest[key]), 'invalid_manifest')
    require(type(manifest['transport']) is str and manifest['transport'] in {'udp', 'tcp'}, 'invalid_manifest')
    counts = manifest['counts']
    require(type(counts) is dict and set(counts) == {'unique_negative', 'warm'} and all(type(v) is int and 1 <= v <= 32 for v in counts.values()) and sum(counts.values()) <= 63, 'invalid_query_budget')
    require(type(manifest['query_timeout_seconds']) is int and 1 <= manifest['query_timeout_seconds'] <= 5 and _number(manifest['total_timeout_seconds'], 1, 300), 'invalid_query_budget')
    _domain(manifest['warm_domain'])
    _domain(manifest['unique_suffix'], 210)
    require(type(manifest['variable']) is str and manifest['variable'] in {'upstream_mode', 'resolver'}, 'invalid_manifest')
    stages = manifest['stages']
    require(type(stages) is dict and set(stages) == set(STAGES), 'invalid_stage_configuration')
    for stage in STAGES:
        config = stages[stage]
        require(type(config) is dict and set(config) == {'resolver', 'upstream_mode', 'configuration_fingerprint'}, 'invalid_stage_configuration')
        try:
            resolver = ipaddress.ip_address(config['resolver'])
        except (ValueError, TypeError):
            raise MeasurementError('invalid_numeric_resolver') from None
        require(type(config['resolver']) is str and not getattr(resolver, 'scope_id', None) and not (resolver.is_unspecified or resolver.is_multicast), 'invalid_numeric_resolver')
        require(type(config['upstream_mode']) is str and config['upstream_mode'] in {'load_balance', 'parallel'}, 'invalid_stage_configuration')
        require(type(config['configuration_fingerprint']) is str and re.fullmatch(r'[0-9a-f]{64}', config['configuration_fingerprint']), 'invalid_stage_configuration')
    require(stages['A1'] == stages['A2'], 'baseline_configuration_mismatch')
    a, b = stages['A1'], stages['B']
    variable = manifest['variable']
    fixed = 'resolver' if variable == 'upstream_mode' else 'upstream_mode'
    require(a[variable] != b[variable] and a[fixed] == b[fixed] and a['configuration_fingerprint'] != b['configuration_fingerprint'], 'invalid_declared_variable')
    thresholds = manifest['thresholds']
    bounds = {'baseline_drift_fraction': (0, .5), 'improvement_fraction': (.001, .99),
        'warm_absolute_allowance_ms': (0, 100), 'warm_relative_allowance': (0, .5)}
    require(type(thresholds) is dict and set(thresholds) == set(bounds) and all(_number(thresholds[k], *bound) for k, bound in bounds.items()), 'invalid_thresholds')
    return manifest


def manifest_digest(manifest):
    validate_manifest(manifest)
    return hashlib.sha256(canonical(manifest)).hexdigest()


def execute_dig(argv, *, timeout, max_output=MAX_QUERY_OUTPUT):
    """No shell; bound both pipes and all descendants to one wall deadline."""
    start = time.monotonic()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, shell=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    except OSError:
        return {'status': 'launch_failed', 'returncode': None, 'stdout': b'', 'stderr': b'', 'output_bytes': 0}
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = selectors.DefaultSelector()
    status = 'completed'
    try:
        for name in streams:
            selector.register(getattr(process, name), selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                status = 'timeout'
                break
            for key, _ in selector.select(min(remaining, .1)):
                chunk = os.read(key.fd, min(4096, max_output + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                streams[key.data].extend(chunk)
                if sum(map(len, streams.values())) > max_output:
                    status = 'output_limit'
                    break
            if status != 'completed':
                break
        if status == 'completed':
            try:
                process.wait(timeout=max(.001, timeout - (time.monotonic() - start)))
            except subprocess.TimeoutExpired:
                status = 'timeout'
    finally:
        if status != 'completed' or process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
    size = sum(map(len, streams.values()))
    return {'status': status, 'returncode': process.returncode,
        'stdout': bytes(streams['stdout'][:max_output]), 'stderr': bytes(streams['stderr'][:max(0, max_output - len(streams['stdout']))]), 'output_bytes': min(size, max_output + 1)}


def parse_dig(result, expected_rcode):
    base = {'state': 'malformed', 'rcode': None, 'latency_ms': None}
    if type(result) is not dict or type(result.get('status')) is not str:
        return base
    if result.get('status') != 'completed':
        base['state'] = {'timeout': 'timeout', 'output_limit': 'output_limit'}.get(result.get('status'), 'process_failed')
        return base
    if type(result.get('returncode')) is not int or result['returncode'] != 0:
        # dig exit 9 means no server reply. It does not distinguish an
        # immediate transport refusal from a query timeout. Parent deadlines
        # retain their separate timeout state above.
        base['state'] = 'no_reply' if type(result.get('returncode')) is int and result['returncode'] == 9 else 'process_failed'
        return base
    try:
        text = result['stdout'].decode('ascii')
    except (UnicodeError, AttributeError, KeyError):
        return base
    headers = re.findall(r'^;; ->>HEADER<<- opcode: QUERY, status: ([A-Z]+), id: [0-9]+\s*$', text, re.M)
    timings = re.findall(r'^;; Query time: ([0-9]{1,7}) msec\s*$', text, re.M)
    flags = re.findall(r'^;; flags: ([a-z ]*); QUERY: [0-9]+, ANSWER: [0-9]+, AUTHORITY: [0-9]+, ADDITIONAL: [0-9]+\s*$', text, re.M)
    if len(headers) != 1 or headers[0] not in RCODES or len(timings) != 1 or len(flags) != 1 or 'tc' in flags[0].split():
        return base
    latency = int(timings[0])
    if latency > 60000:
        return base
    rcode = headers[0]
    return {'state': 'ok' if rcode == expected_rcode else 'servfail' if rcode == 'SERVFAIL' else 'unexpected_rcode', 'rcode': rcode, 'latency_ms': latency}


def _aggregate(samples):
    expected = len(samples)
    ok = [row['latency_ms'] for row in samples if row['state'] == 'ok']
    timed = [row['latency_ms'] for row in samples if row['latency_ms'] is not None]
    states = {state: sum(row['state'] == state for row in samples) for state in sorted(SAMPLE_STATES)}
    attempted = sum(not row['state'].startswith('not_attempted_') for row in samples)
    return {'requested': expected, 'attempted': attempted, 'completed': len(timed), 'successful': len(ok), 'failed_or_missing': expected - len(ok),
        'response_timing_count': len(timed), 'successful_median_ms': statistics.median(ok) if ok else None,
        'observed_response_median_ms': statistics.median(timed) if timed else None, 'state_counts': states}


def sample_dns(manifest, stage, *, execute=execute_dig, monotonic=time.monotonic, utc_clock=utc_now, run_id=None, dig_path=None):
    validate_manifest(manifest)
    require(type(stage) is str and stage in STAGES, 'invalid_stage')
    run_id = secrets.token_hex(16) if run_id is None else run_id
    require(type(run_id) is str and re.fullmatch(r'[0-9a-f]{32}', run_id), 'invalid_run_id')
    binary = dig_path or shutil.which('dig', path='/usr/bin:/bin')
    require(type(binary) is str and os.path.isabs(binary), 'dig_unavailable')
    started = utc_clock()
    require(isinstance(started, datetime) and started.tzinfo is not None and _timestamp(manifest['created_at_utc']) < started, 'manifest_must_precede_sampling')
    start = monotonic()
    require(_number(start, 0, 10**15), 'invalid_measurement_clock')
    deadline = start + manifest['total_timeout_seconds']
    config = manifest['stages'][stage]
    received_bytes, calls = 0, 0
    records = {'unique_negative': [], 'warm': []}
    prime = None
    interrupted = None
    for workload in ('unique_negative', 'warm'):
        iterations = manifest['counts'][workload] + (workload == 'warm')
        for index in range(iterations):
            is_prime = workload == 'warm' and index == 0
            sample_index = index - 1 if workload == 'warm' else index
            now = monotonic()
            require(_number(now, 0, 10**15), 'invalid_measurement_clock')
            if now < start:
                interrupted = 'clock_discontinuity'
            if interrupted or now >= deadline:
                row = {'state': 'not_attempted_deadline', 'rcode': None, 'latency_ms': None}
            elif received_bytes >= MAX_TOTAL_OUTPUT:
                row = {'state': 'not_attempted_output_budget', 'rcode': None, 'latency_ms': None}
            else:
                name = manifest['warm_domain'] if workload == 'warm' else f'm{run_id}-{sample_index}.{manifest["unique_suffix"].rstrip(".")}'
                argv = [binary, '-r', '@' + config['resolver'], '-q', name.rstrip('.') + '.', '-t', 'A', '-c', 'IN',
                    '+tcp' if manifest['transport'] == 'tcp' else '+notcp', '+ignore', '+nosearch',
                    '+tries=1', '+retry=0', '+nobadcookie', '+nocookie', f'+time={manifest["query_timeout_seconds"]}', '+noall', '+comments', '+stats']
                budget = min(MAX_QUERY_OUTPUT, MAX_TOTAL_OUTPUT - received_bytes)
                try:
                    result = execute(argv, timeout=min(manifest['query_timeout_seconds'] + 1, deadline - now), max_output=budget)
                except subprocess.TimeoutExpired:
                    result = {'status': 'timeout', 'returncode': None, 'stdout': b'', 'stderr': b'', 'output_bytes': 0}
                except (OSError, subprocess.SubprocessError):
                    result = {'status': 'launch_failed', 'returncode': None, 'stdout': b'', 'stderr': b'', 'output_bytes': 0}
                require(type(result) is dict, 'invalid_executor_result')
                calls += 1
                size = result.get('output_bytes')
                require(type(size) is int and 0 <= size <= budget + 1, 'invalid_executor_result')
                received_bytes += size
                ended = monotonic()
                require(_number(ended, 0, 10**15), 'invalid_measurement_clock')
                row = parse_dig(result, 'NXDOMAIN' if workload == 'unique_negative' else 'NOERROR')
                if ended < now:
                    interrupted = 'clock_discontinuity'
                    row = {'state': 'timeout', 'rcode': None, 'latency_ms': None}
                elif ended > deadline:
                    row = {'state': 'timeout', 'rcode': None, 'latency_ms': None}
            if is_prime:
                prime = row
            else:
                records[workload].append(row)
    finish = monotonic()
    require(_number(finish, 0, 10**15), 'invalid_measurement_clock')
    ended_at = utc_clock()
    require(isinstance(ended_at, datetime) and ended_at.tzinfo is not None, 'invalid_timestamp')
    duration = max(0, finish - start)
    clock_ok = interrupted is None and ended_at >= started and abs((ended_at - started).total_seconds() - duration) <= 3
    quality = clock_ok and prime['state'] == 'ok' and all(row['state'] == 'ok' for values in records.values() for row in values)
    return {'schema_version': 1, 'kind': 'dns_sample', 'run_id': run_id, 'stage': stage,
        'manifest_sha256': manifest_digest(manifest), 'experiment_id': manifest['experiment_id'],
        'client_role': manifest['client_role'], 'path_id': manifest['path_id'], 'transport': manifest['transport'],
        'configuration_fingerprint': config['configuration_fingerprint'], 'upstream_mode': config['upstream_mode'],
        'started_at_utc': started.astimezone(timezone.utc).isoformat(), 'finished_at_utc': ended_at.astimezone(timezone.utc).isoformat(),
        'observed_at': None, 'freshness': 'unknown', 'unit': 'ms', 'method': 'dig_single_attempt',
        'elapsed_seconds': duration, 'clock_consistent': clock_ok, 'calls': calls, 'output_bytes': received_bytes,
        'prime': prime, 'workloads': {name: {'samples': values, 'aggregate': _aggregate(values)} for name, values in records.items()},
        'sampling_quality_passed': quality, 'limits': list(LIMITS)}


def _validate_sample_row(row):
    require(type(row) is dict and set(row) == {'state', 'rcode', 'latency_ms'}, 'invalid_sample_artifact')
    require(type(row['state']) is str and row['state'] in SAMPLE_STATES, 'invalid_sample_artifact')
    require(row['rcode'] is None or type(row['rcode']) is str and row['rcode'] in RCODES, 'invalid_sample_artifact')
    require(row['latency_ms'] is None or type(row['latency_ms']) is int and 0 <= row['latency_ms'] <= 60000, 'invalid_sample_artifact')
    if row['state'] in {'ok', 'unexpected_rcode', 'servfail'}:
        require(row['rcode'] is not None and row['latency_ms'] is not None, 'invalid_sample_artifact')
    else:
        require(row['rcode'] is None and row['latency_ms'] is None, 'invalid_sample_artifact')
    require(row['state'] != 'servfail' or row['rcode'] == 'SERVFAIL', 'invalid_sample_artifact')


def validate_artifact(artifact, manifest, stage):
    keys = {'schema_version', 'kind', 'run_id', 'stage', 'manifest_sha256', 'experiment_id',
        'client_role', 'path_id', 'transport', 'configuration_fingerprint', 'upstream_mode',
        'started_at_utc', 'finished_at_utc', 'observed_at', 'freshness', 'unit', 'method',
        'elapsed_seconds', 'clock_consistent', 'calls', 'output_bytes', 'prime', 'workloads',
        'sampling_quality_passed', 'limits'}
    require(type(artifact) is dict and set(artifact) == keys and type(artifact['schema_version']) is int and artifact['schema_version'] == 1 and artifact['kind'] == 'dns_sample', 'invalid_sample_artifact')
    require(type(artifact['run_id']) is str and re.fullmatch(r'[0-9a-f]{32}', artifact['run_id']), 'invalid_sample_artifact')
    expected = {'stage': stage, 'manifest_sha256': manifest_digest(manifest),
        'experiment_id': manifest['experiment_id'], 'client_role': manifest['client_role'],
        'path_id': manifest['path_id'], 'transport': manifest['transport'],
        'configuration_fingerprint': manifest['stages'][stage]['configuration_fingerprint'],
        'upstream_mode': manifest['stages'][stage]['upstream_mode'], 'observed_at': None,
        'freshness': 'unknown', 'unit': 'ms', 'method': 'dig_single_attempt', 'limits': LIMITS}
    require(all(artifact[k] == v for k, v in expected.items()), 'measurement_binding_mismatch')
    started, finished = _timestamp(artifact['started_at_utc']), _timestamp(artifact['finished_at_utc'])
    require(_timestamp(manifest['created_at_utc']) < started, 'manifest_must_precede_sampling')
    require(_number(artifact['elapsed_seconds'], 0, manifest['total_timeout_seconds'] + 2), 'invalid_sample_artifact')
    require(type(artifact['clock_consistent']) is bool and type(artifact['sampling_quality_passed']) is bool, 'invalid_sample_artifact')
    if artifact['clock_consistent']:
        require(finished >= started and abs((finished - started).total_seconds() - artifact['elapsed_seconds']) <= 3, 'invalid_sample_artifact')
    require(type(artifact['output_bytes']) is int and 0 <= artifact['output_bytes'] <= MAX_TOTAL_OUTPUT + 1, 'invalid_sample_artifact')
    require(type(artifact['workloads']) is dict and set(artifact['workloads']) == {'unique_negative', 'warm'}, 'invalid_sample_artifact')
    _validate_sample_row(artifact['prime'])
    require(artifact['prime']['state'] != 'ok' or artifact['prime']['rcode'] == 'NOERROR', 'invalid_sample_artifact')
    calls = int(not artifact['prime']['state'].startswith('not_attempted_'))
    all_ok = artifact['clock_consistent'] and artifact['prime']['state'] == 'ok'
    for workload, expected_rcode in [('unique_negative', 'NXDOMAIN'), ('warm', 'NOERROR')]:
        values = artifact['workloads'][workload]
        require(type(values) is dict and set(values) == {'samples', 'aggregate'} and type(values['samples']) is list and len(values['samples']) == manifest['counts'][workload], 'invalid_sample_artifact')
        for row in values['samples']:
            _validate_sample_row(row)
            require(row['state'] != 'ok' or row['rcode'] == expected_rcode, 'invalid_sample_artifact')
            require(row['state'] != 'servfail' or row['rcode'] == 'SERVFAIL', 'invalid_sample_artifact')
            require(row['state'] != 'unexpected_rcode' or row['rcode'] != expected_rcode and row['rcode'] != 'SERVFAIL', 'invalid_sample_artifact')
        require(canonical(values['aggregate']) == canonical(_aggregate(values['samples'])), 'aggregate_mismatch')
        calls += sum(not row['state'].startswith('not_attempted_') for row in values['samples'])
        all_ok = all_ok and all(row['state'] == 'ok' for row in values['samples'])
    require(type(artifact['calls']) is int and artifact['calls'] == calls and calls <= sum(manifest['counts'].values()) + 1, 'invalid_sample_artifact')
    require(artifact['sampling_quality_passed'] is all_ok, 'quality_mismatch')
    return artifact


def compare_dns(manifest, a1, b, a2):
    validate_manifest(manifest)
    artifacts = [validate_artifact(value, manifest, stage) for value, stage in zip((a1, b, a2), STAGES)]
    require(len({value['run_id'] for value in artifacts}) == 3, 'duplicate_run_artifact')
    ordered = all(_timestamp(left['finished_at_utc']) <= _timestamp(right['started_at_utc']) for left, right in zip(artifacts, artifacts[1:]))
    require(ordered, 'stage_order_or_overlap_mismatch')
    quality = ordered and all(value['sampling_quality_passed'] for value in artifacts)
    metrics = {stage: {workload: value['workloads'][workload]['aggregate'] for workload in ('unique_negative', 'warm')} for stage, value in zip(STAGES, artifacts)}
    thresholds = manifest['thresholds']
    clauses = {'stages_chronologically_ordered': ordered, 'all_sampling_quality_passed': all(value['sampling_quality_passed'] for value in artifacts),
        'baseline_medians_agree': None, 'b_unique_improves_against_both': None, 'b_warm_within_both_allowances': None}
    changes = {'unique_negative_percent_vs_a1': None, 'unique_negative_percent_vs_a2': None}
    if quality:
        au, bu, a2u = [metrics[stage]['unique_negative']['successful_median_ms'] for stage in STAGES]
        aw, bw, a2w = [metrics[stage]['warm']['successful_median_ms'] for stage in STAGES]
        clauses['baseline_medians_agree'] = abs(au - a2u) <= thresholds['baseline_drift_fraction'] * min(au, a2u)
        clauses['b_unique_improves_against_both'] = all(bu <= (1 - thresholds['improvement_fraction']) * baseline for baseline in (au, a2u)) and min(au, a2u) > 0
        clauses['b_warm_within_both_allowances'] = all(bw <= baseline + max(thresholds['warm_absolute_allowance_ms'], thresholds['warm_relative_allowance'] * baseline) for baseline in (aw, a2w))
        for key, baseline in [('unique_negative_percent_vs_a1', au), ('unique_negative_percent_vs_a2', a2u)]:
            changes[key] = round(100 * (baseline - bu) / baseline, 4) if baseline else None
    return {'schema_version': 1, 'kind': 'dns_comparison', 'experiment_id': manifest['experiment_id'],
        'manifest_sha256': manifest_digest(manifest), 'run_ids': [value['run_id'] for value in artifacts],
        'unit': 'ms', 'method': 'dig_single_attempt', 'observed_at': None, 'freshness': 'unknown',
        'metrics': metrics, 'thresholds': thresholds, 'quality_eligible': quality, 'clauses': clauses,
        'changes': changes, 'latency_criteria_met': quality and all(value is True for value in clauses.values()),
        'independent_checks': {'filtering': 'pending', 'ha_application': 'pending', 'recovery': 'pending'},
        'overall_gain_established': False, 'security_established': False, 'limits': list(LIMITS)}


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def _reject_constant(_):
    raise MeasurementError('invalid_json_number')


def read_private_json(path):
    path = Path(path).absolute()
    require(not any(component.is_symlink() for component in (path, *path.parents)), 'unsafe_private_file')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise MeasurementError('private_file_unavailable') from None
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077 and info.st_nlink == 1 and info.st_size <= MAX_FILE_BYTES, 'unsafe_private_file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            payload = stream.read(MAX_FILE_BYTES + 1)
        require(len(payload) <= MAX_FILE_BYTES, 'private_file_too_large')
        try:
            return json.loads(payload, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
        except (ValueError, UnicodeError, RecursionError):
            raise MeasurementError('invalid_private_json') from None
    finally:
        os.close(fd)


def create_output_directory(path):
    path = Path(path).absolute()
    require(not any(component.is_symlink() for component in (path, *path.parents)), 'unsafe_output_directory')
    try:
        path.mkdir(mode=0o700, exist_ok=False)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise MeasurementError('output_directory_must_be_new') from None
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(descriptor)
        raise MeasurementError('unsafe_output_directory')
    return descriptor


def write_private_result(directory_fd, result, *, filename='summary.json'):
    require(filename in {'summary.json', 'manifest.json'}, 'invalid_result_filename')
    payload = canonical(result) + b'\n'
    require(len(payload) <= MAX_FILE_BYTES, 'result_file_budget_exceeded')
    try:
        fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600, dir_fd=directory_fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory_fd)
    except OSError:
        raise MeasurementError('result_write_failed') from None


def manifest_template(*, resolver, client_role, path_id, baseline_config, candidate_config, transport='udp', created_at=None, experiment_id=None):
    """Private one-variable upstream-mode proposal; declarations are not observed state."""
    now = utc_now() if created_at is None else created_at
    require(isinstance(now, datetime) and now.tzinfo is not None, 'invalid_timestamp')
    baseline = {'resolver': resolver, 'upstream_mode': 'load_balance', 'configuration_fingerprint': baseline_config}
    candidate = {'resolver': resolver, 'upstream_mode': 'parallel', 'configuration_fingerprint': candidate_config}
    return validate_manifest({'schema_version': 1, 'experiment_id': experiment_id or secrets.token_hex(16),
        'created_at_utc': now.astimezone(timezone.utc).isoformat(), 'client_role': client_role,
        'path_id': path_id, 'transport': transport, 'counts': {'unique_negative': 25, 'warm': 20},
        'query_timeout_seconds': 5, 'total_timeout_seconds': 300, 'warm_domain': 'example.com',
        'unique_suffix': 'example.com', 'variable': 'upstream_mode',
        'stages': {'A1': baseline, 'B': candidate, 'A2': dict(baseline)},
        'thresholds': {'baseline_drift_fraction': .15, 'improvement_fraction': .25,
            'warm_absolute_allowance_ms': 3, 'warm_relative_allowance': .20}})
