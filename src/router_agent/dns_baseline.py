"""Finite descriptive DNS baseline on the client's existing resolver path.

No intervention or configuration binding is claimed. Names, resolver addresses and
subprocess text exist only transiently and are excluded from returned evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import math
import re
import secrets
import shutil
import subprocess
import time

from .network_measurements import (MeasurementError, require, execute_dig, parse_dig,
    _aggregate, utc_now, MAX_QUERY_OUTPUT, MAX_TOTAL_OUTPUT)

CONFIG = {'schema_version': 1, 'mode': 'baseline',
    'resolver_source': 'system_resolv_conf', 'transport': 'udp'}
COUNTS = {'unique_negative': 25, 'warm': 20}
LIMITS = ['descriptive_median_only_no_tail_percentiles',
    'unique_negative_labels_may_use_cached_negative_proofs',
    'upstream_identity_path_configuration_and_cache_freshness_unknown',
    'baseline_does_not_establish_filtering_routing_security_restoration_or_causal_gain',
    'local_unsigned_observation']


def validate_config(config):
    require(type(config) is dict and set(config) == set(CONFIG)
        and type(config.get('schema_version')) is int
        and config == CONFIG, 'invalid_baseline_config')
    return config


def select_system_resolver(text):
    """Parse supplied resolv.conf text; refuse ambiguity instead of picking first."""
    require(type(text) is str and len(text.encode('utf-8')) <= 65536,
        'invalid_system_resolver_configuration')
    resolvers = set()
    for line in text.splitlines():
        fields = re.split(r'[#;]', line, maxsplit=1)[0].split()
        if not fields or fields[0] != 'nameserver':
            continue
        require(len(fields) == 2, 'invalid_system_resolver_configuration')
        try:
            address = ipaddress.ip_address(fields[1])
        except ValueError:
            raise MeasurementError('invalid_system_resolver_configuration') from None
        require(not getattr(address, 'scope_id', None) and not (
            address.is_unspecified or address.is_multicast
            or str(address) == '255.255.255.255'), 'invalid_system_resolver_configuration')
        resolvers.add(str(address))
    require(bool(resolvers), 'system_resolver_unavailable')
    require(len(resolvers) == 1, 'ambiguous_system_resolver')
    return resolvers.pop()


def make_system_config(resolv_conf_text=None):
    """Create the fixed private opt-in config; optional text is a pure preflight."""
    if resolv_conf_text is not None:
        select_system_resolver(resolv_conf_text)
    return dict(CONFIG)


def _system_resolver_text():
    # This known system file commonly is a symlink managed by the operating
    # system. It is not a credential/private artifact and is never written.
    try:
        with open('/etc/resolv.conf', 'rb') as stream:
            raw = stream.read(65537)
        require(len(raw) <= 65536, 'invalid_system_resolver_configuration')
        return raw.decode('ascii')
    except (OSError, UnicodeError):
        raise MeasurementError('system_resolver_unavailable') from None


def _finite_clock(value):
    return type(value) in (float, int) and math.isfinite(value) and 0 <= value <= 10**15


def _utc(value):
    require(isinstance(value, datetime) and value.tzinfo is not None
        and value.utcoffset() is not None, 'invalid_baseline_clock')
    return value.astimezone(timezone.utc)


def observe_baseline(config, *, resolv_conf_text=None, execute=execute_dig,
        monotonic=time.monotonic, utc_clock=utc_now, run_id=None, dig_path=None):
    """Collect at most 46 single-attempt queries; injection supports offline tests.

    A live invocation always reads /etc/resolv.conf here, at execution, rather
    than accepting a persisted resolver address or selecting a public fallback.
    """
    validate_config(config)
    resolver = select_system_resolver(_system_resolver_text()
        if resolv_conf_text is None else resolv_conf_text)
    binary = dig_path or shutil.which('dig', path='/usr/bin:/bin')
    require(type(binary) is str and binary.startswith('/'), 'dig_unavailable')
    run_id = secrets.token_hex(16) if run_id is None else run_id
    require(type(run_id) is str and re.fullmatch(r'[0-9a-f]{32}', run_id), 'invalid_run_id')
    started = _utc(utc_clock())
    start = monotonic()
    require(_finite_clock(start), 'invalid_baseline_clock')
    previous, deadline = start, start + 120
    clock_ok, halted = True, False
    received, calls = 0, 0
    records = {name: [] for name in COUNTS}
    prime = None
    for workload in COUNTS:
        for index in range(COUNTS[workload] + int(workload == 'warm')):
            is_prime = workload == 'warm' and index == 0
            now = monotonic()
            if not _finite_clock(now) or now < previous:
                clock_ok, halted = False, True
            else:
                previous = now
            row = {'state': 'not_attempted_deadline', 'rcode': None, 'latency_ms': None}
            if not halted and now < deadline:
                if received >= MAX_TOTAL_OUTPUT:
                    row['state'] = 'not_attempted_output_budget'
                else:
                    name = 'example.com.' if workload == 'warm' else f'm{run_id}-{index}.example.com.'
                    argv = [binary, '-r', '@' + resolver, '-q', name, '-t', 'A', '-c', 'IN',
                        '+notcp', '+ignore', '+nosearch', '+tries=1', '+retry=0',
                        '+nobadcookie', '+nocookie', '+time=5', '+noall', '+comments', '+stats']
                    budget = min(MAX_QUERY_OUTPUT, MAX_TOTAL_OUTPUT - received)
                    try:
                        # Leave dig one second of process/reporting headroom
                        # beyond its five-second wire timeout. A lost reply
                        # consumes one slot; only the shared deadline or a
                        # clock discontinuity stops subsequent slots.
                        result = execute(argv, timeout=min(6, deadline - now), max_output=budget)
                    except subprocess.TimeoutExpired:
                        result = {'status': 'timeout', 'output_bytes': 0}
                    except (OSError, subprocess.SubprocessError):
                        result = {'status': 'launch_failed', 'output_bytes': 0}
                    calls += 1
                    size = result.get('output_bytes') if type(result) is dict else None
                    require(type(size) is int and 0 <= size <= budget + 1,
                        'invalid_executor_result')
                    received += size
                    # A bounded executor must not deliver more pipe data than
                    # its accounting. Reject malformed injected providers too.
                    streams = [result.get(key, b'') for key in ('stdout', 'stderr')]
                    require(all(type(value) is bytes for value in streams)
                        and sum(map(len, streams)) <= size, 'invalid_executor_result')
                    row = parse_dig(result, 'NXDOMAIN' if workload == 'unique_negative' else 'NOERROR')
                    if size > budget:
                        row = {'state': 'output_limit', 'rcode': None, 'latency_ms': None}
                    ended = monotonic()
                    if not _finite_clock(ended) or ended < previous:
                        clock_ok, halted = False, True
                        row = {'state': 'timeout', 'rcode': None, 'latency_ms': None}
                    else:
                        previous = ended
                        if ended > deadline:
                            row = {'state': 'timeout', 'rcode': None, 'latency_ms': None}
                            halted = True
            if is_prime:
                prime = row
            else:
                records[workload].append(row)
    finish = monotonic()
    if not _finite_clock(finish) or finish < previous:
        clock_ok = False
        finish = previous
    finished = _utc(utc_clock())
    elapsed = finish - start
    clock_ok = clock_ok and finished >= started and abs((finished - started).total_seconds() - elapsed) <= 3
    quality = clock_ok and prime['state'] == 'ok' and all(
        row['state'] == 'ok' for rows in records.values() for row in rows)
    return {'schema_version': 1, 'kind': 'dns_baseline', 'mode': 'baseline',
        'started_at_utc': started.isoformat(), 'finished_at_utc': finished.isoformat(),
        'observed_at': None, 'freshness': 'unknown', 'cache_freshness': 'unknown',
        'resolver_source': 'system_resolv_conf',
        'resolver_kind': 'local_stub' if ipaddress.ip_address(resolver).is_loopback else 'configured_numeric',
        'upstream_identity': 'unknown', 'path': 'unknown', 'configuration': 'unknown',
        'transport': 'udp', 'unit': 'ms', 'method': 'dig_single_attempt',
        'elapsed_seconds': elapsed, 'clock_consistent': clock_ok,
        'calls': calls, 'output_bytes': received, 'prime': prime,
        'workloads': {name: {'samples': rows, 'aggregate': _aggregate(rows)} for name, rows in records.items()},
        'sampling_quality_passed': quality, 'overall_gain_established': False,
        'security_established': False, 'filtering_established': False,
        'routing_established': False, 'restoration_established': False, 'limits': list(LIMITS)}


DIAGNOSTIC_CLASSES = ('example_apex', 'example_fresh_label', 'invalid_fixed_label', 'invalid_fresh_label')
ADDRESS_CLASSES = ('unspecified', 'loopback', 'benchmark', 'shared', 'private', 'reserved', 'public')


def _address_class(address):
    """Order matters: Python's private classification includes special ranges."""
    if address.is_unspecified:
        return 'unspecified'
    if address.is_loopback:
        return 'loopback'
    if address in ipaddress.ip_network('198.18.0.0/15'):
        return 'benchmark'
    if address in ipaddress.ip_network('100.64.0.0/10'):
        return 'shared'
    if address.is_private:
        return 'private'
    if address.is_reserved or address.is_multicast:
        return 'reserved'
    return 'public'


def _diagnostic_row(state, *, rcode=None, latency_ms=None):
    return {'state': state, 'rcode': rcode, 'latency_ms': latency_ms,
        'answer_count': None, 'answer_types': None, 'address_classes': None}


def parse_diagnostic_dig(result):
    """Discard answer owners, addresses, CNAME targets and TTLs in-process."""
    if type(result) is not dict:
        return _diagnostic_row('malformed')
    size = result.get('output_bytes')
    streams = [result.get(key, b'') for key in ('stdout', 'stderr')]
    if (type(size) is not int or size < 0 or not all(type(value) is bytes for value in streams)
            or sum(map(len, streams)) > size):
        return _diagnostic_row('malformed')
    if size > MAX_QUERY_OUTPUT:
        return _diagnostic_row('output_limit')
    base = parse_dig(result, 'NOERROR')
    row = _diagnostic_row(base['state'], rcode=base['rcode'], latency_ms=base['latency_ms'])
    if base['state'] not in {'ok', 'unexpected_rcode', 'servfail'}:
        return row
    text = result['stdout'].decode('ascii')
    counts = re.findall(r'^;; flags: [a-z ]*; QUERY: [0-9]+, ANSWER: ([0-9]+), AUTHORITY: [0-9]+, ADDITIONAL: [0-9]+\s*$', text, re.M)
    if len(counts) != 1:
        return _diagnostic_row('malformed')
    count = int(counts[0])
    if count > 8:
        return _diagnostic_row('output_limit')
    records = [line for line in text.splitlines() if line.strip() and not line.startswith(';')]
    if len(records) != count:
        return _diagnostic_row('malformed')
    types = {name: 0 for name in ('A', 'CNAME', 'other')}
    classes = {name: 0 for name in ADDRESS_CLASSES}
    domain = r'(?=.{1,254}$)(?:[A-Za-z0-9_-]+\.)+'
    for record in records:
        fields = record.split()
        if len(fields) < 5:
            return _diagnostic_row('malformed')
        owner, ttl, rrclass, rrtype = fields[:4]
        if (not re.fullmatch(domain, owner) or not re.fullmatch(r'[0-9]{1,10}', ttl)
                or int(ttl) > 2**32 - 1 or rrclass != 'IN'
                or not re.fullmatch(r'[A-Z][A-Z0-9]{0,15}', rrtype)):
            return _diagnostic_row('malformed')
        if rrtype == 'A':
            if len(fields) != 5:
                return _diagnostic_row('malformed')
            try:
                address = ipaddress.IPv4Address(fields[4])
            except ipaddress.AddressValueError:
                return _diagnostic_row('malformed')
            types['A'] += 1
            classes[_address_class(address)] += 1
        elif rrtype == 'CNAME':
            if len(fields) != 5 or not re.fullmatch(domain, fields[4]):
                return _diagnostic_row('malformed')
            types['CNAME'] += 1
        else:
            types['other'] += 1
    return {'state': 'observed', 'rcode': base['rcode'], 'latency_ms': base['latency_ms'],
        'answer_count': count, 'answer_types': types, 'address_classes': classes}


def observe_dns_diagnostic(config, *, resolv_conf_text=None, execute=execute_dig,
        monotonic=time.monotonic, utc_clock=utc_now, run_id=None, dig_path=None):
    """One additive four-query observation; never another baseline or a diagnosis."""
    validate_config(config)
    resolver = select_system_resolver(_system_resolver_text()
        if resolv_conf_text is None else resolv_conf_text)
    binary = dig_path or shutil.which('dig', path='/usr/bin:/bin')
    require(type(binary) is str and binary.startswith('/'), 'dig_unavailable')
    run_id = secrets.token_hex(16) if run_id is None else run_id
    require(type(run_id) is str and re.fullmatch(r'[0-9a-f]{32}', run_id), 'invalid_run_id')
    names = ('example.com.', f'{run_id}.example.com.', 'example.invalid.', f'{run_id}.invalid.')
    started = _utc(utc_clock())
    start = monotonic()
    require(_finite_clock(start), 'invalid_baseline_clock')
    previous, deadline = start, start + 30
    clock_ok, halted = True, False
    calls, received = 0, 0
    rows = []
    for query_class, name in zip(DIAGNOSTIC_CLASSES, names):
        now = monotonic()
        if not _finite_clock(now) or now < previous:
            clock_ok, halted = False, True
        else:
            previous = now
        row = _diagnostic_row('not_attempted_deadline')
        if not halted and now < deadline:
            argv = [binary, '-r', '@' + resolver, '-q', name, '-t', 'A', '-c', 'IN',
                '+notcp', '+ignore', '+nosearch', '+tries=1', '+retry=0',
                '+nobadcookie', '+nocookie', '+time=5', '+noall', '+comments', '+stats', '+answer']
            try:
                result = execute(argv, timeout=min(6, deadline - now), max_output=MAX_QUERY_OUTPUT)
            except subprocess.TimeoutExpired:
                result = {'status': 'timeout', 'output_bytes': 0}
            except (OSError, subprocess.SubprocessError):
                result = {'status': 'launch_failed', 'output_bytes': 0}
            calls += 1
            size = result.get('output_bytes') if type(result) is dict else None
            require(type(size) is int and 0 <= size <= MAX_QUERY_OUTPUT + 1, 'invalid_executor_result')
            streams = [result.get(key, b'') for key in ('stdout', 'stderr')]
            require(all(type(value) is bytes for value in streams)
                and sum(map(len, streams)) <= size, 'invalid_executor_result')
            received += size
            row = parse_diagnostic_dig(result) if size <= MAX_QUERY_OUTPUT else _diagnostic_row('output_limit')
            ended = monotonic()
            if not _finite_clock(ended) or ended < previous:
                clock_ok, halted = False, True
                row = _diagnostic_row('timeout')
            else:
                previous = ended
                if ended > deadline:
                    row = _diagnostic_row('timeout')
                    halted = True
        rows.append({'query_class': query_class, **row})
    finish = monotonic()
    if not _finite_clock(finish) or finish < previous:
        clock_ok = False
        finish = previous
    finished = _utc(utc_clock())
    elapsed = finish - start
    clock_ok = clock_ok and finished >= started and abs((finished - started).total_seconds() - elapsed) <= 3
    states = sorted({row['state'] for row in rows})
    return {'schema_version': 1, 'kind': 'dns_diagnostic',
        'started_at_utc': started.isoformat(), 'finished_at_utc': finished.isoformat(),
        'observed_at': None, 'freshness': 'unknown', 'path': 'unknown',
        'upstream_identity': 'unknown', 'resolver_source': 'system_resolv_conf',
        'resolver_kind': 'local_stub' if ipaddress.ip_address(resolver).is_loopback else 'configured_numeric',
        'transport': 'udp', 'unit': 'ms', 'method': 'dig_single_attempt',
        'calls': calls, 'output_bytes': received, 'elapsed_seconds': elapsed,
        'clock_consistent': clock_ok, 'samples': rows,
        'aggregate': {'requested': 4, 'attempted': calls,
            'observed': sum(row['state'] == 'observed' for row in rows),
            'failed_or_missing': sum(row['state'] != 'observed' for row in rows),
            'state_counts': {state: sum(row['state'] == state for row in rows) for state in states}},
        'overall_gain_established': False, 'cause_established': False,
        'malware_established': False, 'filtering_established': False,
        'routing_established': False, 'security_established': False,
        'limits': ['four_control_queries_only_not_a_baseline',
            'example_subdomains_are_not_protocol_guaranteed_negative',
            'response_path_cause_upstream_identity_and_freshness_unknown',
            'no_connections_to_returned_addresses', 'local_unsigned_observation']}
