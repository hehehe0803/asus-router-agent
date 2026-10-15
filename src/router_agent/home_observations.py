"""Finite GET-only home aggregate observations. Private config is the only authority.

No discovery, broad state lists, history, retries, or credential scope claims.
Injected transports are trusted test seams; the default verifies HTTPS with system CAs.
"""
from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import time
from urllib.parse import urlsplit

import aiohttp

MAX_RESPONSE = 1024 * 1024
MAX_PRIVATE = 65536
UNITS = frozenset({'queries', 'requests', 'count', 'ms', 's', '%', '°C', 'MB', 'MiB', 'B', 'rules'})
TOTALS = ('num_dns_queries', 'num_blocked_filtering', 'num_replaced_safebrowsing',
          'num_replaced_safesearch', 'num_replaced_parental', 'avg_processing_time')


class ObservationError(ValueError):
    """Only fixed public codes may be raised."""


def _require(ok, code):
    if not ok:
        raise ObservationError(code)


def default_config_path():
    return Path.home() / '.config/asus-router-agent/home-observation.json'


def _parent(path):
    """Pin each ancestor, disallow symlinks and writable untrusted ancestors."""
    path = Path(path)
    _require(path.is_absolute() and '..' not in path.parts, 'unsafe_file')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            st = os.fstat(fd)
            # Root-owned sticky /tmp is safe with a separately pinned private child.
            sticky_root = st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
            _require(st.st_uid in (0, os.getuid()) and (not st.st_mode & 0o022 or sticky_root), 'unsafe_file')
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def _safe_stat(st):
    _require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
             stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
             st.st_size <= MAX_PRIVATE, 'unsafe_file')


def _read_private(path):
    parent, name = _parent(path)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        _safe_stat(before)
        data = os.read(fd, MAX_PRIVATE + 1)
        after = os.fstat(fd)
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _require(len(data) == before.st_size and len(data) <= MAX_PRIVATE and
                 (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                 (after.st_dev, after.st_ino) == (linked.st_dev, linked.st_ino), 'unsafe_file')
        return data
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            _require(key not in out, 'malformed_json')
            out[key] = value
        return out
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ObservationError('malformed_json')))
    except (ValueError, UnicodeError, RecursionError):
        raise ObservationError('malformed_json') from None


def _load(path):
    config = _json(_read_private(path))
    _require(type(config) is dict, 'invalid_config')
    common = {'source', 'origin', 'credential_file'}
    source = config.get('source')
    _require(source in ('home_assistant', 'adguard'), 'invalid_config')
    expected = common | ({'sensors'} if source == 'home_assistant' else {'stats_schema'})
    _require(set(config) == expected, 'invalid_config')
    origin = config['origin']
    _require(type(origin) is str and len(origin) <= 2048 and not re.search(r'[\s\\%]', origin), 'invalid_origin')
    try:
        url = urlsplit(origin)
        _require(url.scheme == 'https' and url.hostname and url.username is None and url.password is None and
                 url.path in ('', '/') and not url.query and not url.fragment and
                 (url.port is None or 1 <= url.port <= 65535), 'invalid_origin')
    except ValueError:
        raise ObservationError('invalid_origin') from None
    config['origin'] = origin.rstrip('/')
    _require(type(config['credential_file']) is str, 'invalid_config')
    if source == 'home_assistant':
        sensors = config['sensors']
        _require(type(sensors) is list and 1 <= len(sensors) <= 8, 'invalid_sensors')
        aliases, entities = set(), set()
        for sensor in sensors:
            _require(type(sensor) is dict and set(sensor) == {'alias', 'entity_id', 'unit'}, 'invalid_sensors')
            alias, entity, unit = sensor['alias'], sensor['entity_id'], sensor['unit']
            _require(type(alias) is str and re.fullmatch(r'metric_[1-8]', alias) and alias not in aliases and
                     type(entity) is str and re.fullmatch(r'sensor\.[a-z0-9_]{1,200}', entity) and entity not in entities and
                     type(unit) is str and unit in UNITS, 'invalid_sensors')
            aliases.add(alias)
            entities.add(entity)
    else:
        _require(config['stats_schema'] in ('current', 'legacy'), 'invalid_config')
    credentials = _json(_read_private(config['credential_file']))
    _require(type(credentials) is dict, 'invalid_credentials')
    if source == 'home_assistant':
        _require(set(credentials) == {'token'} and type(credentials['token']) is str and
                 re.fullmatch(r'[A-Za-z0-9._~+/-]{1,8192}=*', credentials['token']), 'invalid_credentials')
        auth = 'Bearer ' + credentials['token']
    else:
        _require(set(credentials) == {'username', 'password'} and
                 all(type(v) is str and 0 < len(v) <= 8192 and not any(ord(c) < 32 for c in v)
                     for v in credentials.values()) and ':' not in credentials['username'], 'invalid_credentials')
        auth = 'Basic ' + base64.b64encode((credentials['username'] + ':' + credentials['password']).encode()).decode()
    return config, {'Authorization': auth, 'Accept': 'application/json'}


def preflight(config_path=None):
    """Read exactly the selected config and credential, without contacting a source."""
    try:
        config, _ = _load(default_config_path() if config_path is None else config_path)
        return {'status': 'ready', 'source': config['source'], 'configured': True, 'credential_ready': True}
    except (OSError, ObservationError, TypeError):
        return {'status': 'blocked_access', 'source': None, 'configured': False, 'credential_ready': False}


async def _https_get(origin, path, headers, timeout, max_bytes):
    context = ssl.create_default_context()
    connections = sends = 0
    trace = aiohttp.TraceConfig()

    async def connection_start(session, trace_context, params):
        nonlocal connections
        connections += 1
        _require(connections == 1, 'retry_rejected')

    async def headers_sent(session, trace_context, params):
        nonlocal sends
        sends += 1
        _require(sends == 1 and params.method == 'GET', 'retry_rejected')

    # Public trace callbacks run before connector creation / header serialization
    # in pinned aiohttp. Its implicit idempotent retry is rejected before I/O.
    trace.on_connection_create_start.append(connection_start)
    trace.on_request_headers_sent.append(headers_sent)
    # Total timeout bounds DNS/connect/headers/body, including a trickling response.
    async with aiohttp.ClientSession(trust_env=False, timeout=aiohttp.ClientTimeout(total=timeout),
                                     auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar(),
                                     connector=aiohttp.TCPConnector(force_close=True),
                                     trace_configs=[trace]) as session:
        async with session.get(origin + path, headers=headers, ssl=context, allow_redirects=False) as response:
            _require(response.status == 200, 'auth_denied' if response.status in (401, 403) else 'http_error')
            _require(response.headers.get('Content-Encoding', 'identity') == 'identity', 'unsupported_encoding')
            _require(response.content_type == 'application/json', 'malformed_response')
            body = bytearray()
            async for chunk in response.content.iter_chunked(16384):
                body.extend(chunk)
                _require(len(body) <= max_bytes, 'response_limit')
            return bytes(body)


def https_get(origin, path, headers, *, timeout, max_bytes):
    """Exact-origin GET only; no redirects, proxies, downgrade or custom trust bypass."""
    return asyncio.run(_https_get(origin, path, headers, timeout, max_bytes))


def _numeric(value, integer=False):
    return type(value) in ((int,) if integer else (int, float)) and 0 <= value <= 1e30 and math.isfinite(value)


def _time(value):
    if type(value) is not str or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(timezone.utc).isoformat() if parsed.tzinfo else None
    except (ValueError, OverflowError):
        return None


def _ha_metric(spec, state):
    _require(type(state) is dict and state.get('entity_id') == spec['entity_id'], 'malformed_response')
    attributes = state.get('attributes')
    _require(type(attributes) is dict, 'malformed_response')
    raw, value, status = state.get('state'), None, 'non_numeric'
    if raw in ('unknown', 'unavailable'):
        status = raw
    elif type(raw) is str and len(raw) <= 80:
        try:
            number = float(raw)
            if math.isfinite(number) and abs(number) <= 1e30:
                unit = spec['unit']
                bounded = (unit == '°C' or number >= 0) and (unit != '%' or number <= 100)
                whole = unit not in {'queries', 'requests', 'count', 'rules'} or number.is_integer()
                if bounded and whole:
                    value, status = number, 'ok'
                else:
                    status = 'invalid_value'
        except ValueError:
            pass
    checked = attributes.get('unit_of_measurement') == spec['unit']
    if not checked:
        value, status = None, 'unit_mismatch'
    return {'alias': spec['alias'], 'value': value, 'unit': spec['unit'] if checked else None,
            'status': status, 'source_timestamp': _time(state.get('last_updated')),
            'timestamp_semantics': 'ha_state_last_updated_not_provider_poll',
            'measurement_semantics': 'window_or_measurement_not_monotonic'}


def collect_home(config_path=None, *, transport=None, clock=time.monotonic):
    """One finite observation. Responses and all private fields die in-process.

    transport(origin, path, headers, *, timeout, max_bytes) returns JSON bytes.
    It must enforce the timeout and response limit; the collector also checks both.
    """
    result = {'schema_version': 1, 'status': 'blocked_access', 'source': None, 'authenticated_api': False,
              'request_count': 0, 'metrics': [], 'window': None, 'source_version': None,
              'provider_poll_freshness': 'unknown', 'production_admission_verified': False,
              'credential_read_only_scope_verified': False, 'benefit_proven': False,
              'counter_decrease_semantics': 'ambiguous_window_change_not_rate_or_reset_proof'}
    start = clock()
    previous = start
    try:
        config, headers = _load(default_config_path() if config_path is None else config_path)
        result['source'] = config['source']
    except (OSError, ObservationError, TypeError):
        return result
    get = transport or https_get

    def request(path):
        nonlocal previous
        now = clock()
        _require(now >= previous and now - start < 60 and result['request_count'] < 10, 'budget_exhausted')
        previous = now
        timeout = min(5., 60 - (now - start))
        result['request_count'] += 1
        body = get(config['origin'], path, headers, timeout=timeout, max_bytes=MAX_RESPONSE)
        ended = clock()
        _require(ended >= now and ended - now <= timeout and ended - start <= 60, 'timeout')
        previous = ended
        _require(type(body) is bytes and len(body) <= MAX_RESPONSE, 'response_limit')
        payload = _json(body)
        _require(type(payload) is dict, 'malformed_response')
        result['authenticated_api'] = True
        return payload

    try:
        if config['source'] == 'home_assistant':
            ping = request('/api/')
            _require(ping.get('message') == 'API running.', 'malformed_response')
            for spec in config['sensors']:
                result['metrics'].append(_ha_metric(spec, request('/api/states/' + spec['entity_id'])))
        else:
            stats = request('/control/stats')
            for index, key in enumerate(TOTALS, 1):
                value = stats.get(key)
                valid = _numeric(value, integer=key != 'avg_processing_time')
                result['metrics'].append({'alias': 'metric_' + str(index), 'value': value if valid else None,
                    'unit': 's' if key == 'avg_processing_time' else 'count',
                    'status': 'ok' if valid else 'unknown', 'source_timestamp': None,
                    'measurement_semantics': 'window_average' if key == 'avg_processing_time' else 'window_count_not_monotonic'})
            current = config['stats_schema'] == 'current'
            window = request('/control/stats/config' if current else '/control/stats_info')
            interval = window.get('interval')
            valid = _numeric(interval) if current else type(interval) is int and interval in (0, 1, 7, 30, 90)
            enabled = window.get('enabled') if current else interval != 0 if valid else None
            result['window'] = {'interval': interval if valid else None, 'unit': 'ms' if current else 'days',
                                'enabled': enabled if type(enabled) is bool else None,
                                'semantics': 'configured_retention_not_exact_sample_window',
                                'legacy_compatibility_may_round': not current}
        window_known = config['source'] == 'home_assistant' or (result['window']['interval'] is not None and result['window']['enabled'] is not None)
        result['status'] = 'passed' if window_known and all(m['status'] == 'ok' for m in result['metrics']) else 'inconclusive'
    except ObservationError as exc:
        result['status'] = 'inconclusive'
        # All raised messages are fixed literals; no upstream exception is persisted.
        code = str(exc)
        result['error'] = code if code in {'budget_exhausted', 'timeout', 'response_limit',
            'malformed_json', 'malformed_response', 'auth_denied', 'http_error',
            'unsupported_encoding', 'retry_rejected'} else 'observation_error'
    except (TimeoutError, asyncio.TimeoutError):
        result['status'], result['error'] = 'inconclusive', 'timeout'
    except Exception:
        result['status'], result['error'] = 'inconclusive', 'transport_error'
    return result


def write_observation(path, result):
    """Exclusive owner-only evidence; never overwrite or repair private paths."""
    data = json.dumps(result, allow_nan=False, sort_keys=True).encode() + b'\n'
    _require(len(data) <= MAX_PRIVATE, 'output_limit')
    parent, name = _parent(path)
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
