"""Explicit one-session HA loopback observations over strict native OpenSSH.

The owner controls all selected paths. Safe ancestors exclude untrusted replacement;
concurrent replacement by the trusted owner is outside this observation contract.
No SSH settings, credentials, remote files or HA state are changed.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import time

from .home_observations import (ObservationError, UNITS, _ha_metric, _json,
                                _parent, _read_private, _require)

MAX_OUTPUT = 65536
ERRORS = frozenset({'auth_denied', 'http_error', 'malformed_response', 'malformed_json',
                    'response_limit', 'timeout', 'budget_exhausted', 'transport_error'})
# Constant remote code: config values and credentials only enter its bounded stdin.
REMOTE_PROGRAM = r'''
import json, math, re, signal, sys, time, urllib.error, urllib.request
MAX = 1048576
class Stop(Exception): pass
def need(ok, code):
    if not ok: raise Stop(code)
def pairs(items):
    d = {}
    for k,v in items:
        need(k not in d, 'malformed_json')
        d[k]=v
    return d
def parse(data):
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(Stop('malformed_json')))
    except (ValueError, UnicodeError, RecursionError): raise Stop('malformed_json')
def alarm(signum, frame): raise Stop('timeout')
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): raise Stop('http_error')
out={'protocol':1,'authenticated_api':False,'request_count':0,'states':[],'error':None}
start=time.monotonic()
signal.signal(signal.SIGALRM, alarm)
try:
    signal.setitimer(signal.ITIMER_REAL, 5)
    raw=sys.stdin.buffer.read(16385)
    need(len(raw)<=16384, 'malformed_response')
    request=parse(raw)
    need(type(request) is dict and set(request)=={'token','entities'}, 'malformed_response')
    token=request['token']; entities=request['entities']
    need(type(token) is str and re.fullmatch(r'[A-Za-z0-9._~+/-]{1,8192}=*', token), 'malformed_response')
    need(type(entities) is list and 1<=len(entities)<=8 and all(type(e) is str and re.fullmatch(r'sensor\.[a-z0-9_]{1,200}',e) for e in entities) and len(set(entities))==len(entities), 'malformed_response')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def get(path):
        remaining=60-(time.monotonic()-start)
        need(remaining>0 and out['request_count']<9, 'budget_exhausted')
        # POSIX wall timer also bounds trickling bodies; socket timeout alone does not.
        signal.setitimer(signal.ITIMER_REAL, min(5, remaining))
        out['request_count']+=1
        req=urllib.request.Request('http://127.0.0.1:8123'+path, headers={'Authorization':'Bearer '+token,'Accept':'application/json'}, method='GET')
        try:
            with opener.open(req, timeout=min(5,remaining)) as response:
                need(response.status==200, 'http_error')
                need(response.headers.get_content_type()=='application/json' and response.headers.get('Content-Encoding','identity')=='identity', 'malformed_response')
                data=response.read(MAX+1)
                need(len(data)<=MAX,'response_limit')
                result=parse(data)
                need(type(result) is dict,'malformed_response')
                return result
        except urllib.error.HTTPError as e: raise Stop('auth_denied' if e.code in (401,403) else 'http_error')
        except (TimeoutError,): raise Stop('timeout')
        finally: signal.setitimer(signal.ITIMER_REAL, 0)
    ping=get('/api/')
    need(ping.get('message')=='API running.','malformed_response')
    out['authenticated_api']=True
    for entity in entities:
        state=get('/api/states/'+entity)
        need(state.get('entity_id')==entity and type(state.get('attributes')) is dict,'malformed_response')
        value=state.get('state'); unit=state['attributes'].get('unit_of_measurement'); stamp=state.get('last_updated')
        out['states'].append({'entity_id':entity,'state':value if type(value) is str and len(value)<=80 else None,
            'attributes':{'unit_of_measurement':unit if type(unit) is str and len(unit)<=40 else None},
            'last_updated':stamp if type(stamp) is str and len(stamp)<=40 else None})
except Stop as e: out['error']=str(e)
except Exception: out['error']='transport_error'
finally:
    signal.setitimer(signal.ITIMER_REAL,0)
    sys.stdout.write(json.dumps(out,allow_nan=False,separators=(',',':'))+'\n')
'''
REMOTE_COMMAND = '/usr/bin/python3 -c ' + shlex.quote(REMOTE_PROGRAM)


def default_config_path():
    return Path.home() / '.config/asus-router-agent/home-observation-ssh.json'


def _checked_file(path, modes=(0o600,), maximum=65536):
    _require(type(path) is str and len(path) <= 4096 and re.fullmatch(r'/[A-Za-z0-9_./@+-]+', path), 'unsafe_file')
    parent, name = _parent(path)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        st = os.fstat(fd)
        _require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
                 stat.S_IMODE(st.st_mode) in modes and st.st_nlink == 1 and
                 0 < st.st_size <= maximum, 'unsafe_file')
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _token(data):
    _require(len(data) <= 65536, 'invalid_credentials')
    try:
        text = data.decode('utf-8')
        values = []
        for line in text.splitlines():
            parts = shlex.split(line, comments=True, posix=True)
            if parts and parts[0] == 'export':
                parts = parts[1:]
            if parts and parts[0].startswith('HASS_TOKEN='):
                _require(len(parts) == 1, 'invalid_credentials')
                values.append(parts[0][len('HASS_TOKEN='):])
        _require(len(values) == 1 and re.fullmatch(r'[A-Za-z0-9._~+/-]{1,8192}=*', values[0]), 'invalid_credentials')
        return values[0]
    except (ValueError, UnicodeError):
        raise ObservationError('invalid_credentials') from None


def _load(path):
    config = _json(_read_private(path))
    _require(type(config) is dict and set(config) == {'host', 'user', 'keyfile', 'knownhostsfile', 'hass_env_file', 'sensors'}, 'invalid_config')
    host, user = config['host'], config['user']
    _require(type(host) is str and 1 <= len(host) <= 253 and host.isascii(), 'invalid_host')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        _require(all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split('.')), 'invalid_host')
    else:
        _require(not getattr(address, 'scope_id', None) and not address.is_unspecified and not address.is_multicast, 'invalid_host')
    _require(type(user) is str and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user), 'invalid_user')
    sensors = config['sensors']
    _require(type(sensors) is list and 1 <= len(sensors) <= 8, 'invalid_sensors')
    aliases, entities = set(), set()
    for spec in sensors:
        _require(type(spec) is dict and set(spec) == {'alias', 'entity_id', 'unit'}, 'invalid_sensors')
        alias, entity, unit = spec['alias'], spec['entity_id'], spec['unit']
        _require(type(alias) is str and re.fullmatch(r'metric_[1-8]', alias) and alias not in aliases and
                 type(entity) is str and re.fullmatch(r'sensor\.[a-z0-9_]{1,200}', entity) and entity not in entities and
                 type(unit) is str and unit in UNITS, 'invalid_sensors')
        aliases.add(alias)
        entities.add(entity)
    _checked_file(config['keyfile'])
    _checked_file(config['knownhostsfile'], (0o600, 0o644), 1048576)
    _checked_file(config['hass_env_file'])
    token = _token(_read_private(config['hass_env_file']))
    return config, token


def preflight(config_path=None):
    try:
        _load(default_config_path() if config_path is None else config_path)
        return {'status': 'ready', 'configured': True, 'credential_ready': True}
    except (ObservationError, OSError, TypeError):
        return {'status': 'blocked_access', 'configured': False, 'credential_ready': False}


def ssh_argv(config):
    options = ('UpdateHostKeys=no', 'ControlMaster=no', 'ControlPath=none', 'GlobalKnownHostsFile=/dev/null',
               'UserKnownHostsFile=' + config['knownhostsfile'], 'StrictHostKeyChecking=yes', 'BatchMode=yes',
               'IdentitiesOnly=yes', 'IdentityAgent=none', 'PasswordAuthentication=no',
               'KbdInteractiveAuthentication=no', 'ProxyCommand=none', 'ProxyJump=none',
               'PermitLocalCommand=no', 'ClearAllForwardings=yes', 'ConnectionAttempts=1', 'ConnectTimeout=5')
    argv = ['/usr/bin/ssh', '-F', '/dev/null']
    for option in options:
        argv.extend(('-o', option))
    return argv + ['-i', config['keyfile'], '-a', '-x', '-T', '--', config['user'] + '@' + config['host'], REMOTE_COMMAND]


def execute_ssh(argv, request, *, timeout, max_output=MAX_OUTPUT):
    """One process; bounded three pipes, closed input, killed/reaped process group."""
    _require(type(request) is bytes and len(request) <= 16384 and 0 < timeout <= 70, 'invalid_request')
    started = time.monotonic()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False, start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    except OSError:
        return {'status': 'launch_failed', 'returncode': None, 'stdout': b''}
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    received, sent, status = 0, 0, 'completed'
    try:
        for stream, event, role in ((process.stdin, selectors.EVENT_WRITE, 'in'),
                                    (process.stdout, selectors.EVENT_READ, 'out'),
                                    (process.stderr, selectors.EVENT_READ, 'err')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event, role)
        while selector.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                status = 'timeout'
                break
            for key, _ in selector.select(min(.1, remaining)):
                if key.data == 'in':
                    try:
                        sent += os.write(key.fd, request[sent:sent + 4096])
                    except BrokenPipeError:
                        status = 'process_failed'
                        break
                    if sent == len(request):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    chunk = os.read(key.fd, min(4096, max_output + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    received += len(chunk)
                    if received > max_output:
                        status = 'output_limit'
                        break
                    if key.data == 'out':
                        stdout.extend(chunk)
            if status != 'completed':
                break
        if status == 'completed':
            try:
                process.wait(timeout=max(.001, timeout - (time.monotonic() - started)))
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
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    return {'status': status, 'returncode': process.returncode, 'stdout': bytes(stdout) if status == 'completed' else b''}


def collect_home_ssh(config_path=None, *, runner=None, clock=time.monotonic):
    result = {'schema_version': 1, 'status': 'blocked_access', 'source': 'home_assistant',
              'transport': 'openssh_verified_host_loopback_http', 'authenticated_api': False,
              'request_count': 0, 'metrics': [], 'provider_poll_freshness': 'unknown',
              'source_version': None, 'credential_read_only_scope_verified': False,
              'benefit_proven': False, 'production_admission_verified': False,
              'counter_decrease_semantics': 'ambiguous_window_change_not_rate_or_reset_proof'}
    started = clock()
    try:
        config, token = _load(default_config_path() if config_path is None else config_path)
    except (ObservationError, OSError, TypeError):
        return result
    try:
        before = clock()
        _require(started <= before < started + 70, 'budget_exhausted')
        request = json.dumps({'token': token, 'entities': [s['entity_id'] for s in config['sensors']]}, separators=(',', ':')).encode()
        del token
        reply = (runner or execute_ssh)(ssh_argv(config), request, timeout=70 - (before - started), max_output=MAX_OUTPUT)
        ended = clock()
        _require(before <= ended <= started + 70, 'timeout')
        _require(type(reply) is dict and reply.get('status') == 'completed' and reply.get('returncode') == 0,
                 reply.get('status') if type(reply) is dict and reply.get('status') in ('timeout', 'output_limit') else 'transport_error')
        raw = reply.get('stdout')
        _require(type(raw) is bytes and len(raw) <= MAX_OUTPUT, 'output_limit')
        data = _json(raw)
        _require(type(data) is dict and set(data) == {'protocol', 'authenticated_api', 'request_count', 'states', 'error'} and
                 type(data['protocol']) is int and data['protocol'] == 1 and type(data['authenticated_api']) is bool and
                 type(data['request_count']) is int and 0 <= data['request_count'] <= 9 and
                 type(data['states']) is list and len(data['states']) <= len(config['sensors']) and
                 (data['error'] is None or type(data['error']) is str and data['error'] in ERRORS), 'malformed_response')
        count, states, error = data['request_count'], data['states'], data['error']
        _require((error is not None or len(states) == len(config['sensors'])) and
                 (data['authenticated_api'] or not states) and
                 (count == len(states) + 1 if error is None else len(states) <= count <= len(states) + 2), 'malformed_response')
        metrics = []
        for spec, state in zip(config['sensors'], states):
            _require(type(state) is dict and set(state) == {'entity_id', 'state', 'attributes', 'last_updated'} and
                     type(state['attributes']) is dict and set(state['attributes']) == {'unit_of_measurement'} and
                     (state['state'] is None or type(state['state']) is str and len(state['state']) <= 80) and
                     (state['last_updated'] is None or type(state['last_updated']) is str and len(state['last_updated']) <= 40) and
                     (state['attributes']['unit_of_measurement'] is None or type(state['attributes']['unit_of_measurement']) is str and
                      len(state['attributes']['unit_of_measurement']) <= 40), 'malformed_response')
            metrics.append(_ha_metric(spec, state))
        result.update(authenticated_api=data['authenticated_api'], request_count=count, metrics=metrics)
        result['status'] = 'passed' if error is None and all(m['status'] == 'ok' for m in metrics) else 'inconclusive'
        if error:
            result['error'] = error
    except ObservationError as exc:
        code = str(exc)
        result['status'], result['error'] = 'inconclusive', code if code in ERRORS | {'output_limit'} else 'malformed_response'
    except Exception:
        result['status'], result['error'] = 'inconclusive', 'transport_error'
    return result
