#!/usr/bin/env python3
"""Temporary phone-controlled LAN reachability collector; no router operations."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time

PHASES = ('baseline', 'block', 'restored')
STATES = ('reachable', 'timeout', 'rejected', 'unsupported')
PROBES = ('https://www.cloudflare.com/cdn-cgi/trace', 'https://www.wikipedia.org/')
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(item) for item in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
MAX_BODY = 4096
REJECTION_REASONS = ('expired', 'request_limit', 'peer', 'route', 'host_mismatch',
                     'forwarded', 'origin_missing', 'origin_null', 'origin_mismatch',
                     'fetch_site', 'framing', 'headers_size', 'invalid_report', 'report_rate')

# No secure-context-only crypto API: the companion is served over explicit LAN HTTP.
# Every probe URL adds a per-attempt nonce; no response body/header is inspected.
SCRIPT = r'''
const probes = __PROBES__;
const stageNames = __PHASES__;
const reportCount = stageNames.length;
const completeMessage = reportCount + (reportCount === 1 ? ' report received.' : ' reports received.');
const button = document.getElementById('run');
const status = document.getElementById('status');
let busy = false;
let runNonce = String(Date.now()) + '-' + Math.random().toString(36).slice(2);
async function boundedFetch(url, options, limit) {
  if (typeof AbortController !== 'function' || typeof fetch !== 'function' || limit <= 0) {
    throw new Error('unsupported');
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(5000, limit));
  try { return await fetch(url, {...options, signal: controller.signal}); }
  finally { clearTimeout(timer); }
}
function localHttpError(stage, statusCode) {
  const error = new Error('local_http');
  error.observerStage = stage;
  error.observerStatus = [400,403,404,409,410,413,414,415,429,431].includes(statusCode) ? statusCode : 'other';
  return error;
}
function localFailure(error, stage, posted) {
  error = error || {};
  const selected = error.observerStage === 'phase' || error.observerStage === 'report' ? error.observerStage : stage;
  const code = [400,403,404,409,410,413,414,415,429,431,'other'].includes(error.observerStatus) ?
    ' HTTP ' + error.observerStatus : ' transport, timeout or unsupported response';
  return 'Local ' + selected + code + '. ' + (posted ? 'Report was received.' : 'Report delivery is unconfirmed; no endpoint result is established here.') +
    ' Do not repeat probes automatically. Tell the operator; an expired listener needs a new reviewed run.';
}
async function phase() {
  const response = await boundedFetch('phase', {
    mode: 'same-origin', cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'origin'
  }, 5000);
  if (!response.ok) throw localHttpError('phase', response.status);
  return await response.json();
}
async function probe(url, index, sequence, deadline) {
  if (typeof AbortController !== 'function' || typeof fetch !== 'function' || Date.now() >= deadline) {
    return {probe: index, state: 'unsupported'};
  }
  const controller = new AbortController();
  const started = Date.now();
  const budget = Math.min(5000, deadline - started);
  let timer;
  try {
    const nonce = runNonce + '-' + sequence + '-' + index + '-' + started;
    const attempt = fetch(url + '?phone_probe=' + encodeURIComponent(nonce), {
      mode: 'no-cors', cache: 'no-store', credentials: 'omit', redirect: 'error',
      referrerPolicy: 'no-referrer', signal: controller.signal
    }).then(response => ({probe: index, state: Date.now() - started > budget ? 'timeout' :
      (response.type === 'opaque' ? 'reachable' : 'unsupported')}),
      () => ({probe: index, state: 'rejected'}));
    const timeout = new Promise(resolve => {
      timer = setTimeout(() => { resolve({probe: index, state: 'timeout'}); controller.abort(); }, budget);
    });
    return await Promise.race([attempt, timeout]);
  } catch (_) { return {probe: index, state: 'unsupported'}; }
  finally { clearTimeout(timer); }

}
async function refresh() {
  const current = await phase();
  button.disabled = current.phase === null;
  button.textContent = current.phase === null ? 'Reports complete' : 'Observe ' + current.phase;
  status.textContent = current.phase === null ? completeMessage + ' Read the local summary.' :
    'Next stage: ' + current.phase + '. Confirm Wi-Fi and mobile data OFF below.' +
    (reportCount > 1 ? ' Wait for the human operator before block/restored.' : ' Baseline only; no router change is needed.');
}
button.addEventListener('click', async () => {
  if (busy) return;
  if (!document.getElementById('wifi').checked || !document.getElementById('mobile').checked) {
    status.textContent = 'Personally check phone Wi-Fi and mobile data OFF first.'; return;
  }
  busy = true; button.disabled = true;
  let posted = false;
  let localStage = 'phase';
  try {
    const current = await phase();
    if (!stageNames.includes(current.phase)) throw new Error('complete');
    const deadline = Date.now() + Math.max(0, current.remaining_ms - 500);
    status.textContent = 'Observing ' + current.phase + '; keep this browser foregrounded.';
    localStage = 'probes';
    const results = [];
    for (let index = 0; index < probes.length; index++) {
      results.push(await probe(probes[index], index, current.sequence, deadline));
    }
    // Exactly one report attempt. An ambiguous local response must not cause a retry.
    localStage = 'report';
    const response = await boundedFetch('report', {
      method: 'POST', mode: 'same-origin', cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'origin',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({phase: current.phase, sequence: current.sequence,
        wifi_attested: true, mobile_data_off_attested: true, results})
    }, Math.min(5000, deadline - Date.now()));
    if (!response.ok) throw localHttpError('report', response.status);
    posted = true;
    // Attest again at each later stage, since phone routing can change.
    document.getElementById('wifi').checked = false;
    document.getElementById('mobile').checked = false;
    if (current.phase === stageNames[reportCount - 1]) {
      status.textContent = completeMessage + ' Endpoints only; blocking is not established.';
      button.textContent = 'Reports complete';
    } else { localStage = 'phase'; await refresh(); }
  } catch (error) {
    status.textContent = localFailure(error, localStage, posted);
    // Require a deliberate page reload after ambiguous reporting; no hidden re-probe.
    button.disabled = true;
  } finally { busy = false; }
});
refresh().catch(error => { status.textContent = localFailure(error, 'phase', false); button.disabled = true; });
'''.replace('__PROBES__', json.dumps(PROBES))
SCRIPT_TEMPLATE = SCRIPT
SCRIPT = SCRIPT_TEMPLATE.replace('__PHASES__', json.dumps(PHASES))
PAGE = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Phone endpoint observer</title>
<h1>Phone endpoint observer</h1><p>Leave this phone on the test Wi-Fi, disable mobile data and keep this page foregrounded. Check the phone settings yourself at each stage. This page cannot verify them.</p>
<p>Baseline first. Observe block only after the human operator says the separately approved block has been applied. Observe restored only after the operator confirms restoration. This page never approves or changes router settings.</p>
<p>Two fixed HTTPS endpoints are contacted once per stage, for at most five seconds each. Opaque success observes reachability only; timeout/rejection is inconclusive. No response content is read.</p>
<label><input type="checkbox" id="wifi">I checked that this phone is on the test Wi-Fi.</label><br>
<label><input type="checkbox" id="mobile">I checked that mobile data is OFF.</label>
<p><button id="run" disabled>Loading local phase</button></p><p id="status" role="status"></p><script>''' + SCRIPT + '</script></html>'
CSP_HASH = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()


def browser_assets(mode):
    if mode == 'pilot':
        return PAGE, CSP_HASH
    script = SCRIPT_TEMPLATE.replace('__PHASES__', json.dumps(['baseline']))
    page = PAGE.replace(SCRIPT, script).replace(
        'Baseline first. Observe block only after the human operator says the separately approved block has been applied. Observe restored only after the operator confirms restoration. This page never approves or changes router settings.',
        'Baseline only. One report completes this session. No router change is needed; this page never approves or changes router settings.')
    return page, base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()


def private_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        raise ValueError('Use an explicit numeric RFC1918 IPv4 LAN address') from None
    if str(address) != value or not any(address in network for network in PRIVATE_NETWORKS):
        raise ValueError('Bind/peer must be numeric RFC1918 IPv4, not wildcard, public or loopback')
    return str(address)


class RunState:
    def __init__(self, address, port, ttl, *, mode='pilot', clock=time.monotonic):
        if mode not in ('pilot', 'baseline'):
            raise ValueError('Mode must be pilot or baseline')
        self.mode = mode
        self.phases = PHASES if mode == 'pilot' else ('baseline',)
        self.page, self.csp_hash = browser_assets(mode)
        self.address = private_ipv4(address)
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError('Use an explicit unprivileged port 1024..65535')
        if type(ttl) is not int or not 1 <= ttl <= 300:
            raise ValueError('TTL must be 1..300 seconds')
        self.port, self.clock = port, clock
        self.started, self.deadline = clock(), clock() + ttl
        self.origin = f'http://{self.address}:{port}'
        self.token = secrets.token_urlsafe(32)
        self.base = '/t/' + self.token + '/'
        self.lock = threading.Lock()
        self.reports = []
        self.rejections = {reason: 0 for reason in REJECTION_REASONS}
        self.requests = 0
        self.last_report = None
        self.done = threading.Event()

    def _reject_locked(self, reason, code):
        # Fixed enums and saturating counts only: never retain request values.
        self.rejections[reason] = min(60, self.rejections[reason] + 1)
        return code

    def reject(self, reason, code):
        with self.lock:
            return self._reject_locked(reason, code)

    def admit_request(self):
        with self.lock:
            if self.clock() >= self.deadline:
                return self._reject_locked('expired', 410)
            self.requests += 1
            return self._reject_locked('request_limit', 429) if self.requests > 60 else 200

    def phase(self):
        with self.lock:
            count = len(self.reports)
            return {'phase': self.phases[count] if count < len(self.phases) else None, 'sequence': count + 1,
                    'remaining_ms': max(0, int((self.deadline - self.clock()) * 1000))}

    def accept_report(self, data):
        with self.lock:
            now = self.clock()
            if now >= self.deadline:
                return self._reject_locked('expired', 410)
            count = len(self.reports)
            if count >= len(self.phases):
                return self._reject_locked('invalid_report', 409)
            if not isinstance(data, dict) or set(data) != {'phase', 'sequence', 'wifi_attested', 'mobile_data_off_attested', 'results'}:
                return self._reject_locked('invalid_report', 400)
            if (data['phase'] != self.phases[count] or type(data['sequence']) is not int or data['sequence'] != count + 1
                    or data['wifi_attested'] is not True or data['mobile_data_off_attested'] is not True):
                return self._reject_locked('invalid_report', 409)
            results = data['results']
            if type(results) is not list or len(results) != 2:
                return self._reject_locked('invalid_report', 400)
            for index, result in enumerate(results):
                if (type(result) is not dict or set(result) != {'probe', 'state'} or type(result['probe']) is not int
                        or result['probe'] != index or type(result['state']) is not str or result['state'] not in STATES):
                    return self._reject_locked('invalid_report', 400)
            if self.last_report is not None and now - self.last_report < 2:
                return self._reject_locked('report_rate', 429)
            # Copy only the bounded validated fields; never retain request metadata.
            self.reports.append({'phase': self.phases[count], 'sequence': count + 1,
                                 'wifi_attested': True, 'mobile_data_off_attested': True,
                                 'results': [{'probe': index, 'state': result['state']} for index, result in enumerate(results)],
                                 'observation': 'selected_endpoints_reachable' if all(result['state'] == 'reachable' for result in results) else 'inconclusive'})
            self.last_report = now
            return 200

    def summary(self):
        with self.lock:
            return {'schema_version': 1, 'scope': 'Phone-reported observations of two fixed HTTPS endpoints only',
                    'recorded_at_utc': datetime.now(timezone.utc).isoformat(),
                    'mode': self.mode, 'required_reports': len(self.phases),
                    'complete': len(self.reports) == len(self.phases), 'reports': list(self.reports),
                    'phone_routing_verified': False, 'blocking_established': False,
                    'rejection_counts': dict(self.rejections),
                    'limits': ['Wi-Fi/mobile-data state is human attestation, not verified',
                               'Opaque success does not prove content, status or all-internet reachability',
                               'Timeout/rejection may be browser policy, endpoint, DNS, TLS, redirect or network failure',
                               'Reports are self-reported over token-protected LAN HTTP, not device attestation',
                               'No router state, native restoration or approval is verified by this collector']}


class Handler(BaseHTTPRequestHandler):
    server_version = 'PhoneObserver'
    sys_version = ''
    protocol_version = 'HTTP/1.0'

    def log_message(self, *args):
        pass  # Never log IPs, URL tokens, User-Agent, bodies or error diagnostics.

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def parse_request(self):
        if len(self.raw_requestline) > 2048:
            # Establish fields used by send_response before normal parsing.
            self.requestline = ''
            self.request_version = 'HTTP/1.0'
            self.command = ''
            self.respond(414)
            return False
        if not super().parse_request():
            return False
        if self.command not in {'GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'}:
            code = self.gate()
            self.respond(405 if code == 200 else code)
            return False
        return True

    def gate(self, *, post=False):
        state = self.server.state
        admitted = state.admit_request()
        if admitted != 200:
            return admitted
        try:
            private_ipv4(self.client_address[0])
        except ValueError:
            return state.reject('peer', 403)
        if len(self.path) > 256 or '?' in self.path or '#' in self.path:
            return state.reject('route', 404)
        if self.headers.get_all('Host') != [state.origin.removeprefix('http://')]:
            return state.reject('host_mismatch', 403)
        if any(key in self.headers for key in ('Forwarded', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Forwarded-For')):
            return state.reject('forwarded', 403)
        origins = self.headers.get_all('Origin', [])
        if origins and origins != [state.origin]:
            return state.reject('origin_null' if origins == ['null'] else 'origin_mismatch', 403)
        if post and origins != [state.origin]:
            return state.reject('origin_missing', 403)
        sites = self.headers.get_all('Sec-Fetch-Site', [])
        if sites and sites != ['same-origin'] and (post or sites != ['none']):
            return state.reject('fetch_site', 403)
        if 'Transfer-Encoding' in self.headers or 'Expect' in self.headers:
            return state.reject('framing', 400)
        if sum(len(key) + len(value) for key, value in self.headers.items()) > 8192:
            return state.reject('headers_size', 431)
        return 200

    def respond(self, code, payload=None, *, html=False):
        body = self.server.state.page.encode() if html else json.dumps(payload or {'status': 'rejected'}, separators=(',', ':')).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'sha256-" + self.server.state.csp_hash + "'; connect-src 'self' https://www.cloudflare.com https://www.wikipedia.org; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def do_GET(self):
        code = self.gate()
        if code != 200:
            return self.respond(code)
        state = self.server.state
        if self.path == state.base:
            return self.respond(200, html=True)
        if self.path == state.base + 'phase':
            return self.respond(200, state.phase())
        return self.respond(404)

    def do_POST(self):
        code = self.gate(post=True)
        if code != 200:
            return self.respond(code)
        state = self.server.state
        if self.path != state.base + 'report':
            return self.respond(state.reject('route', 404))
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
            return self.respond(state.reject('invalid_report', 400))
        if len(lengths[0]) > 4:
            return self.respond(state.reject('invalid_report', 413))
        length = int(lengths[0])
        if not 1 <= length <= MAX_BODY:
            return self.respond(state.reject('invalid_report', 413))
        if self.headers.get_all('Content-Type') != ['application/json']:
            return self.respond(state.reject('invalid_report', 415))
        raw = self.rfile.read(length)
        if len(raw) != length:
            return self.respond(state.reject('invalid_report', 400))
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate')
                result[key] = value
            return result
        try:
            data = json.loads(raw, object_pairs_hook=unique_pairs)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return self.respond(state.reject('invalid_report', 400))
        code = state.accept_report(data)
        self.respond(code, {'status': 'received'} if code == 200 else None)
        if code == 200 and len(state.reports) == len(state.phases):
            state.done.set()

    # Reject other verbs without exposing BaseHTTPRequestHandler's diagnostic page.
    def do_OPTIONS(self):
        code = self.gate()
        self.respond(405 if code == 200 else code)
    do_HEAD = do_OPTIONS
    do_PUT = do_OPTIONS
    do_DELETE = do_OPTIONS
    do_PATCH = do_OPTIONS
    do_TRACE = do_OPTIONS
    do_CONNECT = do_OPTIONS


class LimitedServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, state):
        self.state = state
        self.slots = threading.BoundedSemaphore(4)
        super().__init__((state.address, state.port), Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, *args):
        pass  # No raw request traceback on stdout/stderr.


def open_output_directory(path):
    path = Path(path).absolute()
    # Refuse existing symlink components, even if the final directory looks safe.
    for parent in (*reversed(path.parents), path):
        if parent.is_symlink():
            raise ValueError('Output path must not contain symlinks')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or os.listdir(fd):
        os.close(fd)
        raise ValueError('Output must be an existing owner-only 0700 empty directory')
    return fd


def write_summary(directory_fd, summary):
    fd = os.open('summary.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, 'w') as output:
        json.dump(summary, output, indent=2, allow_nan=False)
        output.write('\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('pilot', 'baseline'), default='pilot', help='pilot: three stages (default); baseline: one report, no router change')
    parser.add_argument('--bind', required=True, help='Exact numeric RFC1918 IPv4 address of this computer LAN interface')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--ttl', type=int, default=180, help='Global lifetime in seconds, 1..300')
    parser.add_argument('--output-dir', required=True, type=Path, help='Existing empty directory, owned by you with mode 0700')
    args = parser.parse_args(argv)
    directory_fd = None
    server = None
    state = None
    save_failed = False
    try:
        state = RunState(args.bind, args.port, args.ttl, mode=args.mode)
        directory_fd = open_output_directory(args.output_dir)
        server = LimitedServer(state)
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        worker.start()
        print('Human phone URL (local console only; keep private): ' + state.origin + state.base, flush=True)
        print('Keep phone on test Wi-Fi with mobile data OFF; operator approval and all router actions remain separate.', flush=True)
        state.done.wait(max(0, state.deadline - state.clock()))
    except KeyboardInterrupt:
        pass
    except (ValueError, OSError):
        # Avoid echoing local addresses, paths or tokens from exception messages.
        print('Observer could not start or save safely; check bind, port and empty owner-only output directory.')
        return 2
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if directory_fd is not None:
            try:
                if state is not None:
                    write_summary(directory_fd, state.summary())
            except OSError:
                save_failed = True
            finally:
                os.close(directory_fd)
    if save_failed:
        print('Observer stopped; exclusive summary save failed. No existing file was overwritten.')
        return 2
    print('Observer stopped. Sanitized summary.json is in the selected output directory.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
