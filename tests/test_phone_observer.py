"""Synthetic protocol and JS tests; no LAN listener or actual phone/probes."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/phone_observer.py'
spec = importlib.util.spec_from_file_location('phone_observer', SOURCE)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


@pytest.fixture
def state():
    now = [10.0]
    value = observer.RunState('192.168.123.10', 8765, 30, clock=lambda: now[0])
    value.test_clock = now
    return value


def report(phase='baseline', sequence=1, states=('reachable', 'reachable')):
    return {'phase': phase, 'sequence': sequence, 'wifi_attested': True,
            'mobile_data_off_attested': True,
            'results': [{'probe': index, 'state': value} for index, value in enumerate(states)]}


class FakeSocket:
    def __init__(self, wire):
        self.incoming = io.BytesIO(wire)
        self.outgoing = bytearray()
    def makefile(self, *args):
        return self.incoming
    def sendall(self, data):
        self.outgoing.extend(data)
    def settimeout(self, timeout):
        assert timeout <= 5


def request(state, method='GET', route='', *, headers=None, body=b'', peer='192.168.123.20', path_override=None):
    selected = {'Host': '192.168.123.10:8765'}
    if method == 'POST':
        selected.update({'Origin': state.origin, 'Content-Type': 'application/json', 'Content-Length': str(len(body)), 'Sec-Fetch-Site': 'same-origin'})
    selected.update(headers or {})
    path = state.base + route if path_override is None else path_override
    wire = f'{method} {path} HTTP/1.1\r\n' + ''.join(f'{key}: {value}\r\n' for key, value in selected.items() if value is not None) + '\r\n'
    connection = FakeSocket(wire.encode() + body)
    observer.Handler(connection, (peer, 12345), SimpleNamespace(state=state))
    response = bytes(connection.outgoing)
    head, payload = response.split(b'\r\n\r\n', 1)
    return int(head.split(b' ', 2)[1]), head, payload


def post(state, value=None, **kwargs):
    return request(state, 'POST', 'report', body=json.dumps(report() if value is None else value).encode(), **kwargs)


@pytest.mark.parametrize('address', ['0.0.0.0', '127.0.0.1', '::', '::1', '8.8.8.8', '169.254.1.1', '100.64.0.1', '192.0.2.1', 'router.local', '192.168.001.1'])
def test_bind_only_explicit_numeric_rfc1918(address):
    with pytest.raises(ValueError):
        observer.RunState(address, 8765, 180)


@pytest.mark.parametrize('ttl', [0, 301, True, -1])
def test_ttl_is_bounded(ttl):
    with pytest.raises(ValueError):
        observer.RunState('192.168.1.1', 8765, ttl)


def test_token_page_exact_routes_headers_and_phase(state):
    other = observer.RunState(state.address, state.port, 30)
    assert len(state.token) >= 32 and state.token != other.token
    code, headers, page = request(state)
    assert code == 200 and page.decode() == observer.PAGE
    for field in (b'Cache-Control: no-store', b'Referrer-Policy: no-referrer', b'frame-ancestors', b'Content-Security-Policy:'):
        assert field in headers
    code, _, payload = request(state, route='phase')
    assert code == 200 and json.loads(payload)['phase'] == 'baseline'
    for route in ('../', '?extra=1', 'phase?x=y', 'report', 'favicon.ico'):
        assert request(state, route=route)[0] == 404
    original = state.base
    state.base = '/t/wrong/'
    # Old path remains unauthorized after token change.
    assert request(state, path_override=original)[0] == 404
    state.base = original


@pytest.mark.parametrize('headers', [
    {'Host': 'example.com'}, {'Host': '192.168.123.10'}, {'Origin': 'http://evil.invalid'},
    {'Origin': 'null'}, {'Origin': None}, {'Sec-Fetch-Site': 'cross-site'},
    {'Sec-Fetch-Site': 'same-site'}, {'Sec-Fetch-Site': 'none'},
    {'X-Forwarded-Proto': 'https'}, {'Forwarded': 'host=evil'},
])
def test_post_requires_exact_local_host_origin_fetch_site(state, headers):
    assert post(state, headers=headers)[0] == 403
    assert not state.reports


def test_duplicate_headers_unknown_verbs_and_oversized_request_line_rejected(state):
    assert request(state, headers={'Host': '192.168.123.10:8765\r\nHost: 192.168.123.10:8765'})[0] == 403
    assert post(state, headers={'Origin': state.origin + '\r\nOrigin: ' + state.origin})[0] == 403
    assert request(state, method='STRANGE')[0] == 405
    assert request(state, route='x' * 2100)[0] == 414
    assert not state.reports


def test_nonlocal_peer_and_cross_site_navigation_rejected(state):
    assert request(state, peer='127.0.0.1')[0] == 403
    assert request(state, peer='8.8.8.8')[0] == 403
    assert request(state, headers={'Sec-Fetch-Site': 'cross-site'})[0] == 403
    assert request(state, headers={'Sec-Fetch-Site': 'none'})[0] == 200


@pytest.mark.parametrize('headers,expected', [
    ({'Content-Length': '4097'}, 413), ({'Content-Length': '0'}, 413),
    ({'Content-Length': '-1'}, 400), ({'Content-Length': None}, 400),
    ({'Content-Type': 'text/plain'}, 415), ({'Transfer-Encoding': 'chunked'}, 400),
    ({'Expect': '100-continue'}, 400),
])
def test_body_and_content_type_bounds(state, headers, expected):
    assert post(state, headers=headers)[0] == expected
    assert not state.reports


@pytest.mark.parametrize('damage', ['extra', 'phase', 'count', 'bool_count', 'attestation', 'result_key', 'state', 'probe', 'missing_probe'])
def test_only_sanitized_exact_enum_fields_accepted(state, damage):
    value = report()
    if damage == 'extra': value['user_agent'] = 'private-device'
    elif damage == 'phase': value['phase'] = 'restored'
    elif damage == 'count': value['sequence'] = 2
    elif damage == 'bool_count': value['sequence'] = True
    elif damage == 'attestation': value['wifi_attested'] = False
    elif damage == 'result_key': value['results'][0]['url'] = 'http://router.invalid'
    elif damage == 'state': value['results'][0]['state'] = 'blocked'
    elif damage == 'probe': value['results'][0]['probe'] = 1
    else: value['results'].pop()
    assert post(state, value)[0] in (400, 409)
    assert not state.reports


def test_duplicate_json_keys_and_truncated_body_rejected(state):
    body = b'{"phase":"baseline","phase":"baseline"}'
    assert request(state, 'POST', 'report', body=body)[0] == 400
    assert request(state, 'POST', 'report', body=b'{}', headers={'Content-Length': '3'})[0] == 400


def test_three_ordered_stages_and_no_false_block_pass(state):
    assert post(state)[0] == 200
    assert post(state)[0] == 409  # duplicate or delayed replay
    value = report('block', 2, ('timeout', 'rejected'))
    assert post(state, value)[0] == 429  # bounded reporting rate
    state.test_clock[0] += 2
    assert post(state, value)[0] == 200
    state.test_clock[0] += 2
    assert post(state, report('restored', 3))[0] == 200
    assert state.done.is_set()
    assert post(state, report('restored', 3))[0] == 409
    summary = state.summary()
    assert summary['complete'] is True
    assert summary['phone_routing_verified'] is False
    assert summary['blocking_established'] is False
    assert summary['reports'][1]['observation'] == 'inconclusive'
    assert summary['reports'][0]['observation'] == 'selected_endpoints_reachable'
    wire = json.dumps(summary)
    for private in (state.address, state.token, 'User-Agent', 'native_alias', 'phone_probe='):
        assert private not in wire


def test_global_expiry_and_request_limit(state):
    for _ in range(60):
        assert request(state)[0] == 200
    assert request(state)[0] == 429
    state.test_clock[0] = state.deadline
    assert request(state)[0] == 410
    assert state.accept_report(report()) == 410


def test_output_owner_only_empty_no_symlinks_no_overwrite(state, tmp_path):
    directory = tmp_path / 'output'
    directory.mkdir(mode=0o700)
    fd = observer.open_output_directory(directory)
    try:
        observer.write_summary(fd, state.summary())
        summary = directory / 'summary.json'
        assert summary.stat().st_mode & 0o777 == 0o600
        before = summary.read_bytes()
        with pytest.raises(FileExistsError):
            observer.write_summary(fd, state.summary())
        assert summary.read_bytes() == before
    finally:
        os.close(fd)
    with pytest.raises(ValueError):
        observer.open_output_directory(directory)
    empty = tmp_path / 'empty'; empty.mkdir(mode=0o755)
    with pytest.raises(ValueError):
        observer.open_output_directory(empty)
    link = tmp_path / 'link'; link.symlink_to(empty, target_is_directory=True)
    with pytest.raises(ValueError):
        observer.open_output_directory(link)


@pytest.mark.parametrize('mode', ['pilot', 'baseline'])
def test_main_uses_fake_server_only_and_retains_summary(tmp_path, monkeypatch, capsys, mode):
    output = tmp_path / 'output'; output.mkdir(mode=0o700)
    created = []
    class FakeServer:
        def __init__(self, state):
            self.state = state; created.append(self)
        def serve_forever(self, **kwargs):
            if mode == 'baseline':
                assert post(self.state)[0] == 200
                assert self.state.done.is_set()
            else:
                self.state.done.set()
        def shutdown(self): self.stopped = True
        def server_close(self): self.closed = True
    monkeypatch.setattr(observer, 'LimitedServer', FakeServer)
    assert observer.main(['--bind', '192.168.123.10', '--output-dir', str(output), '--ttl', '1', '--mode', mode]) == 0
    assert created[0].stopped and created[0].closed
    assert created[0].state.token in capsys.readouterr().out  # human local console only
    saved = (output / 'summary.json').read_text()
    assert created[0].state.token not in saved
    assert json.loads(saved)['mode'] == mode
    assert json.loads(saved)['complete'] is (mode == 'baseline')


def test_browser_js_contract_with_mocked_fetch_only(tmp_path):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable; JS mock contract not executed')
    # Document/browser globals are synthetic; no browser/network is opened.
    prefix = r'''
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = SOURCE;
let calls = [], timers = [];
const elements = new Map();
const context = {
  document: {getElementById(id) { if (!elements.has(id)) elements.set(id, {checked:false, disabled:false, textContent:'', addEventListener(){}}); return elements.get(id); }},
  AbortController, Date, Math, Promise, JSON, Error, encodeURIComponent,
  setTimeout(fn, ms) { timers.push({fn, ms}); return timers.length; }, clearTimeout(){},
  fetch: async (url, options) => {
    calls.push({url,options});
    if (url === 'phase') return {ok:true, json:async()=>({phase:'baseline',sequence:1,remaining_ms:30000})};
    return {type:'opaque'};
  }
};
vm.createContext(context); vm.runInContext(source, context);
(async () => {
  const good = await vm.runInContext("probe(probes[0], 0, 1, Date.now()+10000)", context);
  assert.equal(good.state, 'reachable');
  const selected = calls.find(call => call.url.startsWith('https:'));
  assert.ok(selected.url.startsWith('https://www.cloudflare.com/cdn-cgi/trace?phone_probe='));
  for (const [key,value] of Object.entries({mode:'no-cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer'})) assert.equal(selected.options[key],value);
  assert.ok(selected.options.signal);
  assert.ok(timers.every(timer=>timer.ms<=5000));
  context.fetch = async()=>{throw new TypeError('synthetic failure');};
  assert.equal((await vm.runInContext("probe(probes[1], 1, 2, Date.now()+10000)",context)).state,'rejected');
  context.fetch = async()=>({type:'basic'});
  assert.equal((await vm.runInContext("probe(probes[1], 1, 2, Date.now()+10000)",context)).state,'unsupported');
  context.fetch = ()=>new Promise(()=>{});
  const pending = vm.runInContext("probe(probes[1], 1, 2, Date.now()+10000)",context);
  timers.at(-1).fn();
  assert.equal((await pending).state,'timeout');
  context.AbortController = undefined;
  assert.equal((await vm.runInContext("probe(probes[1], 1, 2, Date.now()+10000)",context)).state,'unsupported');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''.replace('SOURCE', json.dumps(observer.SCRIPT))
    script = tmp_path / 'contract.cjs'; script.write_text(prefix)
    result = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr



def test_baseline_finishes_after_one_report_and_never_accepts_later_stages():
    state = observer.RunState('192.168.123.10', 8765, 30, mode='baseline')
    assert state.phase()['phase'] == 'baseline'
    assert not state.summary()['complete']
    assert post(state, report('block', 1))[0] == 409
    assert post(state)[0] == 200
    assert state.done.is_set()
    assert state.phase()['phase'] is None
    for value in (report(), report('block', 2), report('restored', 3)):
        assert post(state, value)[0] == 409
    summary = state.summary()
    assert summary['mode'] == 'baseline'
    assert summary['required_reports'] == len(summary['reports']) == 1
    assert summary['complete'] is True
    assert summary['blocking_established'] is summary['phone_routing_verified'] is False
    assert [item['phase'] for item in summary['reports']] == ['baseline']
    assert state.token not in json.dumps(summary)
    assert state.address not in json.dumps(summary)


def test_baseline_page_and_csp_match_its_single_stage():
    import base64
    import hashlib
    state = observer.RunState('192.168.123.10', 8765, 30, mode='baseline')
    code, headers, page = request(state)
    assert code == 200
    script = page.decode().split('<script>', 1)[1].split('</script>', 1)[0]
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest())
    assert b"script-src 'sha256-" + digest + b"'" in headers
    assert "const stageNames = [\"baseline\"];" in script
    assert 'Baseline only. One report completes this session.' in page.decode()
    assert 'Observe block only after' not in page.decode()


def test_baseline_retains_request_origin_expiry_and_privacy_limits():
    now = [10.0]
    state = observer.RunState('192.168.123.10', 8765, 30, mode='baseline', clock=lambda: now[0])
    for headers in ({'Host': 'evil.invalid'}, {'Origin': None}, {'Origin': 'http://evil.invalid'},
                    {'Sec-Fetch-Site': 'cross-site'}, {'Forwarded': 'host=evil'}):
        assert post(state, headers=headers)[0] == 403
    assert request(state, peer='8.8.8.8')[0] == 403
    assert request(state, 'POST', 'report', body=b'x' * 4097)[0] == 413
    assert post(state, {**report(), 'private': 'sentinel'})[0] == 400
    while state.requests < 60:
        assert request(state)[0] == 200
    assert request(state)[0] == 429
    now[0] = state.deadline
    assert post(state)[0] == 410
    assert not state.reports and not state.done.is_set()
    assert 'sentinel' not in json.dumps(state.summary())


def test_invalid_mode_rejected():
    with pytest.raises(ValueError, match='Mode'):
        observer.RunState('192.168.123.10', 8765, 30, mode='block')


@pytest.mark.parametrize('mode', ['pilot', 'baseline'])
def test_browser_js_completes_exact_mode_report_count_with_fake_fetch(tmp_path, mode):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable; JS mock contract not executed')
    page, _ = observer.browser_assets(mode)
    source = page.split('<script>', 1)[1].split('</script>', 1)[0]
    harness = r'''
const vm = require('node:vm');
const assert = require('node:assert/strict');
const phases = PHASES;
let submitted = [], probes = [], click;
const elements = new Map();
const context = {
  document: {getElementById(id) {
    if (!elements.has(id)) elements.set(id, {checked:false, disabled:false, textContent:'',
      addEventListener(event, handler) { click = handler; }});
    return elements.get(id);
  }},
  AbortController, Date, Math, Promise, JSON, Error, encodeURIComponent,
  setTimeout(){return 1;}, clearTimeout(){},
  fetch: async (url, options) => {
    if (url === 'phase' || url === 'report') assert.equal(options.referrerPolicy, 'origin');
    else assert.equal(options.referrerPolicy, 'no-referrer');
    if (url === 'phase') return {ok:true, json:async()=>({
      phase:phases[submitted.length] ?? null, sequence:submitted.length+1, remaining_ms:30000})};
    if (url === 'report') {
      const value = JSON.parse(options.body);
      assert.equal(value.phase, phases[submitted.length]);
      assert.equal(value.sequence, submitted.length+1);
      submitted.push(value);
      return {ok:true};
    }
    probes.push(url);
    return {type:'opaque'};
  }
};
vm.createContext(context); vm.runInContext(SOURCE, context);
(async () => {
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(elements.get('run').textContent, 'Observe baseline');
  for (const phase of phases) {
    context.document.getElementById('wifi').checked = context.document.getElementById('mobile').checked = true;
    await click();
    assert.equal(elements.get('wifi').checked, false);
    assert.equal(elements.get('mobile').checked, false);
  }
  assert.equal(submitted.length, phases.length);
  assert.equal(probes.length, phases.length * 2);
  assert.equal(new Set(probes).size, probes.length);
  assert.equal(elements.get('run').textContent, 'Reports complete');
  assert.equal(elements.get('run').disabled, true);
  assert.equal(elements.get('status').textContent,
    phases.length + (phases.length === 1 ? ' report received.' : ' reports received.') +
    ' Endpoints only; blocking is not established.');
  await vm.runInContext('refresh()', context);
  assert.equal(elements.get('run').disabled, true);
  assert.equal(elements.get('status').textContent,
    phases.length + (phases.length === 1 ? ' report received.' : ' reports received.') +
    ' Read the local summary.');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''.replace('PHASES', json.dumps(['baseline'] if mode == 'baseline' else list(observer.PHASES))).replace('SOURCE', json.dumps(source))
    script = tmp_path / 'mode-contract.cjs'
    script.write_text(harness)
    result = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('headers,reason', [
    ({'Origin': None}, 'origin_missing'), ({'Origin': 'null'}, 'origin_null'),
    ({'Origin': 'http://private-sentinel.invalid'}, 'origin_mismatch'),
    ({'Host': 'private-sentinel.invalid'}, 'host_mismatch'),
    ({'Sec-Fetch-Site': 'cross-site'}, 'fetch_site'),
])
def test_rejection_diagnostics_are_fixed_counts_without_metadata(state, headers, reason):
    assert post(state, headers=headers)[0] == 403
    counts = state.summary()['rejection_counts']
    assert set(counts) == set(observer.REJECTION_REASONS)
    assert counts[reason] == 1 and sum(counts.values()) == 1
    assert all(type(value) is int and 0 <= value <= 60 for value in counts.values())
    assert 'private-sentinel' not in json.dumps(state.summary())
    assert state.token not in json.dumps(state.summary())
    assert not state.reports


def test_rejection_diagnostics_expiry_invalid_report_and_saturation(state):
    assert post(state, {**report(), 'secret': 'private-sentinel'})[0] == 400
    state.test_clock[0] = state.deadline
    for _ in range(65):
        assert request(state)[0] == 410
    counts = state.summary()['rejection_counts']
    assert counts['expired'] == 60
    assert counts['invalid_report'] == 1
    assert 'private-sentinel' not in json.dumps(state.summary())


@pytest.mark.parametrize('stage,status', [('phase', 403), ('report', 403), ('report', 410), ('report', 429), ('report', 599), ('report', None)])
def test_browser_local_delivery_failures_have_bounded_stage_diagnostics(tmp_path, stage, status):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable; JS mock contract not executed')
    harness = r'''
const vm = require('node:vm');
const assert = require('node:assert/strict');
const targetStage = STAGE, statusCode = STATUS;
let click, reports = 0;
const elements = new Map();
const context = {
 document: {getElementById(id) {if(!elements.has(id))elements.set(id,{checked:true,disabled:false,textContent:'',addEventListener(_,fn){click=fn;}});return elements.get(id);}},
 AbortController, Date, Math, Promise, JSON, Error, encodeURIComponent,
 setTimeout(){return 1;},clearTimeout(){},
 fetch: async(url,options)=>{
   if(url === 'report') reports++;
   if(url === targetStage){
     if(statusCode === null) throw new Error('private-sentinel');
     return {ok:false,status:statusCode};
   }
   if(url === 'phase')return{ok:true,json:async()=>({phase:'baseline',sequence:1,remaining_ms:30000})};
   return{type:'opaque'};
 }
};
vm.createContext(context);vm.runInContext(SOURCE,context);
(async()=>{
 await new Promise(resolve=>setImmediate(resolve));
 if(targetStage === 'report')await click();
 const text=elements.get('status').textContent;
 assert.ok(text.startsWith('Local '+targetStage));
 if(statusCode !== null)assert.ok(text.includes('HTTP '+(statusCode===599?'other':statusCode)));
 else assert.ok(text.includes('transport, timeout or unsupported response'));
 assert.ok(text.includes('Report delivery is unconfirmed'));
 assert.ok(!text.includes('private-sentinel'));
 assert.ok(!text.includes('reachable'));
 assert.equal(elements.get('run').disabled,true);
 assert.equal(reports,targetStage==='report'?1:0);
})().catch(error=>{console.error(error);process.exitCode=1;});
'''.replace('STAGE', json.dumps(stage)).replace('STATUS', json.dumps(status)).replace('SOURCE', json.dumps(observer.browser_assets('baseline')[0].split('<script>', 1)[1].split('</script>', 1)[0]))
    script = tmp_path / 'failure-contract.cjs'
    script.write_text(harness)
    result = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
