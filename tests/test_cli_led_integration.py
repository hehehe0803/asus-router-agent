"""Full native CLI LED protocol against localhost, with no real credentials/router."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from urllib.parse import unquote

from tls_helpers import localhost_tls
from router_agent.approval_window import approval_request
from router_agent.operations import FilePlanStore
from router_agent.auth import AuthConfig
from router_agent.cli import main
from router_agent.native_control import led_body
from router_agent.transport import HOOKS

IDENTITY = {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436-ge7c0b5e', 'label_mac': 'AA:BB:CC:DD:EE:FF'}


def test_cli_native_led_full_stack_with_independent_verify_and_reverse(tmp_path, monkeypatch, capsys):
    state = {'enabled': False, 'calls': [], 'invalid': [], 'window_fault': None, 'fault_ready': False, 'final_reads': 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.handle_request()

        def do_POST(self):
            self.handle_request()

        def handle_request(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            state['calls'].append((self.command, self.path, raw))
            status = 200
            if self.path == '/login.cgi':
                response = {'asus_token': 'synthetic-private-session-token'}
            elif self.path == '/Logout.asp':
                response = {'error_status': 8}
            elif self.path == '/appGet.cgi':
                decoded = unquote(raw.decode())
                if decoded == 'hook=' + HOOKS['identity']:
                    response = IDENTITY
                elif decoded == 'hook=' + HOOKS['led']:
                    if state['window_fault']:
                        state['final_reads'] += 1
                        if state['final_reads'] == 2:
                            state['fault_ready'] = True
                    response = {'led_val': str(int(state['enabled'])), 'password': 'synthetic-response-secret'}
                else:
                    state['invalid'].append((self.path, decoded))
                    status, response = 400, {'error': 'unexpected hook'}
            elif self.path == '/applyapp.cgi' and raw in (led_body(False), led_body(True)):
                state['enabled'] = raw == led_body(True)
                response = {'run_service': 'start_ctrl_led'}
            else:
                state['invalid'].append((self.path, raw))
                status, response = 400, {'error': 'unexpected request'}
            encoded = json.dumps(response).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = localhost_tls()
    context, ca_file = tls.__enter__()
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = AuthConfig(f'https://127.0.0.1:{server.server_port}', 'synthetic-admin', ca_file=ca_file)
    monkeypatch.setattr('router_agent.snapshots.default_state_dir', lambda: tmp_path / 'private-state')
    monkeypatch.setattr('router_agent.cli.load_config', lambda: config)
    monkeypatch.setattr('router_agent.cli.get_credentials', lambda: (config, 'synthetic-router-password'))
    monkeypatch.setattr('router_agent.approval_window._read_grant',
                        lambda window_id: approval_request(FilePlanStore(tmp_path / 'private-state' / 'plans').get(window_id)[0]))
    monkeypatch.setattr('sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('sys.stderr.isatty', lambda: True)
    all_output = []

    def command(argv, expected_exit=0):
        if argv[0] == 'apply':
            argv = [*argv, '--window', argv[1]]
        assert main(argv) == expected_exit
        output = capsys.readouterr()
        all_output.append(output.out + output.err)
        return json.loads(output.out)

    def writes():
        return [raw for _, path, raw in state['calls'] if path == '/applyapp.cgi']

    try:
        preview = command(['plan', 'led', '--enabled', 'on'])['data']['plan']
        assert preview['before'] == {'enabled': False}
        assert preview['after'] == {'enabled': True}
        assert not writes()
        plan_id = preview['hash']
        records_before_cancel = len(state['calls'])
        monkeypatch.setattr('builtins.input', lambda _: 'cancel')
        cancelled = command(['apply', plan_id], 1)
        assert cancelled['error']['code'] == 'approval_cancelled'
        assert len(state['calls']) == records_before_cancel and not writes()

        # Administrator revocation or expiry during the prompt denies before login.
        from router_agent.errors import RouterError
        grant_reader = lambda window_id: approval_request(FilePlanStore(tmp_path / 'private-state' / 'plans').get(window_id)[0])
        reads = [0]
        def revoked(window_id):
            reads[0] += 1
            if reads[0] > 1:
                raise RouterError('approval_window_required', 'Administrator approval was revoked.')
            return grant_reader(window_id)
        monkeypatch.setattr('router_agent.approval_window._read_grant', revoked)
        monkeypatch.setattr('builtins.input', lambda _: 'apply ' + plan_id)
        revoked_result = command(['apply', plan_id], 1)
        assert revoked_result['error']['code'] == 'approval_window_required'
        assert len(state['calls']) == records_before_cancel and not writes()
        reads[0] = 0
        def expired(window_id):
            reads[0] += 1
            data = grant_reader(window_id)
            if reads[0] > 1:
                data['expires_at'] = data['issued_at']
            return data
        monkeypatch.setattr('router_agent.approval_window._read_grant', expired)
        expired_result = command(['apply', plan_id], 1)
        assert expired_result['error']['code'] == 'approval_window_expired'
        assert len(state['calls']) == records_before_cancel and not writes()
        def admission_grant(window_id):
            data = grant_reader(window_id)
            if state['fault_ready']:
                if state['window_fault'] == 'revoked':
                    raise RouterError('approval_window_required', 'Administrator approval was revoked.')
                data['expires_at'] = data['issued_at']
            return data
        monkeypatch.setattr('router_agent.approval_window._read_grant', admission_grant)
        for fault, code in [('revoked', 'approval_window_required'), ('expired', 'approval_window_expired')]:
            guarded = command(['plan', 'led', '--enabled', 'on'])['data']['plan']
            state.update(window_fault=fault, fault_ready=False, final_reads=0)
            monkeypatch.setattr('builtins.input', lambda _: 'apply ' + guarded['hash'])
            denied = command(['apply', guarded['hash']], 1)['data']
            assert state['fault_ready'] and denied['phase'] == 'verification_failed'
            assert denied['failure_code'] == code and denied['failure_stage'] == 'write'
            assert not writes()
            persisted = FilePlanStore(tmp_path / 'private-state' / 'plans').get(guarded['hash'])[1]
            assert persisted['failure_code'] == code
            state.update(window_fault=None, fault_ready=False, final_reads=0)
        monkeypatch.setattr('router_agent.approval_window._read_grant', grant_reader)
        monkeypatch.setattr('builtins.input', lambda _: 'apply ' + plan_id)
        applied = command(['apply', plan_id])
        assert applied['data']['phase'] == 'verified'
        assert state['enabled'] is True
        assert writes() == [led_body(True)]
        # Verification is a fresh authenticated read session after the write/logout.
        paths = [path for _, path, _ in state['calls']]
        write_index = paths.index('/applyapp.cgi')
        assert paths[write_index + 1:] == ['/Logout.asp', '/login.cgi', '/appGet.cgi', '/appGet.cgi', '/Logout.asp']
        before_replay = len(state['calls'])
        replay = command(['apply', plan_id], 1)
        assert replay['error']['code'] == 'replay_blocked_verify_first'
        assert len(state['calls']) == before_replay and len(writes()) == 1

        reverse = command(['rollback', plan_id])['data']['plan']
        assert reverse['before'] == {'enabled': True} and reverse['after'] == {'enabled': False}
        assert len(writes()) == 1  # Preview alone cannot mutate the router.
        monkeypatch.setattr('builtins.input', lambda _: 'apply ' + reverse['hash'])
        restored = command(['apply', reverse['hash']])
        assert restored['data']['phase'] == 'verified'
        assert state['enabled'] is False
        assert writes() == [led_body(True), led_body(False)]

        drift_plan = command(['plan', 'led', '--enabled', 'on'])['data']['plan']
        state['enabled'] = True  # A separate actor changes state after preview.
        monkeypatch.setattr('builtins.input', lambda _: 'apply ' + drift_plan['hash'])
        rejected = command(['apply', drift_plan['hash']], 1)
        assert rejected['error']['code'] == 'before_drift'
        assert len(writes()) == 2
        assert not state['invalid']
        paths = [path for _, path, _ in state['calls']]
        assert set(paths) == {'/login.cgi', '/appGet.cgi', '/applyapp.cgi', '/Logout.asp'}
        assert paths.count('/login.cgi') == paths.count('/Logout.asp') == 18
        assert paths.count('/appGet.cgi') == 36
        assert paths.count('/applyapp.cgi') == 2
        rendered = '\n'.join(all_output)
        for private_value in ('synthetic-router-password', 'synthetic-private-session-token', 'synthetic-response-secret', IDENTITY['label_mac']):
            assert private_value not in rendered
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        tls.__exit__(None, None, None)
