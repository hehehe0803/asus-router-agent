"""Real CLI and pristine native library against a synthetic localhost router."""
import ast
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from urllib.parse import unquote

from asusrouter.modules import parental_control as pc
from tls_helpers import localhost_tls
from router_agent.approval_window import approval_request
from router_agent.operations import FilePlanStore
from router_agent.auth import AuthConfig
from router_agent.cli import main
from router_agent.native_parental_control import FULL_POLICY_HOOK
from router_agent.parental_policy import PARENTAL_POLICY_KEYS, client_alias
from router_agent.snapshots import SnapshotStore, private_read
from router_agent.transport import HOOKS
from test_native_parental_control import IDENTITY, MACS, policy, SCHEDULE


def test_parental_cli_native_wire_approval_verify_reverse_and_lossy_branches(tmp_path, monkeypatch, capsys):
    original = policy()
    state = {'policy': deepcopy(original), 'calls': [], 'invalid': [], 'drop_reply': False, 'window_fault': None, 'fault_ready': False, 'final_reads': 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.handle_request()

        def do_GET(self):
            self.handle_request()

        def handle_request(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            state['calls'].append((self.command, self.path, raw))
            decoded = unquote(raw.decode())
            status = 200
            if self.path == '/login.cgi':
                response = {'asus_token': 'synthetic-private-session-token'}
            elif self.path == '/Logout.asp':
                response = {'error_status': 8}
            elif self.path == '/appGet.cgi' and decoded == 'hook=' + HOOKS['identity']:
                response = IDENTITY
            elif self.path == '/appGet.cgi' and decoded == 'hook=' + FULL_POLICY_HOOK:
                if state['window_fault']:
                    state['final_reads'] += 1
                    if state['final_reads'] == 2:
                        state['fault_ready'] = True
                response = state['policy']
            elif self.path == '/appGet.cgi' and decoded == 'hook=' + HOOKS['clients']:
                response = {'get_clientlist': {mac: {'name': 'private-client'} for mac in MACS}}
            elif self.path == '/applyapp.cgi':
                command = ast.literal_eval(decoded)
                assert command['rc_service'] == 'restart_firewall' and command['action_mode'] == 'apply'
                fields = set(command) - {'rc_service', 'action_mode'}
                assert fields in ({pc.KEY_PC_STATE}, {pc.KEY_PC_BLOCK_ALL}, set(pc.PC_RULE_MAP))
                for key in fields:
                    value = str(command[key])
                    if key in pc.PC_RULE_MAP:
                        value = value.replace('>', '&#62')
                        if key == pc.KEY_PC_TIMEMAP:
                            value = value.replace('<', '&#60')
                    state['policy'][key] = value
                if state['drop_reply']:
                    self.close_connection = True
                    return
                response = {'run_service': 'restart_firewall', 'modify': '1'}
            else:
                state['invalid'].append((self.command, self.path, decoded))
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
    state_dir = tmp_path / 'private-state'
    config = AuthConfig(f'https://127.0.0.1:{server.server_port}', 'synthetic-admin', ca_file=ca_file)
    monkeypatch.setattr('router_agent.snapshots.default_state_dir', lambda: state_dir)
    monkeypatch.setattr('router_agent.cli.load_config', lambda: config)
    monkeypatch.setattr('router_agent.cli.get_credentials', lambda: (config, 'synthetic-router-password'))
    def grant_reader(window_id):
        from router_agent.errors import RouterError
        data = approval_request(FilePlanStore(state_dir / 'plans').get(window_id)[0])
        if state['fault_ready']:
            if state['window_fault'] == 'revoked':
                raise RouterError('approval_window_required', 'Administrator approval was revoked.')
            data['expires_at'] = data['issued_at']
        return data
    monkeypatch.setattr('router_agent.approval_window._read_grant', grant_reader)
    monkeypatch.setattr('sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('sys.stderr.isatty', lambda: True)
    store = SnapshotStore(state_dir)
    store.alias('initialize')
    alias = client_alias(private_read(state_dir / 'alias.key'), MACS[1])
    outputs = []

    def command(argv, exit_code=0):
        if argv[0] == 'apply':
            argv = [*argv, '--window', argv[1]]
        assert main(argv) == exit_code
        output = capsys.readouterr()
        outputs.append(output.out + output.err)
        return json.loads(output.out)

    def writes():
        return [ast.literal_eval(unquote(raw.decode())) for _, path, raw in state['calls'] if path == '/applyapp.cgi']

    def apply(plan, exit_code=0):
        monkeypatch.setattr('builtins.input', lambda _: 'apply ' + plan['hash'])
        return command(['apply', plan['hash']], exit_code)

    try:
        preview = command(['plan', 'parental-rule', '--alias', alias, '--type', 'remove'])['data']['plan']
        assert preview['review']['before']['alias'] == alias and preview['review']['after'] is None
        assert command(['plan-show', preview['hash']])['data']['plan'] == preview
        assert not writes()
        calls_before = len(state['calls'])
        monkeypatch.setattr('builtins.input', lambda _: 'cancel')
        assert command(['apply', preview['hash']], 1)['error']['code'] == 'approval_cancelled'
        assert len(state['calls']) == calls_before
        # Final private native policy reads can outlast or revoke the grant.
        for fault, code in [('revoked', 'approval_window_required'), ('expired', 'approval_window_expired')]:
            guarded = command(['plan', 'parental', '--enabled', 'on'])['data']['plan']
            state.update(window_fault=fault, fault_ready=False, final_reads=0)
            denied = apply(guarded, 1)['data']
            assert state['fault_ready'] and denied['phase'] == 'verification_failed'
            assert denied['failure_code'] == code and denied['failure_stage'] == 'write'
            assert not writes()
            persisted = FilePlanStore(state_dir / 'plans').get(guarded['hash'])[1]
            assert persisted['failure_code'] == code
            state.update(window_fault=None, fault_ready=False, final_reads=0)
        assert apply(preview)['data']['phase'] == 'verified'
        assert len(writes()) == 1
        assert state['policy'][pc.KEY_PC_MAC] == '&#62'.join([MACS[0], MACS[2]])
        paths = [path for _, path, _ in state['calls']]
        assert paths[paths.index('/applyapp.cgi') + 1:] == ['/Logout.asp', '/login.cgi', '/appGet.cgi', '/appGet.cgi', '/Logout.asp']
        calls_before = len(state['calls'])
        assert apply(preview, 1)['error']['code'] == 'replay_blocked_verify_first'
        assert len(state['calls']) == calls_before
        reverse = command(['rollback', preview['hash']])['data']['plan']
        assert reverse['review']['after']['alias'] == alias
        assert reverse['intent']['source_plan'] == preview['hash']
        assert len(writes()) == 1
        assert apply(reverse)['data']['phase'] == 'verified'
        assert state['policy'] == original and len(writes()) == 2

        # Global no-op checks the full policy but invokes no write callback.
        noop = command(['plan', 'parental', '--enabled', 'off'])['data']['plan']
        assert apply(noop)['data']['phase'] == 'verified_noop'
        assert len(writes()) == 2
        drift = command(['plan', 'parental', '--enabled', 'on'])['data']['plan']
        state['policy'][pc.KEY_PC_NAME] = 'changed-private-name&#62private-name-1&#62private-name-2'
        assert apply(drift, 1)['error']['code'] == 'before_drift'
        assert len(writes()) == 2

        # Empty native policy with orphan schedule has no faithful rule inverse;
        # individual flag operations must nevertheless preserve that schedule.
        state['policy'] = policy(0)
        state['policy'][pc.KEY_PC_TIMEMAP] = SCHEDULE
        lossy = command(['plan', 'parental-rule', '--alias', alias, '--type', 'block', '--schedule', SCHEDULE], 1)
        assert lossy['error']['code'] == 'policy_recovery_unavailable'
        global_plan = command(['plan', 'parental-block-all', '--blocked', 'on'])['data']['plan']
        assert global_plan['review']['before']['rules_write_recoverable'] is False
        assert 'all_client_internet_blocking_setting' in global_plan['side_effects']
        # The router applies but loses the response: CLI reconciles by a fresh
        # independent read, never by repeating the configuration request.
        state['drop_reply'] = True
        assert apply(global_plan)['data']['phase'] == 'verified'
        state['drop_reply'] = False
        assert len(writes()) == 3
        assert set(writes()[-1]) == {'rc_service', 'action_mode', pc.KEY_PC_BLOCK_ALL}
        assert state['policy'][pc.KEY_PC_TIMEMAP] == SCHEDULE
        reverse_global = command(['rollback', global_plan['hash']])['data']['plan']
        assert apply(reverse_global)['data']['phase'] == 'verified'
        assert state['policy'][pc.KEY_PC_BLOCK_ALL] == '0'
        assert state['policy'][pc.KEY_PC_TIMEMAP] == SCHEDULE and len(writes()) == 4
        assert not state['invalid']
        assert all((path == '/Logout.asp' or method == 'POST') for method, path, _ in state['calls'])
        text = '\n'.join(outputs)
        for private in [*MACS, IDENTITY['label_mac'], SCHEDULE, 'private-name', 'private-client', 'synthetic-router-password', 'synthetic-private-session-token', 'MULTIFILTER']:
            assert private not in text
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in (state_dir / 'parental-recovery').glob('*.json'))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        tls.__exit__(None, None, None)
