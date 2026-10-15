"""CLI expansion boundaries with synthetic credentials, state, and vault only."""
import asyncio
from copy import deepcopy
import json
import logging
import time

import pytest
from router_agent import cli
from router_agent.auth import AuthConfig
from router_agent.approval_window import approval_request
from router_agent.catalog import load_catalog
from router_agent.expansion_backend import ExpansionBackend, SecretServiceContexts
from router_agent.operations import FilePlanStore, OperationEngine
from router_agent.snapshots import SnapshotStore
from test_expansion_backend import KEY, State, Vault, fusion_case
from test_finite_controls import fixture, IDENTITY


@pytest.mark.parametrize('name,extra,operation', [
    ('forwarding', [], 'state.port_forwarding'), ('openvpn-server', [], 'state.openvpn_server'),
    ('wireguard-server', [], 'state.wireguard_server'), ('wlan', ['--target', 'radio0'], 'state.wlan'),
    ('vpnc', ['--profile', 'vpn-' + 'a' * 24], 'state.vpnc'),
    ('openvpn-client', ['--profile', 'vpn-' + 'a' * 24], 'state.openvpn_client'),
    ('wireguard-client', ['--profile', 'vpn-' + 'a' * 24], 'state.wireguard_client'),
])
def test_finite7_cli_names_and_intents(name, extra, operation):
    args = cli.parser().parse_args(['plan', name, '--enabled', 'off', *extra])
    selected, intent = cli._plan_intent(args)
    assert selected == operation and intent['enabled'] is False
    assert set(intent) == {'enabled'} | ({'target'} if name == 'wlan' else {'profile_ref'} if name in {'vpnc', 'openvpn-client', 'wireguard-client'} else set())


@pytest.mark.parametrize('argv', [
    ['plan', 'vpn', '--enabled', 'on'], ['plan', 'wlan', '--enabled', 'on', '--target', 'radio9'],
    ['plan', 'forwarding', '--enabled', 'yes'], ['plan', 'forwarding', '--enabled', 'on', '--raw', 'secret'],
    ['plan', 'vpnc', '--enabled', 'on'], ['plan', 'vpnc', '--enabled', 'on', '--profile', 'raw-secret-id'],
    ['plan', 'wlan', '--enabled', 'on'], ['plan', 'openvpn-server', '--enabled', 'on', '--profile', 'vpn-' + 'a' * 24],
    ['plan', 'wireguard-client', '--enabled', 'on', '--profile', 'vpn-' + 'a' * 24, '--target', 'radio0'],
    ['plan', 'forwarding', '--enabled', 'on', '--blocked', 'on'], ['get', 'vpnc_clientlist', 'vpnc_clientlist'],
])
def test_invalid_expansion_options_reject_before_credentials(monkeypatch, capsys, argv):
    monkeypatch.setattr(cli, 'get_credentials', lambda: pytest.fail('credentials fetched for invalid intent'))
    monkeypatch.setattr(cli, '_engine', lambda *a: pytest.fail('engine created for invalid intent'))
    assert cli.main(argv) in (1, 2)
    output = json.loads(capsys.readouterr().out)
    assert output['error']['code'] in {'invalid_arguments', 'invalid_operation'}
    assert 'raw-secret' not in json.dumps(output)


def configure_engine(tmp_path, monkeypatch, operation, raw):
    state, vault = State(raw), Vault()
    contexts = SecretServiceContexts(vault)
    store = FilePlanStore(tmp_path / 'plans')
    SnapshotStore(tmp_path).ensure_key()
    (tmp_path / 'alias.key').write_bytes(KEY)
    backend = ExpansionBackend(None, 'fixture-password', operation=operation, fingerprint_key=KEY, vault=contexts,
                               reader=state.reader, writer=state.writer, backup_provider=None)
    engine = OperationEngine(load_catalog(), backend, store, clock=time.time)
    state.store = store
    monkeypatch.setattr(cli, '_plan_store', lambda: (tmp_path, store))
    monkeypatch.setattr(cli, '_engine', lambda selected: (tmp_path, engine))
    monkeypatch.setattr(cli, 'load_config', lambda: AuthConfig('https://router.invalid:443', 'synthetic'))
    monkeypatch.setattr(cli, 'get_credentials', lambda: pytest.fail('real credentials requested'))
    monkeypatch.setattr('router_agent.expansion_backend.SecretServiceContexts', lambda: contexts)
    monkeypatch.setattr('router_agent.approval_window._read_grant', lambda window: approval_request(store.get(window)[0]))
    monkeypatch.setattr('sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('sys.stderr.isatty', lambda: True)
    return state, backend, store


@pytest.mark.parametrize('kind', ['fusion', 'forwarding'])
def test_actual_cli_review_confirmation_backup_noop_verify_inverse(tmp_path, monkeypatch, capsys, caplog, kind):
    if kind == 'fusion':
        operation, intent, raw = fusion_case('openvpn_client')
        raw['vpnc_unit'] = '0'
        name, extra = 'openvpn-client', ['--profile', intent['profile_ref']]
    else:
        operation, intent = 'state.port_forwarding', {'enabled': True}
        raw, name, extra = fixture(operation, intent), 'forwarding', []
    state, backend, store = configure_engine(tmp_path, monkeypatch, operation, raw)
    outputs = []
    def command(argv, expected=0):
        if argv[0] == 'apply':
            state.current = store.get(argv[1])[0]
            argv = [*argv, '--window', argv[1]]
        assert cli.main(argv) == expected
        captured = capsys.readouterr()
        outputs.append(captured.out + captured.err)
        return json.loads(captured.out)
    with caplog.at_level(logging.DEBUG):
        planned = command(['plan', name, '--enabled', 'on', *extra])['data']['plan']
        plan_id = planned['hash']
        assert planned['backup_required'] is True and state.writes == 0
        reads = state.reads
        assert command(['plan-show', plan_id])['data']['plan'] == planned
        request = command(['approval-request', plan_id])['data']
        assert request['status'] == 'not_authorized' and request['approval_request']['plan_hash'] == plan_id
        assert state.reads == reads
        monkeypatch.setattr('builtins.input', lambda _: 'cancel')
        assert command(['apply', plan_id], 1)['error']['code'] == 'approval_cancelled'
        assert state.reads == reads and state.writes == 0
        monkeypatch.setattr('builtins.input', lambda _: 'apply ' + plan_id)
        assert command(['apply', plan_id], 1)['error']['code'] == 'backup_required'
        assert state.writes == 0 and store.get(plan_id)[1]['phase'] == 'planned'
        noop = command(['plan', name, '--enabled', 'off', *extra])['data']['plan']
        monkeypatch.setattr('builtins.input', lambda _: 'apply ' + noop['hash'])
        assert command(['apply', noop['hash']])['data']['phase'] == 'verified_noop'
        assert state.writes == 0
        # The synthetic backup prerequisite enables the real engine lifecycle.
        from backup_fixtures import SyntheticBackupProvider
        backend._backup_provider = SyntheticBackupProvider()
        monkeypatch.setattr('builtins.input', lambda _: 'apply ' + plan_id)
        assert command(['apply', plan_id])['data']['phase'] == 'verified'
        assert command(['verify', plan_id])['data']['phase'] == 'verified'
        assert state.writes == 1
        reverse = command(['rollback', plan_id])['data']['plan']
        assert reverse['intent']['source_plan'] == plan_id and reverse['after'] == planned['before']
        assert state.writes == 1
        monkeypatch.setattr('builtins.input', lambda _: 'apply ' + reverse['hash'])
        assert command(['apply', reverse['hash']])['data']['phase'] == 'verified'
        assert state.writes == 2
        assert state.raw == {k: v for k, v in raw.items() if k != 'get_vpnc_status'}
    evidence = '\n'.join(outputs) + caplog.text + '\n'.join(path.read_text() for path in tmp_path.rglob('*.json'))
    for sentinel in ('private-name', 'private-login', 'private-password', 'private-unknown', 'private-preserved-sentinel', 'fixture-password'):
        assert sentinel not in evidence


def configure_reads(tmp_path, monkeypatch, *, mismatch=False):
    monkeypatch.setattr('router_agent.snapshots.default_state_dir', lambda: tmp_path)
    monkeypatch.setattr(cli, 'get_credentials', lambda: (AuthConfig('https://router.invalid:443', 'synthetic'), 'fixture-password'))
    calls = []
    raw = {'vpnc_unit': '0', 'vpnc_clientlist': 'private-name>OpenVPN>1>private-login>private-password>0>7>private-unknown<another-private>WireGuard>2>secret-login>secret-password>1>8', 'get_vpnc_status': '5>0>7'}
    async def protected(config, password, *, fingerprint_key):
        calls.append('protected')
        return {'identity': dict(IDENTITY), 'raw': deepcopy(raw)}
    async def passive(config, password, *, groups, fingerprint_key, **kwargs):
        calls.append(tuple(groups))
        identity = {**IDENTITY, 'device_fingerprint': 'changed'} if mismatch else dict(IDENTITY)
        data = {'identity': identity, **{group: {'enabled': None} for group in groups if group != 'identity'}}
        return {'schema_version': 1, 'source': 'native', 'freshness': 'unknown', 'data': data,
                'sources': {group: {'fetched_at': None, 'observed_at': None, 'freshness': 'unknown'} for group in data}, 'capability_gaps': [{'group': group, 'reason': 'passive-gap'} for group in groups for _ in range(2)]}
    monkeypatch.setattr('router_agent.native_vpn_control.read_vpn', protected)
    monkeypatch.setattr('router_agent.transport.collect_native', passive)
    return calls


def test_protected_get_grouped_safe_stdout_and_snapshot(tmp_path, monkeypatch, capsys, caplog):
    calls = configure_reads(tmp_path, monkeypatch)
    with caplog.at_level(logging.DEBUG):
        assert cli.main(['get', 'openvpn_client', 'vpnc_clientlist', 'led']) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    assert calls == ['protected', ('led',)]
    profiles = result['data']['vpnc_clientlist']['profiles']
    assert len(profiles) == 2 and len(result['data']['openvpn_client']['profiles']) == 1
    assert profiles[0]['enabled'] is False and profiles[0]['status_code'] == 5
    assert profiles[1]['enabled'] is True and profiles[1]['status_code'] is None and profiles[1]['error_code'] is None
    assert profiles[0]['profile_ref'].startswith('vpn-') and result['data']['led']['enabled'] is None
    assert {'group': 'led', 'reason': 'passive-gap'} in result['capability_gaps']
    assert result['capability_gaps'].count({'group': 'led', 'reason': 'passive-gap'}) == 1
    assert all(set(gap) == {'group', 'reason'} for gap in result['capability_gaps'])
    assert 'selected_settings_and_native_status_do_not_prove_tunnel_or_egress' in result['data']['vpnc_clientlist']['gaps']
    record = SnapshotStore(tmp_path).save(result, {'schema': 1, 'device': IDENTITY['device_fingerprint'], 'firmware': IDENTITY['firmware'], 'catalog': load_catalog().hash})
    evidence = output + caplog.text + '\n'.join(path.read_text() for path in tmp_path.rglob('*.json'))
    for sentinel in ('private-name', 'private-login', 'private-password', 'private-unknown', 'another-private', 'secret-login', 'secret-password', 'fixture-password'):
        assert sentinel not in evidence


def test_grouped_protected_passive_identity_mismatch_is_all_or_error(tmp_path, monkeypatch, capsys):
    calls = configure_reads(tmp_path, monkeypatch, mismatch=True)
    assert cli.main(['get', 'vpnc_clientlist', 'led']) == 1
    output = json.loads(capsys.readouterr().out)
    assert set(output) == {'error'} and output['error']['code'] == 'identity_changed'
    assert calls == ['protected', ('led',)]
    assert not list(tmp_path.rglob('*.json'))


def test_status_and_snapshot_defaults_do_not_collect_private_profiles(tmp_path, monkeypatch, capsys):
    calls = configure_reads(tmp_path, monkeypatch)
    assert cli.main(['status']) == 0
    assert 'vpnc_clientlist' not in capsys.readouterr().out
    assert cli.main(['snapshot']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['snapshot_id']
    assert calls == [('identity', 'wan', 'cpu', 'ram')] * 2
    assert 'profiles' not in json.dumps(result)
