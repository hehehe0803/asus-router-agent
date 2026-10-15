"""Guarded expansion integration: actual compilers, OS-vault-shaped storage.

All credentials, identity and transport here are synthetic. No router or desktop
Secret Service is contacted by this module.
"""
from copy import deepcopy
import json

import pytest

from router_agent.approval import validate_local_plan
from router_agent.catalog import canonical, load_catalog
from router_agent.errors import RouterError
from router_agent.expansion_backend import ExpansionBackend, SecretServiceContexts, validate_intent
from router_agent.operations import ApprovedScope, FilePlanStore, OperationEngine, Plan
from router_agent.protected_vpn import parse_snapshot, select_profiles
from test_finite_controls import CASES, IDENTITY, fixture

from backup_fixtures import SyntheticBackupProvider

KEY = b'z' * 32


class Vault:
    def __init__(self):
        self.values = {}

    def get_password(self, service, name):
        return self.values.get((service, name))

    def set_password(self, service, name, value):
        self.values[service, name] = value


def fusion_case(kind='vpnc'):
    raw = {'vpnc_clientlist': 'private-name>OpenVPN>1>private-login>private-password>0>7>private-unknown', 'vpnc_unit': '0', 'get_vpnc_status': '2>0>7'}
    ref = select_profiles(parse_snapshot(raw, KEY, IDENTITY))['profiles'][0]['profile_ref']
    return 'state.' + kind, {'profile_ref': ref, 'enabled': True}, raw


class State:
    def __init__(self, raw):
        self.raw = deepcopy(raw)
        self.writes = 0
        self.reads = 0
        self.failure = False
        self.identity = dict(IDENTITY)

    async def reader(self, config, password, *, operation, fingerprint_key):
        assert password == 'fixture-password' and fingerprint_key == KEY
        self.reads += 1
        return {'identity': deepcopy(self.identity), 'raw': deepcopy(self.raw)}

    async def writer(self, config, password, *, operation, expected_identity, expected_before_raw, expected_after_raw, intent, fingerprint_key, authorization_check):
        assert expected_identity == self.identity
        assert expected_before_raw == {k: self.raw[k] for k in expected_before_raw}
        assert self.store.get(self.current.id)[1]['phase'] == 'outcome_unknown'
        authorization_check()
        self.writes += 1
        self.raw = deepcopy(expected_after_raw)
        if self.failure:
            raise TimeoutError('private-password')
        return {'write_attempted': True}


def setup(tmp_path, monkeypatch, operation, raw, *, backup=True):
    state = State(raw)
    vault = Vault()
    contexts = SecretServiceContexts(vault)
    store = FilePlanStore(tmp_path / 'plans')
    backend = ExpansionBackend(None, 'fixture-password', operation=operation, fingerprint_key=KEY,
                               vault=contexts, reader=state.reader, writer=state.writer,
                               backup_provider=SyntheticBackupProvider() if backup else None)
    engine = OperationEngine(load_catalog(), backend, store, clock=lambda: 100.0)
    state.store = store
    monkeypatch.setattr('router_agent.approval_window.validate_window', lambda plan, window_id, clock: approve(plan))
    return engine, state, backend, vault


def approve(plan):
    return ApprovedScope(plan.id, plan.data['device'], plan.data['operation'], canonical(plan.data['after']), plan.data['expires_at'], plan.id)


@pytest.mark.parametrize('operation,intent,flag', CASES)
def test_full_engine_native_compiler_context_inverse(tmp_path, monkeypatch, operation, intent, flag):
    original = fixture(operation, intent)
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, original)
    plan = engine.plan(operation, intent)
    assert validate_local_plan(plan, clock=lambda: 100)['intent'] == intent
    assert plan.data['backup_required'] is True
    assert state.reads == 1
    assert 'private-' not in plan.payload
    assert all('private-' not in p.read_text() for p in (tmp_path / 'plans').glob('*.json'))
    state.current = plan
    assert engine.apply(plan.id, approve(plan))['phase'] == 'apply_unverified'
    assert engine.verify(plan.id)['phase'] == 'verified'
    reverse = engine.rollback_plan(plan.id)
    assert reverse.data['intent']['source_plan'] == plan.id
    assert reverse.data['after'] == plan.data['before']
    assert reverse.id != plan.id
    assert validate_local_plan(reverse, clock=lambda: 100)['review']['after']['enabled'] is False
    state.current = reverse
    assert engine.apply(reverse.id, approve(reverse))['phase'] == 'apply_unverified'
    assert engine.verify(reverse.id)['phase'] == 'verified'
    assert state.raw == original and state.writes == 2
    assert len(vault.values) == 2


@pytest.mark.parametrize('kind', ['vpnc', 'openvpn_client', 'wireguard_client'])
def test_fusion_secret_vault_lifecycle_and_runtime_excluded(tmp_path, monkeypatch, kind):
    operation, intent, original = fusion_case(kind)
    if kind == 'wireguard_client':
        original['vpnc_clientlist'] = original['vpnc_clientlist'].replace('OpenVPN', 'WireGuard')
        intent['profile_ref'] = select_profiles(parse_snapshot(original, KEY, IDENTITY))['profiles'][0]['profile_ref']
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, original)
    plan = engine.plan(operation, intent)
    assert 'private-' not in plan.payload
    assert any('private-password' in value for value in vault.values.values())
    # Only configuration participates in drift/verification, not tunnel status.
    state.raw['get_vpnc_status'] = '5>0>7'
    state.current = plan
    assert engine.apply(plan.id, approve(plan))['phase'] == 'apply_unverified'
    assert engine.verify(plan.id)['phase'] == 'verified'
    reverse = engine.rollback_plan(plan.id)
    state.current = reverse
    assert engine.apply(reverse.id, approve(reverse))['phase'] == 'apply_unverified'
    assert engine.verify(reverse.id)['phase'] == 'verified'
    assert state.raw == {'vpnc_clientlist': original['vpnc_clientlist'], 'vpnc_unit': '0'}
    assert all('private-' not in path.read_text() for path in tmp_path.rglob('*.json'))


def test_backup_gate_noop_and_uncertain_no_replay(tmp_path, monkeypatch):
    operation, intent, flag = CASES[0]
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, fixture(operation, intent), backup=False)
    plan = engine.plan(operation, intent)
    state.current = plan
    with pytest.raises(RouterError, match='backup'):
        engine.apply(plan.id, approve(plan))
    assert state.writes == 0 and state.store.get(plan.id)[1]['phase'] == 'planned'
    noop = engine.plan(operation, {'enabled': False})
    assert engine.apply(noop.id, approve(noop))['phase'] == 'verified_noop'
    assert state.writes == 0
    backend._backup_provider = SyntheticBackupProvider()
    state.failure = True
    assert engine.apply(plan.id, approve(plan)) == {'phase': 'outcome_unknown', 'failure_code': 'timeout', 'failure_stage': 'write'}
    with pytest.raises(ValueError, match='replay'):
        engine.apply(plan.id, approve(plan))
    assert engine.verify(plan.id)['phase'] == 'verified'
    assert state.writes == 1


def test_whole_context_drift_and_tamper_fail_before_write(tmp_path, monkeypatch):
    operation, intent, flag = CASES[0]
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, fixture(operation, intent))
    plan = engine.plan(operation, intent)
    state.raw['future_setting'] = 'changed-private-value'
    with pytest.raises(ValueError, match='before_drift'):
        engine.apply(plan.id, approve(plan))
    assert state.writes == 0
    key = next(iter(vault.values))
    context = json.loads(vault.values[key]);context['before']['future_setting'] = 'tampered'
    vault.values[key] = canonical(context)
    with pytest.raises(RouterError, match='context'):
        engine.apply(plan.id, approve(plan))
    assert state.writes == 0


def test_unavailable_vault_no_plaintext_fallback(tmp_path, monkeypatch):
    class Locked(Vault):
        def set_password(self, *args):
            raise RuntimeError('private-password')
    operation, intent, flag = CASES[0]
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, fixture(operation, intent))
    backend.vault = SecretServiceContexts(Locked())
    with pytest.raises(RouterError) as caught:
        engine.plan(operation, intent)
    assert caught.value.code == 'keyring_unavailable' and 'private-' not in str(caught.value)
    assert list((tmp_path / 'plans').glob('*.json')) == []


def test_locked_vault_is_distinct_from_missing_or_malformed_context():
    class Locked(Vault):
        def get_password(self, *args):
            raise RuntimeError('private-password')
    with pytest.raises(RouterError) as caught:
        SecretServiceContexts(Locked()).get('a' * 64)
    assert caught.value.code == 'keyring_unavailable'
    assert 'private-password' not in str(caught.value)
    for payload in (None, 'invalid-json', '[]'):
        vault = Vault()
        vault.values[(SecretServiceContexts.service, 'a' * 64)] = payload
        with pytest.raises(RouterError) as caught:
            SecretServiceContexts(vault).get('a' * 64)
        assert caught.value.code == 'invalid_policy_context'


@pytest.mark.parametrize('operation,intent', [('state.system', {'enabled': True}), ('state.vpnc', {'enabled': True, 'profile_ref': 'raw-secret'}), ('state.wlan', {'enabled': True, 'target': 'guest9.1'}), ('state.openvpn_server', {'enabled': True, 'id': 2})])
def test_invalid_finite_intent(operation, intent):
    with pytest.raises(RouterError):
        validate_intent(operation, intent)


BACKUP_GATED_OPERATIONS = ('state.vpnc', 'state.openvpn_client', 'state.wireguard_client',
                           'state.port_forwarding', 'state.openvpn_server',
                           'state.wireguard_server', 'state.wlan')


def backup_case(operation):
    """Finite real compiler input for each production backup-gated operation."""
    if operation in {'state.vpnc', 'state.openvpn_client', 'state.wireguard_client'}:
        _, intent, raw = fusion_case(operation.removeprefix('state.'))
        if operation == 'state.wireguard_client':
            raw['vpnc_clientlist'] = raw['vpnc_clientlist'].replace('OpenVPN', 'WireGuard')
            intent['profile_ref'] = select_profiles(parse_snapshot(raw, KEY, IDENTITY))['profiles'][0]['profile_ref']
        return intent, raw
    intent = {'enabled': True}
    if operation == 'state.wlan':
        intent['target'] = 'radio0'
    return intent, fixture(operation, intent)


@pytest.mark.parametrize('operation', BACKUP_GATED_OPERATIONS)
def test_every_effective_production_backup_gate_preserves_plan_and_never_admits_write(tmp_path, monkeypatch, operation):
    intent, original = backup_case(operation)
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, original, backup=False)
    plan = engine.plan(operation, intent)
    assert plan.data['backup_required'] is True and plan.data['before'] != plan.data['after']
    initial_plan, initial_state = state.store.get(plan.id)
    contexts = deepcopy(vault.values)
    admissions = []
    monkeypatch.setattr('router_agent.approval_window.validate_window', lambda *a, **k: admissions.append(True))
    for _ in range(2):
        with pytest.raises(RouterError) as caught:
            engine.apply(plan.id, approve(plan))
        assert caught.value.code == 'backup_required'
        # Backup refusal precedes send admission and durable uncertainty. A
        # refused attempt has not consumed or rewritten its original preview.
        saved_plan, saved_state = state.store.get(plan.id)
        assert saved_plan == initial_plan and saved_state == initial_state == {'phase': 'planned'}
        assert state.writes == 0 and state.raw == original and admissions == []
        assert vault.values == contexts
    with pytest.raises(ValueError, match='not_applied'):
        engine.verify(plan.id)
    with pytest.raises(ValueError, match='not_applied'):
        engine.rollback_plan(plan.id)


@pytest.mark.parametrize('operation', BACKUP_GATED_OPERATIONS)
def test_noop_still_needs_scope_but_neither_backup_nor_writer(tmp_path, monkeypatch, operation):
    intent, original = backup_case(operation)
    intent['enabled'] = False
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, original, backup=False)
    plan = engine.plan(operation, intent)
    assert plan.data['before'] == plan.data['after'] and plan.data['backup_required'] is True
    with pytest.raises(ValueError, match='approval_scope_mismatch'):
        engine.apply(plan.id, None)
    assert state.store.get(plan.id)[1]['phase'] == 'planned'
    admissions = []
    monkeypatch.setattr('router_agent.approval_window.validate_window', lambda *a, **k: admissions.append(True))
    assert engine.apply(plan.id, approve(plan)) == {'phase': 'verified_noop'}
    assert state.writes == 0 and state.raw == original and admissions == []
    with pytest.raises(ValueError, match='replay_blocked'):
        engine.apply(plan.id, approve(plan))


@pytest.mark.parametrize('operation', BACKUP_GATED_OPERATIONS)
def test_production_factory_does_not_trust_local_artifact_or_synthetic_provider_evidence(tmp_path, monkeypatch, operation):
    """Exercise actual CLI backend construction without credentials or IO calls.

    Existing lifecycle tests inject a provider callback. Neither that injection
    nor an export-shaped local file can silently install a production provider.
    """
    from router_agent import cli
    from router_agent.auth import AuthConfig
    fake_cfg = tmp_path / 'synthetic-not-a-real-backup.CFG'
    fake_cfg.write_bytes(b'synthetic configuration bytes; no restoration evidence')
    fake_cfg.chmod(0o600)
    (tmp_path / 'backup-evidence.json').write_text(json.dumps({'path': str(fake_cfg), 'restored': True,
        'provider': 'fixture-verified-backup', 'model': IDENTITY['model'], 'firmware': IDENTITY['firmware']}))
    monkeypatch.setattr(cli, 'get_credentials', lambda: (AuthConfig('https://router.invalid', 'synthetic-admin'), 'synthetic-password'))
    monkeypatch.setattr(cli, '_plan_store', lambda: (tmp_path, FilePlanStore(tmp_path / 'production-plans')))
    directory, engine = cli._engine(operation)
    assert directory == tmp_path
    with pytest.raises(RouterError) as caught:
        from router_agent.backup_admission import BackupAttempt
        BackupAttempt(engine.backend, None, lambda: 100)
    assert caught.value.code == 'backup_required'
    assert list((tmp_path / 'production-plans').glob('*.json')) == []
