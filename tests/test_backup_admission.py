"""Synthetic authorities and configuration only; no real artifacts or services."""
import asyncio
from dataclasses import replace
import json
from types import SimpleNamespace

import aiohttp
import pytest
from yarl import URL

from backup_fixtures import SyntheticBackupProvider
from router_agent.backup_admission import BackupAttempt
from router_agent.errors import RouterError
from router_agent.native_finite_control import FiniteGuard
from router_agent.native_vpn_control import VPNGuard
from router_agent.transport import TransportConfig
from test_expansion_backend import BACKUP_GATED_OPERATIONS, approve, backup_case, setup


def case(tmp_path, monkeypatch, operation):
    intent, original = backup_case(operation)
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, original)
    plan = engine.plan(operation, intent)
    state.current = plan
    return engine, state, backend, plan


def secret_exception(*args):
    raise RuntimeError('private-secret-provider-path')


INVALID = [
    lambda q, r: None,
    lambda q, r: 'restored:true',
    lambda q, r: {'restored': True},
    lambda q, r: replace(r, request_binding='b'*64),
    lambda q, r: replace(r, challenge='another-attempt'),
    lambda q, r: replace(r, source_identity_json='{}'),
    lambda q, r: replace(r, restore_identity_json='{}'),
    lambda q, r: replace(r, operation='state.other'),
    lambda q, r: replace(r, coverage=r.coverage[:-1]),
    lambda q, r: replace(r, artifact_sha256='edited'),
    lambda q, r: replace(r, artifact_bytes=True),
    lambda q, r: replace(r, recovery_disposition='observed_restore_on_spare'),
    lambda q, r: replace(r, recovery_disposition='outcome_unknown'),
    lambda q, r: replace(r, configuration_revision=''),
    lambda q, r: replace(r, invalidation_evidence_id=''),
    lambda q, r: replace(r, recovery_evidence_id=''),
    lambda q, r: replace(r, expires_at=100),
    lambda q, r: replace(r, maximum_age=0.5),
    lambda q, r: replace(r, exported_at=1, maximum_age=50, expires_at=150),
    lambda q, r: replace(r, exported_at=101),
    lambda q, r: replace(r, trial_completed_at=102),
    lambda q, r: replace(r, observed_at=float('nan')),
    secret_exception,
]


@pytest.mark.parametrize('operation', BACKUP_GATED_OPERATIONS)
@pytest.mark.parametrize('alter', INVALID)
def test_invalid_initial_evidence_preserves_plan(tmp_path, monkeypatch, operation, alter):
    engine, state, backend, plan = case(tmp_path, monkeypatch, operation)
    backend.backup_provider.admit_hook = alter
    with pytest.raises(RouterError) as error:
        engine.apply(plan.id, approve(plan))
    assert error.value.code == 'backup_required'
    assert 'private-' not in str(error.value)
    assert state.writes == backend.backup_provider.rechecks == 0
    assert engine.store.get(plan.id)[1] == {'phase': 'planned'}


@pytest.mark.parametrize('operation', BACKUP_GATED_OPERATIONS)
@pytest.mark.parametrize('alter', [secret_exception,
    lambda q, r: replace(r, artifact_sha256='b'*64),
    lambda q, r: replace(r, artifact_id='replacement'),
    lambda q, r: replace(r, configuration_revision='changed'),
    lambda q, r: replace(r, coverage=r.coverage[:-1]),
    lambda q, r: replace(r, issued_at=r.issued_at + 0.1),
    lambda q, r: replace(r, recovery_disposition='outcome_unknown')])
def test_send_revalidation_failure_precedes_approval_consumption(tmp_path, monkeypatch, operation, alter):
    engine, state, backend, plan = case(tmp_path, monkeypatch, operation)
    calls = []
    monkeypatch.setattr('router_agent.approval_window.validate_window',
                        lambda *a, **kw: (calls.append(True), approve(plan))[1])
    backend.backup_provider.recheck_hook = alter
    result = engine.apply(plan.id, approve(plan))
    assert result == {'phase': 'outcome_unknown', 'failure_code': 'backup_required', 'failure_stage': 'write'}
    assert state.writes == 0 and calls == [True]  # initial approval only
    with pytest.raises(ValueError, match='replay'):
        engine.apply(plan.id, approve(plan))
    assert 'private-' not in json.dumps(result)


@pytest.mark.parametrize('operation', BACKUP_GATED_OPERATIONS)
def test_exact_complete_private_request_and_inverse_separation(tmp_path, monkeypatch, operation):
    engine, state, backend, plan = case(tmp_path, monkeypatch, operation)
    assert engine.apply(plan.id, approve(plan))['phase'] == 'apply_unverified'
    provider = backend.backup_provider
    first = provider.requests[0]
    context = backend.vault.get(plan.id)
    assert json.loads(first.context_json) == context
    assert json.loads(first.before_json) == context['before']
    assert json.loads(first.identity_json) == state.identity
    assert first.plan_json == plan.payload
    engine.verify(plan.id)
    inverse = engine.rollback_plan(plan.id)
    state.current = inverse
    assert engine.apply(inverse.id, approve(inverse))['phase'] == 'apply_unverified'
    second = provider.requests[-1]
    assert first.binding != second.binding and first.challenge != second.challenge
    assert first.plan_json != second.plan_json
    assert provider.rechecks == state.writes == 2


@pytest.mark.parametrize('stage', ['admit', 'recheck'])
@pytest.mark.parametrize('target_time', [99.0, 401.0])
def test_provider_call_cannot_hide_expiry_or_clock_reversal(tmp_path, monkeypatch, stage, target_time):
    engine, state, backend, plan = case(tmp_path, monkeypatch, 'state.port_forwarding')
    clock = [100.0]
    engine.clock = lambda: clock[0]
    def advance(q, r):
        clock[0] = target_time
        return r
    setattr(backend.backup_provider, 'admit_hook' if stage == 'admit' else 'recheck_hook', advance)
    if stage == 'admit':
        with pytest.raises(RouterError, match='backup'):
            engine.apply(plan.id, approve(plan))
        assert engine.store.get(plan.id)[1]['phase'] == 'planned'
    else:
        assert engine.apply(plan.id, approve(plan))['failure_code'] == 'backup_required'
    assert state.writes == 0


@pytest.mark.parametrize('mode', ['double', 'context', 'provider', 'plan_expiry', 'grant_expiry'])
def test_send_races_and_single_use(tmp_path, monkeypatch, mode):
    engine, state, backend, plan = case(tmp_path, monkeypatch, 'state.port_forwarding')
    clock = [100.0]
    engine.clock = lambda: clock[0]
    approval = approve(plan)
    if mode == 'grant_expiry':
        approval = replace(approval, expires_at=101)
    monkeypatch.setattr('router_agent.approval_window.validate_window', lambda *a, **kw: approval)
    async def writer(*args, authorization_check, **kwargs):
        if mode == 'double':
            authorization_check()
        elif mode == 'context':
            context = backend.vault.get(plan.id)
            context['before']['future-private-setting'] = 'private-secret'
            from router_agent.catalog import canonical
            backend.vault._injected.set_password(backend.vault.service, plan.id, canonical(context))
        elif mode == 'provider':
            backend._backup_provider = SyntheticBackupProvider()
        else:
            clock[0] = 400 if mode == 'plan_expiry' else 101
        authorization_check()
        state.writes += 1
    backend._writer = writer
    result = engine.apply(plan.id, approval)
    assert result['phase'] == 'outcome_unknown' and state.writes == 0
    assert result['failure_code'] == ('approval_scope_mismatch' if mode.endswith('expiry') else 'backup_required')


@pytest.mark.parametrize('operation', BACKUP_GATED_OPERATIONS)
def test_actual_native_middleware_denies_before_handler_and_write_attempt(tmp_path, monkeypatch, operation):
    engine, state, backend, plan = case(tmp_path, monkeypatch, operation)
    backend.backup_provider.recheck_hook = secret_exception
    guards = []
    async def writer(*args, authorization_check, **kwargs):
        config = TransportConfig('router.invalid', 'synthetic-admin')
        if operation in {'state.vpnc', 'state.openvpn_client', 'state.wireguard_client'}:
            guard = VPNGuard(config, authorization_check=authorization_check)
        else:
            guard = FiniteGuard(config, operation, kwargs['intent'], authorization_check=authorization_check)
        # Payload/target/compiler checking is covered by native writer fixtures;
        # here exercise the real middleware admission order with an armed payload.
        guard.expected_body = b'synthetic-reviewed-body'
        guard.authenticated = True
        guards.append(guard)
        request = SimpleNamespace(url=URL('https://router.invalid/applyapp.cgi'),
                                  body=aiohttp.payload.StringPayload('synthetic-reviewed-body'))
        async def handler(request):
            state.writes += 1
            raise AssertionError('transport handler must not run')
        await guard.middleware(request, handler)
    backend._writer = writer
    assert engine.apply(plan.id, approve(plan))['failure_code'] == 'backup_required'
    assert state.writes == 0 and len(guards) == 1 and not guards[0].write_attempted


def test_legacy_provider_and_live_missing_boundary_fail_closed(tmp_path, monkeypatch):
    engine, state, backend, plan = case(tmp_path, monkeypatch, 'state.port_forwarding')
    backend._backup_provider = lambda *args: 'restored:true'
    with pytest.raises(RouterError, match='backup'):
        engine.apply(plan.id, approve(plan))
    backend._backup_provider = SyntheticBackupProvider()
    backend.authorization_at_send = False
    with pytest.raises(RouterError, match='backup'):
        engine.apply(plan.id, approve(plan))
    assert state.writes == 0 and not backend.backup_provider.requests


def test_receipt_from_other_attempt_cannot_replay(tmp_path, monkeypatch):
    engine, state, backend, plan = case(tmp_path, monkeypatch, 'state.port_forwarding')
    with backend.transaction():
        backend.attach_plan(plan)
        backend.device_identity()
        backend.read(plan.data['operation'], plan.data['fields'])
        first = BackupAttempt(backend, plan, engine.clock)
        backend.backup_provider.admit_hook = lambda q, r: first.receipt
        with pytest.raises(RouterError, match='backup'):
            BackupAttempt(backend, plan, engine.clock)
        first.revalidate()
        with pytest.raises(RouterError, match='backup'):
            first.revalidate()


@pytest.mark.parametrize('operation', BACKUP_GATED_OPERATIONS)
def test_noop_does_not_request_or_consume_backup(tmp_path, monkeypatch, operation):
    intent, original = backup_case(operation)
    intent['enabled'] = False
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, original)
    plan = engine.plan(operation, intent)
    assert engine.apply(plan.id, approve(plan)) == {'phase': 'verified_noop'}
    assert state.writes == backend.backup_provider.rechecks == 0
    assert backend.backup_provider.requests == []


@pytest.mark.parametrize('operation', BACKUP_GATED_OPERATIONS)
@pytest.mark.parametrize('field,value', [('plan_json', '{}'), ('identity_json', '{}'),
    ('before_json', '{}'), ('context_json', '{}'), ('challenge', 'replayed')])
def test_malformed_private_request_never_reaches_provider(tmp_path, monkeypatch, operation, field, value):
    engine, state, backend, plan = case(tmp_path, monkeypatch, operation)
    original = backend.backup_request
    backend.backup_request = lambda p, c: replace(original(p, c), **{field: value})
    with pytest.raises(RouterError, match='backup'):
        engine.apply(plan.id, approve(plan))
    assert state.writes == 0 and not backend.backup_provider.requests
