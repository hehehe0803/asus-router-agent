"""Encoded Fusion recovery through the real plan/context/inverse engine.

Transport storage is synthetic; native HTTP serialization has its own tests.
No actual router, desktop credentials or verified backup is used here.
"""
from copy import deepcopy

import pytest

from router_agent.errors import RouterError
from test_expansion_backend import approve, fusion_case, setup


@pytest.mark.parametrize('kind', ['vpnc', 'openvpn_client', 'wireguard_client'])
def test_encoded_recovery_context_binds_full_list_and_inverse(tmp_path, monkeypatch, kind):
    operation, intent, original = fusion_case(kind)
    if kind == 'wireguard_client':
        original['vpnc_clientlist'] = original['vpnc_clientlist'].replace('OpenVPN', 'WireGuard')
        from router_agent.protected_vpn import parse_snapshot
        from test_expansion_backend import KEY, IDENTITY
        intent['profile_ref'] = parse_snapshot(original, KEY, IDENTITY).profiles[0]['profile_ref']
    original['vpnc_clientlist'] += '<<private-other>UnknownVendor>2>private-user>private-secret>1>9>private-extra<'
    original['vpnc_clientlist'] = original['vpnc_clientlist'].replace('>', '&#62').replace('<', '&#60')
    baseline = {k: deepcopy(original[k]) for k in ('vpnc_clientlist', 'vpnc_unit')}
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, original)
    plan = engine.plan(operation, intent)
    assert 'private-' not in plan.payload
    assert any(baseline['vpnc_clientlist'] in value for value in vault.values.values())
    # Runtime status can change independently of exact encoded configuration.
    state.raw['get_vpnc_status'] = '5>0>7'
    state.current = plan
    assert engine.apply(plan.id, approve(plan))['phase'] == 'apply_unverified'
    assert engine.verify(plan.id)['phase'] == 'verified'
    reverse = engine.rollback_plan(plan.id)
    state.current = reverse
    assert engine.apply(reverse.id, approve(reverse))['phase'] == 'apply_unverified'
    assert engine.verify(reverse.id)['phase'] == 'verified'
    assert state.raw == baseline and state.writes == 2
    assert all('private-' not in path.read_text() for path in tmp_path.rglob('*.json'))


def test_encoded_recovery_drift_does_not_consume_or_rewrite_context(tmp_path, monkeypatch):
    operation, intent, original = fusion_case()
    original['vpnc_clientlist'] = original['vpnc_clientlist'].replace('>', '&#62')
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, original)
    plan = engine.plan(operation, intent)
    saved = deepcopy(vault.values)
    state.raw['vpnc_clientlist'] += '&#60private-new>UnknownVendor>2>user>secret>1>9'.replace('>', '&#62')
    with pytest.raises(ValueError, match='before_drift'):
        engine.apply(plan.id, approve(plan))
    assert state.writes == 0 and vault.values == saved
    assert state.store.get(plan.id)[1] == {'phase': 'planned'}


def test_encoded_plan_does_not_unlock_production_backup_gate(tmp_path, monkeypatch):
    operation, intent, original = fusion_case()
    original['vpnc_clientlist'] = original['vpnc_clientlist'].replace('>', '&#62')
    engine, state, backend, vault = setup(tmp_path, monkeypatch, operation, original, backup=False)
    plan = engine.plan(operation, intent)
    with pytest.raises(RouterError) as caught:
        engine.apply(plan.id, approve(plan))
    assert caught.value.code == 'backup_required'
    assert state.writes == 0 and state.raw == original
