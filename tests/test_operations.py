import json
import pytest

from router_agent.catalog import Catalog, canonical, load_catalog
from router_agent.operations import ApprovedScope, FilePlanStore, MemoryPlanStore, OperationEngine, Plan


from backup_fixtures import SyntheticBackupBackend


class Backend(SyntheticBackupBackend):
    live = False

    def __init__(self):
        self.values = {"enabled": False}
        self.writes = 0
        self.fail = False
        self.backup_ok = True

    def device_identity(self):
        return {"device": "SYNTHETIC", "firmware": "fixture-1"}

    def read(self, operation, fields):
        return {key: self.values[key] for key in fields}

    def write(self, operation, values):
        self.writes += 1
        self.values.update(values)
        if self.fail:
            raise TimeoutError("sensitive error not emitted")


def setup(store=None):
    backend = Backend()
    store = store or MemoryPlanStore()
    clock = [100.0]
    engine = OperationEngine(load_catalog(), backend, store, clock=lambda: clock[0])
    return engine, backend, store, clock


def approval(plan):
    data = plan.data
    return ApprovedScope(plan.id, data["device"], data["operation"], canonical(data["after"]), 1000)


def test_write_once_independent_verify_and_rollback():
    engine, backend, _, _ = setup()
    plan = engine.plan("synthetic.led", {"enabled": True})
    assert engine.apply(plan.id, approval(plan))["phase"] == "apply_unverified"
    assert backend.writes == 1
    assert engine.verify(plan.id)["phase"] == "verified"
    reverse = engine.rollback_plan(plan.id)
    engine.apply(reverse.id, approval(reverse))
    assert engine.verify(reverse.id)["phase"] == "verified"
    assert backend.values == {"enabled": False}


def test_tampering_and_unknown_keys():
    engine, _, store, _ = setup()
    plan = engine.plan("synthetic.led", {"enabled": True})
    data = plan.data
    data["after"]["enabled"] = False
    store.put(Plan(canonical(data)), {"phase": "planned"})
    with pytest.raises(ValueError, match="tampered"):
        engine.apply(plan.id, approval(plan))
    data["extra"] = True
    store.put(Plan(canonical(data)), {"phase": "planned"})
    with pytest.raises(ValueError, match="structure"):
        engine.apply(plan.id, approval(plan))


def test_stale_before_and_wrong_approval():
    engine, backend, _, _ = setup()
    plan = engine.plan("synthetic.led", {"enabled": True})
    with pytest.raises(ValueError, match="approval"):
        engine.apply(plan.id, ApprovedScope(plan.id, "other", "synthetic.led", canonical({"enabled": True}), 1000))
    backend.values["enabled"] = True
    with pytest.raises(ValueError, match="before_drift"):
        engine.apply(plan.id, approval(plan))
    assert backend.writes == 0


def test_unknown_outcome_replay_blocked_and_recovery_after_expiry():
    engine, backend, _, clock = setup()
    plan = engine.plan("synthetic.led", {"enabled": True}, ttl=1)
    backend.fail = True
    assert engine.apply(plan.id, approval(plan))["phase"] == "outcome_unknown"
    with pytest.raises(ValueError, match="replay"):
        engine.apply(plan.id, approval(plan))
    clock[0] = 200
    assert engine.verify(plan.id)["phase"] == "verified"
    assert backend.writes == 1


def test_backup_failure_expiry_live_and_noop():
    engine, backend, _, clock = setup()
    plan = engine.plan("synthetic.led", {"enabled": True})
    backend.backup_ok = False
    from router_agent.errors import RouterError
    with pytest.raises(RouterError, match="backup"):
        engine.apply(plan.id, approval(plan))
    backend.backup_ok = True
    backend.live = True
    with pytest.raises(ValueError, match="human_handoff"):
        engine.apply(plan.id, approval(plan))
    clock[0] = 500
    with pytest.raises(ValueError, match="expired"):
        engine.apply(plan.id, approval(plan))
    backend.live = False
    noop = engine.plan("synthetic.led", {"enabled": False})
    assert engine.apply(noop.id, approval(noop))["phase"] == "verified_noop"
    assert backend.writes == 0


def test_partial_verify_and_rollback_drift():
    engine, backend, _, _ = setup()
    plan = engine.plan("synthetic.led", {"enabled": True})
    engine.apply(plan.id, approval(plan))
    backend.values["enabled"] = False
    assert engine.verify(plan.id)["phase"] == "verification_failed"
    with pytest.raises(ValueError, match="rollback_drift"):
        engine.rollback_plan(plan.id)


def test_secret_fields_never_read_or_stored():
    data = load_catalog().manifest()
    data["operations"][0]["fields"]["password"] = {"type": "str", "secret": True}
    backend = Backend()
    store = MemoryPlanStore()
    engine = OperationEngine(Catalog(data), backend, store)
    with pytest.raises(ValueError, match="secret_operation"):
        engine.plan("synthetic.led", {"password": "secret-value"})
    assert store._records == {}


def test_file_store_roundtrip_and_reverse_plan(tmp_path):
    engine, _, _, _ = setup(FilePlanStore(tmp_path / "plans"))
    plan = engine.plan("synthetic.led", {"enabled": True})
    engine.apply(plan.id, approval(plan))
    reverse = engine.rollback_plan(plan.id)
    assert reverse.data["before"] == {"enabled": True}
    assert reverse.data["after"] == {"enabled": False}


def test_plan_is_immutable_copy_and_unknown_fields():
    engine, _, _, _ = setup()
    plan = engine.plan("synthetic.led", {"enabled": True})
    plan.data["after"]["enabled"] = False
    assert plan.data["after"] == {"enabled": True}
    with pytest.raises(ValueError, match="unsupported_fields"):
        engine.plan("synthetic.led", {"rc_service": "reboot"})


def test_incomplete_postread_not_verified():
    engine, backend, _, _ = setup()
    plan = engine.plan("synthetic.led", {"enabled": True})
    engine.apply(plan.id, approval(plan))
    backend.read = lambda *args: {}
    assert engine.verify(plan.id)["phase"] == "verification_failed"

def test_file_store_rejects_ancestor_symlink(tmp_path):
    from router_agent.errors import RouterError
    target=tmp_path/'target';target.mkdir(mode=0o700)
    link=tmp_path/'link';link.symlink_to(target)
    with pytest.raises(RouterError): FilePlanStore(link/'plans')


def test_file_store_lock_security_and_contention(tmp_path):
    from router_agent.errors import RouterError
    store=FilePlanStore(tmp_path/'plans')
    with store.lock():
        with pytest.raises(RouterError) as error:
            with store.lock(): pass
        assert error.value.code == 'state_busy'
    (store.directory/'.lock').chmod(0o644)
    with pytest.raises(RouterError) as error:
        with store.lock(): pass
    assert error.value.code == 'unsafe_path'


def test_file_store_refuses_hardlink_and_fifo(tmp_path):
    import os
    from router_agent.errors import RouterError
    store=FilePlanStore(tmp_path/'plans')
    engine, _, _, _=setup(store)
    plan=engine.plan('synthetic.led',{'enabled':True})
    path=store.directory/(plan.id+'.json')
    os.link(path, store.directory/'extra.json')
    with pytest.raises(RouterError): store.get(plan.id)
    (store.directory/'extra.json').unlink();path.unlink()
    os.mkfifo(path,0o600)
    with pytest.raises(RouterError): store.get(plan.id)


def test_noop_verification_preserves_noop_semantics():
    engine,backend,_,_=setup()
    plan=engine.plan('synthetic.led',{'enabled':False})
    assert engine.apply(plan.id,approval(plan))['phase'] == 'verified_noop'
    assert engine.verify(plan.id)['phase'] == 'verified_noop'
    assert backend.writes == 0


def test_live_dual_allowlist_blocks_synthetic_even_when_backend_claims_support():
    engine, backend, _, _ = setup()
    backend.live = True
    backend.live_operations = {"synthetic.led"}
    plan = engine.plan("synthetic.led", {"enabled": True})
    with pytest.raises(ValueError, match="human_handoff"):
        engine.apply(plan.id, approval(plan))
    assert backend.writes == 0


def test_live_real_operation_requires_exact_backend_allowlist(monkeypatch):
    engine, backend, _, _ = setup()
    backend.live = True
    backend.live_operations = {"led"}
    plan = engine.plan("led.set", {"enabled": True})
    with pytest.raises(ValueError, match="human_handoff"):
        engine.apply(plan.id, approval(plan))
    backend.live_operations = {"led.set"}
    monkeypatch.setattr("router_agent.approval_window.validate_window", lambda *args, **kwargs: approval(plan))
    assert engine.apply(plan.id, approval(plan))["phase"] == "apply_unverified"
    assert backend.writes == 1


def test_failure_diagnostics_are_durable_sanitized_and_retained(tmp_path):
    from router_agent.errors import RouterError
    store = FilePlanStore(tmp_path / "plans")
    engine, backend, _, _ = setup(store)
    plan = engine.plan("synthetic.led", {"enabled": True})
    def fail(*args):
        raise RouterError("private credential leaked in code", "secret exception text")
    backend.write = fail
    result = engine.apply(plan.id, approval(plan))
    assert result == {"phase": "outcome_unknown", "failure_code": "write_failed", "failure_stage": "write"}
    backend.read = fail
    result = engine.verify(plan.id)
    assert result["failure_code"] == "write_failed"
    assert result["verification_failure_code"] == "verification_read_failed"
    persisted = store.get(plan.id)[1]
    assert persisted == result
    assert "secret" not in canonical(persisted) and "credential" not in canonical(persisted)
    backend.read = lambda *args: {"enabled": True}
    result = engine.verify(plan.id)
    assert result == {"phase": "verified", "failure_code": "write_failed", "failure_stage": "write"}


def test_timeout_diagnostic_survives_successful_verification():
    engine, backend, store, _ = setup()
    plan = engine.plan("synthetic.led", {"enabled": True})
    backend.fail = True
    assert engine.apply(plan.id, approval(plan))["failure_code"] == "timeout"
    assert engine.verify(plan.id)["failure_code"] == "timeout"


def test_live_write_revalidates_authority_after_before_read(monkeypatch):
    from router_agent.approval_window import approval_request, validate_window
    from router_agent.errors import RouterError
    engine, backend, _, clock = setup()
    backend.live = True
    backend.live_operations = {'led.set'}
    plan = engine.plan('led.set', {'enabled': True})
    grant = approval_request(plan)
    grant['expires_at'] = 101
    monkeypatch.setattr('router_agent.approval_window._read_grant', lambda _: grant)
    approved = validate_window(plan, plan.id, clock=lambda: clock[0])
    original_read = backend.read
    def read(*args):
        clock[0] = 102
        return original_read(*args)
    backend.read = read
    with pytest.raises(RouterError) as error:
        engine.apply(plan.id, approved)
    assert error.value.code == 'approval_window_expired'
    assert backend.writes == 0


def test_verify_fresh_identity_reader_failure_persists_and_retains_write_diagnostic():
    from router_agent.errors import RouterError
    engine, backend, store, _ = setup()
    plan = engine.plan('synthetic.led', {'enabled': True})
    backend.fail = True
    engine.apply(plan.id, approval(plan))
    def fresh_reader_failure():
        raise RouterError('auth_failed', 'private failure text must stay private')
    backend.device_identity = fresh_reader_failure
    result = engine.verify(plan.id)
    assert result['phase'] == 'verification_failed'
    assert result['failure_code'] == 'timeout'
    assert result['verification_failure_code'] == 'auth_failed'
    assert store.get(plan.id)[1] == result
    assert 'private' not in canonical(result)
