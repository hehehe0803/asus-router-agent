import pytest

from router_agent.catalog import canonical, load_catalog
from router_agent.errors import RouterError
from router_agent.native_backend import NativeLEDBackend
from router_agent.operations import ApprovedScope, MemoryPlanStore, OperationEngine

ACTIVE_STORE = None

@pytest.fixture(autouse=True)
def synthetic_authority(monkeypatch):
    from router_agent.approval_window import approval_request
    monkeypatch.setattr('router_agent.approval_window._read_grant', lambda window: approval_request(ACTIVE_STORE.get(window)[0]))


KEY = b"k" * 32
IDENTITY = {"model": "RT-AX86U", "firmware": "3.0.0.4.388_24436-ge7c0b5e", "device_fingerprint": "device-a"}


class NativeFixture:
    def __init__(self):
        self.identity = dict(IDENTITY)
        self.enabled = False
        self.reads = []
        self.writes = []
        self.fail_write = False
        self.before_write = None
        self.read_warnings = []
        self.write_warnings = []

    async def collect(self, config, password, **kwargs):
        assert config == "synthetic-config" and password == "synthetic-password"
        assert kwargs == {"groups": ("identity", "led"), "fingerprint_key": KEY}
        self.reads.append(dict(self.identity))
        return {"data": {"identity": dict(self.identity), "led": {"enabled": self.enabled}},
                "warnings": self.read_warnings}

    async def set_led(self, config, password, **kwargs):
        if self.before_write:
            self.before_write()
        assert kwargs["fingerprint_key"] == KEY
        assert kwargs["expected_identity"] == self.identity
        assert kwargs["expected_before"] == self.enabled
        kwargs["authorization_check"]()
        self.writes.append(kwargs)
        self.enabled = kwargs["enabled"]
        if self.fail_write:
            raise TimeoutError("synthetic-secret")
        return {"write_attempted": True, "warnings": self.write_warnings}


def setup():
    fixture = NativeFixture()
    backend = NativeLEDBackend("synthetic-config", "synthetic-password", fingerprint_key=KEY,
                               collector=fixture.collect, writer=fixture.set_led)
    global ACTIVE_STORE
    store = MemoryPlanStore()
    ACTIVE_STORE = store
    return fixture, backend, store, OperationEngine(load_catalog(), backend, store, clock=lambda: 100)


def approved(plan):
    data = plan.data
    return ApprovedScope(plan.id, data["device"], "led.set", canonical(data["after"]), data["expires_at"], plan.id)


def test_fresh_plan_apply_verify_and_reverse_plan_are_bound_and_separate():
    fixture, backend, _, engine = setup()
    plan = engine.plan("led.set", {"enabled": True})
    assert len(fixture.reads) == 1 and not fixture.writes
    assert "synthetic-password" not in plan.payload and "RT-AX86U" not in plan.payload
    assert engine.apply(plan.id, approved(plan))["phase"] == "apply_unverified"
    assert len(fixture.reads) == 2 and len(fixture.writes) == 1
    assert fixture.writes[0]["expected_identity"] == IDENTITY
    assert fixture.writes[0]["expected_before"] is False
    assert engine.verify(plan.id)["phase"] == "verified"
    assert len(fixture.reads) == 3 and len(fixture.writes) == 1
    reverse = engine.rollback_plan(plan.id)
    assert len(fixture.reads) == 4
    with pytest.raises(ValueError, match="approval_scope_mismatch"):
        engine.apply(reverse.id, approved(plan))
    assert len(fixture.writes) == 1
    assert engine.apply(reverse.id, approved(reverse))["phase"] == "apply_unverified"
    assert engine.verify(reverse.id)["phase"] == "verified"
    assert fixture.enabled is False and len(fixture.writes) == 2
    with pytest.raises(RouterError, match="transaction"):
        backend.read("led.set", ["enabled"])


def test_cache_is_single_read_and_cleared_even_after_exception():
    fixture, backend, _, _ = setup()
    with pytest.raises(RuntimeError):
        with backend.transaction():
            backend.device_identity()
            assert backend.read("led.set", ["enabled"]) == {"enabled": False}
            with pytest.raises(RouterError, match="fresh"):
                backend.read("led.set", ["enabled"])
            raise RuntimeError("synthetic")
    with backend.transaction():
        with pytest.raises(RouterError, match="fresh"):
            backend.read("led.set", ["enabled"])
    assert len(fixture.reads) == 1


def test_unknown_led_or_incomplete_exact_identity_cannot_create_plan():
    fixture, _, store, engine = setup()
    fixture.enabled = None
    with pytest.raises(RouterError, match="known LED"):
        engine.plan("led.set", {"enabled": True})
    fixture.enabled = False
    fixture.identity.pop("device_fingerprint")
    with pytest.raises(RouterError, match="Exact identity"):
        engine.plan("led.set", {"enabled": True})
    assert not store._records and not fixture.writes


def test_same_model_different_device_is_not_an_identity_match():
    fixture, _, _, engine = setup()
    plan = engine.plan("led.set", {"enabled": True})
    fixture.identity["device_fingerprint"] = "device-b"
    with pytest.raises(ValueError, match="incompatible_plan"):
        engine.apply(plan.id, approved(plan))
    assert not fixture.writes


@pytest.mark.parametrize("field,value", [("model", "RT-AX88U"), ("firmware", "3.0.0.4.388_unreviewed")])
def test_unreviewed_model_or_firmware_rejected_before_plan_creation(field, value):
    fixture, _, store, engine = setup()
    fixture.identity[field] = value
    with pytest.raises(RouterError) as caught:
        engine.plan("led.set", {"enabled": True})
    assert caught.value.code == "unsupported_firmware"
    assert not store._records and not fixture.writes


def test_read_cleanup_warning_prevents_planning_and_new_write():
    fixture, _, store, engine = setup()
    fixture.read_warnings = ["logout_unconfirmed"]
    with pytest.raises(RouterError) as caught:
        engine.plan("led.set", {"enabled": True})
    assert caught.value.code == "native_cleanup_unconfirmed"
    assert not store._records and not fixture.writes
    fixture.read_warnings = []
    plan = engine.plan("led.set", {"enabled": True})
    fixture.read_warnings = ["logout_unconfirmed"]
    with pytest.raises(RouterError) as caught:
        engine.apply(plan.id, approved(plan))
    assert caught.value.code == "native_cleanup_unconfirmed"
    assert store.get(plan.id)[1]["phase"] == "planned" and not fixture.writes


def test_write_cleanup_warning_preserves_uncertainty_and_blocks_replay():
    fixture, _, store, engine = setup()
    plan = engine.plan("led.set", {"enabled": True})
    fixture.write_warnings = ["logout_unconfirmed"]
    assert engine.apply(plan.id, approved(plan))["phase"] == "outcome_unknown"
    assert store.get(plan.id)[1]["phase"] == "outcome_unknown"
    with pytest.raises(ValueError, match="replay"):
        engine.apply(plan.id, approved(plan))
    assert len(fixture.writes) == 1
    assert engine.verify(plan.id)["phase"] == "verified"
    assert len(fixture.writes) == 1


def test_approval_and_before_drift_gate_writes_and_noop_has_zero_writes():
    fixture, _, _, engine = setup()
    plan = engine.plan("led.set", {"enabled": True})
    with pytest.raises(ValueError, match="approval"):
        engine.apply(plan.id, None)
    fixture.enabled = True
    with pytest.raises(ValueError, match="before_drift"):
        engine.apply(plan.id, approved(plan))
    noop = engine.plan("led.set", {"enabled": True})
    assert engine.apply(noop.id, approved(noop))["phase"] == "verified_noop"
    assert engine.verify(noop.id)["phase"] == "verified_noop"
    assert not fixture.writes


def test_uncertain_write_is_persisted_before_call_and_never_replayed():
    fixture, _, store, engine = setup()
    plan = engine.plan("led.set", {"enabled": True})
    fixture.fail_write = True
    def check_state():
        assert store.get(plan.id)[1]["phase"] == "outcome_unknown"
    fixture.before_write = check_state
    assert engine.apply(plan.id, approved(plan))["phase"] == "outcome_unknown"
    with pytest.raises(ValueError, match="replay"):
        engine.apply(plan.id, approved(plan))
    assert engine.verify(plan.id)["phase"] == "verified"
    assert len(fixture.writes) == 1


@pytest.mark.parametrize("operation,fields", [("synthetic.led", ["enabled"]), ("led.set", ["secret"]), ("reboot", ["enabled"])])
def test_backend_rejects_every_other_native_control(operation, fields):
    _, backend, _, _ = setup()
    with backend.transaction():
        backend.device_identity()
        with pytest.raises(RouterError, match="Only the native LED"):
            backend.read(operation, fields)
        with pytest.raises(RouterError, match="Only the native LED"):
            backend.write(operation, {fields[0]: True})
