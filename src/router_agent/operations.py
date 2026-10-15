"""Change protocol with finite injected backend and independent approval authority.

Hashes bind content, never authorize it. Native operations need dual allowlists.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import threading
import time
import uuid

from .catalog import Catalog, canonical, exact_keys
from .snapshots import private_dir, state_lock, private_read, atomic_write

PARENTAL_OPERATIONS = frozenset({"parental.enable", "parental.block_all", "parental.rule"})
EXPANSION_OPERATIONS = frozenset({'state.vpnc', 'state.openvpn_client', 'state.wireguard_client', 'state.port_forwarding', 'state.openvpn_server', 'state.wireguard_server', 'state.wlan'})
BOUND_OPERATIONS = PARENTAL_OPERATIONS | EXPANSION_OPERATIONS

PLAN_KEYS = {"device", "firmware", "catalog_hash", "operation", "fields", "before", "after", "verification", "created_at", "expires_at", "risk", "backup_required", "hash"}

PARENTAL_PLAN_KEYS = PLAN_KEYS | {"review", "intent", "side_effects", "context_binding"}


@dataclass(frozen=True)
class Plan:
    payload: str

    @property
    def data(self) -> dict:
        return json.loads(self.payload)

    @property
    def id(self) -> str:
        return self.data["hash"]


@dataclass(frozen=True)
class ApprovedScope:
    """Supplied by the caller's independent approval authority, never by plan()."""
    plan_hash: str
    device: str
    operation: str
    after_json: str
    expires_at: float
    window_id: str | None = None


class MemoryPlanStore:
    def __init__(self):
        self._records = {}
        self._lock = threading.RLock()

    def lock(self):
        return self._lock

    def put(self, plan: Plan, state: dict):
        self._records[plan.id] = (plan.payload, canonical(state))

    def get(self, plan_id: str):
        payload, state = self._records[plan_id]
        return Plan(payload), json.loads(state)


class FilePlanStore:
    """Owner-only atomic persistence. One lock covers reads, plans and mutations."""
    def __init__(self, directory):
        self.directory = private_dir(directory)

    def _path(self, plan_id):
        if not isinstance(plan_id, str) or len(plan_id) != 64 or any(c not in "0123456789abcdef" for c in plan_id):
            raise ValueError("invalid_plan_id")
        return self.directory / (plan_id + ".json")

    def lock(self):
        return state_lock(self.directory)

    def put(self, plan: Plan, state: dict):
        atomic_write(self._path(plan.id), canonical({"plan": plan.data, "state": state}).encode())

    def get(self, plan_id):
        path = self._path(plan_id)
        if not path.exists() and not path.is_symlink():
            raise FileNotFoundError(path)
        record = json.loads(private_read(path))
        exact_keys(record, {"plan", "state"})
        plan = Plan(canonical(record["plan"]))
        if plan.id != plan_id:
            raise ValueError("plan_id_mismatch")
        return plan, record["state"]


class OperationEngine:
    def __init__(self, catalog: Catalog, backend, store, *, clock=time.time):
        self.catalog, self.backend, self.store, self.clock = catalog, backend, store, clock

    def _transaction(self):
        transaction = getattr(self.backend, "transaction", None)
        return transaction() if transaction is not None else nullcontext()

    def _identity(self):
        identity = self.backend.device_identity()
        exact_keys(identity, {"device", "firmware"})
        if not all(isinstance(v, str) and v for v in identity.values()):
            raise ValueError("invalid_identity")
        return identity

    def _values(self, op, values):
        if not isinstance(values, dict) or not values or not set(values) <= set(op["fields"]):
            raise ValueError("unsupported_fields")
        for key, value in values.items():
            spec = op["fields"][key]
            if spec["secret"] or any(marker in key.lower() for marker in ("password", "passwd", "secret", "token", "psk", "private_key", "credential")):
                raise ValueError("secret_operation_human_handoff")
            expected = {"bool": bool, "int": int, "str": str}[spec["type"]]
            if type(value) is not expected:
                raise ValueError("invalid_field_value")

    def _read(self, op, fields):
        values = self.backend.read(op["name"], fields)
        if not isinstance(values, dict) or set(values) != set(fields):
            raise ValueError("incomplete_read")
        self._values(op, values)
        return values

    def _validate(self, plan, *, check_expiry=True, check_identity=True):
        data = plan.data
        parental = data.get("operation") in BOUND_OPERATIONS
        exact_keys(data, PARENTAL_PLAN_KEYS if parental else PLAN_KEYS)
        digest = data.pop("hash")
        if hashlib.sha256(canonical(data).encode()).hexdigest() != digest:
            raise ValueError("plan_tampered")
        data["hash"] = digest
        if parental:
            self.backend.attach_plan(plan)
        op = self.catalog.operation(data["operation"])
        if data["risk"] != op["risk"] or data["backup_required"] != op["backup_required"]:
            raise ValueError("invalid_plan_policy")
        self._values(op, data["after"])
        self._values(op, data["before"])
        if data["fields"] != sorted(data["after"]) or set(data["before"]) != set(data["after"]) or data["verification"] != data["after"]:
            raise ValueError("invalid_plan_scope")
        if data["catalog_hash"] != self.catalog.hash or (check_identity and self._identity() != {k: data[k] for k in ("device", "firmware")}):
            raise ValueError("incompatible_plan")
        if type(data["created_at"]) not in (int, float) or type(data["expires_at"]) not in (int, float) or data["expires_at"] <= data["created_at"] or (check_expiry and not data["created_at"] <= self.clock() < data["expires_at"]):
            raise ValueError("expired_plan")
        return data, op

    def _parental_plan(self, operation, intent, ttl):
        op = self.catalog.operation(operation)
        prepared = self.backend.prepare_plan(operation, intent)
        return self._persist_parental(op, prepared, ttl)

    def _persist_parental(self, op, prepared, ttl):
        exact_keys(prepared, {"before", "after", "review", "intent", "side_effects"})
        self._values(op, prepared["before"])
        self._values(op, prepared["after"])
        identity = self._identity()
        now = self.clock()
        data = {**identity, "catalog_hash": self.catalog.hash, "operation": op["name"], "fields": ["policy_fingerprint"],
                **prepared, "verification": dict(prepared["after"]), "created_at": now, "expires_at": now + ttl,
                "risk": op["risk"], "backup_required": op["backup_required"]}
        data["context_binding"] = self.backend.seal_plan(data)
        data["hash"] = hashlib.sha256(canonical(data).encode()).hexdigest()
        plan = Plan(canonical(data))
        self.backend.bind_plan(plan)
        try:
            self.store.get(plan.id)
        except (KeyError, FileNotFoundError):
            self.store.put(plan, {"phase": "planned"})
        return plan

    def plan(self, operation: str, after: dict, *, ttl=300) -> Plan:
        if type(ttl) not in (int, float) or not 0 < ttl <= 3600:
            raise ValueError("invalid_ttl")
        with self.store.lock(), self._transaction():
            if operation in BOUND_OPERATIONS:
                return self._parental_plan(operation, after, ttl)
            op = self.catalog.operation(operation)
            self._values(op, after)
            identity = self._identity()
            before = self._read(op, sorted(after))
            now = self.clock()
            data = {**identity, "catalog_hash": self.catalog.hash, "operation": operation, "fields": sorted(after), "before": before, "after": dict(after), "verification": dict(after), "created_at": now, "expires_at": now + ttl, "risk": op["risk"], "backup_required": op["backup_required"]}
            data["hash"] = hashlib.sha256(canonical(data).encode()).hexdigest()
            plan = Plan(canonical(data))
            try:
                self.store.get(plan.id)
            except (KeyError, FileNotFoundError):
                self.store.put(plan, {"phase": "planned"})
            return plan

    def apply(self, plan_id: str, approval: ApprovedScope) -> dict:
        with self.store.lock(), self._transaction():
            plan, state = self.store.get(plan_id)
            data, op = self._validate(plan)
            if state["phase"] != "planned":
                raise ValueError("replay_blocked_verify_first")
            if not isinstance(approval, ApprovedScope) or approval.plan_hash != plan.id or approval.device != data["device"] or approval.operation != data["operation"] or approval.after_json != canonical(data["after"]) or type(approval.expires_at) not in (int, float) or not math.isfinite(approval.expires_at) or approval.expires_at <= self.clock():
                raise ValueError("approval_scope_mismatch")
            if self._read(op, data["fields"]) != data["before"]:
                raise ValueError("before_drift")
            live_operations = getattr(self.backend, "live_operations", ())
            if getattr(self.backend, "live", True) and (op["offline_only"] or not isinstance(live_operations, (set, frozenset, tuple, list)) or op["name"] not in live_operations):
                raise ValueError("live_execution_human_handoff")
            if data["before"] == data["after"]:
                result = {"phase": "verified_noop"}
                self.store.put(plan, result)
                return result
            backup = None
            if op["backup_required"]:
                from .backup_admission import BackupAttempt, denied
                # Live evidence must be revalidated at the guarded native send boundary.
                if getattr(self.backend, 'live', True) and not getattr(self.backend, 'authorization_at_send', False):
                    raise denied()
                backup = BackupAttempt(self.backend, plan, self.clock)
            if getattr(self.backend, "live", True):
                from .approval_window import validate_window
                current = validate_window(plan, approval.window_id, clock=self.clock)
                if current != approval:
                    raise ValueError("approval_scope_mismatch")
            # Persist before invoking write: an exception or process crash cannot permit replay.
            state = {"phase": "outcome_unknown", "failure_code": "write_interrupted", "failure_stage": "write"}
            self.store.put(plan, state)
            try:
                if getattr(self.backend, "authorization_at_send", False):
                    def authorization_check():
                        from .errors import RouterError
                        now = self.clock()
                        if not data['created_at'] <= now < data['expires_at'] or not now < approval.expires_at:
                            raise RouterError('approval_scope_mismatch', 'Plan or approval expired before write admission.')
                        if backup is not None:
                            backup.revalidate()
                        now = self.clock()
                        if not data['created_at'] <= now < data['expires_at'] or not now < approval.expires_at:
                            raise RouterError('approval_scope_mismatch', 'Plan or approval expired before write admission.')
                        from .approval_window import validate_window
                        if validate_window(plan, approval.window_id, clock=self.clock) != approval:
                            raise RouterError("approval_scope_mismatch", "Administrator approval changed before write admission.")
                    self.backend.write(op["name"], dict(data["after"]), authorization_check=authorization_check)
                else:
                    if backup is not None:
                        backup.revalidate()  # offline-only fixtures; no live boundary bypass
                    self.backend.write(op["name"], dict(data["after"]))
            except Exception as error:
                state["failure_code"] = sanitized_failure_code(error, stage="write")
                self.store.put(plan, state)
                return dict(state)
            state = {"phase": "apply_unverified"}
            self.store.put(plan, state)
            return dict(state)

    def verify(self, plan_id: str) -> dict:
        with self.store.lock(), self._transaction():
            plan, state = self.store.get(plan_id)
            data, op = self._validate(plan, check_expiry=False, check_identity=False)
            if state["phase"] not in {"apply_unverified", "outcome_unknown", "verified", "verification_failed", "verified_noop"}:
                raise ValueError("not_applied")
            try:
                if self._identity() != {k: data[k] for k in ("device", "firmware")}:
                    from .errors import RouterError
                    raise RouterError("identity_changed", "Verification target identity changed.")
                matches = self._read(op, data["fields"]) == data["verification"]
            except Exception as error:
                matches = False
                verification_code = sanitized_failure_code(error, stage="verify")
            else:
                verification_code = "state_mismatch" if not matches else None
            result = {key: value for key, value in state.items() if key in {"failure_code", "failure_stage"}}
            result.update({"phase": ("verified_noop" if state["phase"] == "verified_noop" else "verified") if matches else "verification_failed"})
            if verification_code:
                result.update(verification_failure_code=verification_code, verification_failure_stage="verify")
            self.store.put(plan, result)
            return result

    def rollback_plan(self, plan_id: str, *, ttl=300) -> Plan:
        with self.store.lock(), self._transaction():
            plan, state = self.store.get(plan_id)
            data, op = self._validate(plan, check_expiry=False)
            if state["phase"] not in {"verified", "apply_unverified", "outcome_unknown", "verification_failed"}:
                raise ValueError("not_applied")
            if self._read(op, data["fields"]) != data["after"]:
                raise ValueError("rollback_drift")
            if data["operation"] in BOUND_OPERATIONS:
                if type(ttl) not in (int, float) or not 0 < ttl <= 3600:
                    raise ValueError("invalid_ttl")
                return self._persist_parental(op, self.backend.prepare_reverse(plan), ttl)
            # Generate a fresh reverse plan; apply() requires separate approval for its hash.
            if type(ttl) not in (int, float) or not 0 < ttl <= 3600:
                raise ValueError("invalid_ttl")
            now = self.clock()
            reverse = {**{k: data[k] for k in ("device", "firmware", "catalog_hash", "operation", "fields")}, "before": data["after"], "after": data["before"], "verification": data["before"], "created_at": now, "expires_at": now + ttl, "risk": op["risk"], "backup_required": op["backup_required"]}
            reverse["hash"] = hashlib.sha256(canonical(reverse).encode()).hexdigest()
            result = Plan(canonical(reverse))
            self.store.put(result, {"phase": "planned"})
            return result


# Never serialize exception text or unrecognized codes, even from RouterError.
FAILURE_CODES = frozenset({"backup_required", "approval_window_required", "approval_window_expired", "approval_authority_unsafe", "approval_scope_mismatch", "apply_uncertain", "timeout", "auth_failed", "auth_locked", "auth_required", "write_boundary", "request_budget", "identity_changed", "state_changed", "policy_changed", "after_policy_changed", "native_cleanup_unconfirmed", "native_state_unknown", "malformed_response", "invalid_policy_context", "incomplete_read"})


def sanitized_failure_code(error, *, stage):
    from .errors import RouterError
    if isinstance(error, RouterError) and error.code in FAILURE_CODES:
        return error.code
    if isinstance(error, TimeoutError):
        return "timeout"
    return "write_failed" if stage == "write" else "verification_read_failed"
