"""Private admission machinery, not a production evidence provider.

Implementing TrustedBackupProvider is an explicit authority injection. The host
must review its evidence authentication, custody, complete coverage, recovery and
whole-covered-configuration invalidation. Shapes and hashes cannot prove these.
There is intentionally no file loader or concrete production implementation.
"""
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re
import uuid

from .catalog import canonical
from .errors import RouterError


def denied():
    # Preserve the public fail-closed contract and frozen CLI benchmark wording.
    # Invalid evidence also means the verified prerequisite is missing.
    return RouterError('backup_required', 'A verified configuration backup and restoration prerequisite is missing; the pinned native library has no backup/restore provider.')


@dataclass(frozen=True, repr=False, slots=True)
class BackupRequest:
    plan_json: str
    identity_json: str
    before_json: str
    context_json: str
    challenge: str

    @property
    def binding(self):
        return hashlib.sha256(canonical(asdict(self)).encode()).hexdigest()


@dataclass(frozen=True, repr=False, slots=True)
class BackupAdmission:
    admission_id: str
    request_binding: str
    challenge: str
    artifact_id: str
    artifact_sha256: str
    artifact_bytes: int
    source_identity_json: str
    restore_identity_json: str
    operation: str
    coverage: tuple[str, ...]
    configuration_revision: str
    invalidation_evidence_id: str
    recovery_evidence_id: str
    recovery_disposition: str
    exported_at: float
    observed_at: float
    trial_started_at: float
    trial_completed_at: float
    issued_at: float
    expires_at: float
    maximum_age: float


REQUIRED_COVERAGE = ('complete_selected_configuration', 'secrets_and_unknown_fields',
                     'whole_covered_configuration_invalidation', 'independent_recovery_and_effect_checks')


class TrustedBackupProvider(ABC):
    """Reviewed executable authority; never deserialize this from operator data.

    admit authenticates evidence origin and validates exact original bytes/custody,
    source and intended restore device/build, complete operation coverage including
    secrets, successful independent intended-device recovery/effect observations,
    reviewed maximum age and verifiable invalidation of the entire covered config.
    Unknown fields, uncertainty or missing evidence must raise. A new issue time
    cannot refresh export age. revalidate repeats those guarantees against current
    authoritative evidence immediately before send and returns the SAME receipt.
    A provider must reject revoked/replayed attempts and uncertain collection order.
    Merely implementing these methods does not make a provider production-ready.
    """
    @abstractmethod
    def admit(self, request: BackupRequest) -> BackupAdmission: ...

    @abstractmethod
    def revalidate(self, request: BackupRequest, admission: BackupAdmission) -> BackupAdmission: ...


def request_for(plan, identity, before, context, challenge):
    return BackupRequest(plan.payload, canonical(identity), canonical(before), canonical(context), challenge)


def _validate_request(request, plan):
    if type(request) is not BackupRequest or request.plan_json != plan.payload:
        raise denied()
    if type(request.challenge) is not str or re.fullmatch('[0-9a-f]{32}', request.challenge) is None:
        raise denied()
    identity, before, context = [json.loads(value) for value in
                                (request.identity_json, request.before_json, request.context_json)]
    if (type(identity) is not dict or set(identity) != {'model', 'firmware', 'device_fingerprint'}
            or any(type(v) is not str or not v for v in identity.values())
            or identity['firmware'] != plan.data['firmware']
            or identity['device_fingerprint'] != plan.data['device']
            or type(before) is not dict or not before or type(context) is not dict
            or context.get('before') != before or 'after' not in context
            or canonical(identity) != request.identity_json or canonical(before) != request.before_json
            or canonical(context) != request.context_json):
        raise denied()


def _validate(receipt, request, now):
    if type(receipt) is not BackupAdmission or type(request) is not BackupRequest:
        raise denied()
    plan = json.loads(request.plan_json)
    for name in ('admission_id', 'artifact_id', 'configuration_revision',
                 'invalidation_evidence_id', 'recovery_evidence_id'):
        value = getattr(receipt, name)
        if type(value) is not str or re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value) is None:
            raise denied()
    if (type(receipt.artifact_sha256) is not str
            or re.fullmatch('[0-9a-f]{64}', receipt.artifact_sha256) is None
            or type(receipt.artifact_bytes) is not int or not 0 < receipt.artifact_bytes <= 2**63-1
            or receipt.request_binding != request.binding or receipt.challenge != request.challenge
            or receipt.source_identity_json != request.identity_json
            or receipt.restore_identity_json != request.identity_json
            or receipt.operation != plan['operation']
            or type(receipt.coverage) is not tuple or receipt.coverage != REQUIRED_COVERAGE
            or receipt.recovery_disposition != 'complete_intended_device_restore'):
        raise denied()
    times = [receipt.exported_at, receipt.observed_at, receipt.trial_started_at,
             receipt.trial_completed_at, receipt.issued_at, receipt.expires_at,
             receipt.maximum_age, now]
    if any(type(t) not in (float, int) or not math.isfinite(t) for t in times):
        raise denied()
    if not (0 <= receipt.exported_at <= receipt.observed_at <= receipt.trial_started_at
            <= receipt.trial_completed_at <= receipt.issued_at <= now < receipt.expires_at
            and receipt.maximum_age > 0 and now - receipt.exported_at < receipt.maximum_age
            and receipt.expires_at <= receipt.exported_at + receipt.maximum_age):
        raise denied()


class BackupAttempt:
    """One private apply attempt, consumed before independent send authorization."""
    def __init__(self, backend, plan, clock):
        self.backend, self.plan, self.clock = backend, plan, clock
        self.used = False
        try:
            self.provider = backend.backup_provider
            if not isinstance(self.provider, TrustedBackupProvider):
                raise denied()
            self.request = backend.backup_request(plan, uuid.uuid4().hex)
            _validate_request(self.request, plan)
            self.admitted_at = clock()
            self.receipt = self.provider.admit(self.request)
            completed_at = clock()
            if completed_at < self.admitted_at:
                raise denied()
            _validate(self.receipt, self.request, completed_at)
            self.admitted_at = completed_at
        except Exception:
            raise denied() from None

    def revalidate(self):
        if self.used:
            raise denied()
        self.used = True
        try:
            now = self.clock()
            if now < self.admitted_at or self.backend.backup_provider is not self.provider:
                raise denied()
            # Detect changed private context as well as provider-side configuration drift.
            if self.backend.backup_request(self.plan, self.request.challenge) != self.request:
                raise denied()
            current = self.provider.revalidate(self.request, self.receipt)
            completed_at = self.clock()
            if completed_at < now:
                raise denied()
            if type(current) is not BackupAdmission or current != self.receipt:
                raise denied()
            _validate(current, self.request, completed_at)
        except Exception:
            raise denied() from None
