"""Explicitly trusted synthetic authority; no files, services or real evidence."""
import json

from router_agent.backup_admission import (BackupAdmission, REQUIRED_COVERAGE,
                                         TrustedBackupProvider, request_for)


class SyntheticBackupProvider(TrustedBackupProvider):
    def __init__(self):
        self.requests = []
        self.rechecks = 0
        self.admit_hook = None
        self.recheck_hook = None

    def admit(self, request):
        self.requests.append(request)
        plan = json.loads(request.plan_json)
        base = plan['created_at'] - 1
        receipt = BackupAdmission('synthetic-admission', request.binding, request.challenge,
            'synthetic-artifact', 'a'*64, 16, request.identity_json, request.identity_json,
            plan['operation'], REQUIRED_COVERAGE, 'synthetic-revision', 'synthetic-invalidation',
            'synthetic-recovery', 'complete_intended_device_restore', base, base, base, base,
            plan['created_at'], plan['expires_at'], plan['expires_at'] - base + 1)
        return self.admit_hook(request, receipt) if self.admit_hook else receipt

    def revalidate(self, request, admission):
        self.rechecks += 1
        return self.recheck_hook(request, admission) if self.recheck_hook else admission


class SyntheticBackupBackend:
    @property
    def backup_provider(self):
        if not getattr(self, 'backup_ok', True):
            return None
        if not hasattr(self, '_synthetic_backup'):
            self._synthetic_backup = SyntheticBackupProvider()
        return self._synthetic_backup

    def backup_request(self, plan, challenge):
        public = self.device_identity()
        identity = {'device_fingerprint': public['device'], 'firmware': public['firmware'], 'model': 'synthetic'}
        return request_for(plan, identity, plan.data['before'], plan.data, challenge)
