"""Dated expansion evidence, separate from the immutable October 12 audit."""
from importlib.resources import files
import json

from .errors import RouterError


def load_expansion():
    try:
        data = json.loads(files('router_agent').joinpath('data/expansion_2026_10_15.json').read_text())
        from .native_audit import load_native_audit
        expected = {row['id'] for row in load_native_audit().manifest()['capabilities'] if row['cli_status'] == 'unimplemented'}
        rows = data['capabilities']
        if (data['schema_version'] != 1 or data['upstream_version'] != '1.21.3'
                or len(rows) != 16 or {row['id'] for row in rows} != expected):
            raise ValueError
        for row in rows:
            if (set(row) != {'id', 'implementation', 'offline', 'live', 'interface', 'limits', 'next_action'}
                    or row['implementation'] not in {'implemented_selected', 'implemented_guarded', 'source_limitation', 'recovery_blocked'}
                    or row['offline'] not in {'passed', 'pending'}
                    or row['live'] not in {'not_attempted', 'passed_selected', 'unavailable_target', 'blocked_prerequisite'}
                    or not isinstance(row['limits'], list) or not row['limits']
                    or any(not isinstance(v, str) or not v for v in row['limits'])):
                raise ValueError
        return data
    except (ValueError, KeyError, TypeError, OSError):
        raise RouterError('invalid_expansion_manifest', 'The dated expansion evidence is invalid.') from None


def page(capability_id=None, *, offset=0, limit=5):
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 20:
        raise RouterError('invalid_arguments', 'Capability limit must be 1..20 and offset nonnegative.', 2)
    manifest = load_expansion()
    rows = sorted(manifest['capabilities'], key=lambda row: row['id'])
    if capability_id is not None:
        rows = [row for row in rows if row['id'] == capability_id]
        if not rows:
            raise RouterError('unknown_capability', 'Unknown expansion capability ID.')
    selected = rows[offset:offset + limit]
    return {'schema_version': 1, 'source': 'offline_expansion_evidence', 'fetched_at': None,
            'observed_at': None, 'freshness': 'not_collected',
            'data': {'evidence_date': manifest['evidence_date'], 'upstream_version': manifest['upstream_version'],
                     'historical_audit_unchanged': True, 'capabilities': selected,
                     'pagination': {'offset': offset, 'limit': limit, 'total': len(rows),
                                    'next_offset': offset + len(selected) if offset + len(selected) < len(rows) else None}},
            'capability_gaps': ['Dated implementation and selected-response evidence do not establish live write readiness, successful restoration or WebUI parity.']}
