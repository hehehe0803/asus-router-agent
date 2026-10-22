"""Strict offline WebUI operation inventory; never an execution catalog."""
from __future__ import annotations

from collections import Counter
from datetime import date
import hashlib
from importlib.resources import files
import json
from pathlib import Path, PurePosixPath
import re

from .errors import RouterError

ID = re.compile(r'[a-zA-Z][a-zA-Z0-9_.-]{0,127}\Z')
VARIANTS = frozenset('read write create delete on off import export job destructive local_ui'.split())
REFERENCE_KINDS = frozenset('planning official upstream_source local_code synthetic_test dated_live'.split())
HIDDEN_IDS = frozenset('''hidden.fusion.wireguard hidden.fusion.openvpn hidden.fusion.other_protocols
hidden.fusion.assignments_failure hidden.server.wireguard hidden.server.openvpn hidden.server.other_protocols
hidden.usb.aidisk_servers hidden.usb.storage_management hidden.usb.printer_modem hidden.usb.download_master
hidden.aicloud.products hidden.aimesh.nodes_uplinks hidden.admin.certificates_access hidden.admin.system_topbar
hidden.firewall.ipv6 hidden.alexa.ifttt hidden.common.notifications hidden.common.tables_reports
hidden.common.mode_hardware_account'''.split())
IMPLEMENTATION = frozenset({'unimplemented', 'partial', 'implemented'})
GAP = 'Unresolved firmware branches keep the applicable denominator unknown; inventory is not CLI parity.'


def _require(condition):
    if not condition:
        raise ValueError


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names.split()))


def _text(value, maximum=4096):
    _require(type(value) is str and 0 < len(value) <= maximum)
    _require(not any(ord(c) < 32 and c not in '\n\t' for c in value))


def _id(value):
    _require(type(value) is str and ID.fullmatch(value) is not None)


def _enum(value, values):
    _require(type(value) is str and value in values)


def _date(value):
    _text(value, 256)
    _require(re.fullmatch(r'\d{4}-\d{2}-\d{2}', value) is not None)
    date.fromisoformat(value)


def _strings(value, *, nonempty=False, ids=False):
    _require(type(value) is list and (bool(value) or not nonempty))
    for item in value:
        (_id if ids else _text)(item)
    _require(len(value) == len(set(value)))


def _invalid():
    return RouterError('invalid_webui_manifest', 'Packaged WebUI inventory metadata is invalid.')


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


class WebUIOperations:
    def __init__(self, data: dict):
        try:
            self._validate(data)
            self._payload = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
            self.hash = hashlib.sha256(self._payload.encode('utf-8')).hexdigest()
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
            raise _invalid() from exc

    @staticmethod
    def _validate(data):
        _keys(data, 'schema_version inventory_revision target upstream baseline references branches operations')
        _require(type(data['schema_version']) is int and data['schema_version'] == 1)
        _date(data['inventory_revision'])
        _keys(data['target'], 'model firmware')
        for value in data['target'].values():
            _text(value, 256)
        _keys(data['upstream'], 'package version release_ref')
        _require(data['upstream']['package'] == 'asusrouter' and data['upstream']['version'] == '1.21.3')
        _keys(data['baseline'], 'catalog_sha256 matrix_ref source_baseline_ref')
        _require(type(data['baseline']['catalog_sha256']) is str and re.fullmatch('[0-9a-f]{64}', data['baseline']['catalog_sha256']) is not None)

        refs = {}
        _require(type(data['references']) is list)
        for ref in data['references']:
            _keys(ref, 'id kind path revision line_start line_end date')
            _id(ref['id'])
            _require(ref['id'] not in refs)
            _enum(ref['kind'], REFERENCE_KINDS)
            path = ref['path']
            _text(path)
            _require(not PurePosixPath(path).is_absolute() and '..' not in path.split('/')
                     and not any(c in path for c in '\\?#:') and not any(c.isspace() for c in path))
            if ref['revision'] is not None:
                _text(ref['revision'])
            start, end = ref['line_start'], ref['line_end']
            _require((start is None and end is None) or (type(start) is int and type(end) is int and 1 <= start <= end))
            if ref['date'] is not None:
                _date(ref['date'])
            if ref['kind'] == 'upstream_source':
                _require(ref['revision'] is not None)
            if ref['kind'] == 'dated_live':
                _require(ref['date'] is not None)
            refs[ref['id']] = ref

        def ref_list(values, *, nonempty=False, kinds=None):
            _strings(values, nonempty=nonempty, ids=True)
            _require(all(v in refs for v in values))
            if kinds is not None:
                _require(any(refs[v]['kind'] in kinds for v in values))

        for ref_id in (data['upstream']['release_ref'], data['baseline']['matrix_ref'], data['baseline']['source_baseline_ref']):
            _id(ref_id)
            _require(ref_id in refs)

        from .catalog import load_catalog
        catalog = load_catalog()
        _require(data['baseline']['catalog_sha256'] == catalog.hash)
        expected_pages = {(p['group'], p['page']) for p in catalog.manifest()['pages']}
        _require(type(data['branches']) is list)
        branches, page_pairs, hidden = {}, set(), set()
        for branch in data['branches']:
            _keys(branch, 'id origin catalog_page parent_branch_ids label navigation enumeration evidence_refs variant_presence')
            _id(branch['id'])
            _require(branch['id'] not in branches)
            _enum(branch['origin'], {'catalog_page', 'hidden_register', 'newly_discovered'})
            if branch['origin'] == 'catalog_page':
                _keys(branch['catalog_page'], 'group page')
                for value in branch['catalog_page'].values():
                    _text(value)
                pair = (branch['catalog_page']['group'], branch['catalog_page']['page'])
                _require(pair not in page_pairs)
                page_pairs.add(pair)
            else:
                _require(branch['catalog_page'] is None)
            _strings(branch['parent_branch_ids'], ids=True)
            if branch['origin'] == 'hidden_register':
                _require(bool(branch['parent_branch_ids']))
                hidden.add(branch['id'])
            _text(branch['label'])
            _enum(branch['navigation'], {'unresolved', 'present', 'renamed', 'disappeared'})
            _enum(branch['enumeration'], {'unresolved', 'partial', 'enumerated'})
            ref_list(branch['evidence_refs'], nonempty=True)
            _keys(branch['variant_presence'], ' '.join(VARIANTS))
            for presence in branch['variant_presence'].values():
                _enum(presence, {'unresolved', 'conditional', 'present', 'absent_verified'})
            if (branch['navigation'] != 'unresolved' or branch['enumeration'] == 'enumerated'
                    or 'absent_verified' in branch['variant_presence'].values()):
                ref_list(branch['evidence_refs'], kinds={'official', 'dated_live'})
            if branch['enumeration'] == 'enumerated':
                _require('unresolved' not in branch['variant_presence'].values())
            branches[branch['id']] = branch
        _require(page_pairs == expected_pages and HIDDEN_IDS <= hidden)
        # Iterative DAG walk avoids recursion on hostile/deep metadata.
        pending = set(branches)
        done = set()
        for branch in branches.values():
            _require(all(p in branches and p != branch['id'] for p in branch['parent_branch_ids']))
        while pending:
            ready = {b for b in pending if set(branches[b]['parent_branch_ids']) <= done}
            _require(bool(ready))
            done.update(ready)
            pending.difference_update(ready)

        from .native_audit import load_native_audit
        native_ids = {e['id'] for e in load_native_audit().manifest()['capabilities']}
        _require(type(data['operations']) is list)
        operation_ids, bound = set(), set()
        for op in data['operations']:
            _keys(op, 'id family title variant bindings applicability schema source implementation live policy blockers next')
            _id(op['id'])
            _require(op['id'] not in operation_ids)
            operation_ids.add(op['id'])
            _id(op['family'])
            _text(op['title'])
            _enum(op['variant'], VARIANTS)
            _require(type(op['bindings']) is list and bool(op['bindings']))
            bindings = set()
            for index, binding in enumerate(op['bindings']):
                _keys(binding, 'branch_id control conditions alias_equivalence_ref')
                _id(binding['branch_id'])
                _require(binding['branch_id'] in branches)
                _text(binding['control'])
                _strings(binding['conditions'])
                key = (binding['branch_id'], binding['control'])
                _require(key not in bindings)
                bindings.add(key)
                alias = binding['alias_equivalence_ref']
                if alias is not None:
                    ref_list([alias])
                _require(index == 0 or alias is not None)
                presence = branches[binding['branch_id']]['variant_presence'][op['variant']]
                _require(presence != 'absent_verified')
                if presence == 'conditional':
                    _require(bool(binding['conditions']))
                bound.add((binding['branch_id'], op['variant']))

            app = op['applicability']
            _keys(app, 'status confidence reason evidence_refs')
            _enum(app['status'], {'unknown', 'conditional', 'applicable', 'not_applicable'})
            _enum(app['confidence'], {'candidate', 'source_supported', 'target_observed'})
            _text(app['reason'])
            ref_list(app['evidence_refs'])
            if app['status'] == 'unknown':
                _require(app['confidence'] == 'candidate')
            if app['status'] == 'conditional':
                _require(app['confidence'] in {'candidate', 'source_supported'})
            if app['status'] in {'applicable', 'not_applicable'}:
                _require(app['confidence'] != 'candidate')
                ref_list(app['evidence_refs'], kinds={'official', 'dated_live'})
            if app['confidence'] == 'source_supported':
                ref_list(app['evidence_refs'], kinds={'official', 'upstream_source', 'dated_live'})
            if app['confidence'] == 'target_observed':
                ref_list(app['evidence_refs'], kinds={'dated_live'})
            schema = op['schema']
            _keys(schema, 'status input output evidence_refs')
            _enum(schema['status'], {'unknown', 'partial'})
            _require(schema['input'] is None and schema['output'] is None)
            ref_list(schema['evidence_refs'])
            source = op['source']
            _keys(source, 'status native_audit_ids api limits')
            _enum(source['status'], {'unassessed', 'candidate', 'unsupported', 'contract_verified'})
            _strings(source['native_audit_ids'], ids=True)
            _require(set(source['native_audit_ids']) <= native_ids)
            _strings(source['limits'])
            if source['status'] == 'contract_verified':
                _keys(source['api'], 'symbol signature upstream_version evidence_refs')
                _text(source['api']['symbol'])
                _text(source['api']['signature'])
                _require(source['api']['upstream_version'] == '1.21.3')
                ref_list(source['api']['evidence_refs'], kinds={'upstream_source'})
                _require(refs[data['baseline']['source_baseline_ref']]['kind'] == 'upstream_source')
            else:
                _require(source['api'] is None)
            if source['status'] == 'unsupported':
                _require(bool(source['limits']))
            impl = op['implementation']
            _keys(impl, 'status interfaces test_refs limits')
            _enum(impl['status'], IMPLEMENTATION)
            _strings(impl['interfaces'])
            _strings(impl['limits'])
            ref_list(impl['test_refs'])
            if impl['status'] == 'unimplemented':
                _require(not impl['interfaces'] and not impl['test_refs'])
            else:
                _require(bool(impl['interfaces']))
                ref_list(impl['test_refs'], kinds={'synthetic_test'})
                ref_list(impl['test_refs'], kinds={'local_code'})
            live = op['live']
            _keys(live, 'execution outcome evidence_refs limits')
            _enum(live['execution'], {'not_attempted', 'blocked', 'attempted'})
            _enum(live['outcome'], {'unverified', 'partial', 'verified', 'failed', 'unknown'})
            ref_list(live['evidence_refs'])
            _strings(live['limits'])
            if live['execution'] == 'attempted':
                ref_list(live['evidence_refs'], kinds={'dated_live'})
            else:
                _require(live['outcome'] == 'unverified')
            policy = op['policy']
            _keys(policy, 'mutation risk authorization privacy side_effects preservation atomic_apply_group recovery')
            _enum(policy['mutation'], {'unknown', 'none', 'router', 'local', 'external'})
            _enum(policy['risk'], {'unknown', 'low', 'exposure', 'disruptive', 'critical'})
            for key in ('authorization', 'privacy', 'side_effects', 'preservation'):
                _strings(policy[key], nonempty=True)
            if policy['atomic_apply_group'] is not None:
                _id(policy['atomic_apply_group'])
            recovery = policy['recovery']
            _keys(recovery, 'status detail evidence_refs')
            _enum(recovery['status'], {'unknown', 'not_required', 'inverse', 'recovery_procedure', 'unavailable'})
            _text(recovery['detail'])
            ref_list(recovery['evidence_refs'])
            if recovery['status'] in {'inverse', 'recovery_procedure'}:
                ref_list(recovery['evidence_refs'], kinds={'official', 'upstream_source', 'local_code'})
            if recovery['status'] == 'not_required':
                _require(policy['mutation'] in {'none', 'local'})
            _require(type(op['blockers']) is list)
            codes = set()
            for blocker in op['blockers']:
                _keys(blocker, 'code detail')
                _id(blocker['code'])
                _text(blocker['detail'])
                _require(blocker['code'] not in codes)
                codes.add(blocker['code'])
            _keys(op['next'], 'owner task evidence_required')
            for value in op['next'].values():
                _text(value)
        for branch in branches.values():
            for variant, presence in branch['variant_presence'].items():
                if presence == 'present':
                    _require((branch['id'], variant) in bound)

    def manifest(self) -> dict:
        return json.loads(self._payload)

    def page(self, operation_id=None, *, family=None, status=None, blocker=None, offset=0, limit=5) -> dict:
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 20 or (status is not None and (type(status) is not str or status not in IMPLEMENTATION)):
            raise RouterError('invalid_arguments', 'WebUI limit must be 1..20, offset nonnegative and status valid.', 2)
        manifest = self.manifest()
        operations = manifest['operations']
        selectors = (
            (operation_id, {op['id'] for op in operations}, 'unknown_webui_operation', 'Unknown WebUI operation ID.'),
            (family, {op['family'] for op in operations}, 'unknown_webui_family', 'Unknown WebUI family.'),
            (blocker, {b['code'] for op in operations for b in op['blockers']}, 'unknown_webui_blocker', 'Unknown WebUI blocker.'),
        )
        for value, allowed, code, message in selectors:
            if value is not None and (type(value) is not str or value not in allowed):
                raise RouterError(code, message)
        filtered = sorted((op for op in operations
                           if (operation_id is None or op['id'] == operation_id)
                           and (family is None or op['family'] == family)
                           and (status is None or op['implementation']['status'] == status)
                           and (blocker is None or any(b['code'] == blocker for b in op['blockers']))), key=lambda op: op['id'])
        rows = [{'id': op['id'], 'family': op['family'], 'title': op['title'], 'variant': op['variant'],
                 'applicability': op['applicability']['status'], 'source_status': op['source']['status'],
                 'implementation_status': op['implementation']['status'], 'live_outcome': op['live']['outcome'],
                 'branch_ids': [b['branch_id'] for b in op['bindings']],
                 'blockers': [b['code'] for b in op['blockers']], 'next_action': op['next']['task']}
                for op in filtered[offset:offset + limit]]
        applicability = Counter(op['applicability']['status'] for op in operations)
        counts = {'candidates': len(operations), 'confirmed_applicable': applicability['applicable'],
                  'verified_not_applicable': applicability['not_applicable'], 'unknown_applicability': applicability['unknown'],
                  'conditional_applicability': applicability['conditional'],
                  'unresolved_branches': sum(b['enumeration'] != 'enumerated' for b in manifest['branches']),
                  'source_supported': sum(op['source']['status'] == 'contract_verified' for op in operations),
                  'implemented_offline': sum(op['implementation']['status'] == 'implemented' for op in operations),
                  'live_verified': sum(op['live']['outcome'] == 'verified' for op in operations),
                  'blocked': sum(bool(op['blockers']) for op in operations)}
        return {'schema_version': 1, 'source': 'offline_webui_operations', 'observed_at': None,
                'freshness': 'not_collected', 'data': {'manifest_hash': self.hash,
                'inventory_revision': manifest['inventory_revision'], 'target': manifest['target'],
                'upstream_version': manifest['upstream']['version'], 'inventory_complete': False,
                'applicable_denominator': None, 'counts': counts, 'operations': rows,
                'pagination': {'offset': offset, 'limit': limit, 'total': len(filtered),
                               'next_offset': offset + len(rows) if offset + len(rows) < len(filtered) else None}},
                'capability_gaps': [GAP]}


def load_webui_operations(path=None) -> WebUIOperations:
    source = files('router_agent').joinpath('data/webui_operations_v1.json') if path is None else Path(path)
    try:
        return WebUIOperations(json.loads(source.read_text(encoding='utf-8'), object_pairs_hook=_json_object,
                                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError())))
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise _invalid() from exc
