"""Offline inventory rejects unsupported claims and never contacts a router."""
from copy import deepcopy
import json

import pytest

from router_agent.catalog import load_catalog
from router_agent.cli import main
from router_agent.errors import RouterError
from router_agent.webui_operations import HIDDEN_IDS, VARIANTS, WebUIOperations, load_webui_operations


@pytest.fixture
def metadata():
    catalog = load_catalog()
    def branch(branch_id, **extra):
        return {'id': branch_id, 'origin': 'catalog_page', 'catalog_page': None,
                'parent_branch_ids': [], 'label': 'Synthetic branch', 'navigation': 'unresolved',
                'enumeration': 'unresolved', 'evidence_refs': ['plan'],
                'variant_presence': dict.fromkeys(VARIANTS, 'unresolved'), **extra}
    branches = [branch(f'page.p{index}', catalog_page={'group': page['group'], 'page': page['page']})
                for index, page in enumerate(catalog.manifest()['pages'])]
    branches += [branch(branch_id, origin='hidden_register', parent_branch_ids=['page.p0']) for branch_id in sorted(HIDDEN_IDS)]
    def reference(ref_id, kind):
        return {'id': ref_id, 'kind': kind, 'path': 'docs/coverage/source-baseline.md',
                'revision': 'v1.21.3' if kind == 'upstream_source' else None,
                'line_start': 1, 'line_end': 2, 'date': '2026-10-22' if kind == 'dated_live' else None}
    def operation(index):
        return {'id': f'example.op{index}', 'family': 'example' if index % 2 else 'other',
                'title': 'Synthetic operation', 'variant': 'read',
                'bindings': [{'branch_id': 'page.p0', 'control': f'Synthetic {index}', 'conditions': [], 'alias_equivalence_ref': None}],
                'applicability': {'status': 'unknown', 'confidence': 'candidate', 'reason': 'Not enumerated', 'evidence_refs': ['plan']},
                'schema': {'status': 'unknown', 'input': None, 'output': None, 'evidence_refs': []},
                'source': {'status': 'candidate', 'native_audit_ids': [], 'api': None, 'limits': ['Unreviewed']},
                'implementation': {'status': 'unimplemented', 'interfaces': [], 'test_refs': [], 'limits': ['Pending']},
                'live': {'execution': 'not_attempted', 'outcome': 'unverified', 'evidence_refs': [], 'limits': ['No live evidence']},
                'policy': {'mutation': 'unknown', 'risk': 'unknown', 'authorization': ['Unknown'],
                           'privacy': ['Unknown'], 'side_effects': ['Unknown'], 'preservation': ['Unknown'],
                           'atomic_apply_group': None, 'recovery': {'status': 'unknown', 'detail': 'Unknown', 'evidence_refs': []}},
                'blockers': [{'code': 'inventory', 'detail': 'Enumeration pending'}] if index % 2 else [],
                'next': {'owner': 'Data author', 'task': 'Review source', 'evidence_required': 'Exact released contract'}}
    return {'schema_version': 1, 'inventory_revision': '2026-10-22',
            'target': {'model': 'RT-AX86U', 'firmware': 'synthetic'},
            'upstream': {'package': 'asusrouter', 'version': '1.21.3', 'release_ref': 'upstream'},
            'baseline': {'catalog_sha256': catalog.hash, 'matrix_ref': 'plan', 'source_baseline_ref': 'upstream'},
            'references': [reference('plan', 'planning'), reference('upstream', 'upstream_source'),
                           reference('official', 'official'), reference('code', 'local_code'),
                           reference('test', 'synthetic_test'), reference('live', 'dated_live')],
            'branches': branches, 'operations': [operation(i) for i in range(13)]}


def test_manifest_copy_hash_and_bootstrap(metadata):
    inventory = WebUIOperations(metadata)
    reverse = dict(reversed(list(metadata.items())))
    assert WebUIOperations(reverse).hash == inventory.hash
    inventory.manifest()['branches'].clear()
    metadata['branches'].clear()
    assert len(inventory.manifest()['branches']) == 89
    empty = inventory.manifest()
    empty['operations'] = []
    assert WebUIOperations(empty).page()['data']['pagination']['total'] == 0


@pytest.mark.parametrize('arguments', [
    ['--webui', '--limit', '0'], ['--webui', '--limit', '21'], ['--webui', '--offset', '-1'],
    ['--webui', '--native'], ['--webui', '--expansion'], ['--webui', '--group', 'WAN'],
    ['--family', 'example'], ['--status', 'partial'], ['--blocker', 'inventory'],
    ['--native', '--family', 'example'], ['--webui', '--status', 'complete'],
])
def test_cli_argument_rejections(arguments, capsys):
    assert main(['capabilities', *arguments]) == 2
    assert json.loads(capsys.readouterr().out)['error']['code'] == 'invalid_arguments'


def test_cli_pagination_filters_projection_and_no_runtime(metadata, monkeypatch, capsys):
    inventory = WebUIOperations(metadata)
    monkeypatch.setattr('router_agent.webui_operations.load_webui_operations', lambda: inventory)
    def forbidden(*args, **kwargs):
        pytest.fail('offline inventory touched runtime')
    for name in ('get_credentials', 'load_config', 'auth_status', '_collect', '_operation_engine'):
        # _operation_engine may be renamed independently; concrete current names only.
        if hasattr(__import__('router_agent.cli', fromlist=[name]), name):
            monkeypatch.setattr(f'router_agent.cli.{name}', forbidden)
    rows, offset = [], 0
    while offset is not None:
        assert main(['capabilities', '--webui', '--limit', '5', '--offset', str(offset)]) == 0
        value = json.loads(capsys.readouterr().out)
        assert value['source'] == 'offline_webui_operations'
        assert value['freshness'] == 'not_collected' and value['observed_at'] is None
        data = value['data']
        assert data['manifest_hash'] == inventory.hash
        assert data['inventory_complete'] is False and data['applicable_denominator'] is None
        assert data['counts']['candidates'] == 13 and data['counts']['unresolved_branches'] == 89
        assert len(data['operations']) <= 5
        rows.extend(data['operations'])
        offset = data['pagination']['next_offset']
    assert [r['id'] for r in rows] == sorted(op['id'] for op in metadata['operations'])
    assert set(rows[0]) == {'id', 'family', 'title', 'variant', 'applicability', 'source_status', 'implementation_status', 'live_outcome', 'branch_ids', 'blockers', 'next_action'}
    assert main(['capabilities', '--webui', rows[0]['id']]) == 0
    assert json.loads(capsys.readouterr().out)['data']['operations'] == [rows[0]]
    filtered = inventory.page(family='example', status='unimplemented', blocker='inventory')['data']
    assert filtered['pagination']['total'] == 6
    assert filtered['counts']['candidates'] == 13
    assert inventory.page(family='other', blocker='inventory')['data']['operations'] == []
    assert inventory.page(status='partial')['data']['operations'] == []
    beyond = inventory.page(offset=10000)['data']
    assert beyond['operations'] == [] and beyond['pagination']['next_offset'] is None
    assert inventory.page()['data']['pagination']['limit'] == 5


@pytest.mark.parametrize('selector,code', [
    ('operation_id', 'unknown_webui_operation'), ('family', 'unknown_webui_family'), ('blocker', 'unknown_webui_blocker')])
def test_unknown_selectors_are_sanitized(metadata, monkeypatch, capsys, selector, code):
    inventory = WebUIOperations(metadata)
    monkeypatch.setattr('router_agent.webui_operations.load_webui_operations', lambda: inventory)
    args = ['capabilities', '--webui']
    args += ['sensitive-selector'] if selector == 'operation_id' else [f'--{selector}', 'sensitive-selector']
    assert main(args) == 1
    text = capsys.readouterr().out
    assert json.loads(text)['error']['code'] == code
    assert 'sensitive-selector' not in text


@pytest.mark.parametrize('mutate', [
    lambda d: d.update(schema_version=True),
    lambda d: d.update(unexpected='secret'),
    lambda d: d.update(inventory_revision='2026-02-30'),
    lambda d: d['target'].update(extra='x'),
    lambda d: d['upstream'].update(version='dev'),
    lambda d: d['upstream'].update(release_ref='missing'),
    lambda d: d['baseline'].update(catalog_sha256='0' * 64),
    lambda d: d['references'].append(deepcopy(d['references'][0])),
    lambda d: d['references'][0].update(path='/private/file'),
    lambda d: d['references'][0].update(path='../private'),
    lambda d: d['references'][0].update(path='https://example.com'),
    lambda d: d['references'][0].update(line_start=True),
    lambda d: d['references'][0].update(line_end=None),
    lambda d: d['references'][1].update(revision=None),
    lambda d: d['references'][-1].update(date=None),
    lambda d: d['branches'].pop(),
    lambda d: d['branches'].pop(0),
    lambda d: d['branches'][0]['catalog_page'].update(page='Phantom'),
    lambda d: d['branches'][0].update(id='bad id'),
    lambda d: d['branches'][0].update(parent_branch_ids=['missing']),
    lambda d: d['branches'][0].update(parent_branch_ids=['page.p0']),
    lambda d: d['branches'][0].update(evidence_refs=[]),
    lambda d: d['branches'][0].update(navigation='present'),
    lambda d: d['branches'][0].update(enumeration='enumerated'),
    lambda d: d['branches'][0]['variant_presence'].update(export='absent_verified'),
    lambda d: d['branches'][1]['variant_presence'].update(write='present'),
    lambda d: d['operations'].append(deepcopy(d['operations'][0])),
    lambda d: d['operations'][0].update(variant='toggle'),
    lambda d: d['operations'][0].update(bindings=[]),
    lambda d: d['operations'][0]['bindings'][0].update(branch_id='missing'),
    lambda d: d['operations'][0]['bindings'].append(deepcopy(d['operations'][0]['bindings'][0])),
    lambda d: d['operations'][0]['applicability'].update(status='applicable'),
    lambda d: d['operations'][0]['applicability'].update(confidence='target_observed'),
    lambda d: d['operations'][0]['schema'].update(input={}),
    lambda d: d['operations'][0]['schema'].update(status='specified'),
    lambda d: d['operations'][0]['source'].update(native_audit_ids=['phantom']),
    lambda d: d['operations'][0]['source'].update(status='contract_verified'),
    lambda d: d['operations'][0]['source'].update(api={'symbol': 'generic_api'}),
    lambda d: d['operations'][0]['source'].update(status='unsupported', limits=[]),
    lambda d: d['operations'][0]['implementation'].update(status='implemented'),
    lambda d: d['operations'][0]['implementation'].update(interfaces=['get identity']),
    lambda d: d['operations'][0]['live'].update(outcome='verified'),
    lambda d: d['operations'][0]['live'].update(execution='attempted'),
    lambda d: d['operations'][0]['policy'].update(privacy=[]),
    lambda d: d['operations'][0]['policy']['recovery'].update(status='inverse'),
    lambda d: d['operations'][0]['policy']['recovery'].update(status='not_required'),
    lambda d: d['operations'][1]['blockers'].append(deepcopy(d['operations'][1]['blockers'][0])),
    lambda d: d['operations'][0]['next'].update(task=''),
])
def test_invalid_metadata_fails_closed(metadata, mutate):
    mutate(metadata)
    with pytest.raises(RouterError) as exc:
        WebUIOperations(metadata)
    assert exc.value.code == 'invalid_webui_manifest'


def test_supported_claims_need_separate_evidence(metadata):
    op = metadata['operations'][0]
    op['applicability'].update(status='applicable', confidence='source_supported', evidence_refs=['official'])
    op['source'].update(status='contract_verified', api={'symbol': 'ExactSource.symbol', 'signature': '(finite)', 'upstream_version': '1.21.3', 'evidence_refs': ['upstream']})
    op['implementation'].update(status='implemented', interfaces=['get identity'], test_refs=['test', 'code'])
    op['live'].update(execution='attempted', outcome='partial', evidence_refs=['live'])
    op['policy'].update(mutation='none')
    op['policy']['recovery'].update(status='not_required')
    data = WebUIOperations(metadata).page()['data']
    assert data['counts']['source_supported'] == data['counts']['implemented_offline'] == 1
    assert data['counts']['live_verified'] == 0
    assert data['applicable_denominator'] is None
    for section, key, value in [('source', 'api', None), ('implementation', 'test_refs', ['plan']), ('live', 'evidence_refs', ['test'])]:
        bad = deepcopy(metadata)
        bad['operations'][0][section][key] = value
        with pytest.raises(RouterError):
            WebUIOperations(bad)


@pytest.mark.parametrize('args', [{'offset': True}, {'limit': False}, {'limit': 21}, {'offset': -1}, {'status': []}])
def test_direct_query_bounds(metadata, args):
    with pytest.raises(RouterError) as exc:
        WebUIOperations(metadata).page(**args)
    assert exc.value.code == 'invalid_arguments'


def test_internal_evidence_is_not_public(metadata):
    metadata['references'][0]['revision'] = 'sensitive-sentinel'
    metadata['operations'][0]['source']['limits'] = ['sensitive-sentinel']
    assert 'sensitive-sentinel' not in json.dumps(WebUIOperations(metadata).page())


@pytest.mark.parametrize('text', ['{"secret":"sensitive-sentinel"', '{"schema_version":1,"schema_version":1}', '{"value":NaN}'])
def test_bad_files_never_print_contents(tmp_path, monkeypatch, capsys, text):
    path = tmp_path / 'manifest.json'
    path.write_text(text)
    with pytest.raises(RouterError) as exc:
        load_webui_operations(path)
    assert exc.value.code == 'invalid_webui_manifest'
    monkeypatch.setattr('router_agent.webui_operations.load_webui_operations', lambda: load_webui_operations(path))
    assert main(['capabilities', '--webui']) == 1
    rendered = capsys.readouterr().out
    assert json.loads(rendered)['error']['code'] == 'invalid_webui_manifest'
    assert 'sensitive-sentinel' not in rendered and str(path) not in rendered


def test_packaged_crosswalk_and_frozen_artifacts():
    manifest = load_webui_operations().manifest()
    catalog = load_catalog()
    expected = {(p['group'], p['page']) for p in catalog.manifest()['pages']}
    actual = {(b['catalog_page']['group'], b['catalog_page']['page']) for b in manifest['branches'] if b['origin'] == 'catalog_page'}
    assert actual == expected and len(actual) == 69
    assert manifest['baseline']['catalog_sha256'] == catalog.hash
    assert HIDDEN_IDS <= {b['id'] for b in manifest['branches'] if b['origin'] == 'hidden_register'}
