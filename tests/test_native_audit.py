"""Native audit metadata is offline evidence, never a request to a router."""
import json
import pytest
from router_agent.cli import main


def test_native_selector_bounds_and_mutual_exclusion(capsys):
    for arguments in (['--native','--limit','0'],['--native','--limit','21'],['--native','--offset','-1'],['--native','--group','WAN']):
        assert main(['capabilities',*arguments]) == 2
        value=json.loads(capsys.readouterr().out)
        assert value['error']['code'] == 'invalid_arguments'

from collections import Counter
from copy import deepcopy
from router_agent.native_audit import NativeAudit, load_native_audit
from router_agent.errors import RouterError


def test_packaged_inventory_matches_pinned_enum_and_each_symbol_has_one_entry():
    from asusrouter.modules.data import AsusData
    from asusrouter.modules.state import AsusState
    audit=load_native_audit().manifest()
    assert set(audit['inventory']['asus_data']) == set(AsusData.__members__)
    assert set(audit['inventory']['asus_state']) == set(AsusState.__members__)
    expected={**{f'AsusData.{name}':'read' for name in AsusData.__members__},**{f'AsusState.{name}':'state' for name in AsusState.__members__},**{name:'dynamic_read' for name in audit['inventory']['dynamic_reads']}}
    counts=Counter(entry['upstream_symbol'] for entry in audit['capabilities'])
    assert counts == Counter({symbol:1 for symbol in expected})
    for entry in audit['capabilities']:
        assert entry['kind'] == expected[entry['upstream_symbol']]


def test_actual_cli_native_pages_roundtrip_every_row_without_credentials(monkeypatch,capsys):
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:pytest.fail('offline audit must not request credentials'))
    async def forbidden(*args,**kwargs):pytest.fail('offline audit must not collect')
    monkeypatch.setattr('router_agent.cli._collect',forbidden)
    ledger=load_native_audit()
    recovered=[];offset=0
    while offset is not None:
        assert main(['capabilities','--native','--limit','7','--offset',str(offset)]) == 0
        result=json.loads(capsys.readouterr().out)
        assert result['source'] == 'offline_native_audit'
        assert result['observed_at'] is None and result['freshness'] == 'not_collected'
        data=result['data']
        assert data['audit_hash'] == ledger.hash
        assert data['upstream_version'] == '1.21.3'
        assert data['target']['date'] == '2026-10-12'
        assert len(data['capabilities'])<=7
        recovered.extend(data['capabilities'])
        offset=data['pagination']['next_offset']
    assert [entry['id'] for entry in recovered] == sorted(entry['id'] for entry in ledger.manifest()['capabilities'])
    assert len(recovered) == data['counts']['entries'] == data['pagination']['total']
    assert all('source_refs' not in row and 'source_mapping' not in row for row in recovered)
    first_id=recovered[0]['id']
    assert main(['capabilities','--native',first_id]) == 0
    exact=json.loads(capsys.readouterr().out)['data']
    assert exact['capabilities'] == [recovered[0]]
    assert exact['pagination']['total']==1 and exact['pagination']['next_offset'] is None
    assert main(['capabilities','--native','--offset','1000']) == 0
    beyond=json.loads(capsys.readouterr().out)['data']
    assert beyond['capabilities'] == [] and beyond['pagination']['next_offset'] is None


def test_unknown_id_is_sanitized(capsys):
    assert main(['capabilities','--native','unknown-sensitive-value']) == 1
    result=json.loads(capsys.readouterr().out)
    assert result['error']['code']=='unknown_capability'
    assert 'unknown-sensitive-value' not in str(result)


@pytest.mark.parametrize('mutation',[
    lambda x:x.update(schema_version=True),
    lambda x:x['capabilities'].append(deepcopy(x['capabilities'][0])),
    lambda x:x['capabilities'][0].update(kind='working_feature'),
    lambda x:x['capabilities'][0].update(source_support='router_healthy'),
    lambda x:x['capabilities'][0].update(cli_status='complete'),
    lambda x:x['capabilities'][0].update(live_status='healthy'),
    lambda x:x['capabilities'][0].update(next_action={'unexpected':'object'}),
    lambda x:x['capabilities'][0]['blocks'][0].update(code=[]),
    lambda x:x['capabilities'][0]['source_refs'][0].update(line_start=0),
    lambda x:x['upstream'].update(version='different'),
    lambda x:x['evidence_boundary'].update(audit_network_calls=True),
    lambda x:x['evidence_boundary']['live_evidence_target'].update(date='invalid'),
    lambda x:x['inventory']['asus_data'].append(x['inventory']['asus_data'][0]),
])
def test_malformed_and_duplicate_metadata_fail_closed(mutation):
    metadata=load_native_audit().manifest()
    mutation(metadata)
    with pytest.raises(RouterError) as error:NativeAudit(metadata)
    assert error.value.code == 'invalid_native_audit'


def test_malformed_file_and_failed_cli_never_print_metadata(tmp_path,monkeypatch,capsys):
    path=tmp_path/'audit.json';path.write_text('{"secret":"fake-sensitive-value"')
    with pytest.raises(RouterError):load_native_audit(path)
    monkeypatch.setattr('router_agent.native_audit.load_native_audit',lambda:load_native_audit(path))
    assert main(['capabilities','--native']) == 1
    rendered=capsys.readouterr().out
    assert json.loads(rendered)['error']['code']=='invalid_native_audit'
    assert 'fake-sensitive-value' not in rendered
