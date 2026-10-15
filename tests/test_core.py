import json
from router_agent.cli import main
from router_agent.output import envelope, safe_data

def test_allowlist_and_unknown_default():
    value=envelope({'model':'fixture','password':'fake-secret','nested_unknown':{'model':'fixture'}})
    assert value['freshness'] == 'unknown'
    assert value['data'] == {'model':'fixture'}

def test_cli_errors_are_structured_and_sanitized(capsys):
    assert main(['get','invalid-secret-group']) == 2
    value=json.loads(capsys.readouterr().out)
    assert value['error']['code'] == 'invalid_arguments'
    assert 'invalid-secret-group' not in str(value)

def test_unexpected_exception_never_prints_traceback(monkeypatch,capsys):
    def fail(_):raise RuntimeError('fake-secret')
    monkeypatch.setattr('router_agent.cli.execute',fail)
    assert main(['status']) == 1
    assert 'fake-secret' not in capsys.readouterr().out

def test_capability_summary_and_detail_boundaries(capsys):
    assert main(['capabilities']) == 0
    summary=json.loads(capsys.readouterr().out)
    assert isinstance(summary['data']['pages'], int)
    assert summary['freshness'] == 'not_collected'
    group=summary['data']['groups'][0]
    assert main(['capabilities','--group',group,'--limit','1']) == 0
    detail=json.loads(capsys.readouterr().out)
    assert len(detail['data']['pages']) == 1
    assert main(['capabilities','--limit','21']) == 2

def test_clients_filters_precede_paging_and_preserve_counts(monkeypatch,capsys):
    async def collect(groups):
        assert groups == ['clients']
        return {'data':{'clients':[
            {'alias':'client-0000000000000001','online':False},
            {'alias':'client-0000000000000002','online':True},
            {'alias':'client-0000000000000003','online':True},
        ]},'freshness':'unknown','observed_at':None,'source':'native'}
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['clients','--online','--limit','1','--offset','1']) == 0
    result=json.loads(capsys.readouterr().out)
    assert result['data']['clients'] == [{'alias':'client-0000000000000003','online':True}]
    assert result['pagination'] == {'offset':1,'limit':1,'total':2,'total_known':3,'next_offset':None}
    assert result['freshness'] == 'unknown'
    assert main(['clients','--alias','client-0000000000000002']) == 0
    result=json.loads(capsys.readouterr().out)
    assert len(result['data']['clients']) == 1
    assert result['pagination']['total'] == 1
    assert result['pagination']['total_known'] == 3
    assert main(['clients','--online','--alias','client-0000000000000001']) == 0
    result=json.loads(capsys.readouterr().out)
    assert result['data']['clients'] == []
    assert result['pagination']['total'] == 0
    assert main(['clients','--alias','client-ffffffffffffffff']) == 0
    result=json.loads(capsys.readouterr().out)
    assert result['data']['clients'] == []
    assert result['pagination']['total'] == 0
    assert main(['clients']) == 0
    assert len(json.loads(capsys.readouterr().out)['data']['clients']) == 3


def test_invalid_client_alias_rejected_before_collection(monkeypatch,capsys):
    async def collect(groups): raise AssertionError('must not collect')
    monkeypatch.setattr('router_agent.cli._collect',collect)
    for alias in ['mac-address','client-123','client-FFFFFFFFFFFFFFFF','prefix-client-0000000000000001','client-0000000000000001suffix']:
        assert main(['clients','--alias',alias]) == 2
        result=json.loads(capsys.readouterr().out)
        assert result['error']['code'] == 'invalid_arguments'

def test_capabilities_discover_native_reads_without_claiming_device_support(capsys):
    from router_agent.transport import GROUPS
    assert main(['capabilities']) == 0
    result=json.loads(capsys.readouterr().out)
    assert result['source'] == 'offline_catalog'
    assert result['freshness'] == 'not_collected'
    from router_agent.cli import PROTECTED_GROUPS
    assert result['data']['native_reads'] == [*GROUPS, *PROTECTED_GROUPS]
    assert result['data']['native_write_operations'][0]['name'] == 'led.set'
    assert result['data']['native_write_operations'][0]['status'] == 'implemented_live_unverified'
    assert 'slot status only' in result['data']['native_read_limits']['vpn']
    assert 'bounded read' in result['data']['native_read_limits']['compatibility']

def test_cli_diff_paging_preserves_next_offset_and_presence(tmp_path,monkeypatch,capsys):
    from router_agent.snapshots import SnapshotStore
    from test_snapshots import IDENTITY
    store=SnapshotStore(tmp_path/'state')
    old=store.save({'clients':[]},IDENTITY)['snapshot_id']
    new=store.save({'clients':[None for _ in range(25)]},IDENTITY)['snapshot_id']
    monkeypatch.setattr('router_agent.cli.SnapshotStore',lambda:store)
    assert main(['diff','--since',old,'--to',new,'--offset','20','--limit','5']) == 0
    value=json.loads(capsys.readouterr().out)['data']
    assert value['total_changes'] == 25
    assert value['pagination'] == {'offset':20,'limit':5,'next_offset':None}
    assert len(value['changes']) == 5
    assert value['changes'][0]['path'] == '/clients/20'
    assert value['changes'][0]['before_present'] is False
    for arguments in (['--offset','-1'],['--limit','0'],['--limit','21']):
        assert main(['diff','--since',old,'--to',new,*arguments]) == 2
        assert json.loads(capsys.readouterr().out)['error']['code'] == 'invalid_arguments'

def test_diff_table_is_lossless_for_every_page_and_errors_stay_json(tmp_path,monkeypatch,capsys):
    from router_agent.compact import unpack
    from router_agent.snapshots import SnapshotStore
    from test_snapshots import IDENTITY
    store=SnapshotStore(tmp_path/'state')
    old=store.save({'clients':[{'alias':f'client-{i:016x}','online':False} for i in range(25)]},IDENTITY)['snapshot_id']
    new=store.save({'clients':[{'alias':f'client-{i:016x}','online':True} for i in range(25)],'wan':None},IDENTITY)['snapshot_id']
    monkeypatch.setattr('router_agent.cli.SnapshotStore',lambda:store)
    offset=0;recovered=[]
    while offset is not None:
        base=['diff','--since',old,'--to',new,'--offset',str(offset),'--limit','8']
        assert main(base) == 0
        plain=json.loads(capsys.readouterr().out)
        assert main([*base,'--format','table']) == 0
        compact=json.loads(capsys.readouterr().out)
        assert unpack(compact) == plain
        recovered.extend(plain['data']['changes'])
        offset=plain['data']['pagination']['next_offset']
    assert len(recovered) == 26
    assert recovered[-1] == {'path':'/wan','before':None,'after':None,'before_present':False,'after_present':True}
    assert main(['diff','--since',old,'--to',new,'--offset','-1','--format','table']) == 2
    error=json.loads(capsys.readouterr().out)
    assert error == {'error':{'code':'invalid_arguments','message':'Diff limit must be 1..20 and offset nonnegative.'}}
    assert '$table' not in str(error)


def test_diff_help_exposes_decoder_and_format_option(capsys):
    import pytest
    from router_agent.compact import TABLE_HELP
    with pytest.raises(SystemExit) as exit:
        main(['diff','--help'])
    assert exit.value.code == 0
    help_text=capsys.readouterr().out
    assert '--format {json,table}' in help_text
    assert ' '.join(TABLE_HELP.split()) in ' '.join(help_text.split())

def test_get_ports_routes_named_collector_group_and_preserves_output(monkeypatch,capsys):
    calls=[]
    payload={'schema_version':1,'source':'native','observed_at':None,'freshness':'unknown','data':{'ports':{'scope':'ethernet_link_status_only','ports':[{'port':1,'link':True,'speed_mbps':1000}]}},'capability_gaps':[]}
    async def collect(groups):
        calls.append(groups)
        return payload
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get','ports']) == 0
    assert calls == [['ports']]
    assert json.loads(capsys.readouterr().out) == payload

def test_get_aimesh_routes_named_collector_group_without_expanding_status(monkeypatch,capsys):
    calls=[]
    payload={'schema_version':1,'source':'native','observed_at':None,'freshness':'unknown','data':{'aimesh':{'nodes':[{'node_alias':'node-0000000000000001','model':'RT-AX86U','firmware':'fixture','online':True,'level':0,'type':'router','parent_connection':None,'signal_dbm':None}], 'count':1,'gaps':['node_state_is_not_backhaul_or_client_connectivity','client_inventory_and_configuration_not_collected']}},'sources':{'aimesh':{'observed_at':None,'freshness':'unknown'}},'capability_gaps':[]}
    async def collect(groups):
        calls.append(groups)
        return payload
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get','aimesh']) == 0
    assert calls == [['aimesh']]
    assert json.loads(capsys.readouterr().out) == payload
    assert main(['status']) == 0
    assert calls[-1] == ['identity','wan','cpu','ram']
