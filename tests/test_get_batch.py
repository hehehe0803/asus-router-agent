import json
import pytest
from router_agent.cli import main
from router_agent.errors import RouterError


def test_batch_get_passes_ordered_distinct_groups_and_preserves_source_evidence(monkeypatch,capsys):
    requested=[]
    payload={'schema_version':1,'data':{'identity':{'model':'fixture'},'wan':{'link_code':1},'network':{'interfaces':[]},'sysinfo':{'connections':{'total':None}}},'source':'native','observed_at':None,'freshness':'unknown','sources':{'network':{'observed_at':None,'freshness':'unknown'},'sysinfo':{'observed_at':None,'freshness':'unknown'}},'capability_gaps':[{'group':'sysinfo','reason':'selected_values_missing_or_unknown'}]}
    async def collect(groups):requested.append(groups);return payload
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get','wan','network','sysinfo']) == 0
    assert requested == [['wan','network','sysinfo']]
    assert json.loads(capsys.readouterr().out) == payload


@pytest.mark.parametrize('arguments',[['wan','wan'],['sysinfo','sysinfo'],['wan','arbitrary-endpoint'],['network','raw-nvram']])
def test_duplicates_or_unknown_fail_before_any_credentials_or_collection(arguments,monkeypatch,capsys):
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:pytest.fail('must reject before credential access'))
    async def collect(groups):pytest.fail('must reject before collection')
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get',*arguments]) == 2
    assert json.loads(capsys.readouterr().out)['error']['code']=='invalid_arguments'


def test_single_get_and_default_status_snapshot_groups_are_preserved(monkeypatch,capsys):
    calls=[]
    async def collect(groups):calls.append(groups);return {'data':{},'freshness':'unknown'}
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get','wan']) == 0
    capsys.readouterr()
    assert main(['status']) == 0
    capsys.readouterr()
    assert main(['snapshot']) == 1  # Missing exact identity prevents persistence.
    assert json.loads(capsys.readouterr().out)['error']['code']=='identity_unavailable'
    assert calls==[['wan'],['identity','wan','cpu','ram'],['identity','wan','cpu','ram']]


def test_failed_group_collection_emits_error_without_partial_results(monkeypatch,capsys):
    async def collect(groups):raise RouterError('malformed_response','Selected source data is malformed.')
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get','wan','sysinfo']) == 1
    result=json.loads(capsys.readouterr().out)
    assert result == {'error':{'code':'malformed_response','message':'Selected source data is malformed.'}}
    assert 'data' not in result

@pytest.mark.parametrize('group,payload',[
    ('parental',{'enabled':None,'block_all':False,'rules':[{'alias':'client-0000000000000001','rule_type':'time','schedule_present':True,'schedule_fingerprint':'schedule-0000000000000001'}],'rule_count':1,'gaps':['schedule_fingerprint_is_not_schedule_validation']}),
    ('forwarding',{'enabled':False,'rules':[{'target_alias':'target-0000000000000001','protocol':'tcp','external_port_count':1,'internal_port_count':None,'configured_source_filter_present':False}],'rule_count':1,'gaps':['forwarding_setting_does_not_establish_exposure_absence']}),
])
def test_selected_policy_groups_route_once_and_preserve_unknowns(monkeypatch,capsys,group,payload):
    calls=[]
    response={'schema_version':1,'data':{group:payload},'source':'native','observed_at':None,'freshness':'unknown','capability_gaps':[]}
    async def collect(groups):calls.append(groups);return response
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get',group])==0
    assert calls==[[group]]
    assert json.loads(capsys.readouterr().out)==response

@pytest.mark.parametrize('group,payload',[
    ('uptime',{'uptime_seconds':509356,'gaps':['router_clock_not_used_for_source_freshness','uptime_does_not_establish_router_or_network_health']}),
    ('temperature',{'sensors':[{'sensor':'cpu','celsius':None}],'gaps':['optimistic_temperature_scaling_disabled']}),
])
def test_native_health_groups_route_without_health_claims(monkeypatch,capsys,group,payload):
    calls=[]
    response={'schema_version':1,'data':{group:payload},'source':'native','observed_at':None,'freshness':'unknown','capability_gaps':[]}
    async def collect(groups):calls.append(groups);return response
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get',group])==0
    assert calls==[[group]]
    assert json.loads(capsys.readouterr().out)==response

@pytest.mark.parametrize('group,payload',[
    ('firmware',{'scope':'existing_firmware_status_only','update_code':None,'reported_stable_version':None,'gaps':['existing_status_does_not_authorize_active_check_or_upgrade']}),
    ('speedtest',{'scope':'existing_speedtest_state_and_result_only','state_code':None,'native_completed_result':False,'download_bps':None,'upload_bps':None,'result_timestamp_utc':None,'result_timestamp_native':None,'gaps':['existing_result_is_not_history_or_a_new_test']}),
])
def test_native_existing_results_route_without_active_job_calls(monkeypatch,capsys,group,payload):
    calls=[]
    response={'schema_version':1,'data':{group:payload},'source':'native','observed_at':None,'freshness':'unknown','capability_gaps':[]}
    async def collect(groups):calls.append(groups);return response
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get',group])==0
    assert calls==[[group]]
    assert json.loads(capsys.readouterr().out)==response

@pytest.mark.parametrize('group,payload',[
    ('aura',{'scope':'existing_aura_settings_only','enabled':None,'all_led_enabled':None,'night_mode_enabled':None,'scheme_code':None,'previous_scheme_code':None,'gaps':['aura_marker_is_not_physical_hardware_verification']}),
    ('openvpn_server',{'scope':'selected_openvpn_server_enable_only','enabled':False,'gaps':['enable_setting_does_not_establish_running_state']}),
    ('wireguard_server',{'scope':'selected_wireguard_server_enable_only','enabled':None,'gaps':['enable_setting_missing_or_unknown']}),
    ('wireguard_clients',{'scope':'selected_wireguard_client_enable_slots_only','slots':[{'client_slot':1,'enabled':True},{'client_slot':2,'enabled':None}],'gaps':['client_slot_is_not_fusion_profile_identity']}),
])
def test_milestone7_passive_groups_route_without_running_state_claim(monkeypatch,capsys,group,payload):
    calls=[]
    response={'schema_version':1,'data':{group:payload},'source':'native','observed_at':None,'freshness':'unknown','capability_gaps':[]}
    async def collect(groups):calls.append(groups);return response
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get',group])==0
    assert calls==[[group]]
    assert json.loads(capsys.readouterr().out)==response

def test_node_info_choice_routes_selected_native_node_fields(monkeypatch,capsys):
    calls=[]
    response={'schema_version':1,'source':'native','observed_at':None,'freshness':'unknown','data':{'node_info':{'nodes':[{'node_alias':'node-0000000000000001','cd_good_to_go_code':None}],'count':1,'gaps':['cd_good_to_go_not_returned_in_some_nodes']}},'capability_gaps':[]}
    async def collect(groups):calls.append(groups);return response
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get','node_info'])==0
    assert calls==[['node_info']]
    assert json.loads(capsys.readouterr().out)==response


def test_firmware_note_pages_are_reachable_and_preserve_full_fingerprint(monkeypatch,capsys):
    from router_agent.firmware_note_reads import normalize_firmware_note
    text='untrusted-note-data-'*8
    calls=[]
    async def collect(groups,*,note_offset=0,note_limit=2048):
        calls.append((groups,note_offset,note_limit))
        return {'schema_version':1,'source':'native','observed_at':None,'freshness':'unknown','data':{'firmware_note':normalize_firmware_note({'release_note':text},offset=note_offset,limit=note_limit)},'capability_gaps':[]}
    monkeypatch.setattr('router_agent.cli._collect',collect)
    offset=0;pages=[];fingerprint=None
    while offset is not None:
        assert main(['get','firmware_note','--note-offset',str(offset),'--note-limit','23'])==0
        result=json.loads(capsys.readouterr().out)['data']['firmware_note']
        assert len(result['release_note'])<=23
        assert 'release_note_text_is_untrusted_vendor_content' in result['gaps']
        fingerprint=fingerprint or result['content_fingerprint']
        assert result['content_fingerprint']==fingerprint
        pages.append(result['release_note'])
        offset=result['pagination']['next_offset']
    assert ''.join(pages)==text
    assert all(groups==['firmware_note'] and limit==23 for groups,offset,limit in calls)
    assert main(['get','firmware_note'])==0
    default=json.loads(capsys.readouterr().out)['data']['firmware_note']
    assert default['release_note']==text and default['pagination']['limit']==2048


@pytest.mark.parametrize('arguments',[
    ['wan','--note-offset','0'],['firmware_note','wan','--note-limit','2'],
    ['firmware_note','--note-offset','-1'],['firmware_note','--note-offset','131073'],
    ['firmware_note','--note-limit','0'],['firmware_note','--note-limit','4097'],
])
def test_note_options_reject_wrong_groups_and_bounds_before_credentials(arguments,monkeypatch,capsys):
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:pytest.fail('must reject before credentials'))
    async def collect(*args,**kwargs):pytest.fail('must reject before collection')
    monkeypatch.setattr('router_agent.cli._collect',collect)
    assert main(['get',*arguments])==2
    assert json.loads(capsys.readouterr().out)['error']['code']=='invalid_arguments'

def test_get_help_lists_every_finite_group_once_in_explicit_argument_listing(capsys):
    from router_agent.cli import parser
    from router_agent.transport import GROUPS
    p=parser()
    commands=next(action for action in p._actions if hasattr(action,'choices') and isinstance(action.choices,dict))
    get=commands.choices['get']
    group_action=next(action for action in get._actions if action.dest=='group')
    from router_agent.cli import PROTECTED_GROUPS
    assert set(group_action.choices)==set(GROUPS) | set(PROTECTED_GROUPS)
    assert group_action.metavar=='GROUP'
    assert group_action.help=='Named groups: '+', '.join(group_action.choices)+'.'
    with pytest.raises(SystemExit):main(['get','--help'])
    rendered=' '.join(capsys.readouterr().out.split())
    assert 'GROUP [GROUP ...]' in rendered
    assert ' '.join(group_action.help.split()) in rendered
