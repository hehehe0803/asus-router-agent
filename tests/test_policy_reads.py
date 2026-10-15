import pytest
from router_agent.errors import RouterError
from router_agent.policy_reads import PARENTAL_KEYS,FORWARDING_KEYS,PARENTAL_HOOK,FORWARDING_HOOK,normalize_parental,normalize_forwarding

KEY=b'k'*32
MACS=['AA:BB:CC:DD:EE:01','AA:BB:CC:DD:EE:02']


def pc(**changes):
    return {'MULTIFILTER_ALL':'1','MULTIFILTER_BLOCK_ALL':'0','MULTIFILTER_MAC':'&#62'.join(MACS),'MULTIFILTER_MACFILTER_DAYTIME_V2':'W03E21000700<W04122000800&#62','MULTIFILTER_ENABLE':'1&#620',**changes}


def pf(**changes):
    return {'vts_enable_x':'0','vts_rulelist':'private-name&#6280,443,1000:1002&#62192.0.2.10&#628080&#62TCP&#62198.51.100.1',**changes}


def test_selected_hooks_are_exact_native_mapping_subsets_without_names():
    from asusrouter.modules.parental_control import HOOK_PC,KEY_PC_NAME
    from asusrouter.modules.data_finder import ASUSDATA_NVRAM
    assert set(PARENTAL_KEYS)<=set(HOOK_PC)
    assert KEY_PC_NAME not in PARENTAL_KEYS and KEY_PC_NAME not in PARENTAL_HOOK
    assert set(FORWARDING_KEYS)==set(ASUSDATA_NVRAM['port_forwarding'])
    assert PARENTAL_HOOK==''.join(f'nvram_get({key});' for key in PARENTAL_KEYS)
    assert FORWARDING_HOOK==''.join(f'nvram_get({key});' for key in FORWARDING_KEYS)
    assert 'rc_service' not in PARENTAL_HOOK+FORWARDING_HOOK


def test_parental_native_rules_aliased_schedule_fingerprints_no_names_or_schedule():
    raw=pc(MULTIFILTER_DEVICENAME='private-name&#62private-other',password='secret-password')
    result=normalize_parental(raw,KEY)
    assert result['enabled'] is True and result['block_all'] is False
    assert result['rule_count']==2
    assert {rule['rule_type'] for rule in result['rules']}=={'time','disabled'}
    assert {rule['schedule_present'] for rule in result['rules']}=={True,False}
    assert all(rule['alias'].startswith('client-') for rule in result['rules'])
    assert result==normalize_parental(raw,KEY)
    assert result['rules']!=normalize_parental(raw,b'z'*32)['rules']
    changed=normalize_parental(pc(MULTIFILTER_MACFILTER_DAYTIME_V2='opaque-unknown-private-schedule&#62'),KEY)
    by_alias={rule['alias']:rule for rule in result['rules']}
    assert any(rule['schedule_fingerprint']!=by_alias[rule['alias']]['schedule_fingerprint'] for rule in changed['rules'])
    for private in (*MACS,'private-name','secret-password','W03E21000700','opaque-unknown-private-schedule'):
        assert private not in str(result)+str(changed)
    assert 'schedule_fingerprint_is_not_schedule_validation' in result['gaps']


def test_policy_missing_vs_explicit_empty_and_unknowns_are_preserved():
    missing=normalize_parental({'MULTIFILTER_ALL':'','MULTIFILTER_BLOCK_ALL':'-999'},KEY)
    empty=normalize_parental(pc(MULTIFILTER_MAC='',MULTIFILTER_MACFILTER_DAYTIME_V2='',MULTIFILTER_ENABLE=''),KEY)
    assert missing['rules'] is None and missing['rule_count'] is None
    assert missing['enabled'] is None and missing['block_all'] is None
    assert empty['rules']==[] and empty['rule_count']==0
    unknown=normalize_parental(pc(MULTIFILTER_ENABLE='-999&#620'),KEY)
    assert any(rule['rule_type']=='unknown' for rule in unknown['rules'])
    for fn,key in ((normalize_parental,'MULTIFILTER_ALL'),(normalize_forwarding,'vts_enable_x')):
        result=fn({key:None},KEY)
        assert result['enabled'] is None and result['rules'] is None
    assert normalize_forwarding(pf(vts_rulelist=''),KEY)['rules']==[]


def test_forwarding_summary_no_exposure_or_client_identity_claim():
    result=normalize_forwarding(pf(password='secret-password'),KEY)
    assert result['enabled'] is False and result['rule_count']==1
    row=result['rules'][0]
    assert row['target_alias'].startswith('target-') and not row['target_alias'].startswith('client-')
    assert row['protocol']=='tcp' and row['external_port_count']==5 and row['internal_port_count']==1
    assert row['configured_source_filter_present'] is True
    assert 'forwarding_setting_does_not_establish_exposure_absence' in result['gaps']
    for private in ('private-name','192.0.2.10','198.51.100.1','secret-password'):
        assert private not in str(result)
    assert result==normalize_forwarding(pf(),KEY)
    assert row['target_alias']!=normalize_forwarding(pf(),b'z'*32)['rules'][0]['target_alias']


def test_overlapping_port_ranges_count_distinct_ports_and_unknown_protocol_not_guessed():
    raw=pf(vts_rulelist='name&#6280:82,81,82-84&#62192.0.2.10&#62&#62UDP&#62')
    row=normalize_forwarding(raw,KEY)['rules'][0]
    assert row['external_port_count']==5 and row['internal_port_count'] is None
    for protocol in ('OTHER','private-unknown-protocol'):
        result=normalize_forwarding(pf(vts_rulelist=f'name&#62255&#62192.0.2.10&#62&#62{protocol}&#62'),KEY)
        assert result['rules'][0]['external_port_count'] is None
        assert 'port_or_protocol_semantics_unknown' in result['gaps']


@pytest.mark.parametrize('raw',[{},pc(MULTIFILTER_ENABLE='1'),pc(MULTIFILTER_MAC='bad-mac&#62'+MACS[1]),pc(MULTIFILTER_MAC='&#62'.join([MACS[0],MACS[0]])),pc(MULTIFILTER_ENABLE='3&#620'),pc(MULTIFILTER_MACFILTER_DAYTIME_V2='x'*513+'&#62'),{'MULTIFILTER_ALL':True},pc(MULTIFILTER_ENABLE=None)])
def test_parental_malformed_alignment_unknown_type_and_fields_fail_closed(raw):
    with pytest.raises(RouterError) as error:normalize_parental(raw,KEY)
    assert error.value.code=='malformed_response'


@pytest.mark.parametrize('raw',[{},pf(vts_rulelist='truncated-secret'),pf(vts_rulelist='name&#6280&#62bad-private-address&#6280&#62TCP&#62'),pf(vts_rulelist='name&#6280&#62192.0.2.10&#6280&#62TCP&#62&#62extra'),pf(vts_rulelist=None),pf(vts_enable_x='2'),pf(vts_rulelist='x'*32769)])
def test_forwarding_malformed_private_fields_are_safe_errors(raw):
    with pytest.raises(RouterError) as error:normalize_forwarding(raw,KEY)
    assert error.value.code=='malformed_response'
    assert 'secret' not in str(error.value) and 'private-address' not in str(error.value)


def test_list_bounds_and_invalid_keys():
    large=pc(MULTIFILTER_MAC='&#62'.join(f'AA:BB:CC:DD:EE:{i:02X}' for i in range(65)),MULTIFILTER_ENABLE='&#62'.join('0' for _ in range(65)),MULTIFILTER_MACFILTER_DAYTIME_V2='&#62'.join('' for _ in range(65)))
    with pytest.raises(RouterError):normalize_parental(large,KEY)
    with pytest.raises(RouterError):normalize_forwarding(pf(vts_rulelist='&#60'.join('name&#6280&#62192.0.2.10&#6280&#62TCP&#62' for _ in range(65))),KEY)
    for fn in (normalize_parental,normalize_forwarding):
        with pytest.raises(RouterError) as error:fn({},b'short')
        assert error.value.code=='identity_key_required'

@pytest.mark.parametrize('kind,expected',[('0','disabled'),('2','block'),('','unknown')])
def test_single_native_rule_empty_schedule_and_unknown_empty_type(kind,expected):
    raw={'MULTIFILTER_ALL':'1','MULTIFILTER_BLOCK_ALL':'0','MULTIFILTER_MAC':MACS[0],'MULTIFILTER_MACFILTER_DAYTIME_V2':'','MULTIFILTER_ENABLE':kind}
    result=normalize_parental(raw,KEY)
    assert result['rule_count']==1
    assert result['rules'][0]['rule_type']==expected
    assert result['rules'][0]['schedule_present'] is False
    assert result['rules'][0]['schedule_fingerprint'] is None

def test_native_no_rule_state_ignores_bounded_unused_stored_schedule():
    raw={'MULTIFILTER_ALL':'0','MULTIFILTER_BLOCK_ALL':'0','MULTIFILTER_MAC':'','MULTIFILTER_ENABLE':'','MULTIFILTER_MACFILTER_DAYTIME_V2':'unused-private-schedule-data'}
    assert len(raw['MULTIFILTER_MACFILTER_DAYTIME_V2'])==28
    result=normalize_parental(raw,KEY)
    assert result['enabled'] is False and result['block_all'] is False
    assert result['rules']==[] and result['rule_count']==0
    assert 'unused_schedule_data_present' in result['gaps']
    assert 'unused-private-schedule-data' not in str(result)
    assert 'schedule-' not in str(result)
    for changed in ({'MULTIFILTER_ENABLE':'0'},{'MULTIFILTER_MAC':MACS[0],'MULTIFILTER_ENABLE':'0&#620'}):
        with pytest.raises(RouterError):normalize_parental({**raw,**changed},KEY)
