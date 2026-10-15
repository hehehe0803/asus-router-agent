import asyncio
import hashlib
import hmac
import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from router_agent.errors import RouterError
from router_agent.node_info_reads import normalize_node_info
from router_agent.traffic_reads import prepare_traffic_request,normalize_traffic
from router_agent.firmware_note_reads import read_firmware_note_text,normalize_firmware_note

KEY=b'k'*32
MAC='AA:BB:CC:DD:EE:00'
PEER='AA:BB:CC:DD:EE:02'
BAND='AA:BB:CC:DD:EE:04'


def alias(mac):
    return 'node-'+hmac.new(KEY,b'node:'+mac.encode(),hashlib.sha256).hexdigest()[:16]


def inventory():
    return {'get_cfg_clientlist':[[{'mac':MAC,'ap2g':BAND,'ap5g':'','ssid':'synthetic-private'}, {'mac':PEER}]]}


def prepare(kind='ethernet',**kwargs):
    return asyncio.run(prepare_traffic_request(kind,alias(MAC),inventory(),KEY,**kwargs))


def test_fixture_proven_node_info_field_is_raw_code_not_readiness():
    p=Path('/tmp/asusrouter-research-1.21.3/tests/test_data/rt_ax88u_merlin_388/port_status_001.content')
    if not p.is_file():pytest.skip('pristine fixture unavailable')
    source=json.loads(p.read_text())
    result=normalize_node_info(source,KEY)
    assert result['nodes'][0]['cd_good_to_go_code']==1
    assert '00:00:00:00:00:00' not in json.dumps(result)
    assert 'cd_good_to_go_semantics_unverified' in result['gaps']
    assert 'native_node_identifier_is_a_placeholder' in result['gaps']


def test_node_info_missing_code_null_and_private_fields_removed():
    result=normalize_node_info({'node_info':{MAC:{'cd_good_to_go':'999','password':'synthetic-private'},PEER:{}}},KEY)
    values={row['node_alias']:row['cd_good_to_go_code'] for row in result['nodes']}
    assert values[alias(MAC)]==999 and values[alias(PEER)] is None
    assert 'synthetic-private' not in json.dumps(result)
    assert normalize_node_info({},KEY)['nodes']==[]


@pytest.mark.parametrize('value',[True,'synthetic-private','2147483648',{}])
def test_node_info_malformed_selected_code_fails_fixed(value):
    with pytest.raises(RouterError) as caught:normalize_node_info({'node_info':{MAC:{'cd_good_to_go':value}}},KEY)
    assert 'synthetic-private' not in str(caught.value)


@pytest.mark.parametrize('kind,kwargs,path,extra',[('ethernet',{},'get_diag_eth_traffic.cgi',{'is_bh':['0']}),
 ('ethernet',{'backhaul':True},'get_diag_eth_traffic.cgi',{'is_bh':['1']}),
 ('wifi',{'band':'2ghz'},'get_diag_wifi_traffic.cgi',{'band_mac':[BAND]}),
 ('backhaul',{'peer_alias':alias(PEER)},'get_diag_sta_traffic.cgi',{'sta_mac':[PEER]})])
def test_preparation_uses_typed_native_request_and_only_private_inventory_targets(kind,kwargs,path,extra):
    prepared=prepare(kind,**kwargs)
    assert prepared.endpoint.value==path
    assert parse_qs(prepared.request)=={'node_mac':[MAC],**extra}
    assert MAC not in repr(prepared) and BAND not in repr(prepared) and PEER not in repr(prepared)


def test_native_rates_units_are_from_native_translator_not_measured_throughput():
    source={'data_rx':1,'data_tx':2,'data_avg_rx':3,'data_avg_tx':4,'phy_rx':5,'phy_tx':6,'error_status':200,'private':'synthetic-private'}
    from asusrouter.modules.traffic import translate_state
    native=translate_state(source)
    result=normalize_traffic(source,prepare())
    assert result['rx_bps']==native['rx_speed']==1024
    assert result['phy_rx_bps']==native['phy_rx']==5*2**20
    assert result['status_code']==200
    assert 'synthetic-private' not in json.dumps(result) and MAC not in json.dumps(result)
    assert 'native_rates_are_not_throughput_or_egress_verification' in result['gaps']


def test_dynamic_missing_rates_stay_unknown_not_native_zero_fallback():
    result=normalize_traffic({'error_status':200},prepare())
    assert result['rx_bps'] is None and result['phy_rx_bps'] is None
    assert 'selected_rate_fields_missing_or_unknown' in result['gaps']


def test_gpl_handler_nested_rate_wire_shape_uses_unchanged_native_flattening():
    source={'data':{'rx':'1.000000','tx':'2.000000','avg_rx':'3.000000','avg_tx':'4.000000'},
            'phy':{'rx':'5','tx':'6.5'},'error_status':'200'}
    result=normalize_traffic(source,prepare())
    assert result['rx_bps']==1024 and result['tx_avg_bps']==4096
    assert result['phy_tx_bps']==6.5*2**20


@pytest.mark.parametrize('kwargs',[{'node_alias':MAC},{'node_alias':'node-'+'0'*16},{'kind':'wifi','band':'5ghz'},
 {'kind':'backhaul','peer_alias':MAC},{'kind':'wifi','band':BAND},{'kind':'ethernet','peer_alias':alias(PEER)}])
def test_traffic_target_requires_fresh_opaque_alias_and_finite_band(kwargs):
    args={'kind':'ethernet','node_alias':alias(MAC),'raw_onboarding':inventory(),'fingerprint_key':KEY,**kwargs}
    with pytest.raises(RouterError) as caught:asyncio.run(prepare_traffic_request(**args))
    assert caught.value.code=='traffic_target_unavailable'
    assert MAC not in str(caught.value)


@pytest.mark.parametrize('value',[True,'synthetic-private',float('inf'),-1,{'private':'value'}])
def test_malformed_traffic_selected_metric_fails_without_echo(value):
    with pytest.raises(RouterError) as caught:normalize_traffic({'data_rx':value},prepare())
    assert 'synthetic-private' not in str(caught.value)


def test_native_release_note_reader_selects_text_and_reconstructs_pagination():
    from asusrouter.modules.endpoint.firmware_note import read
    text='Firmware version 3004_388_1\nRelease Note\nFix one\nVendor URL https://example.test\nFix two\n'
    raw=read_firmware_note_text(text)
    assert raw==read(text)
    first=normalize_firmware_note(raw,limit=8)
    assert 'release_note_raw' not in first and first['truncated']
    pieces=[];offset=0
    while True:
        page=normalize_firmware_note(raw,offset=offset,limit=8)
        pieces.append(page['release_note'])
        assert page['content_fingerprint']==first['content_fingerprint']
        offset=page['pagination']['next_offset']
        if offset is None:break
    assert ''.join(pieces)==raw['release_note']
    assert 'release_note_text_is_untrusted_vendor_content' in first['gaps']


@pytest.mark.parametrize('text,code',[('{"error_status":2}', 'auth_2'),("error_status = '2';\n",'auth_2'),
 ('<html><form>synthetic-private</form></html>','malformed_response'),('x'*131073,'malformed_response')])
def test_release_note_auth_html_and_oversize_fail_before_native_retry(text,code):
    with pytest.raises(RouterError) as caught:read_firmware_note_text(text)
    assert caught.value.code==code and 'synthetic-private' not in str(caught.value)


def test_empty_native_note_is_not_absence_of_updates():
    result=normalize_firmware_note(read_firmware_note_text('\n\n'))
    assert result['release_note'] is None and not result['truncated']
    assert 'empty_note_does_not_establish_no_available_firmware' in result['gaps']
