import json

import pytest

from router_agent.errors import RouterError
from router_agent.speedtest_reads import SPEEDTEST_HOOK, SPEEDTEST_CAPABILITY_HOOK, normalize_speedtest, normalize_speedtest_capability


def raw(timestamp='2026-10-12T12:00:00+07:00'):
    return {'ookla_state':'2', 'ookla_speedtest_get_result':[
        {'type':'ping','server':'synthetic-private'},
        {'type':'result','timestamp':timestamp,'download':{'bandwidth':100,'servers':['synthetic-private']},
         'upload':{'bandwidth':25.5},'public_ip':'192.0.2.1','latency':12.3},
        {'type':'log','message':'synthetic-secret'}]}


def test_existing_result_uses_native_penultimate_step_and_bps_conversion():
    from asusrouter.modules.endpoint.hook import process_speedtest
    source = raw()
    # Native processor mutates sections; use independent copies for comparison.
    native = process_speedtest(json.loads(json.dumps(source)))['data']
    result = normalize_speedtest(source)
    assert SPEEDTEST_HOOK == 'nvram_get(ookla_state);ookla_speedtest_get_result();'
    assert result['native_completed_result'] is True
    assert result['download_bps'] == native['download']['bandwidth'] == 800
    assert result['upload_bps'] == native['upload']['bandwidth'] == 204
    assert result['result_timestamp_utc'] == '2026-10-12T05:00:00+00:00'
    assert result['result_timestamp_native'] == '2026-10-12T12:00:00+07:00'
    assert not any(private in json.dumps(result) for private in ('synthetic-', '192.0.2.1'))
    assert 'latency' not in result


def test_no_result_is_not_history_or_current_egress():
    result = normalize_speedtest({'ookla_state':'0','ookla_speedtest_get_result':[{'type':'result','download':{'bandwidth':5}}]})
    assert result['native_completed_result'] is False
    assert result['download_bps'] is None
    assert 'no_native_completed_result_returned' in result['gaps']


def test_naive_timestamp_is_retained_without_guessing_timezone():
    result = normalize_speedtest(raw('2026-10-12T12:00:00'))
    assert result['result_timestamp_utc'] is None
    assert result['result_timestamp_native'] == '2026-10-12T12:00:00'
    assert 'result_timestamp_timezone_unavailable' in result['gaps']


@pytest.mark.parametrize('field,value', [('download',{'bandwidth':True}), ('upload',{'bandwidth':float('inf')}),
    ('download',{'bandwidth':-1}), ('download',{'bandwidth':'synthetic-secret'}), ('timestamp','synthetic-secret')])
def test_invalid_result_numbers_or_timestamp_fail_fixed(field,value):
    source=raw(); source['ookla_speedtest_get_result'][-2][field]=value
    with pytest.raises(RouterError) as caught: normalize_speedtest(source)
    assert caught.value.code=='malformed_response'
    assert 'synthetic-secret' not in str(caught.value)


@pytest.mark.parametrize('source', [{}, {'ookla_state':True}, {'ookla_state':'2','ookla_speedtest_get_result':'secret'},
    {'ookla_state':'2','ookla_speedtest_get_result':[{}]*65}])
def test_missing_or_malformed_result_contract_fails_closed(source):
    with pytest.raises(RouterError): normalize_speedtest(source)


def test_capability_gate_matches_native_service_union_without_discovery_or_raw_output():
    assert SPEEDTEST_CAPABILITY_HOOK == 'nvram_get(rc_support);nvram_get(ss_support);'
    assert normalize_speedtest_capability({'rc_support':'2.4G 5G ookla', 'ss_support':''}) == {'ookla_supported':True}
    assert normalize_speedtest_capability({'rc_support':'2.4G  5G', 'ss_support':'ookla'}) == {'ookla_supported':True}
    assert normalize_speedtest_capability({'rc_support':'  2.4G  ookla  ', 'ss_support':''}) == {'ookla_supported':True}
    assert normalize_speedtest_capability({'rc_support':'2.4G 5G', 'ss_support':''}) == {'ookla_supported':False}
    assert normalize_speedtest_capability({'rc_support':'', 'ss_support':''}) == {'ookla_supported':False}


@pytest.mark.parametrize('source', [{'rc_support':'ookla'}, {'rc_support':None,'ss_support':''},
    {'rc_support':'ookla\nprivate','ss_support':''}, {'rc_support':'x'*4097,'ss_support':''}])
def test_unknown_or_malformed_capability_fails_closed(source):
    with pytest.raises(RouterError): normalize_speedtest_capability(source)
