import json
import logging
import pytest
from router_agent.errors import RouterError
from router_agent.sysinfo_reads import read_sysinfo_text, normalize_sysinfo, validate_sysinfo_shape


def native_text(raw):
    return ''.join(f'{key} = {json.dumps(value)};\n' for key,value in raw.items()) + '\n'


def test_pristine_reader_processor_counts_load_and_private_selection():
    raw={'wlc_0_arr':['4','3','2'],'wlc_1_arr':[1,1,1],'conn_stats_arr':['30','12'],'cpu_stats_arr':['0.25','1.5','2'],'mem_stats_arr':['private-memory-detail'],'processes':['private-process'],'password':'synthetic-private-value','client_mac':'AA:BB:CC:DD:EE:FF'}
    parsed=read_sysinfo_text(native_text(raw))
    result=normalize_sysinfo(parsed)
    assert result['connections']=={'total':30,'active':12}
    assert result['load_avg']=={'one_minute':0.25,'five_minutes':1.5,'fifteen_minutes':2.0}
    assert result['wlan']==[{'radio_index':0,'client_associated':4,'client_authorized':3,'client_authenticated':2},{'radio_index':1,'client_associated':1,'client_authorized':1,'client_authenticated':1}]
    for private in ('synthetic-private-value','private-process','private-memory-detail','AA:BB:CC:DD:EE:FF'):
        assert private not in str(result)


def test_unknowns_remain_null_and_sparse_radio_not_dropped():
    result=normalize_sysinfo({'wlc_1_arr':[None,'unknown','-1'],'conn_stats_arr':[],'cpu_stats_arr':['',None,'N/A']})
    assert result['connections']=={'total':None,'active':None}
    assert all(v is None for v in result['load_avg'].values())
    assert result['wlan']==[{'radio_index':1,'client_associated':None,'client_authorized':None,'client_authenticated':None}]
    assert 'selected_values_missing_or_unknown' in result['gaps']


@pytest.mark.parametrize('raw',[{}, {'processes':[]},{'conn_stats_arr':[1]},{'conn_stats_arr':[1,2,3]},{'cpu_stats_arr':{}},{'wlc_0_arr':[1,2,3,4]},{'conn_stats_arr':[True,1]},{'conn_stats_arr':[-2,1]},{'cpu_stats_arr':[float('nan'),1,2]},{'cpu_stats_arr':[float('inf'),1,2]},{'conn_stats_arr':['secret-text',1]},{'cpu_stats_arr':[1000001,1,2]},{'conn_stats_arr':[2147483648,1]}])
def test_malformed_selected_data_is_safe_error(raw):
    with pytest.raises(RouterError) as error:normalize_sysinfo(raw)
    assert error.value.code=='malformed_response'
    assert 'secret-text' not in str(error.value)


@pytest.mark.parametrize('text',['','<html><form>login</form></html>','<script>private</script>','cpu_stats_arr = broken-private-value;\n','{"cpu_stats_arr":[1,2,3]}','x'*65537])
def test_malformed_html_or_oversized_text_does_not_log_payload(text,caplog):
    caplog.set_level(logging.DEBUG)
    with pytest.raises(RouterError) as error:read_sysinfo_text(text)
    assert error.value.code=='malformed_response'
    assert 'broken-private-value' not in caplog.text


@pytest.mark.parametrize('code',[2,3,7,9,10,11])
def test_auth_failures_json_and_native_assignments_stop(code):
    for text in (json.dumps({'error_status':code,'password':'synthetic-private-value'}),native_text({'error_status':str(code)})):
        with pytest.raises(RouterError) as error:read_sysinfo_text(text)
        assert error.value.code==f'auth_{code}'
        assert 'synthetic-private-value' not in str(error.value)


def test_unknown_native_status_and_field_bound_fail_closed():
    with pytest.raises(RouterError) as error:read_sysinfo_text(json.dumps({'error_status':55}))
    assert error.value.code=='native_status_failed'
    with pytest.raises(RouterError):validate_sysinfo_shape({'conn_stats_arr':[1,2],**{f'private-{i}':None for i in range(128)}})
