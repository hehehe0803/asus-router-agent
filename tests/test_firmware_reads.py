import json
from pathlib import Path

import pytest

from router_agent.errors import RouterError
from router_agent.firmware_reads import FIRMWARE_PATH, read_firmware_text, normalize_firmware, validate_firmware_shape

TEXT = "webs_state_update = '1';\nwebs_state_error = '0';\nwebs_state_info = '3004_388_4_0';\nwebs_state_flag = '1';\n"


def test_native_reader_and_status_selection_match_upstream_processing():
    from asusrouter.modules.endpoint.firmware import read, process
    from asusrouter.modules.data import AsusData
    assert FIRMWARE_PATH == '/detect_firmware.asp'
    raw = read_firmware_text(TEXT)
    assert raw == read(TEXT)
    native = process(raw)[AsusData.FIRMWARE]
    result = normalize_firmware({**raw, 'server_url': 'https://synthetic-private.example', 'password': 'synthetic-secret'})
    assert result['update_code'] == native['webs']['update'].value
    assert result['error_code'] == native['webs']['error'].value
    assert result['reported_stable_version'] == '3004_388_4_0'
    assert result['upgrade_code'] is None  # Do not reuse upstream missing -> INACTIVE default.
    assert 'synthetic-' not in json.dumps(result)
    assert 'stored_firmware_status_is_not_a_new_update_check' in result['gaps']


def test_pristine_native_firmware_fixture_reader_is_unchanged():
    fixture = Path('/tmp/asusrouter-research-1.21.3/tests/test_data/rt_ax88u_merlin_388/firmware_001.content')
    if not fixture.is_file():
        pytest.skip('pristine native fixture is unavailable')
    from asusrouter.modules.endpoint.firmware import read
    text = fixture.read_text()
    assert read_firmware_text(text) == read(text)


@pytest.mark.parametrize('text,code', [('{"error_status":2,"password":"synthetic-secret"}', 'auth_2'),
    ("error_status = '2';\n", 'auth_2'), ("error_status = '999';\n", 'native_status_failed'),
    ('<html><form>synthetic-secret</form></html>', 'malformed_response'),
    ('{"webs_state_update":1}', 'malformed_response'), ('synthetic-secret', 'malformed_response'),
    ('x'*65537, 'malformed_response')])
def test_auth_html_malformed_and_oversize_fail_without_private_echo(text, code, caplog):
    with pytest.raises(RouterError) as caught:
        read_firmware_text(text)
    assert caught.value.code == code
    assert 'synthetic-secret' not in str(caught.value) + caplog.text


@pytest.mark.parametrize('raw', [{}, {'webs_state_update': True}, {'webs_state_update': 'synthetic-secret'},
    {'webs_state_info': 'https://synthetic-private.example/fw'}, {'webs_state_upgrade': '2147483648'}])
def test_malformed_selected_values_fail_closed(raw):
    with pytest.raises(RouterError):
        validate_firmware_shape(raw)


def test_finite_unknown_codes_and_missing_optional_versions_are_preserved():
    result = normalize_firmware({'webs_state_update': '999', 'webs_state_upgrade': '-1', 'webs_state_info_beta': ''})
    assert result['update_code'] == 999 and result['upgrade_code'] == -1
    assert result['reported_beta_version'] is None


@pytest.mark.parametrize('sentinel', ['__', '___'])
def test_native_unknown_version_sentinels_are_null_with_gap(sentinel):
    result=normalize_firmware({'webs_state_info':sentinel})
    assert result['reported_stable_version'] is None
    assert 'selected_firmware_fields_missing_or_unknown' in result['gaps']
