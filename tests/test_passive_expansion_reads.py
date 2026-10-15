import json
from datetime import datetime, timedelta
import pytest
from router_agent.dsl_reads import normalize_dsl, validate_dsl_probe
from router_agent.flags_reads import observe_flags
from router_agent.openvpn_reads import normalize_openvpn, read_openvpn_text
from router_agent.errors import RouterError

IDENTITY = {'device_fingerprint': 'a' * 24, 'firmware': 'synthetic-388'}
BASE = datetime(2026, 10, 15, 1, 0, 0)


def raw(boot=BASE, uptime=1000):
    clock = boot + timedelta(seconds=uptime)
    return {'sys': {'uptimeStr': f'{clock.isoformat()}({uptime} secs since boot)'}}


def observe(directory, boot=BASE, uptime=1000, wall=10000, mono=1000, identity=IDENTITY, host='synthetic-host-boot'):
    return observe_flags(raw(boot, uptime), identity, state_dir=directory, wall_time=wall, monotonic_time=mono, host_boot_id=host)


@pytest.mark.parametrize('value,expected,unit', [(None, None, None), ('', None, None), ('0 kbps', 0, 'kbps'), ('123 Mbps', 123, 'Mbps'), ('123 widgets', 123, None), ('123', 123, None)])
def test_dsl_preserves_missing_zero_and_unknown_unit(value, expected, unit):
    result = normalize_dsl({'dsllog_dataratedown': value})
    assert result['rates']['down'] == {'value': expected, 'unit': unit}
    assert result['rates']['up']['value'] is None
    assert 'widgets' not in json.dumps(result)
    assert 'native_missing_rate_defaults_to_zero' in result['gaps']


@pytest.mark.parametrize('value', [True, 0, {}, '-1 kbps', 'secret', '1 kbps secret', '1\nkbps'])
def test_dsl_malformed(value):
    with pytest.raises(RouterError):
        normalize_dsl({'dsllog_datarateup': value})


@pytest.mark.parametrize('reader', [normalize_dsl, lambda raw: normalize_openvpn(raw, flavor='stock')])
def test_auth_readers(reader):
    with pytest.raises(RouterError) as caught:
        reader({'error_status': 2, 'password': 'sentinel'})
    assert caught.value.code == 'auth_2'
    assert 'sentinel' not in str(caught.value)


@pytest.mark.parametrize('text', ['', '{}', '<html>sentinel</html>', 'not assignments'])
def test_dsl_probe_empty_html_malformed(text):
    with pytest.raises(RouterError):
        validate_dsl_probe(text)


def test_dsl_probe_auth_and_native_shape():
    validate_dsl_probe('dsl_status = "up";')
    with pytest.raises(RouterError) as caught:
        validate_dsl_probe('{"error_status": 10}')
    assert caught.value.code == 'auth_10'


def test_flags_first_unknown_persistence_and_equal(tmp_path):
    first = observe(tmp_path)
    assert first['reboot'] is None and first['native_reboot_signal'] is None
    second = observe(tmp_path, uptime=1010, wall=10010, mono=1010)
    assert second['reboot'] is False and second['boot_delta_seconds'] == 0
    path = tmp_path / 'boot-history' / 'observation.json'
    assert path.stat().st_mode & 0o077 == 0
    assert 'uptimeStr' not in path.read_text()


@pytest.mark.parametrize('delta,uptime,expected,gap', [
    (1005, 5, True, None),
    (-2, 1012, None, 'negative_boot_delta_native_day_wrap_risk'),
    (86400, 10, None, 'router_clock_correction_or_counter_discontinuity'),
    (30, 1010, None, 'router_clock_correction_or_counter_discontinuity'),
    (2, 1008, None, 'signed_boot_or_uptime_delta_ambiguous'),
])
def test_flags_signed_counter_comparison(tmp_path, delta, uptime, expected, gap):
    observe(tmp_path)
    result = observe(tmp_path, boot=BASE + timedelta(seconds=delta), uptime=uptime, wall=10010, mono=1010)
    assert result['reboot'] is expected
    assert result['boot_delta_seconds'] == delta
    if gap:
        assert gap in result['gaps']


@pytest.mark.parametrize('kwargs,gap', [({'wall': 9990, 'mono': 1010}, 'local_clock_correction'), ({'wall': 10010, 'mono': 1010, 'host': 'new-host'}, 'local_monotonic_history_unavailable'), ({'wall': 100000, 'mono': 91000}, 'observation_gap_exceeds_one_day')])
def test_flags_clocks_and_gaps(tmp_path, kwargs, gap):
    observe(tmp_path)
    result = observe(tmp_path, uptime=1010, **kwargs)
    assert result['reboot'] is None and gap in result['gaps']


@pytest.mark.parametrize('identity', [{'device_fingerprint': 'b' * 24, 'firmware': 'synthetic-388'}, {'device_fingerprint': 'a' * 24, 'firmware': 'new-fw'}])
def test_flags_target_firmware_change(tmp_path, identity):
    observe(tmp_path)
    result = observe(tmp_path, identity=identity)
    assert result['reboot'] is None and 'identity_or_firmware_changed' in result['gaps']


def test_flags_malformed_history_and_no_persistence(tmp_path):
    observe(tmp_path)
    path = tmp_path / 'boot-history' / 'observation.json'
    path.write_text('{"private":"sentinel"}')
    result = observe(tmp_path)
    assert result['reboot'] is None and 'history_malformed' in result['gaps']
    assert 'sentinel' not in json.dumps(result)
    assert 'history_persistence_not_configured' in observe(None)['gaps']


@pytest.mark.parametrize('payload', [{}, {'vpn': {}}, {'vpn': {'client1_state': None}}])
def test_stock_openvpn_missing_empty_unknown(payload):
    result = normalize_openvpn(payload, flavor='stock')
    assert not result['slots'] or result['slots'][0]['state_code'] is None


def test_stock_openvpn_bounded_private_fields():
    result = normalize_openvpn({'vpn': {'client1_state': '2', 'client1_errno': '0', 'server2_state': '0', 'password': 'sentinel', 'client6_state': '1'}}, flavor='stock')
    assert result['slots'] == [{'party': 'client', 'slot': 1, 'state_code': 2, 'error_code': 0}, {'party': 'server', 'slot': 2, 'state_code': 0, 'error_code': None}]
    assert 'sentinel' not in json.dumps(result)


@pytest.mark.parametrize('state', [True, 'secret', '3', [], {}])
def test_stock_openvpn_malformed_status(state):
    with pytest.raises(RouterError):
        normalize_openvpn({'vpn': {'client1_state': state}}, flavor='stock')


def test_merlin_native_reader_dispatch_and_privacy():
    text = 'vpn_client1_status = "None"; vpn_server1_status = "sentinel"; vpn_client1_ip = "192.0.2.1";'
    result = normalize_openvpn(read_openvpn_text(text), flavor='merlin')
    assert [row['state_code'] for row in result['slots']] == [0, 2]
    assert 'sentinel' not in json.dumps(result) and '192.0.2.1' not in json.dumps(result)
    assert normalize_openvpn({'client': None, 'server': {}}, flavor='merlin')['slots'] == []
    with pytest.raises(RouterError) as caught:
        read_openvpn_text('{"error_status": 7}')
    assert caught.value.code == 'auth_7'


def test_flags_missing_observation_cannot_be_no_reboot(tmp_path):
    with pytest.raises(RouterError):
        observe_flags({}, IDENTITY, state_dir=tmp_path)
    assert not (tmp_path / 'boot-history').exists()


def test_flags_history_permissions_fail_closed(tmp_path):
    observe(tmp_path)
    path = tmp_path / 'boot-history' / 'observation.json'
    path.chmod(0o644)
    with pytest.raises(RouterError) as caught:
        observe(tmp_path)
    assert caught.value.code == 'unsafe_path'


def test_flags_history_symlink_fail_closed(tmp_path):
    observe(tmp_path)
    path = tmp_path / 'boot-history' / 'observation.json'
    path.unlink()
    path.symlink_to(tmp_path / 'elsewhere')
    with pytest.raises(RouterError):
        observe(tmp_path)


@pytest.mark.parametrize('payload', [{'vpn': None}, {'vpn': {'client1_state': '2', 'client1_errno': 'private'}}, {'vpn': {'client1_state': '2', 'client1_errno': False}}])
def test_openvpn_malformed_shape_and_errors(payload):
    with pytest.raises(RouterError):
        normalize_openvpn(payload, flavor='stock')


def test_dsl_auth_only_is_not_positive_capability():
    with pytest.raises(RouterError) as caught:
        validate_dsl_probe('{"error_status": 0}')
    assert caught.value.code == 'capability_unknown'


def test_flags_auth_failure_preserves_history(tmp_path):
    observe(tmp_path)
    path = tmp_path / 'boot-history' / 'observation.json'
    before = path.read_bytes()
    with pytest.raises(RouterError) as caught:
        observe_flags({'error_status': 2, 'password': 'sentinel'}, IDENTITY, state_dir=tmp_path)
    assert caught.value.code == 'auth_2' and path.read_bytes() == before


def test_pinned_native_passive_contracts():
    from asusrouter.modules.data_finder import ASUSDATA_NVRAM
    from asusrouter.modules.endpoint import Endpoint
    from asusrouter.modules.endpoint.devicemap import process_ovpn
    from asusrouter.modules.endpoint.vpn import read
    from router_agent.dsl_reads import DSL_PATH, DSL_HOOK
    assert DSL_PATH == '/' + Endpoint.DSL.value
    assert ASUSDATA_NVRAM['dsl'] == ['dsllog_dataratedown', 'dsllog_datarateup']
    assert DSL_HOOK == ''.join(f'nvram_get({key});' for key in ASUSDATA_NVRAM['dsl'])
    native = process_ovpn({'vpn': {'client1_state': '2', 'client1_errno': '0', 'server1_state': '0'}})
    actual = normalize_openvpn({'vpn': {'client1_state': '2', 'client1_errno': '0', 'server1_state': '0'}}, flavor='stock')
    assert actual['slots'][0]['state_code'] == int(native['client'][1]['state'])
    assert actual['slots'][1]['state_code'] == int(native['server'][1]['state'])
    native_merlin = read('vpn_client1_status = "None";')
    assert normalize_openvpn(native_merlin, flavor='merlin')['slots'][0]['state_code'] == int(native_merlin['client'][1]['state'])
