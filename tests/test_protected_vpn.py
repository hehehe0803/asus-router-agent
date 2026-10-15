import asyncio
from copy import deepcopy
import json
import logging
import pytest
from router_agent.errors import RouterError
from router_agent.protected_vpn import parse_snapshot, select_profiles, prepare, config_snapshot

KEY = b'v' * 32
IDENTITY = {'model': 'RT-AX86U', 'firmware': '3.0.0.4.388_24436-ge7c0b5e', 'device_fingerprint': 'abc123'}
SECRET = 'credential-sentinel'
RAW = {'vpnc_unit': '0', 'vpnc_clientlist': f'private-name>OpenVPN>1>private-login>{SECRET}>0>5>unknown>Web<other-name>WireGuard>2>login>secret2>1>9>opaque', 'get_vpnc_status': '5>0>5'}


def intent(raw=RAW, kind='vpnc', index=0, enabled=True):
    selected = parse_snapshot(raw, KEY, IDENTITY).profiles[index]
    return {'kind': kind, 'profile_ref': selected['profile_ref'], 'enabled': enabled}


def run(raw=RAW, **kwargs):
    return asyncio.run(prepare(raw, intent(raw, **kwargs), KEY, IDENTITY))


def test_private_safe_repr_and_nullable_status():
    snapshot = parse_snapshot(RAW, KEY, IDENTITY)
    public = select_profiles(snapshot)
    assert public['profiles'][0]['status_code'] == 5
    assert public['profiles'][1]['status_code'] is None
    assert public['profiles'][1]['error_code'] is None
    assert public['profiles'][0]['enabled'] is False
    for value in (repr(snapshot), json.dumps(public)):
        assert SECRET not in value and 'private-name' not in value and 'private-login' not in value
    assert len(select_profiles(snapshot, 'openvpn')['profiles']) == 1


def test_reference_stable_across_credentials_name_state_order_status():
    first = {p['protocol']: p['profile_ref'] for p in parse_snapshot(RAW, KEY, IDENTITY).profiles}
    changed = {'vpnc_clientlist': '<'.join(reversed(RAW['vpnc_clientlist'].replace('private-name', 'new-name').replace(SECRET, 'new-secret').replace('>0>5', '>1>5').split('<')))}
    second = {p['protocol']: p['profile_ref'] for p in parse_snapshot(changed, KEY, IDENTITY).profiles}
    assert first == second
    assert parse_snapshot(RAW, b'w' * 32, IDENTITY).profiles[0]['profile_ref'] != first['openvpn']
    assert parse_snapshot(RAW, KEY, {**IDENTITY, 'device_fingerprint': 'another'}).profiles[0]['profile_ref'] != first['openvpn']


@pytest.mark.parametrize('kind,index,enabled', [('vpnc', 0, True), ('openvpn_client', 0, True), ('wireguard_client', 1, False)])
def test_native_compiler_complete_preservation_inverse(kind, index, enabled):
    raw = {**RAW, 'vpnc_unit': str(index)}
    change = run(raw, kind=kind, index=index, enabled=enabled)
    assert change['before_raw'] == config_snapshot(None, raw)
    expected = RAW['vpnc_clientlist'].split('<')
    columns = expected[index].split('>')
    columns[5] = str(int(enabled))
    expected[index] = '>'.join(columns)
    assert change['after_raw'] == {'vpnc_clientlist': '<'.join(expected), 'vpnc_unit': str(index)}
    assert change['commands'][0]['arguments']['vpnc_clientlist'] == change['after_raw']['vpnc_clientlist']
    restore = asyncio.run(prepare(change['after_raw'], {**change['intent'], 'enabled': not enabled}, KEY, IDENTITY))
    assert restore['after_raw'] == change['before_raw']


def test_runtime_status_excluded_from_binding_and_noop():
    altered = {**RAW, 'get_vpnc_status': '2>0>5'}
    assert parse_snapshot(altered, KEY, IDENTITY).fingerprint == parse_snapshot(RAW, KEY, IDENTITY).fingerprint
    assert run(enabled=False)['noop'] is True


@pytest.mark.parametrize('prefix', ['<', '<<'])
def test_empty_prefix_unsafe_native_index(prefix):
    raw = {**RAW, 'vpnc_clientlist': prefix + RAW['vpnc_clientlist']}
    assert len(select_profiles(parse_snapshot(raw, KEY, IDENTITY))['profiles']) == 2
    with pytest.raises(RouterError, match='protected VPN') as error:
        run(raw)
    assert error.value.code == 'unsafe_vpn_unit'


def test_empty_interior_preserved_no_cross_profile_write():
    raw = {**RAW, 'vpnc_clientlist': RAW['vpnc_clientlist'].replace('<', '<<') + '<'}
    change = run(raw)
    assert '<<' in change['after_raw']['vpnc_clientlist'] and change['after_raw']['vpnc_clientlist'].endswith('<')
    with pytest.raises(RouterError) as error:
        run(raw, index=1, kind='wireguard_client')
    assert error.value.code == 'unsafe_vpn_unit'


def test_canonical_entity_read_and_decoded_command_domains():
    raw = {**RAW, 'vpnc_clientlist': RAW['vpnc_clientlist'].replace('>', '&#62').replace('<', '&#60')}
    snapshot = parse_snapshot(raw, KEY, IDENTITY)
    assert len(snapshot.profiles) == 2
    change = run(raw)
    assert change['before_raw'] == config_snapshot(None, raw)
    assert change['after_raw']['vpnc_clientlist'] == raw['vpnc_clientlist'].replace('&#620&#625', '&#621&#625')
    assert change['commands'][0]['arguments']['vpnc_clientlist'] == RAW['vpnc_clientlist'].replace('>0>5', '>1>5')
    assert parse_snapshot(raw, KEY, IDENTITY).fingerprint != parse_snapshot(RAW, KEY, IDENTITY).fingerprint
    reverse = asyncio.run(prepare(change['after_raw'], {**change['intent'], 'enabled': False}, KEY, IDENTITY))
    assert reverse['after_raw'] == change['before_raw']
    assert run(raw, enabled=False)['noop'] is True


@pytest.mark.parametrize('mutate', [lambda s: s + '<' + s.split('<')[0], lambda s: s.replace('WireGuard>2', 'OpenVPN>1'), lambda s: s.replace('>1>9', '>1>5'), lambda s: 'broken', lambda s: s.replace('OpenVPN>1', 'OpenVPN>wat')])
def test_malformed_and_duplicate_fail_closed(mutate):
    with pytest.raises(RouterError):
        parse_snapshot({'vpnc_clientlist': mutate(RAW['vpnc_clientlist'])}, KEY, IDENTITY)


def test_unknown_protocol_never_exported_or_activated():
    raw = {**RAW, 'vpnc_clientlist': RAW['vpnc_clientlist'].replace('OpenVPN', 'private-protocol')}
    assert select_profiles(parse_snapshot(raw, KEY, IDENTITY))['profiles'][0]['protocol'] == 'unknown'
    with pytest.raises(RouterError) as error:
        run(raw)
    assert error.value.code == 'unsupported_vpn_profile'


def test_compiler_privacy(caplog):
    with caplog.at_level(logging.DEBUG):
        change = run()
    for sentinel in (SECRET, 'private-name', 'private-login', 'unknown', 'other-name', 'secret2', 'opaque'):
        assert sentinel not in caplog.text
        assert sentinel not in json.dumps(change['review'])


@pytest.mark.parametrize('status', ['2>0>999', '2>0>5<1>0>5', 'secret-status', 1])
def test_bad_status_never_leaks(status):
    with pytest.raises(RouterError) as error:
        parse_snapshot({**RAW, 'get_vpnc_status': status}, KEY, IDENTITY)
    assert 'secret-status' not in str(error.value)


@pytest.mark.parametrize('protocol', ['L2TP', 'PPTP', 'Surfshark'])
def test_generic_fusion_known_protocol_native_dispatch(protocol):
    raw = {**RAW, 'vpnc_clientlist': RAW['vpnc_clientlist'].replace('OpenVPN', protocol)}
    assert run(raw)['commands'][0]['service'] == 'restart_vpnc'


def test_native_serializer_loss_fails_closed(monkeypatch):
    from asusrouter.modules import vpnc
    async def lossy(callback, state, **kwargs):
        return await callback(service='restart_vpnc', arguments={'vpnc_unit': 0, 'vpnc_clientlist': 'lost-secret-content'}, apply=True, expect_modify=False)
    monkeypatch.setattr(vpnc, 'set_state', lossy)
    with pytest.raises(RouterError) as error:
        run()
    assert error.value.code == 'native_serializer_loss'


@pytest.mark.parametrize('changed', [lambda d: {**d, 'profile_ref': 'vpn-guessed'}, lambda d: {**d, 'enabled': 1}, lambda d: {**d, 'kind': 'wireguard_client'}, lambda d: {**d, 'extra': 'secret'}])
def test_bad_intents_and_cross_protocol_selection(changed):
    with pytest.raises(RouterError):
        asyncio.run(prepare(RAW, changed(intent()), KEY, IDENTITY))


@pytest.mark.parametrize('unit', [None, '', 'unknown-private-unit', '01', '1', '-1', ' 0'])
def test_selected_scalar_exact_recovery_gate(unit):
    raw = {**RAW, 'vpnc_unit': unit}
    snapshot = parse_snapshot(raw, KEY, IDENTITY)
    assert 'vpnc_unit' not in json.dumps(select_profiles(snapshot))
    with pytest.raises(RouterError) as error:
        run(raw)
    assert error.value.code == 'exact_recovery_unavailable'
    assert 'unknown-private-unit' not in str(error.value)


def test_scalar_participates_in_configuration_fingerprint():
    before = parse_snapshot(RAW, KEY, IDENTITY)
    after = parse_snapshot({**RAW, 'vpnc_unit': '1'}, KEY, IDENTITY)
    assert before.fingerprint != after.fingerprint
    change = run()
    assert change['before_raw']['vpnc_unit'] == change['after_raw']['vpnc_unit'] == '0'


@pytest.mark.parametrize('value', ['&#38', '&#34', '&#39', '&amp;', '&#x3e;', '&#62;', '&#60;', '&raw', '"raw-quote', '\\raw-backslash', 'é'])
@pytest.mark.parametrize('encoded', [False, True])
def test_unproven_field_representation_blocked_everywhere(value, encoded):
    raw = {**RAW, 'vpnc_clientlist': RAW['vpnc_clientlist'].replace(SECRET, value)}
    if encoded:
        raw['vpnc_clientlist'] = raw['vpnc_clientlist'].replace('>', '&#62').replace('<', '&#60')
    with pytest.raises(RouterError):
        run(raw)


@pytest.mark.parametrize('separator', ['>', '<'])
def test_mixed_delimiter_domain_rejected(separator):
    encoded = RAW['vpnc_clientlist'].replace('>', '&#62').replace('<', '&#60')
    token = '&#62' if separator == '>' else '&#60'
    raw = {**RAW, 'vpnc_clientlist': encoded.replace(token, separator, 1)}
    with pytest.raises(RouterError) as error:
        run(raw)
    assert error.value.code == 'native_serializer_loss'


def test_encoded_unknown_fields_and_safe_empty_records_preserved():
    native = RAW['vpnc_clientlist'] + '<<'
    raw = {**RAW, 'vpnc_clientlist': native.replace('>', '&#62').replace('<', '&#60')}
    change = run(raw)
    assert change['after_raw']['vpnc_clientlist'].endswith('&#60&#60')
    assert 'unknown&#62Web' in change['after_raw']['vpnc_clientlist']
    assert change['commands'][0]['arguments']['vpnc_clientlist'].endswith('<<')
    unsafe = {**raw, 'vpnc_clientlist': '&#60' + raw['vpnc_clientlist']}
    with pytest.raises(RouterError) as error:
        run(unsafe)
    assert error.value.code == 'unsafe_vpn_unit'
