"""Prevent source limitations from becoming enum-only implemented features."""
import asyncio
import inspect
import json

import pytest

from router_agent.cli import main
from router_agent.expansion_manifest import load_expansion
from router_agent.transport import RequestGuard, TransportConfig


def test_pinned_system_has_no_read_mapping_and_ping_only_wraps_json():
    from asusrouter.modules import data_finder
    from asusrouter.modules.data import AsusData
    from asusrouter.modules.endpoint import network, EndpointTools
    assert 'AsusData.SYSTEM' not in inspect.getsource(data_finder)
    assert data_finder.ASUSDATA_MAP[AsusData.PING].endpoint == [EndpointTools.NETWORK]
    assert network.process({'synthetic': 1}) == {AsusData.PING: {'synthetic': 1}}
    assert not any(hasattr(network, name) for name in ('start', 'poll', 'cancel', 'expire'))


@pytest.mark.parametrize('group', ['ping', 'system'])
def test_no_passive_command_invented_from_enum(group, monkeypatch, capsys):
    monkeypatch.setattr('router_agent.cli.get_credentials', lambda: pytest.fail('credential access'))
    assert main(['get', group]) == 2
    assert json.loads(capsys.readouterr().out)['error']['code'] == 'invalid_arguments'


def test_diagnostic_route_never_passes_passive_guard():
    from types import SimpleNamespace
    from yarl import URL
    from router_agent.errors import RouterError
    guard = RequestGuard(TransportConfig('router.example', 'synthetic'))
    guard.authenticated = True
    with pytest.raises(RouterError) as caught:
        asyncio.run(guard.start(None, None, SimpleNamespace(url=URL('https://router.example/netool.cgi'), method='GET')))
    assert caught.value.code == 'read_boundary'


def test_all_sixteen_dispositions_without_rewriting_source_audit(capsys):
    from router_agent.native_audit import load_native_audit
    data = load_expansion()
    historical = load_native_audit().manifest()
    ids = {row['id'] for row in historical['capabilities'] if row['cli_status'] == 'unimplemented'}
    assert {row['id'] for row in data['capabilities']} == ids
    assert len(data['capabilities']) == 16
    assert all(row['offline'] == 'passed' for row in data['capabilities'])
    assert main(['capabilities', '--expansion', '--limit', '20']) == 0
    public = json.loads(capsys.readouterr().out)
    assert public['data']['historical_audit_unchanged'] is True
    assert public['data']['pagination']['total'] == 16
    source_only = {row['id'] for row in data['capabilities'] if row['implementation'] in {'source_limitation', 'recovery_blocked'}}
    assert source_only == {'read.ping', 'read.system', 'state.aura', 'state.system'}
    assert all(row['interface'] is None for row in data['capabilities'] if row['id'] in source_only)
