import ast
import asyncio
from copy import deepcopy
import json
import logging
import socket
from urllib.parse import unquote

from aiohttp import web
import pytest
from asusrouter.modules import parental_control as pc

from tls_helpers import localhost_tls
from router_agent.errors import RouterError
from router_agent.native_parental_control import (FULL_POLICY_HOOK, ParentalGuard, parental_body, read_parental_policy,
    set_parental_global, set_parental_block_all, set_parental_rule, restore_parental_rules)
from router_agent.parental_policy import (PARENTAL_POLICY_KEYS, read_policy_snapshot, prepare_enable, prepare_block_all, prepare_rule, prepare_restore, client_alias)
from router_agent.transport import HOOKS, TransportConfig, _normalize

KEY = b'p' * 32
MACS = ['AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02', 'AA:BB:CC:DD:EE:03', 'AA:BB:CC:DD:EE:04']
IDENTITY = {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436-ge7c0b5e', 'label_mac': 'AA:BB:CC:DD:EE:FF'}
SCHEDULE = pc.DEFAULT_PC_TIMEMAP


def policy(count=3):
    raw = dict.fromkeys(PARENTAL_POLICY_KEYS, '')
    raw.update({pc.KEY_PC_STATE: '0', pc.KEY_PC_BLOCK_ALL: '0'})
    for key, values in ((pc.KEY_PC_MAC, MACS[:count]), (pc.KEY_PC_NAME, [f'private-name-{i}' for i in range(count)]),
                        (pc.KEY_PC_TIMEMAP, [SCHEDULE.replace('<', '&#60')] * count), (pc.KEY_PC_TYPE, ['1'] * count)):
        raw[key] = '&#62'.join(values)
    return raw


class ParentalTestServer:
    """Reusable synthetic native wire fixture; async context yields server.config.

    raw/identity/inventory are mutable synthetic responses, calls records wire
    requests, mode controls apply ACK/failure. Never bind to non-localhost.
    """
    def __init__(self, *, raw=None, identity=IDENTITY, mode='ok', calls=None):
        self.raw = deepcopy(policy() if raw is None else raw)
        self.identity = deepcopy(identity)
        self.mode = mode
        self.calls = [] if calls is None else calls
        self.inventory = {'get_clientlist': {'maclist': MACS, 'ClientAPILevel': '1', **{mac: {'name': 'private-client', 'ip': '192.0.2.1'} for mac in MACS}}}

    async def __aenter__(self):
        async def handle(request):
            payload = await request.text()
            self.calls.append((request.method, request.path, unquote(payload)))
            if request.path == '/login.cgi':
                return web.json_response({'asus_token': 'synthetic-token'})
            if request.path == '/Logout.asp':
                return web.json_response({'error_status': 8})
            if request.path == '/appGet.cgi':
                selected = unquote(payload)
                if selected == 'hook=' + HOOKS['identity']:
                    return web.json_response(self.identity)
                if selected == 'hook=' + FULL_POLICY_HOOK:
                    if self.mode == 'auth_error':
                        return web.json_response({'error_status': 2, 'private': 'synthetic-secret'})
                    return web.json_response(self.raw)
                if selected == 'hook=' + HOOKS['clients']:
                    return web.json_response(self.inventory)
                raise AssertionError('unexpected hook')
            if request.path == '/applyapp.cgi':
                commands = ast.literal_eval(unquote(payload))
                if self.mode != 'ignore':
                    for key in PARENTAL_POLICY_KEYS:
                        if key in commands:
                            value = str(commands[key])
                            if key in pc.PC_RULE_MAP:
                                value = value.replace('>', '&#62')
                                if key == pc.KEY_PC_TIMEMAP:
                                    value = value.replace('<', '&#60')
                            self.raw[key] = value
                if self.mode == 'timeout':
                    await asyncio.sleep(.2)
                if self.mode == 'secret_error':
                    return web.json_response({'run_service': 'wrong', 'raw': 'private-name-synthetic-secret'})
                return web.json_response({'run_service': 'restart_firewall', 'modify': '1'})
            raise AssertionError('unreviewed endpoint')
        app = web.Application()
        app.router.add_route('*', '/{path:.*}', handle)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        self.tls = localhost_tls()
        context, ca_file = self.tls.__enter__()
        await web.SockSite(self.runner, sock, ssl_context=context).start()
        self.config = TransportConfig('127.0.0.1', 'synthetic-admin', ca_file=ca_file,
                                      port=sock.getsockname()[1], timeout=.05 if self.mode == 'timeout' else 1)
        return self

    async def __aexit__(self, *exc):
        await self.runner.cleanup()
        self.tls.__exit__(None, None, None)


async def scenario(kind='enable', *, raw=None, expected_raw=None, expected_after=None, enabled=True, alias=None,
                   rule_type='block', schedule=None, original=None, identity=IDENTITY, expected_identity=None,
                   mode='ok', calls=None, factory=None, include_clients=False, observe_after=False):
    calls = [] if calls is None else calls
    current = deepcopy(policy() if raw is None else raw)
    original_raw = deepcopy(current)
    before = read_policy_snapshot(expected_raw or current, KEY)
    target_alias = alias or client_alias(KEY, MACS[1])
    if kind == 'enable':
        prepared = await prepare_enable(before, enabled)
    elif kind == 'block_all':
        prepared = await prepare_block_all(before, enabled)
    elif kind == 'rule':
        # Lossy branches are purposefully still passed to the setter to test its
        # own fresh-policy refusal, without needing a fictitious approved after.
        try:
            prepared = await prepare_rule(before, target_alias, rule_type, {mac: {} for mac in MACS}, schedule)
        except RouterError:
            prepared = None
    elif kind == 'restore':
        prepared = await prepare_restore(before, read_policy_snapshot(original, KEY))
    else:
        prepared = None
    desired = expected_after or (prepared.after.fingerprint if prepared is not None else before.fingerprint)
    common = {'expected_identity': expected_identity or _normalize('identity', IDENTITY, KEY), 'expected_policy_fingerprint': before.fingerprint,
              'expected_after_policy_fingerprint': desired, 'fingerprint_key': KEY, 'router_factory': factory, 'authorization_check': lambda:None}
    async with ParentalTestServer(raw=current, identity=identity, mode=mode, calls=calls) as server:
        cfg = server.config
        if kind == 'read':
            result = await read_parental_policy(cfg, 'synthetic-password', fingerprint_key=KEY, include_clients=include_clients, router_factory=factory)
        elif kind == 'enable':
            result = await set_parental_global(cfg, 'synthetic-password', enabled=enabled, **common)
        elif kind == 'block_all':
            result = await set_parental_block_all(cfg, 'synthetic-password', blocked=enabled, **common)
        elif kind == 'rule':
            result = await set_parental_rule(cfg, 'synthetic-password', client_alias=target_alias, rule_type=rule_type, schedule=schedule, **common)
        else:
            result = await restore_parental_rules(cfg, 'synthetic-password', restore_snapshot=read_policy_snapshot(original, KEY), **common)
        observed = await read_parental_policy(cfg, 'synthetic-password', fingerprint_key=KEY) if observe_after else None
        return result, calls, server.raw, original_raw, prepared, observed


def test_private_observation_includes_full_policy_and_only_requested_flat_client_identifiers():
    result, calls, *_ = asyncio.run(scenario('read', include_clients=True))
    assert result['policy'].fingerprint == read_policy_snapshot(policy(), KEY).fingerprint
    assert result['client_inventory'] == {mac: {} for mac in MACS}
    assert 'private-name' not in repr(result['policy'])
    assert [path for _, path, _ in calls] == ['/login.cgi', '/appGet.cgi', '/appGet.cgi', '/appGet.cgi', '/Logout.asp']
    assert calls[2][2] == 'hook=' + FULL_POLICY_HOOK


@pytest.mark.parametrize('kind,key', [('enable', pc.KEY_PC_STATE), ('block_all', pc.KEY_PC_BLOCK_ALL)])
def test_native_global_and_distinct_blockall_write_one_flag_preserve_all_rule_fields(kind, key, caplog):
    caplog.set_level(logging.DEBUG)
    result, calls, after, before, prepared, _ = asyncio.run(scenario(kind))
    writes = [payload for _, path, payload in calls if path == '/applyapp.cgi']
    assert writes == [str({'rc_service': 'restart_firewall', key: 1, 'action_mode': 'apply'})]
    assert all(after[field] == before[field] for field in PARENTAL_POLICY_KEYS if field != key)
    assert result['freshness'] == 'applied_unverified' and result['write_attempted']
    for private in ('private-name', 'private-client', MACS[0], SCHEDULE, 'synthetic-password', 'synthetic-token'):
        assert private not in json.dumps(result) and private not in caplog.text


def test_global_or_blockall_noop_zero_writes():
    for kind in ('enable', 'block_all'):
        result, calls, *_ = asyncio.run(scenario(kind, enabled=False))
        assert result['noop'] is True and result['write_attempted'] is False
        assert all(path != '/applyapp.cgi' for _, path, _ in calls)


def test_native_rule_update_preserves_entire_ordered_policy_without_router_private_state():
    from asusrouter import AsusRouter
    class ForbidUninitializedSetter(AsusRouter):
        async def async_set_state(self, *args, **kwargs):
            raise AssertionError('uninitialized router rule setter used')
    result, calls, after, before, prepared, _ = asyncio.run(scenario('rule', factory=ForbidUninitializedSetter))
    payload = next(value for _, path, value in calls if path == '/applyapp.cgi')
    assert payload.encode() != b''
    assert ast.literal_eval(payload) == {'rc_service': 'restart_firewall', **prepared.arguments, 'action_mode': 'apply'}
    assert after == prepared.after.raw
    assert after[pc.KEY_PC_MAC] == before[pc.KEY_PC_MAC]
    assert after[pc.KEY_PC_NAME] == before[pc.KEY_PC_NAME]
    assert after[pc.KEY_PC_TIMEMAP] == before[pc.KEY_PC_TIMEMAP]
    assert after[pc.KEY_PC_TYPE] == '1&#622&#621'
    assert result['after']['rules'][1]['rule_type'] == 'block'


def test_new_rule_alias_uses_unwrapped_fresh_private_inventory_and_explicit_schedule():
    result, calls, after, before, prepared, _ = asyncio.run(scenario('rule', raw=policy(0), alias=client_alias(KEY, MACS[3]), rule_type='time', schedule=SCHEDULE))
    assert after == prepared.after.raw
    assert after[pc.KEY_PC_MAC] == MACS[3]
    assert result['after']['intent']['schedule'] == SCHEDULE  # Explicit supplied intent only.
    assert calls[3][2] == 'hook=' + HOOKS['clients']
    assert all(mac not in json.dumps(result) for mac in MACS)


def test_remove_middle_then_native_whole_list_restore_recovers_original_order():
    removed_result, _, removed, original, _, _ = asyncio.run(scenario('rule', rule_type='remove'))
    assert removed[pc.KEY_PC_MAC] == '&#62'.join([MACS[0], MACS[2]])
    restored, calls, after, _, prepared, _ = asyncio.run(scenario('restore', raw=removed, original=original))
    assert after == original
    assert restored['policy_fingerprint'] == read_policy_snapshot(original, KEY).fingerprint
    assert ast.literal_eval(next(value for _, path, value in calls if path == '/applyapp.cgi')) == {'rc_service': 'restart_firewall', **pc.write_pc_rules(read_policy_snapshot(original, KEY).rules), 'action_mode': 'apply'}


@pytest.mark.parametrize('field,value', [(pc.KEY_PC_NAME, 'changed-private-name&#62private-name-1&#62private-name-2'), (pc.KEY_PC_BLOCK_ALL, '1'), (pc.KEY_PC_TIMEMAP, 'changed'), (pc.KEY_PC_TYPE, '2&#621&#621')])
def test_any_full_policy_drift_blocks_before_write(field, value):
    current = policy()
    current[field] = value
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(raw=current, expected_raw=policy(), calls=calls))
    assert caught.value.code in {'policy_changed', 'malformed_response'}
    assert all(path != '/applyapp.cgi' for _, path, _ in calls)


def test_approved_after_fingerprint_mismatch_blocks_before_write():
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(expected_after='different-approved-result', calls=calls))
    assert caught.value.code == 'after_policy_changed'
    assert all(path != '/applyapp.cgi' for _, path, _ in calls)


def test_identity_drift_blocks_before_full_policy_read():
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(identity={**IDENTITY, 'label_mac': 'AA:BB:CC:DD:EE:00'}, calls=calls))
    assert caught.value.code == 'identity_changed'
    assert all(payload != 'hook=' + FULL_POLICY_HOOK for _, _, payload in calls)


@pytest.mark.parametrize('field,value', [(pc.KEY_PC_NAME, ''), (pc.KEY_PC_TIMEMAP, ''), (pc.KEY_PC_NAME, ' name ')])
def test_native_lossy_rule_branch_is_explicit_and_never_writes(field, value):
    raw = policy(1)
    raw[field] = value
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario('rule', raw=raw, alias=client_alias(KEY, MACS[0]), calls=calls))
    assert caught.value.code == 'policy_recovery_unavailable'
    assert all(path != '/applyapp.cgi' for _, path, _ in calls)


def test_orphan_schedule_is_preserved_by_global_toggle_but_rule_edit_rejected():
    raw = policy(0)
    raw[pc.KEY_PC_TIMEMAP] = SCHEDULE
    result, _, after, before, *_ = asyncio.run(scenario(raw=raw))
    assert after[pc.KEY_PC_TIMEMAP] == before[pc.KEY_PC_TIMEMAP]
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario('rule', raw=raw, alias=client_alias(KEY, MACS[3]), rule_type='time', schedule=SCHEDULE))
    assert caught.value.code == 'policy_recovery_unavailable'


@pytest.mark.parametrize('mode', ['timeout', 'secret_error'])
def test_after_admitted_write_failure_is_uncertain_no_retry_and_logs_private(mode, caplog):
    caplog.set_level(logging.DEBUG)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(mode=mode, calls=calls))
    assert caught.value.code == 'apply_uncertain'
    assert sum(path == '/applyapp.cgi' for _, path, _ in calls) == 1
    assert sum(path == '/login.cgi' for _, path, _ in calls) == 1
    for private in ('private-name', 'synthetic-secret', MACS[0], 'synthetic-password', 'synthetic-token'):
        assert private not in caplog.text and private not in str(caught.value)


def test_native_success_ack_does_not_claim_independently_verified_policy():
    result, _, after, original, _, observed = asyncio.run(scenario(mode='ignore', observe_after=True))
    assert result['freshness'] == 'applied_unverified'
    assert observed['policy'].fingerprint == read_policy_snapshot(original, KEY).fingerprint
    assert result['policy_fingerprint'] != observed['policy'].fingerprint


def test_wrong_service_or_extra_argument_rejected_before_server_receives_apply():
    from asusrouter import AsusRouter
    class WrongService(AsusRouter):
        async def async_run_service(self, service, arguments=None, **kwargs):
            return await super().async_run_service('reboot', arguments, **kwargs)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(factory=WrongService, calls=calls))
    assert caught.value.code == 'write_boundary'
    assert all(path != '/applyapp.cgi' for _, path, _ in calls)


@pytest.mark.parametrize('mode', ['extra_argument', 'twice'])
def test_exact_native_body_and_single_attempt_guard(mode):
    from asusrouter import AsusRouter
    class DeviatingService(AsusRouter):
        async def async_run_service(self, service, arguments=None, **kwargs):
            if mode == 'extra_argument':
                return await super().async_run_service(service, {**arguments, 'unapproved': '1'}, **kwargs)
            await super().async_run_service(service, arguments, **kwargs)
            return await super().async_run_service(service, arguments, **kwargs)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(factory=DeviatingService, calls=calls))
    assert caught.value.code == ('write_boundary' if mode == 'extra_argument' else 'apply_uncertain')
    assert sum(path == '/applyapp.cgi' for _, path, _ in calls) == (0 if mode == 'extra_argument' else 1)
    assert sum(path == '/login.cgi' for _, path, _ in calls) == 1


def test_full_policy_auth_error_stops_without_retry_write_or_private_output(caplog):
    calls = []
    caplog.set_level(logging.DEBUG)
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(mode='auth_error', calls=calls))
    assert caught.value.code == 'auth_2'
    assert sum(path == '/login.cgi' for _, path, _ in calls) == 1
    assert all(path != '/applyapp.cgi' for _, path, _ in calls)
    assert 'synthetic-secret' not in str(caught.value) + caplog.text


def test_low_request_budget_refuses_before_login():
    async def check():
        async with ParentalTestServer() as server:
            from dataclasses import replace
            cfg = replace(server.config, max_requests=4)
            before = read_policy_snapshot(server.raw, KEY)
            after = await prepare_enable(before, True)
            with pytest.raises(RouterError) as caught:
                await set_parental_global(cfg, 'synthetic-password', enabled=True,
                    expected_identity=_normalize('identity', IDENTITY, KEY),
                    expected_policy_fingerprint=before.fingerprint,
                    expected_after_policy_fingerprint=after.after.fingerprint, fingerprint_key=KEY)
            assert caught.value.code == 'request_budget'
            assert server.calls == []
    asyncio.run(check())
