import ast
import asyncio
from copy import deepcopy
import json
import logging
import socket
from urllib.parse import unquote
from aiohttp import web
import pytest
from tls_helpers import localhost_tls
from test_protected_vpn import RAW, KEY, SECRET
from router_agent.errors import RouterError
from router_agent.protected_vpn import VPN_HOOK, prepare, parse_snapshot, select_profiles
from router_agent.native_vpn_control import read_vpn, write_vpn, VPNGuard
from router_agent.transport import HOOKS, TransportConfig

NATIVE_IDENTITY = {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436-ge7c0b5e', 'label_mac': 'AA:BB:CC:DD:EE:FF'}


def firmware_hook_encode(value):
    """Independent ej_nvram_get fixture: encode storage, not compiler output."""
    result = []
    for char in value:
        if char in '<>&"' or not 32 <= ord(char) <= 126:
            result.append('&#' + str(ord(char)))
        elif char == '\\':
            result.append('\\\\')  # app-origin branch; this domain remains rejected.
        else:
            result.append(char)
    return ''.join(result)


class VPNServer:
    def __init__(self, mode='ok', *, encoded=False):
        self.encoded = encoded
        self.raw, self.identity, self.calls, self.mode = deepcopy(RAW), deepcopy(NATIVE_IDENTITY), [], mode

    async def __aenter__(self):
        async def handle(request):
            payload = unquote(await request.text())
            self.calls.append((request.path, payload))
            if request.path == '/login.cgi':
                return web.json_response({'asus_token': 'synthetic-token'})
            if request.path == '/Logout.asp':
                return web.json_response({'error_status': 8})
            if request.path == '/appGet.cgi':
                if payload == 'hook=' + HOOKS['identity']:
                    return web.json_response(self.identity)
                if payload == 'hook=' + VPN_HOOK:
                    response = deepcopy(self.raw)
                    if self.encoded:
                        response['vpnc_clientlist'] = firmware_hook_encode(response['vpnc_clientlist'])
                    return web.json_response(response)
                raise AssertionError('unexpected hook')
            if request.path == '/applyapp.cgi':
                command = ast.literal_eval(payload)
                self.raw['vpnc_clientlist'] = command['vpnc_clientlist']
                self.raw['vpnc_unit'] = str(command['vpnc_unit'])
                if self.mode == 'timeout':
                    await asyncio.sleep(.2)
                if self.mode == 'secret_error':
                    return web.json_response({'run_service': SECRET})
                return web.json_response({'run_service': command['rc_service'], 'modify': '1'})
            raise AssertionError('unexpected request')
        app = web.Application()
        app.router.add_route('*', '/{path:.*}', handle)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        self.tls = localhost_tls()
        context, ca = self.tls.__enter__()
        await web.SockSite(self.runner, sock, ssl_context=context).start()
        self.config = TransportConfig('127.0.0.1', 'synthetic-admin', port=sock.getsockname()[1], ca_file=ca, timeout=.05 if self.mode == 'timeout' else 1)
        return self

    async def __aexit__(self, *args):
        await self.runner.cleanup()
        self.tls.__exit__(*args)

    @property
    def writes(self):
        return [payload for path, payload in self.calls if path == '/applyapp.cgi']


async def planned(server, enabled=True, *, index=0, kind='openvpn_client'):
    observed = await read_vpn(server.config, SECRET, fingerprint_key=KEY)
    profile_ref = parse_snapshot(observed['raw'], KEY, observed['identity']).profiles[index]['profile_ref']
    intent = {'kind': kind, 'profile_ref': profile_ref, 'enabled': enabled}
    prepared = await prepare(observed['raw'], intent, KEY, observed['identity'])
    return {'expected_identity': observed['identity'], 'before_raw': prepared['before_raw'], 'after_raw': prepared['after_raw'], 'intent': intent, 'fingerprint_key': KEY}


def test_exact_native_send_independent_verify_and_inverse(caplog):
    async def scenario():
        async with VPNServer() as server:
            args = await planned(server)
            admissions = []
            result = await write_vpn(server.config, SECRET, **args, authorization_check=lambda: admissions.append(True))
            assert result['write_attempted'] is True and admissions == [True] and len(server.writes) == 1
            command = ast.literal_eval(server.writes[0])
            assert command == {'rc_service': 'restart_vpnc', 'vpnc_unit': 0, 'vpnc_clientlist': args['after_raw']['vpnc_clientlist'], 'action_mode': 'apply'}
            fresh = await read_vpn(server.config, SECRET, fingerprint_key=KEY)
            assert fresh['raw']['vpnc_clientlist'] == args['after_raw']['vpnc_clientlist']
            inverse = await planned(server, enabled=False)
            await write_vpn(server.config, SECRET, **inverse, authorization_check=lambda: None)
            assert server.raw['vpnc_clientlist'] == RAW['vpnc_clientlist']
            assert SECRET not in json.dumps(result)
    with caplog.at_level(logging.DEBUG):
        asyncio.run(scenario())
    assert SECRET not in caplog.text and 'private-name' not in caplog.text


def test_noop_zero_send_and_no_admission():
    async def scenario():
        async with VPNServer() as server:
            args = await planned(server, enabled=False)
            def forbidden():
                raise AssertionError('noop admission')
            result = await write_vpn(server.config, SECRET, **args, authorization_check=forbidden)
            assert result['noop'] is True and result['write_attempted'] is False and server.writes == []
    asyncio.run(scenario())


@pytest.mark.parametrize('drift', ['identity', 'credentials', 'order', 'authorization', 'missing_authorization', 'expected_after', 'selected_unit'])
def test_admission_drift_rejections_have_zero_sends(drift):
    async def scenario():
        async with VPNServer() as server:
            args = await planned(server)
            def admission():
                if drift == 'authorization':
                    raise RouterError('expired', 'Expired operation.')
            if drift == 'identity':
                server.identity['label_mac'] = 'AA:BB:CC:DD:EE:01'
            elif drift == 'credentials':
                server.raw['vpnc_clientlist'] = server.raw['vpnc_clientlist'].replace(SECRET, 'changed-secret')
            elif drift == 'order':
                server.raw['vpnc_clientlist'] = '<'.join(reversed(server.raw['vpnc_clientlist'].split('<')))
            elif drift == 'selected_unit':
                server.raw['vpnc_unit'] = '1'
            elif drift == 'expected_after':
                args['after_raw']['vpnc_clientlist'] += '<'
            with pytest.raises(RouterError):
                await write_vpn(server.config, SECRET, **args, authorization_check=None if drift == 'missing_authorization' else admission)
            assert not server.writes
    asyncio.run(scenario())


def test_runtime_status_drift_allowed():
    async def scenario():
        async with VPNServer() as server:
            args = await planned(server)
            server.raw['get_vpnc_status'] = '2>0>5'
            await write_vpn(server.config, SECRET, **args, authorization_check=lambda: None)
            assert len(server.writes) == 1
    asyncio.run(scenario())


@pytest.mark.parametrize('mode', ['timeout', 'secret_error'])
def test_uncertain_outcome_one_send_no_replay_or_leak(mode):
    async def scenario():
        async with VPNServer(mode) as server:
            args = await planned(server)
            with pytest.raises(RouterError) as error:
                await write_vpn(server.config, SECRET, **args, authorization_check=lambda: None)
            assert error.value.code == 'apply_uncertain'
            assert SECRET not in str(error.value) and len(server.writes) == 1
    asyncio.run(scenario())


def test_guard_body_and_second_send_rejected_before_handler():
    from types import SimpleNamespace
    from aiohttp.payload import StringPayload
    from yarl import URL
    async def scenario():
        config = TransportConfig('127.0.0.1', 'synthetic-admin', port=12345)
        guard = VPNGuard(config, authorization_check=lambda: None)
        guard.authenticated = True
        command = {'service': 'restart_vpnc', 'arguments': {'vpnc_unit': 0, 'vpnc_clientlist': RAW['vpnc_clientlist']}, 'apply': True, 'expect_modify': False}
        guard.arm(command)
        request = SimpleNamespace(url=URL('https://127.0.0.1:12345/applyapp.cgi'), body=StringPayload('unexpected-secret'))
        sent = []
        async def handler(req):
            sent.append(True)
        with pytest.raises(RouterError):
            await guard.middleware(request, handler)
        assert sent == []
        request.body = StringPayload(guard.expected_body.decode())
        # RequestGuard's read middleware has no action branch and forwards exact bytes.
        await guard.middleware(request, handler)
        with pytest.raises(RouterError):
            await guard.middleware(request, handler)
        assert sent == [True]
    asyncio.run(scenario())


@pytest.mark.parametrize('kind,index', [('vpnc', 0), ('openvpn_client', 0), ('wireguard_client', 1)])
def test_encoded_hook_actual_native_https_forward_inverse(kind, index, caplog):
    async def scenario():
        async with VPNServer(encoded=True) as server:
            server.raw['vpnc_unit'] = str(index)
            # Single quote, percent, braces and ordinary semicolons survive the
            # maintained str/URL quoting path. Double quote/backslash stay blocked.
            server.raw['vpnc_clientlist'] = server.raw['vpnc_clientlist'].replace('opaque', "opaque'%;{}[]") + '<<'
            original_storage = deepcopy(server.raw)
            original_read = firmware_hook_encode(original_storage['vpnc_clientlist'])
            enabled = index == 0
            args = await planned(server, enabled, index=index, kind=kind)
            assert args['before_raw']['vpnc_clientlist'] == original_read
            output = await write_vpn(server.config, SECRET, **args, authorization_check=lambda: None)
            command = ast.literal_eval(server.writes[0])
            assert command['vpnc_clientlist'] == server.raw['vpnc_clientlist']
            assert '>' in command['vpnc_clientlist'] and '&#62' not in command['vpnc_clientlist']
            observed = await read_vpn(server.config, SECRET, fingerprint_key=KEY)
            assert observed['raw']['vpnc_clientlist'] == args['after_raw']['vpnc_clientlist']
            inverse = await planned(server, not enabled, index=index, kind=kind)
            await write_vpn(server.config, SECRET, **inverse, authorization_check=lambda: None)
            restored = await read_vpn(server.config, SECRET, fingerprint_key=KEY)
            assert server.raw == original_storage
            assert restored['raw']['vpnc_clientlist'] == original_read
            assert len(server.writes) == 2
            assert SECRET not in json.dumps(output)
    with caplog.at_level(logging.DEBUG):
        asyncio.run(scenario())
    for secret in (SECRET, 'private-name', 'private-login', "opaque'%;{}[]"):
        assert secret not in caplog.text


def test_encoded_noop_and_storage_drift_send_boundary():
    async def scenario():
        async with VPNServer(encoded=True) as server:
            noop = await planned(server, enabled=False)
            result = await write_vpn(server.config, SECRET, **noop)
            assert result['noop'] is True and not server.writes
            change = await planned(server)
            server.raw['vpnc_clientlist'] = server.raw['vpnc_clientlist'].replace(SECRET, 'changed-private-secret')
            with pytest.raises(RouterError) as error:
                await write_vpn(server.config, SECRET, **change, authorization_check=lambda: None)
            assert error.value.code == 'policy_changed' and not server.writes
    asyncio.run(scenario())


@pytest.mark.parametrize('secret', ['a&b', 'a"b', 'a\\b', 'a&#62b', 'aé'])
def test_firmware_encoding_unproven_native_credentials_no_send(secret, caplog):
    async def scenario():
        async with VPNServer(encoded=True) as server:
            server.raw['vpnc_clientlist'] = server.raw['vpnc_clientlist'].replace(SECRET, secret)
            with pytest.raises(RouterError):
                await planned(server)
            assert not server.writes
    with caplog.at_level(logging.DEBUG):
        asyncio.run(scenario())
    assert 'private-name' not in caplog.text and SECRET not in caplog.text
