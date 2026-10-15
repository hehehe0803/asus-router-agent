import asyncio
import json
import logging
import socket
from urllib.parse import unquote

import aiohttp
from aiohttp import web
import pytest

from tls_helpers import localhost_tls
from router_agent.errors import RouterError
from router_agent.native_control import LEDGuard, SUPPORTED_FIRMWARE, led_body, set_led
from router_agent.transport import HOOKS, TransportConfig, _normalize

KEY = b'k' * 32
IDENTITY = {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': '24436-ge7c0b5e', 'label_mac': 'AA:BB:CC:DD:EE:FF'}


async def scenario(*, enabled=False, before=True, raw_identity=None, expected=None, led='1', apply_mode='ok', router_factory=None, calls=None):
    calls = [] if calls is None else calls
    async def handler(request):
        payload = await request.text()
        calls.append((request.path, payload))
        if request.path == '/login.cgi':
            return web.json_response({'asus_token': 'synthetic-token'})
        if request.path == '/Logout.asp':
            return web.json_response({'error_status': 8})
        if request.path == '/appGet.cgi':
            return web.json_response((raw_identity or IDENTITY) if unquote(payload) == 'hook=' + HOOKS['identity'] else {'led_val': led, 'password': 'synthetic-secret'})
        if request.path == '/applyapp.cgi':
            if apply_mode == 'timeout':
                await asyncio.sleep(.2)
            if apply_mode == 'secret_error':
                return web.json_response({'run_service': 'wrong', 'password': 'synthetic-secret'})
            return web.json_response({'run_service': 'start_ctrl_led'})
        raise AssertionError('unreviewed endpoint')
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    tls = localhost_tls()
    context, ca_file = tls.__enter__()
    await web.SockSite(runner, sock, ssl_context=context).start()
    cfg = TransportConfig('127.0.0.1', 'synthetic-admin', ca_file=ca_file, port=port, timeout=.05 if apply_mode == 'timeout' else 1)
    try:
        result = await set_led(cfg, 'synthetic-password', expected_identity=expected or _normalize('identity', raw_identity or IDENTITY, KEY), expected_before=before, enabled=enabled, fingerprint_key=KEY, router_factory=router_factory, authorization_check=lambda:None)
        return result, calls
    finally:
        await runner.cleanup()
        tls.__exit__(None, None, None)


@pytest.mark.parametrize('enabled,led', [(False, '1'), (True, '0')])
def test_pristine_upstream_led_wire_body_is_exactly_reviewed(enabled, led):
    result, calls = asyncio.run(scenario(enabled=enabled, before=not enabled, led=led))
    assert [path for path, _ in calls] == ['/login.cgi', '/appGet.cgi', '/appGet.cgi', '/applyapp.cgi', '/Logout.asp']
    assert calls[3][1].encode() == led_body(enabled)
    assert unquote(calls[3][1]) == str({'rc_service': 'start_ctrl_led', 'led_val': int(enabled), 'action_mode': 'apply'})
    assert result['freshness'] == 'applied_unverified'
    assert result['write_attempted'] is True


def test_noop_issues_zero_writes():
    result, calls = asyncio.run(scenario(enabled=True))
    assert all(path != '/applyapp.cgi' for path, _ in calls)
    assert result['noop'] is True and result['write_attempted'] is False
    assert result['freshness'] == 'unknown'


@pytest.mark.parametrize('kwargs,code', [({'before': False}, 'state_changed'), ({'led': ''}, 'state_changed'), ({'expected': {'device_fingerprint': 'different', 'model': 'RT-AX86U', 'firmware': SUPPORTED_FIRMWARE}}, 'identity_changed'), ({'raw_identity': {**IDENTITY, 'productid': 'OTHER-MODEL'}}, 'unsupported_firmware'), ({'raw_identity': {**IDENTITY, 'extendno': 'different'}}, 'unsupported_firmware')])
def test_prewrite_identity_model_firmware_or_before_drift_never_writes(kwargs, code):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(calls=calls, **kwargs))
    assert caught.value.code == code
    assert all(path != '/applyapp.cgi' for path, _ in calls)


@pytest.mark.parametrize('mode', ['timeout', 'secret_error'])
def test_postwrite_failure_is_uncertain_no_retry_and_scrubbed(mode, caplog):
    caplog.set_level(logging.DEBUG)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(calls=calls, apply_mode=mode))
    assert caught.value.code == 'apply_uncertain'
    assert sum(path == '/applyapp.cgi' for path, _ in calls) == 1
    assert sum(path == '/login.cgi' for path, _ in calls) == 1
    assert 'synthetic-secret' not in caplog.text
    assert 'synthetic-secret' not in str(caught.value)


@pytest.mark.parametrize('body', ["{'rc_service': 'reboot', 'led_val': 0, 'action_mode': 'apply'}", "{'rc_service': 'start_ctrl_led', 'led_val': 1, 'action_mode': 'apply'}", "{'rc_service': 'start_ctrl_led', 'led_val': 0, 'action_mode': 'apply', 'wgc1_priv': 'synthetic-secret'}"])
def test_wrong_body_rejected_before_handler_transmits_bytes(body):
    async def run():
        cfg = TransportConfig('127.0.0.1', 'synthetic', use_ssl=False, allow_plain_http=True)
        guard = LEDGuard(cfg, False, authorization_check=lambda:None)
        guard.authenticated = True
        guard.armed = True
        reached = []
        async def forbidden_handler(request):
            reached.append(True)
            raise AssertionError('request reached sender')
        request = aiohttp.ClientRequest('POST', cfg.origin.with_path('/applyapp.cgi'), data=__import__('urllib.parse', fromlist=['quote']).quote(body))
        with pytest.raises(RouterError) as caught:
            await guard.middleware(request, forbidden_handler)
        assert caught.value.code == 'write_boundary'
        assert not reached and not guard.write_attempted
    asyncio.run(run())


def test_second_exact_write_is_rejected_before_handler():
    async def run():
        cfg = TransportConfig('127.0.0.1', 'synthetic', use_ssl=False, allow_plain_http=True)
        guard = LEDGuard(cfg, False, authorization_check=lambda:None)
        guard.authenticated = True
        guard.armed = True
        sends = []
        async def handler(request):
            sends.append(True)
            return None
        request = aiohttp.ClientRequest('POST', cfg.origin.with_path('/applyapp.cgi'), data=led_body(False).decode())
        await guard.middleware(request, handler)
        with pytest.raises(RouterError):
            await guard.middleware(request, handler)
        assert sends == [True]
    asyncio.run(run())


def test_wrong_public_service_is_rejected_before_server_receives_write():
    from asusrouter import AsusRouter
    class WrongService(AsusRouter):
        async def async_set_state(self, state, **kwargs):
            return await self.async_run_service('reboot', {'led_val': 0}, apply=True)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(router_factory=WrongService, calls=calls))
    assert caught.value.code == 'write_boundary'
    assert all(path != '/applyapp.cgi' for path, _ in calls)


def test_upstream_second_write_attempt_never_reaches_server():
    from asusrouter import AsusRouter
    class Twice(AsusRouter):
        async def async_set_state(self, state, **kwargs):
            await super().async_set_state(state, **kwargs)
            return await super().async_set_state(state, **kwargs)
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(router_factory=Twice, calls=calls))
    assert caught.value.code == 'apply_uncertain'
    assert sum(path == '/applyapp.cgi' for path, _ in calls) == 1


def test_guard_missing_authority_callback_refuses_exact_body():
    async def run():
        cfg = TransportConfig('127.0.0.1', 'synthetic', use_ssl=False, allow_plain_http=True)
        guard = LEDGuard(cfg, False)
        guard.authenticated = guard.armed = True
        request = aiohttp.ClientRequest('POST', cfg.origin.with_path('/applyapp.cgi'), data=led_body(False).decode())
        async def handler(_): pytest.fail('must refuse before handler')
        with pytest.raises(RouterError) as error:
            await guard.middleware(request, handler)
        assert error.value.code == 'approval_window_required' and not guard.write_attempted
    asyncio.run(run())
