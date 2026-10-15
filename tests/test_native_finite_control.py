import ast
import asyncio
from copy import deepcopy
import socket
from urllib.parse import unquote

import pytest
from aiohttp import web

from router_agent.errors import RouterError
from router_agent.finite_controls import prepare, settings_hook
from router_agent.native_finite_control import read, write
from router_agent.transport import HOOKS, TransportConfig, _normalize
from tls_helpers import localhost_tls
from test_finite_controls import CASES, fixture
from test_native_parental_control import IDENTITY

KEY = b'f'*32


async def scenario(operation,intent,*,mode='ok',noop=False):
    raw = fixture(operation,intent)
    if noop:
        flag = next(flag for op, case, flag in CASES if op == operation and case == intent)
        raw[flag] = '1'
    expected = deepcopy(raw)
    prepared = await prepare(operation,expected,intent)
    if mode == 'drift':raw['future_setting'] = 'changed'
    calls = [];admissions=[]
    async def handle(request):
        body = unquote(await request.text());calls.append((request.path,body))
        if request.path == '/login.cgi':return web.json_response({'asus_token':'synthetic-token'})
        if request.path == '/Logout.asp':return web.json_response({'error_status':8})
        if request.path == '/appGet.cgi':
            if body == 'hook='+HOOKS['identity']:
                identity = {**IDENTITY,'productid':'unsupported'} if mode=='target' else IDENTITY
                return web.json_response(identity)
            assert body == 'hook='+settings_hook(operation,intent)
            return web.json_response(raw)
        assert request.path == '/applyapp.cgi'
        command = ast.literal_eval(body)
        assert command == {'rc_service':prepared.service,**prepared.arguments,'action_mode':'apply'}
        for key,value in prepared.after.items():
            if key in command:raw[key]=str(command[key])
        if mode == 'timeout':await asyncio.sleep(.2)
        if mode == 'bad_ack':return web.json_response({'run_service':'private-secret-vendor-error'})
        return web.json_response({'run_service':prepared.service,'modify':'1'})
    app = web.Application();app.router.add_route('*','/{path:.*}',handle)
    runner = web.AppRunner(app,access_log=None);await runner.setup()
    sock = socket.socket();sock.bind(('127.0.0.1',0))
    with localhost_tls() as (context,ca_file):
        await web.SockSite(runner,sock,ssl_context=context).start()
        config = TransportConfig('127.0.0.1','synthetic-admin',ca_file=ca_file,port=sock.getsockname()[1],timeout=.05 if mode=='timeout' else 1)
        def admit():
            admissions.append(True)
            if mode == 'denied':raise RouterError('approval_expired','Synthetic expiration.')
        try:
            result = await write(config,'synthetic-password',operation,intent=intent,expected_identity=_normalize('identity',IDENTITY,KEY),expected_before_raw=expected,expected_after_raw=prepared.after,fingerprint_key=KEY,authorization_check=admit)
            if mode == 'inverse':
                inverse_intent={**intent,'enabled':False}
                inverse=await prepare(operation,prepared.after,inverse_intent)
                assert inverse.after == expected
                prepared=inverse
                restored=await write(config,'synthetic-password',operation,intent=inverse_intent,expected_identity=_normalize('identity',IDENTITY,KEY),expected_before_raw=inverse.before,expected_after_raw=inverse.after,fingerprint_key=KEY,authorization_check=admit)
                assert restored['write_attempted'] and raw == expected
            return result,calls,admissions
        except RouterError as error:return error,calls,admissions
        finally:await runner.cleanup()


@pytest.mark.parametrize('operation,intent,flag',CASES)
def test_native_wire_one_send(operation,intent,flag):
    result,calls,admissions = asyncio.run(scenario(operation,intent))
    assert not isinstance(result,Exception),result
    assert result['write_attempted'] and len(admissions)==1
    assert sum(path=='/applyapp.cgi' for path,body in calls)==1


@pytest.mark.parametrize('mode,code,send',[('drift','policy_changed',0),('target','unsupported_vpn_settings_target',0),('denied','approval_expired',0),('bad_ack','apply_uncertain',1),('timeout','apply_uncertain',1)])
def test_drift_admission_uncertainty(mode,code,send):
    operation,intent,flag = CASES[0]
    result,calls,admissions = asyncio.run(scenario(operation,intent,mode=mode))
    assert isinstance(result,RouterError) and result.code==code
    assert 'private-secret' not in str(result)
    assert sum(path=='/applyapp.cgi' for path,body in calls)==send
    if mode == 'target':assert len([path for path,body in calls if path=='/appGet.cgi'])==1


def test_native_noop_zero_admission_zero_send():
    result,calls,admissions = asyncio.run(scenario(*CASES[0][:2],noop=True))
    assert result['noop'] and not result['write_attempted'] and admissions==[]
    assert all(path!='/applyapp.cgi' for path,body in calls)


def test_aura_capability_gate_before_settings(monkeypatch):
    import router_agent.native_finite_control as native
    from router_agent.hardware_reads import AURA_CAPABILITY_HOOK
    class Router:
        def __init__(self, marker):self.calls=[];self.marker=marker
        async def async_api_hook(self, hook):
            self.calls.append(hook)
            if hook == HOOKS['identity']:return IDENTITY
            assert hook == AURA_CAPABILITY_HOOK
            return {'ledg_rgb1':self.marker}
    for marker,code in [('', 'unsupported_capability'),(None,'unsupported_capability')]:
        router=Router(marker)
        with pytest.raises(RouterError) as exc:
            asyncio.run(native._observe(router,'state.aura',None,KEY))
        assert exc.value.code == code
        assert router.calls == [HOOKS['identity'],AURA_CAPABILITY_HOOK]


def test_exact_body_guard_rejects_payload_change_and_replay():
    from types import SimpleNamespace
    import aiohttp
    from yarl import URL
    from router_agent.native_finite_control import FiniteGuard, finite_body
    operation,intent,flag = CASES[0]
    prepared=asyncio.run(prepare(operation,fixture(operation,intent),intent))
    async def run():
        calls=[];admit=[]
        guard=FiniteGuard(TransportConfig('localhost','synthetic'),operation,intent,lambda:admit.append(True))
        guard.authenticated=True;await guard.arm(prepared)
        async def handler(request):calls.append(True);return 'synthetic'
        request=SimpleNamespace(url=URL('https://localhost:8443/applyapp.cgi'),body=aiohttp.payload.StringPayload(finite_body(prepared.service,{'vts_enable_x':0}).decode()))
        with pytest.raises(RouterError):await guard.middleware(request,handler)
        assert not calls and not admit
        request.body=aiohttp.payload.StringPayload(guard.expected_body.decode())
        assert await guard.middleware(request,handler)=='synthetic'
        with pytest.raises(RouterError):await guard.middleware(request,handler)
        assert len(calls)==len(admit)==1
    asyncio.run(run())


@pytest.mark.parametrize('operation,intent,flag',CASES)
def test_native_independently_admitted_exact_inverse(operation,intent,flag):
    result,calls,admissions=asyncio.run(scenario(operation,intent,mode='inverse'))
    assert not isinstance(result,Exception),result
    assert len(admissions)==2
    assert sum(path=='/applyapp.cgi' for path,body in calls)==2


def test_guard_refuses_nonfinite_service_even_with_valid_snapshot():
    from dataclasses import replace
    from router_agent.native_finite_control import FiniteGuard
    operation,intent,flag=CASES[0]
    prepared=asyncio.run(prepare(operation,fixture(operation,intent),intent))
    guard=FiniteGuard(TransportConfig('localhost','synthetic'),operation,intent,lambda:None)
    with pytest.raises(RouterError) as exc:
        asyncio.run(guard.arm(replace(prepared,service='unreviewed_service')))
    assert exc.value.code=='write_boundary' and guard.expected_body is None
