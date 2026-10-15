import asyncio
import json
import ssl

from aiohttp import web
import pytest

from tls_helpers import localhost_tls
from router_agent.auth import init_auth, load_config, validate_config
from router_agent.errors import RouterError
from router_agent.native_control import set_led
from router_agent.native_parental_control import set_parental_global
from router_agent.tls import ssl_context
from router_agent.transport import TransportConfig, probe_auth


def test_ssl_defaults_and_auth_config_roundtrip(tmp_path):
    with localhost_tls() as (_, ca_file):
        config = validate_config('https://localhost', 'synthetic', ca_file=ca_file)
        assert TransportConfig.from_auth(config).ca_file == ca_file
        context = ssl_context(ca_file)
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED


def test_ca_config_persists_without_credentials_and_old_config_still_loads(tmp_path, monkeypatch):
    monkeypatch.setattr('sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('sys.stderr.isatty', lambda: True)
    class Backend:
        def set_password(self, *args):
            pass
    with localhost_tls() as (_, ca_file):
        state = tmp_path / 'state'
        init_auth('https://localhost', 'synthetic', state_dir=state, backend=Backend(),
                  password_reader=lambda _: 'synthetic-secret', ca_file=ca_file)
        assert load_config(state).ca_file == ca_file
        raw = (state / 'config.json').read_text()
        assert 'synthetic-secret' not in raw
        old = json.loads(raw)
        del old['ca_file']
        (state / 'config.json').write_text(json.dumps(old))
        assert load_config(state).ca_file is None


@pytest.mark.parametrize('kind', ['missing', 'directory', 'invalid', 'oversized', 'unreadable'])
def test_bad_ca_fails_before_password_or_keyring(tmp_path, monkeypatch, kind):
    ca = tmp_path / 'ca.pem'
    if kind == 'directory':
        ca.mkdir()
    elif kind != 'missing':
        ca.write_bytes(b'x' * (1024 * 1024 + 1 if kind == 'oversized' else 10))
    if kind == 'unreadable':
        monkeypatch.setattr('router_agent.tls.ssl.create_default_context', lambda **kw: (_ for _ in ()).throw(PermissionError()))
    with pytest.raises(RouterError) as caught:
        init_auth('https://localhost', 'synthetic', state_dir=tmp_path/'state',
                  backend=object(), password_reader=lambda _: pytest.fail('password accessed'), ca_file=str(ca))
    assert caught.value.code == 'invalid_ca_file'
    assert not (tmp_path/'state').exists()


@pytest.mark.parametrize('mode', ['trusted', 'untrusted', 'wrong_hostname'])
def test_actual_upstream_login_obeys_connector_ca_and_hostname(mode):
    async def run():
        calls = []
        async def handle(request):
            calls.append(request.path)
            return web.json_response({'asus_token': 'synthetic-token'} if request.path == '/login.cgi' else {'error_status': 8})
        with localhost_tls(san='DNS:wrong.invalid' if mode == 'wrong_hostname' else 'IP:127.0.0.1,DNS:localhost') as (context, ca_file):
            app = web.Application()
            app.router.add_route('*', '/{path:.*}', handle)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, '127.0.0.1', 0, ssl_context=context)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            config = TransportConfig('127.0.0.1', 'synthetic', port=port,
                                     ca_file=None if mode == 'untrusted' else ca_file, timeout=2)
            try:
                if mode == 'trusted':
                    await probe_auth(config, 'synthetic-password')
                    assert calls == ['/login.cgi', '/Logout.asp']
                else:
                    with pytest.raises(RouterError):
                        await probe_auth(config, 'synthetic-password')
                    assert not calls  # TLS fails before an HTTP login body is sent.
            finally:
                await runner.cleanup()
    asyncio.run(run())


@pytest.mark.parametrize('operation', ['led', 'parental'])
def test_native_http_write_rejected_before_login_even_invalid_or_noop_binding(operation, monkeypatch):
    config = TransportConfig('localhost', 'synthetic', use_ssl=False, allow_plain_http=True)
    monkeypatch.setattr('router_agent.tls.verified_session', lambda *a, **kw: pytest.fail('session opened'))
    async def run():
        if operation == 'led':
            return await set_led(config, 'synthetic', expected_identity={}, expected_before=True, enabled=True, fingerprint_key=b'x'*32)
        return await set_parental_global(config, 'synthetic', expected_identity={}, expected_policy_fingerprint='',
                                         expected_after_policy_fingerprint='', enabled=True, fingerprint_key=b'x'*32)
    with pytest.raises(RouterError) as caught:
        asyncio.run(run())
    assert caught.value.code == 'https_required'
