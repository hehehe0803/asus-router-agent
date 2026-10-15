import asyncio
import json
import socket
from types import SimpleNamespace
from urllib.parse import unquote

import aiohttp
from aiohttp import web
import pytest
from yarl import URL

from router_agent.errors import RouterError
from router_agent.transport import HOOKS, RequestGuard, TransportConfig, collect_native

NATIVE_TEXT = ('conn_stats_arr = ["100","20"];\n'
               'cpu_stats_arr = ["0.1","0.2","0.3"];\n'
               'wlc_0_arr = ["3","2","1"];\n'
               'private_fixture = ["synthetic-secret"];\n\n')


async def scenario(mode="ok", factory=None, capture=None):
    calls = [] if capture is None else capture
    async def route(request):
        body = unquote(await request.text())
        calls.append((request.method, request.path, request.query_string, body))
        if request.path == "/login.cgi":
            return web.json_response({"asus_token": "synthetic-token"})
        if request.path == "/Logout.asp":
            return web.json_response({"error_status": 8})
        if request.path == "/appGet.cgi":
            assert body == "hook=" + HOOKS["identity"]
            return web.json_response({"productid": "RT-AX86U", "firmver": "3.0.0.4", "buildno": "388", "extendno": "24436", "label_mac": "AA:BB:CC:DD:EE:FF"})
        assert request.path == "/ajax_sysinfo.asp"
        if mode == "redirect":
            raise web.HTTPFound("/login.cgi")
        if mode == "json_auth":
            return web.json_response({"error_status": 2, "password": "synthetic-secret"})
        if mode == "text_auth":
            return web.Response(text='error_status = 2;\n\n')
        if mode == "native_error":
            return web.Response(text='error_status = 999;\n\n')
        if mode == "html":
            return web.Response(text='<html><form>synthetic-secret</form></html>')
        if mode == "malformed":
            return web.Response(text='conn_stats_arr = ["synthetic-secret"];\n\n')
        if mode == "json_success":
            return web.json_response({"conn_stats_arr": [100, 20]})
        if mode == "404":
            return web.Response(status=404)
        return web.Response(text=NATIVE_TEXT)
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", route)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    cfg = TransportConfig("127.0.0.1", "synthetic-admin", use_ssl=False, allow_plain_http=True,
                          port=sock.getsockname()[1], timeout=1)
    await web.SockSite(runner, sock).start()
    try:
        return await collect_native(cfg, "synthetic-password", ("sysinfo",), fingerprint_key=b"k" * 32, router_factory=factory), calls
    finally:
        await runner.cleanup()


def test_pristine_upstream_sysinfo_one_exact_request_without_discovery_or_led_restore():
    result, calls = asyncio.run(scenario())
    assert [(m, p, q) for m, p, q, _ in calls] == [
        ("POST", "/login.cgi", ""), ("POST", "/appGet.cgi", ""),
        ("POST", "/ajax_sysinfo.asp", ""), ("POST", "/Logout.asp", "")]
    assert calls[2][3] == ""
    selected = result["data"]["sysinfo"]
    assert selected["connections"] == {"total": 100, "active": 20}
    assert selected["load_avg"] == {"one_minute": .1, "five_minutes": .2, "fifteen_minutes": .3}
    assert "synthetic-secret" not in json.dumps(result)
    assert result["sources"]["sysinfo"]["freshness"] == "unknown"
    assert result["sources"]["sysinfo"]["observed_at"] is None


@pytest.mark.parametrize("mode,code", [("json_auth", "auth_2"), ("text_auth", "auth_2"),
    ("native_error", "native_status_failed"), ("html", "malformed_response"),
    ("malformed", "malformed_response"), ("json_success", "malformed_response"),
    ("redirect", "redirect_blocked"), ("404", "http_error")])
def test_sysinfo_failures_stop_before_upstream_retry_and_never_echo_vendor_text(mode, code, caplog):
    calls = []
    with pytest.raises(RouterError) as caught:
        asyncio.run(scenario(mode, capture=calls))
    assert caught.value.code == code
    assert sum(path == "/login.cgi" for _, path, _, _ in calls) == 1
    assert sum(path == "/ajax_sysinfo.asp" for _, path, _, _ in calls) == 1
    assert "synthetic-secret" not in str(caught.value) + caplog.text
    assert not any(path in {"/apply.cgi", "/applyapp.cgi"} for _, path, _, _ in calls)


def test_upstream_repeat_blocked_and_bad_body_rejected_before_send():
    from asusrouter import AsusRouter
    from asusrouter.modules.endpoint import Endpoint
    class Repeated(AsusRouter):
        async def async_api_load(self, endpoint, request="", retry=0):
            result = await super().async_api_load(endpoint, request, retry)
            if endpoint == Endpoint.SYSINFO:
                await super().async_api_load(endpoint, request, retry)
            return result
    class BadBody(AsusRouter):
        async def async_api_load(self, endpoint, request="", retry=0):
            return await super().async_api_load(endpoint, "synthetic-secret" if endpoint == Endpoint.SYSINFO else request, retry)
    for factory, sent in ((Repeated, 1), (BadBody, 0)):
        calls = []
        with pytest.raises(RouterError) as caught:
            asyncio.run(scenario(factory=factory, capture=calls))
        assert caught.value.code == "read_boundary"
        assert sum(path == "/ajax_sysinfo.asp" for _, path, _, _ in calls) == sent
        assert not any(body == "synthetic-secret" for _, _, _, body in calls)


@pytest.mark.parametrize("url,method,allowed,auth", [
    ("https://router.example/ajax_sysinfo.asp", "GET", True, True),
    ("https://router.example/ajax_sysinfo.asp?x=1", "POST", True, True),
    ("https://other.example/ajax_sysinfo.asp", "POST", True, True),
    ("https://router.example/ajax_sysinfo.asp", "POST", False, True),
    ("https://router.example/ajax_sysinfo.asp", "POST", True, False),
])
def test_sysinfo_exact_origin_method_query_and_auth_boundary(url, method, allowed, auth):
    async def run():
        guard = RequestGuard(TransportConfig("router.example", "synthetic-admin"), allow_sysinfo=allowed)
        guard.authenticated = auth
        with pytest.raises(RouterError) as caught:
            await guard.start(None, None, SimpleNamespace(url=URL(url), method=method))
        assert caught.value.code == ("auth_required" if not auth else "read_boundary")
    asyncio.run(run())
