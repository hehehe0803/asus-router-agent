import asyncio
import json

import pytest

from router_agent.errors import RouterError
from router_agent.output import envelope
from router_agent.snapshots import SnapshotStore
from router_agent.transport import HOOKS, TransportConfig, collect_native
from router_agent.wan_reads import WAN_HOOK, normalize_wan


def complete():
    raw = {"get_wan_unit": "0", "link_internet": "2", "link_wan": "1", "link_wan1": "0", "wans_mode": "fo"}
    for i in (0, 1):
        raw.update({f"wan{i}_state_t": "2", f"wan{i}_sbstate_t": "0", f"wan{i}_auxstate_t": "0",
                    f"wan{i}_primary": str(1-i), f"wan{i}_proto": "dhcp" if i == 0 else "manual"})
    return raw


def test_pinned_selected_hook_and_schema_omit_addresses_and_secrets():
    assert HOOKS["wan"] == WAN_HOOK
    assert WAN_HOOK.startswith("get_wan_unit();nvram_get(link_internet);")
    for name in ("realip", "ipaddr", "dns", "gateway", "passwd", "psk"):
        assert name not in WAN_HOOK
    raw = {**complete(), "wan0_ipaddr": "192.0.2.1", "wan0_passwd": "synthetic-secret"}
    result = normalize_wan(raw)
    assert result["unit"] == 0 and result["link_code"] == 2
    assert result["slots"][0] == {"unit": 0, "link_code": 1, "state_code": 2,
                                  "sbstate_code": 0, "auxstate_code": 0, "primary": True, "protocol": "dhcp"}
    assert result["slots"][1]["protocol"] == "static"
    assert result["dualwan_mode"] == "fo"
    assert "synthetic-secret" not in json.dumps(result) and "192.0.2.1" not in json.dumps(result)


def test_missing_optional_contract_fields_are_unknown_not_health():
    result = normalize_wan({"get_wan_unit": "1", "link_internet": "2"})
    assert result["slots"][0]["state_code"] is None
    assert result["slots"][1]["primary"] is None
    assert result["slots"][1]["protocol"] == "unknown"
    assert result["dualwan_mode"] is None
    assert "wan0_state_t_unavailable" in result["gaps"]


def test_unrecognised_protocol_is_finite_unknown_and_codes_preserved():
    raw = complete()
    raw["wan0_proto"] = "synthetic-secret"
    raw["wan0_state_t"] = "999"
    result = normalize_wan(raw)
    assert result["slots"][0]["protocol"] == "unknown"
    assert result["slots"][0]["state_code"] == 999
    assert "wan0_proto_unrecognised" in result["gaps"]
    assert "synthetic-secret" not in json.dumps(result)


@pytest.mark.parametrize("key,value", [("get_wan_unit", "2"), ("link_internet", "10"),
    ("wan0_state_t", ""), ("wan1_sbstate_t", None), ("wan1_auxstate_t", True),
    ("link_wan", "x"), ("wan1_primary", "2"), ("wan0_proto", []),
    ("wan0_proto", "x" * 65), ("wans_mode", "private-mode"), ("wan0_state_t", "2147483648")])
def test_malformed_present_fields_fail_closed(key, value):
    raw = complete()
    raw[key] = value
    with pytest.raises(RouterError) as caught:
        normalize_wan(raw)
    assert caught.value.code == "malformed_response"
    assert "private-mode" not in str(caught.value)


def test_snapshot_and_envelope_preserve_exact_normalized_fields(tmp_path):
    result = normalize_wan(complete())
    payload = {"data": {"wan": result}, "freshness": "unknown"}
    store = SnapshotStore(tmp_path / "state")
    saved = store.save(payload, {"schema": 1, "device": "fixture", "firmware": "fixture", "catalog": "fixture"})
    assert saved["data"] == payload
    assert envelope(payload)["data"] == payload


def test_actual_pristine_upstream_localhost_trace_uses_one_selected_wan_hook():
    from aiohttp import web
    import socket
    async def scenario():
        calls = []
        async def route(request):
            from urllib.parse import unquote
            body = unquote(await request.text())
            calls.append((request.path, body))
            if request.path == "/login.cgi":
                return web.json_response({"asus_token": "synthetic-token"})
            if request.path == "/Logout.asp":
                return web.json_response({"error_status": 8})
            if body == "hook=" + HOOKS["identity"]:
                return web.json_response({"productid": "RT-AX86U", "firmver": "3.0.0.4", "buildno": "388", "extendno": "24436", "label_mac": "AA:BB:CC:DD:EE:FF"})
            assert body == "hook=" + WAN_HOOK
            return web.json_response(complete())
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
            result = await collect_native(cfg, "synthetic-password", ("wan",), fingerprint_key=b"k" * 32)
        finally:
            await runner.cleanup()
        assert [path for path, _ in calls] == ["/login.cgi", "/appGet.cgi", "/appGet.cgi", "/Logout.asp"]
        assert result["data"]["wan"]["slots"][0]["primary"] is True
        assert result["sources"]["wan"]["freshness"] == "unknown"
        assert any(gap["group"] == "wan" for gap in result["capability_gaps"])
    asyncio.run(scenario())
