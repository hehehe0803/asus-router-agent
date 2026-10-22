"""Synthetic selected settings; source maps are read from the installed pin."""
import asyncio
import json
import re
import socket
from types import SimpleNamespace

import pytest

from router_agent.errors import RouterError
from router_agent.native_reads import GUEST_STATE_HOOK, WLAN_STATE_HOOK, normalize_guest_state, normalize_wlan_state
from router_agent.output import envelope
from router_agent.transport import HOOKS, RequestGuard, TransportConfig, collect_native
from router_agent.wan_reads import WAN_HOOK, normalize_wan


def test_selected_hooks_are_subsets_of_installed_native_maps():
    from asusrouter.modules.data_finder import ASUSDATA_NVRAM
    from asusrouter.modules.wlan import Wlan, gwlan_nvram_request, wlan_nvram_request
    keys = lambda hook: re.findall(r"nvram_get\(([^)]+)\);", hook)
    timing_keys = {f"wan{i}_{extra}{field}" for i in (0, 1) for extra in ("", "x") for field in ("lease", "expires")}
    assert timing_keys <= set(ASUSDATA_NVRAM["wan"])
    assert timing_keys <= set(keys(WAN_HOOK))
    assert not any("_x_" in key for key in keys(WAN_HOOK))
    radios = [Wlan.FREQ_2G, Wlan.FREQ_5G]
    assert set(keys(WLAN_STATE_HOOK)) <= set(keys(wlan_nvram_request(radios)))
    assert set(keys(GUEST_STATE_HOOK)) <= set(keys(gwlan_nvram_request(radios)))
    for hook in (WAN_HOOK, WLAN_STATE_HOOK, GUEST_STATE_HOOK):
        assert not any(private in hook for private in ("ssid", "psk", "key", "mac", "ipaddr", "dns", "auth_mode", "crypto", "country_code", "mfp", "nmode"))


def test_wan_timing_representations_are_independent_native_integers():
    raw = {"get_wan_unit": "0", "link_internet": "2", "wan0_lease": "3600", "wan0_expires": "-1",
           "wan0_xlease": 7200, "wan0_xexpires": 2147483647, "wan1_lease": "0", "wan1_expires": None,
           "wan1_xlease": "", "wan0_ipaddr": "192.0.2.1", "wan0_passwd": "synthetic-private"}
    result = normalize_wan(raw)
    assert {k: result["slots"][0][k] for k in ("lease_native", "expires_native", "xlease_native", "xexpires_native")} == {
        "lease_native": 3600, "expires_native": -1, "xlease_native": 7200, "xexpires_native": 2147483647}
    assert result["slots"][1]["lease_native"] == 0
    assert all(result["slots"][1][key] is None for key in ("expires_native", "xlease_native", "xexpires_native"))
    assert "native_timing_units_and_countdown_not_established" in result["gaps"]
    assert "synthetic-private" not in json.dumps(result) and "192.0.2.1" not in json.dumps(result)
    assert envelope({"wan": result})["data"]["wan"] == result


def test_guest_capacity_bandwidth_hidden_sync_preserve_native_settings():
    result = normalize_guest_state({"wl0.1_bss_enabled": "0", "wl0.1_bw_enabled": "1", "wl0.1_bw_dl": "12345",
        "wl0.1_bw_ul": 678, "wl0.1_bss_maxassoc": "16", "wl0.1_maxassoc": "32", "wl0.1_closed": "1",
        "wl0.1_sync_node": "0", "wl0.1_ssid": "synthetic-private", "wl0.1_wpa_psk": "synthetic-private"})
    first = result["slots"][0]
    assert first["enabled"] is False and first["bandwidth_limit_enabled"] is True
    assert first["hidden"] is True and first["sync_nodes_enabled"] is False
    assert [first[k] for k in ("download_limit_native", "upload_limit_native", "bss_maxassoc_native", "maxassoc_native")] == [12345, 678, 16, 32]
    assert "synthetic-private" not in json.dumps(result)
    assert "bandwidth_limit_units_and_capacity_enforcement_not_established" in result["gaps"]
    assert envelope({"guest": result})["data"]["guest"] == result


def test_radio_hidden_and_missing_settings_are_unknown_without_security_text():
    result = normalize_wlan_state({"wl0_radio": "1", "wl0_closed": "0", "wl0_auth_mode_x": "synthetic-private", "wl0_crypto": "synthetic-private"})
    assert result["slots"][0]["hidden"] is False and result["slots"][1]["hidden"] is None
    assert "security_settings_not_collected" in result["gaps"]
    assert "synthetic-private" not in json.dumps(result)
    assert envelope({"wlan": result})["data"]["wlan"] == result
    result = normalize_guest_state({"wl0.1_bss_enabled": "1"})
    for field in ("bandwidth_limit_enabled", "download_limit_native", "upload_limit_native", "bss_maxassoc_native", "maxassoc_native", "hidden", "sync_nodes_enabled"):
        assert all(slot[field] is None for slot in result["slots"])
        assert result["gaps"].count(field + "_unavailable_in_some_slots") == 1


@pytest.mark.parametrize("field", ["lease", "expires", "xlease", "xexpires"])
@pytest.mark.parametrize("value", [True, [], {}, 1.5, "synthetic-private", "4294967296", "-2147483649", "1\n", "１"])
def test_wan_timing_malformed_is_rejected_without_echo(field, value):
    with pytest.raises(RouterError) as caught:
        normalize_wan({"get_wan_unit": "0", "link_internet": "2", "wan0_" + field: value})
    assert caught.value.code == "malformed_response" and "synthetic-private" not in str(caught.value)


@pytest.mark.parametrize("slot", [0, 1])
@pytest.mark.parametrize("field", ["lease", "expires", "xlease", "xexpires"])
@pytest.mark.parametrize("value", [-2147483648, -1, 0, 2147483647, 2147483648, 4294967295])
@pytest.mark.parametrize("wire_type", [str, int])
def test_wan_timing_full_native_signed_unsigned_boundaries(slot, field, value, wire_type):
    from asusrouter.tools.converters import safe_int
    assert safe_int(wire_type(value)) == value
    result = normalize_wan({"get_wan_unit": "0", "link_internet": "2",
                            f"wan{slot}_{field}": wire_type(value), "wan0_passwd": "synthetic-private"})
    assert result["slots"][slot][field + "_native"] == value
    assert envelope({"wan": result})["data"]["wan"] == result
    assert "synthetic-private" not in json.dumps(result)


@pytest.mark.parametrize("slot", [0, 1])
@pytest.mark.parametrize("field", ["lease", "expires", "xlease", "xexpires"])
@pytest.mark.parametrize("value", [-2147483649, 4294967296, "-2147483649", "4294967296", True, "synthetic-private"])
def test_wan_timing_out_of_range_and_malformed_all_slots(slot, field, value):
    with pytest.raises(RouterError) as caught:
        normalize_wan({"get_wan_unit": "0", "link_internet": "2", f"wan{slot}_{field}": value})
    assert caught.value.code == "malformed_response" and "synthetic-private" not in str(caught.value)


@pytest.mark.parametrize("field", ["bw_dl", "bw_ul", "bss_maxassoc", "maxassoc"])
@pytest.mark.parametrize("value", [True, -1, "2147483648", "synthetic-private", {}, 0.5])
def test_guest_numeric_settings_reject_malformed_values(field, value):
    with pytest.raises(RouterError) as caught:
        normalize_guest_state({"wl0.1_bss_enabled": "1", "wl1.3_" + field: value})
    assert caught.value.code == "malformed_response" and "synthetic-private" not in str(caught.value)


@pytest.mark.parametrize("normalizer,raw,prefix,field", [
    (normalize_wlan_state, {"wl0_radio": "1"}, "wl1_", "closed"),
    *[(normalize_guest_state, {"wl0.1_bss_enabled": "1"}, "wl1.3_", f) for f in ("closed", "sync_node", "bw_enabled")]])
@pytest.mark.parametrize("value", [2, -1, "synthetic-private", [], 0.0])
def test_boolean_settings_reject_unknown_and_wrong_types(normalizer, raw, prefix, field, value):
    with pytest.raises(RouterError) as caught:
        normalizer({**raw, prefix + field: value})
    assert caught.value.code == "malformed_response" and "synthetic-private" not in str(caught.value)


def test_selected_hook_guard_rejects_added_private_fields_and_setters():
    async def run():
        cfg = TransportConfig("router.example", "synthetic-admin")
        for hook in (WAN_HOOK, WLAN_STATE_HOOK, GUEST_STATE_HOOK):
            guard = RequestGuard(cfg, (hook,))
            params = lambda value: SimpleNamespace(url="https://router.example/appGet.cgi", chunk=value.encode())
            await guard.chunk(None, None, params("hook=" + hook))
            for extra in ("nvram_get(wl0_ssid);", "nvram_set(wl0_radio=0);", "nvram_get(wan0_ipaddr);"):
                with pytest.raises(RouterError) as caught:
                    await guard.chunk(None, None, params("hook=" + hook + extra))
                assert caught.value.code == "read_boundary"
    asyncio.run(run())


def test_actual_upstream_loopback_trace_uses_only_named_selected_reads():
    from aiohttp import web
    async def run():
        calls = []
        fixtures = {
            HOOKS["identity"]: {"productid": "RT-AX86U", "firmver": "3.0.0.4", "buildno": "388", "extendno": "24436", "label_mac": "AA:BB:CC:DD:EE:FF"},
            WAN_HOOK: {"get_wan_unit": "0", "link_internet": "2", "wan0_xexpires": "123"},
            WLAN_STATE_HOOK: {"wl0_radio": "1", "wl0_closed": "1"},
            GUEST_STATE_HOOK: {"wl0.1_bss_enabled": "0", "wl0.1_bw_dl": "42"},
        }
        async def route(request):
            from urllib.parse import unquote
            body = unquote(await request.text())
            calls.append((request.method, request.path, body))
            if request.path == "/login.cgi":
                return web.json_response({"asus_token": "synthetic-token"})
            if request.path == "/Logout.asp":
                return web.json_response({"error_status": 8})
            assert request.path == "/appGet.cgi" and body.startswith("hook=")
            return web.json_response({**fixtures[body[5:]], "private": "synthetic-private"})
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", route)
        runner = web.AppRunner(app)
        await runner.setup()
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        cfg = TransportConfig("127.0.0.1", "synthetic-admin", use_ssl=False, allow_plain_http=True, port=sock.getsockname()[1], timeout=2)
        await web.SockSite(runner, sock).start()
        try:
            result = await collect_native(cfg, "synthetic-password", ("wan", "wlan", "guest"), fingerprint_key=b"k" * 32)
        finally:
            await runner.cleanup()
        assert [path for _, path, _ in calls] == ["/login.cgi", *["/appGet.cgi"] * 4, "/Logout.asp"]
        assert all(method == "POST" for method, _, _ in calls)
        assert [body for _, path, body in calls if path == "/appGet.cgi"] == ["hook=" + hook for hook in fixtures]
        assert result["data"]["wan"]["slots"][0]["xexpires_native"] == 123
        assert result["data"]["wlan"]["slots"][0]["hidden"] is True
        assert result["data"]["guest"]["slots"][0]["download_limit_native"] == 42
        for group in ("wan", "wlan", "guest"):
            assert result["sources"][group]["freshness"] == "unknown"
            assert result["sources"][group]["observed_at"] is None
            assert result["sources"][group]["fetched_at"]
        assert "synthetic-private" not in json.dumps(envelope(result))
    asyncio.run(run())
