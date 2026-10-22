import ast
import json
import re
from pathlib import Path

import pytest

from router_agent.errors import RouterError
from router_agent.native_reads import (
    WLAN_STATE_HOOK, GUEST_STATE_HOOK, normalize_wlan_state, normalize_guest_state,
)


def _mapped_templates(name):
    # Installed pinned package source has the same version as pristine source;
    # use pristine local source where available, otherwise packaged source.
    path = Path("/tmp/asusrouter-research-1.21.3/asusrouter/modules/wlan.py")
    if not path.is_file():
        import asusrouter.modules.wlan as wlan
        path = Path(wlan.__file__)
    tree = ast.parse(path.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.AnnAssign) and n.target.id == name)
    return {ast.literal_eval(n.elts[0]) if isinstance(n, ast.Tuple) else ast.literal_eval(n) for n in node.value.elts}


def test_fixed_hook_fields_match_native_maps_and_no_private_fields():
    radio_templates = _mapped_templates("MAP_WLAN")
    guest_templates = _mapped_templates("MAP_GWLAN")
    radio_expected = {f"wl{i}_{f}" for i in (0, 1) for f in ("radio", "channel", "bw", "closed")}
    guest_expected = {f"wl{i}.{g}_{f}" for i in (0, 1) for g in (1, 2, 3)
                      for f in ("bss_enabled", "expire", "expire_tmp", "lanaccess", "ap_isolate", "bw_enabled", "bw_dl", "bw_ul", "bss_maxassoc", "maxassoc", "closed", "sync_node")}
    assert set(re.findall(r"nvram_get\(([^)]+)\);", WLAN_STATE_HOOK)) == radio_expected
    assert set(re.findall(r"nvram_get\(([^)]+)\);", GUEST_STATE_HOOK)) == guest_expected
    assert {"wl{}_" + f for f in ("radio", "channel", "bw", "closed")} <= radio_templates
    assert {"wl{}_" + f for f in ("bss_enabled", "expire", "expire_tmp", "lanaccess", "ap_isolate", "bw_enabled", "bw_dl", "bw_ul", "bss_maxassoc", "maxassoc", "closed", "sync_node")} <= guest_templates
    assert not any(key in WLAN_STATE_HOOK + GUEST_STATE_HOOK for key in ("ssid", "psk", "key", "mac", "name", "ifname"))


def test_radio_codes_preserve_configuration_without_claiming_channel_or_mhz():
    result = normalize_wlan_state({"wl0_radio": "1", "wl1_radio": "0", "wl0_channel": "0", "wl0_bw": "3",
                                   "wl1_channel": 149, "wl1_bw": 999, "wl0_ssid": "synthetic-private"})
    assert result["slots"][0] == {"radio_index": 0, "enabled": True, "channel_code": 0, "bandwidth_code": 3, "hidden": None}
    assert result["slots"][1]["channel_code"] == 149 and result["slots"][1]["bandwidth_code"] == 999
    assert "synthetic-private" not in json.dumps(result)
    assert "channel_and_bandwidth_codes_are_settings_not_measured_rf_state" in result["gaps"]


def test_guest_expiry_access_and_raw_isolation_settings():
    raw = {f"wl{i}.{g}_bss_enabled": "0" for i in (0, 1) for g in (1, 2, 3)}
    raw.update({"wl0.1_expire": "3600", "wl0.1_expire_tmp": "120", "wl0.1_lanaccess": "1", "wl0.1_ap_isolate": "7",
                "wl1.3_expire": "0", "wl1.3_lanaccess": False, "wl0.1_wpa_psk": "synthetic-private"})
    result = normalize_guest_state(raw)
    first, last = result["slots"][0], result["slots"][-1]
    assert first["expire_seconds"] == 3600 and first["expire_remaining_seconds"] == 120
    assert first["lan_access_enabled"] is True and first["ap_isolation_code"] == 7
    assert last["expire_seconds"] == 0 and last["lan_access_enabled"] is False
    assert last["expire_remaining_seconds"] is None
    assert "synthetic-private" not in json.dumps(result)
    assert result["gaps"].count("expire_remaining_seconds_unavailable_in_some_slots") == 1


def test_all_missing_diagnostics_stay_null_with_one_gap_per_field():
    result = normalize_guest_state({"wl0.1_bss_enabled": "0"})
    for slot in result["slots"]:
        for field in ("expire_seconds", "expire_remaining_seconds", "lan_access_enabled", "ap_isolation_code"):
            assert slot[field] is None
    for field in ("expire_seconds", "expire_remaining_seconds", "lan_access_enabled", "ap_isolation_code"):
        assert result["gaps"].count(field + "_unavailable_in_some_slots") == 1


@pytest.mark.parametrize("value,expected", [("on", True), ("off", False), ("true", True), ("false", False),
    ("allow", True), ("block", False), ("enabled", True), ("disabled", False), ("1", True), ("0", False),
    (" ON ", True), ("OFF", False)])
def test_guest_lan_access_accepts_finite_upstream_boolean_forms(value, expected):
    result = normalize_guest_state({"wl0.1_bss_enabled": "0", "wl0.1_lanaccess": value})
    assert result["slots"][0]["lan_access_enabled"] is expected


@pytest.mark.parametrize("value", [None, ""])
def test_empty_diagnostic_values_are_unknown(value):
    result = normalize_wlan_state({"wl0_radio": "1", "wl0_channel": value, "wl0_bw": value})
    assert result["slots"][0]["channel_code"] is None and result["slots"][0]["bandwidth_code"] is None


@pytest.mark.parametrize("normalizer,key,value", [
    (normalize_wlan_state, "wl0_channel", "synthetic-private"),
    (normalize_wlan_state, "wl1_bw", True),
    (normalize_wlan_state, "wl0_channel", -1),
    (normalize_wlan_state, "wl0_bw", "2147483648"),
    (normalize_guest_state, "wl0.1_expire", "3600seconds"),
    (normalize_guest_state, "wl0.1_expire_tmp", []),
    (normalize_guest_state, "wl1.3_lanaccess", "yes"),
    (normalize_guest_state, "wl1.3_ap_isolate", {}),
])
def test_malformed_present_or_private_values_fail_without_vendor_echo(normalizer, key, value):
    raw = {"wl0_radio": "1"} if normalizer is normalize_wlan_state else {"wl0.1_bss_enabled": "0"}
    raw[key] = value
    with pytest.raises(RouterError) as caught:
        normalizer(raw)
    assert caught.value.code == "malformed_response"
    assert "synthetic-private" not in str(caught.value)
