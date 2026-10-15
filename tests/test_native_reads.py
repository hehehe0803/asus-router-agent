"""Synthetic fixtures for the upstream-defined VPN status-only wire contract."""
import json

import pytest

from router_agent.errors import RouterError
from router_agent.native_reads import VPN_STATUS_HOOK, normalize_vpn_status
from router_agent.native_reads import (
    LED_STATE_HOOK, WLAN_STATE_HOOK, GUEST_STATE_HOOK, DDNS_STATE_HOOK,
    normalize_led_state, normalize_wlan_state, normalize_guest_state,
    normalize_ddns_state,
)


def test_fixed_status_hook_and_fields_without_profile_association():
    assert VPN_STATUS_HOOK == "get_vpnc_status();"
    result = normalize_vpn_status({"get_vpnc_status": "<5>0>8<2>0>4",
                                   "vpnc_clientlist": "synthetic-name>OpenVPN>1>synthetic-login>synthetic-password",
                                   "default_route": "synthetic-route"})
    assert result["slots"] == [
        {"vpnc_id": 4, "state_code": 2, "error_code": 0, "protocol": "unknown"},
        {"vpnc_id": 8, "state_code": 5, "error_code": 0, "protocol": "unknown"},
    ]
    assert "synthetic-" not in json.dumps(result)
    assert result["default_route"] is None
    assert result["egress_verified"] is False
    assert "vpn_server_state_not_collected" in result["gaps"]


def test_unrecognised_codes_are_preserved_without_health_inference():
    result = normalize_vpn_status({"get_vpnc_status": "999>123>0<-999>-1>3"})
    assert result["slots"][0]["state_code"] == 999
    assert result["slots"][0]["error_code"] == 123
    assert result["slots"][1]["state_code"] == -999
    assert "connected" not in json.dumps(result)


@pytest.mark.parametrize("status", ["", "<", "<<"])
def test_empty_observation_is_explicitly_unknown(status):
    result = normalize_vpn_status({"get_vpnc_status": status})
    assert result["slots"] == []
    assert "empty_status_does_not_establish_configuration_or_health" in result["gaps"]


@pytest.mark.parametrize("raw", [None, [], {}, {"get_vpnc_status": None},
    {"get_vpnc_status": False}, {"get_vpnc_status": ["2>0>1"]},
    {"get_vpnc_status": "2>0"}, {"get_vpnc_status": "2>0>1>synthetic-password"},
    {"get_vpnc_status": "synthetic-password>0>1"}, {"get_vpnc_status": "2>x>1"},
    {"get_vpnc_status": "2>0>-1"}, {"get_vpnc_status": "2>0>1<5>0>1"},
    {"get_vpnc_status": "2147483648>0>1"}, {"get_vpnc_status": "2>0>2147483648"},
    {"get_vpnc_status": "2>0>1\n"}, {"get_vpnc_status": "２>0>1"},
    {"get_vpnc_status": "x" * 8193},
    {"get_vpnc_status": "<".join(f"2>0>{i}" for i in range(65))}])
def test_malformed_duplicate_and_unbounded_payloads_fail_closed(raw):
    with pytest.raises(RouterError) as caught:
        normalize_vpn_status(raw)
    assert caught.value.code == "malformed_response"
    assert "synthetic-password" not in str(caught.value)


def test_selected_fixed_hooks_never_request_names_keys_or_credentials():
    assert LED_STATE_HOOK == "nvram_get(led_val);"
    assert WLAN_STATE_HOOK.count("nvram_get(") == 6
    assert "nvram_get(wl0_radio);" in WLAN_STATE_HOOK and "nvram_get(wl1_radio);" in WLAN_STATE_HOOK
    assert GUEST_STATE_HOOK.count("nvram_get(") == 30
    assert "wl1.3_bss_enabled" in GUEST_STATE_HOOK
    assert "wl2" not in WLAN_STATE_HOOK + GUEST_STATE_HOOK
    for hook in (LED_STATE_HOOK, WLAN_STATE_HOOK, GUEST_STATE_HOOK, DDNS_STATE_HOOK):
        assert not any(secret in hook for secret in ("ssid", "key", "passwd", "hostname", "ipaddr"))


def test_led_selected_state_and_unknown_are_not_inferred():
    assert normalize_led_state({"led_val": "1", "secret": "synthetic-secret"})["enabled"] is True
    assert normalize_led_state({"led_val": 0})["enabled"] is False
    assert normalize_led_state({"led_val": "-999"})["enabled"] is None
    assert normalize_led_state({"led_val": ""})["enabled"] is None


def test_radio_guest_slots_are_settings_not_proof_of_actual_hardware():
    radios = normalize_wlan_state({"wl0_radio": "1", "wl1_radio": "", "wl0_ssid": "synthetic-secret"})
    assert radios["slots"] == [{"radio_index": 0, "enabled": True, "channel_code": None, "bandwidth_code": None},
                              {"radio_index": 1, "enabled": None, "channel_code": None, "bandwidth_code": None}]
    guests = normalize_guest_state({"wl0.1_bss_enabled": "0", "wl1.3_bss_enabled": "1",
                                     "wl0.1_wpa_psk": "synthetic-secret"})
    assert len(guests["slots"]) == 6
    assert guests["slots"][0]["enabled"] is False
    assert guests["slots"][-1]["enabled"] is True
    assert guests["slots"][1]["enabled"] is None
    assert "synthetic-secret" not in json.dumps(radios) + json.dumps(guests)
    assert "slot_hardware_applicability_not_discovered" in guests["gaps"]


def test_ddns_finite_status_drops_hostname_and_does_not_treat_substring_as_success():
    raw = {"ddns_enable_x": "1", "ddns_updated": "0", "ddns_return_code_chk": "200",
           "ddns_hostname_x": "synthetic-secret", "ddns_ipaddr": "192.0.2.1"}
    result = normalize_ddns_state(raw)
    assert result["enabled"] is True and result["updated"] is False
    assert result["status_code"] == 200 and result["status"] == "success"
    assert "unrecognised_status_text_discarded" not in result["gaps"]
    assert "synthetic-secret" not in json.dumps(result) and "192.0.2.1" not in json.dumps(result)
    raw["ddns_return_code_chk"] = "private-host200.example"
    unknown = normalize_ddns_state(raw)
    assert unknown["status"] == "other"
    assert "unrecognised_status_text_discarded" in unknown["gaps"]
    assert "private-host200.example" not in json.dumps(unknown)
    raw["ddns_return_code_chk"] = "ddns_query"
    assert normalize_ddns_state(raw)["status"] == "query"


@pytest.mark.parametrize("token,code,name", [("0", 0, "none"), ("1004", 1004, "no_change")])
def test_ddns_exact_numeric_enum_codes_do_not_use_substring_helper(token, code, name):
    result = normalize_ddns_state({"ddns_return_code_chk": token})
    assert result["status_code"] == code and result["status"] == name
    assert "unrecognised_status_text_discarded" not in result["gaps"]


@pytest.mark.parametrize("normalizer,raw", [
    (normalize_led_state, {}), (normalize_led_state, {"led_val": 2}),
    (normalize_wlan_state, {"wl0_ssid": "synthetic-secret"}),
    (normalize_wlan_state, {"wl0_radio": "yes"}),
    (normalize_guest_state, {"wl0.1_bss_enabled": []}),
    (normalize_ddns_state, {"ddns_enable_x": "secret"}),
    (normalize_ddns_state, {"ddns_return_code_chk": 200}),
    (normalize_ddns_state, {"ddns_return_code_chk": "x" * 257}),
])
def test_selected_state_parsers_fail_closed_without_vendor_details(normalizer, raw):
    with pytest.raises(RouterError) as caught:
        normalizer(raw)
    assert caught.value.code == "malformed_response"
    assert "secret" not in str(caught.value)
