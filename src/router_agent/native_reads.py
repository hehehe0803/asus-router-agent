"""Selected native read contracts from pristine asusrouter 1.21.3.

VPN hook: modules/data_finder.py ASUSDATA_REQUEST['vpnc'].
Wire fields: modules/endpoint/hook.py process_vpnc, lines 530-550.
Profile association requires vpnc_clientlist, which contains login/password;
this read deliberately never requests it or runs its credential-bearing parser.
"""
from __future__ import annotations

import re
from typing import Any

from .errors import RouterError

VPN_STATUS_HOOK = "get_vpnc_status();"
LED_STATE_HOOK = "nvram_get(led_val);"
# Exact templates/index order: modules/wlan.py MAP_WLAN/MAP_GWLAN,
# WLAN_TYPE; _nvram_request and endpoint/hook.py process_gwlan.
# Target selection 0/1 follows the parent's RT-AX86U UI inventory. Templates
# are upstream native contracts; this is not a general four-radio scan.
_RADIO_INDICES = (0, 1)
_GUEST_IDS = tuple(range(1, 4))
# Selected settings from MAP_WLAN lines 112-139 / MAP_GWLAN lines 52-109.
_WLAN_DIAGNOSTICS = {"channel": "channel_code", "bw": "bandwidth_code", "closed": "hidden"}
_GUEST_DIAGNOSTICS = {"expire": "expire_seconds", "expire_tmp": "expire_remaining_seconds",
                      "lanaccess": "lan_access_enabled", "ap_isolate": "ap_isolation_code",
                      "bw_enabled": "bandwidth_limit_enabled", "bw_dl": "download_limit_native",
                      "bw_ul": "upload_limit_native", "bss_maxassoc": "bss_maxassoc_native",
                      "maxassoc": "maxassoc_native", "closed": "hidden", "sync_node": "sync_nodes_enabled"}
_BOOLEAN_SETTINGS = frozenset({"lanaccess", "closed", "bw_enabled", "sync_node"})
WLAN_STATE_HOOK = "".join(f"nvram_get(wl{i}_{field});" for i in _RADIO_INDICES
                          for field in ("radio", *_WLAN_DIAGNOSTICS))
GUEST_STATE_HOOK = "".join(f"nvram_get(wl{i}.{g}_{field});" for i in _RADIO_INDICES
                           for g in _GUEST_IDS for field in ("bss_enabled", *_GUEST_DIAGNOSTICS))
# Exact selected keys: data_finder.py ASUSDATA_NVRAM['ddns']; ddns.py.
DDNS_STATE_HOOK = "nvram_get(ddns_enable_x);nvram_get(ddns_updated);nvram_get(ddns_return_code_chk);"
_MAX_STATUS_BYTES = 8192
_MAX_SLOTS = 64
_INTEGER = re.compile(r"-?[0-9]{1,10}\Z")
VPN_STATUS_GAPS = (
    "profile_identity_and_protocol_unavailable",
    "default_route_and_policy_unavailable",
    "egress_not_verified",
    "vpn_server_state_not_collected",
)


def _invalid() -> RouterError:
    return RouterError("malformed_response", "Native VPN slot status is missing or malformed.")


def _code(value: str, *, identifier: bool = False) -> int:
    if not _INTEGER.fullmatch(value):
        raise _invalid()
    number = int(value)
    if not -(2**31) <= number < 2**31 or identifier and number < 0:
        raise _invalid()
    return number


def normalize_vpn_status(raw: Any) -> dict[str, Any]:
    """Return observed Fusion identifiers and uninterpreted numeric codes.

    An empty status is not proof of no configured profiles or a healthy VPN.
    Unknown codes are preserved; their semantics are not guessed. All vendor
    fields except the exact status string are discarded, including client lists.
    """
    if not isinstance(raw, dict):
        raise _invalid()
    status = raw.get("get_vpnc_status")
    if not isinstance(status, str) or len(status) > _MAX_STATUS_BYTES:
        raise _invalid()
    rows = [row for row in status.split("<") if row]
    if len(rows) > _MAX_SLOTS:
        raise _invalid()
    slots = []
    seen = set()
    for row in rows:
        fields = row.split(">")
        if len(fields) != 3:
            raise _invalid()
        state_code = _code(fields[0])
        error_code = _code(fields[1])
        vpnc_id = _code(fields[2], identifier=True)
        if vpnc_id in seen:
            raise _invalid()
        seen.add(vpnc_id)
        slots.append({"vpnc_id": vpnc_id, "state_code": state_code,
                      "error_code": error_code, "protocol": "unknown"})
    gaps = list(VPN_STATUS_GAPS)
    if not slots:
        gaps.append("empty_status_does_not_establish_configuration_or_health")
    return {"scope": "fusion_slot_status_only", "slots": sorted(slots, key=lambda s: s["vpnc_id"]),
            "default_route": None, "egress_verified": False, "gaps": gaps}


def _state_object(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or not raw:
        raise RouterError("malformed_response", "Native selected state is missing or malformed.")
    return raw


def _enabled(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    if type(value) is str and value in ("0", "1"):
        return value == "1"
    raise RouterError("malformed_response", "Native selected state is missing or malformed.")


def normalize_led_state(raw: Any) -> dict[str, Any]:
    """Read led_val without upstream SYSINFO/LED keep-state side effects."""
    raw = _state_object(raw)
    if "led_val" not in raw:
        raise RouterError("malformed_response", "Native selected state is missing or malformed.")
    value = raw["led_val"]
    if value is None or value == "" or value == -999 or value == "-999":
        return {"enabled": None, "gaps": ["led_state_or_hardware_support_unknown"]}
    return {"enabled": _enabled(value), "gaps": ["hardware_applicability_not_verified"]}


def _diagnostic_number(value: Any) -> int | None:
    """Strict finite setting values; no interpretation of vendor numeric codes."""
    if value is None or value == "":
        return None
    if type(value) is int:
        number = value
    elif type(value) is str and re.fullmatch(r"[0-9]{1,10}", value):
        number = int(value)
    else:
        raise RouterError("malformed_response", "Native radio diagnostic setting is malformed.")
    if not 0 <= number <= 2**31 - 1:
        raise RouterError("malformed_response", "Native radio diagnostic setting is malformed.")
    return number


def _setting_bool(value: Any) -> bool | None:
    """Strict recognized native safe_bool forms; no unknown coercion."""
    from asusrouter.tools.converters import false_values, safe_bool, true_values
    if value is None or value == "":
        return None
    if type(value) is bool or type(value) is int and value in (0, 1):
        return bool(value)
    if type(value) is str and value.strip().lower() in true_values | false_values:
        return safe_bool(value.strip().lower())
    raise RouterError("malformed_response", "Native selected boolean setting is malformed.")


def _radio_slots(raw: Any, guest: bool) -> dict[str, Any]:
    raw = _state_object(raw)
    slots = []
    selected_keys = []
    unavailable = set()
    for index in _RADIO_INDICES:
        for guest_id in _GUEST_IDS if guest else (None,):
            key = f"wl{index}.{guest_id}_bss_enabled" if guest else f"wl{index}_radio"
            selected_keys.append(key)
            slot = {"radio_index": index, "enabled": _enabled(raw.get(key))}
            if guest:
                slot["guest_index"] = guest_id
            prefix = f"wl{index}.{guest_id}_" if guest else f"wl{index}_"
            diagnostics = _GUEST_DIAGNOSTICS if guest else _WLAN_DIAGNOSTICS
            for native_field, output_field in diagnostics.items():
                parser = _setting_bool if native_field in _BOOLEAN_SETTINGS else _diagnostic_number
                slot[output_field] = parser(raw.get(prefix + native_field))
                if slot[output_field] is None:
                    unavailable.add(output_field)
            slots.append(slot)
    if not any(key in raw for key in selected_keys):
        raise RouterError("malformed_response", "Native selected state is missing or malformed.")
    gaps = ["slot_hardware_applicability_not_discovered", "enabled_setting_is_not_link_or_access_verification"]
    gaps.extend(field + "_unavailable_in_some_slots" for field in sorted(unavailable))
    gaps.append("guest_settings_do_not_verify_access_or_expiry_enforcement" if guest
                else "channel_and_bandwidth_codes_are_settings_not_measured_rf_state")
    if guest:
        gaps.append("bandwidth_limit_units_and_capacity_enforcement_not_established")
    else:
        gaps.append("security_settings_not_collected")
    return {"scope": "guest_bss_state_slots" if guest else "radio_state_slots", "slots": slots, "gaps": gaps}


def normalize_wlan_state(raw: Any) -> dict[str, Any]:
    return _radio_slots(raw, False)


def normalize_guest_state(raw: Any) -> dict[str, Any]:
    return _radio_slots(raw, True)


def normalize_ddns_state(raw: Any) -> dict[str, Any]:
    """Finite DDNS status without upstream hint text containing hostnames.

    Upstream's helper accepts substring matches in arbitrary text. Only exact
    enum tokens enter it here; unmatched vendor text is unknown and discarded.
    No DNS lookup or published-address correctness is established by this read.
    """
    from asusrouter.modules.ddns import DDNSStatusCode, DDNSStatusHint, read_ddns_status_code
    raw = _state_object(raw)
    keys = ("ddns_enable_x", "ddns_updated", "ddns_return_code_chk")
    if not any(key in raw for key in keys):
        raise RouterError("malformed_response", "Native selected state is missing or malformed.")
    value = raw.get("ddns_return_code_chk")
    if value is not None and (type(value) is not str or len(value) > 256):
        raise RouterError("malformed_response", "Native selected state is missing or malformed.")
    numeric_codes = {str(code.value): code for code in DDNSStatusCode}
    hint_tokens = {hint.value for hint in DDNSStatusHint}
    unmatched = False
    if value in numeric_codes:
        status = numeric_codes[value]
    elif value in hint_tokens:
        status = read_ddns_status_code(value)
    elif value in (None, ""):
        status = DDNSStatusCode.NONE
    else:
        status = DDNSStatusCode.OTHER
        unmatched = True
    gaps = ["hostname_and_address_not_collected", "dns_resolution_not_verified"]
    if unmatched:
        gaps.append("unrecognised_status_text_discarded")
    return {"enabled": _enabled(raw.get("ddns_enable_x")), "updated": _enabled(raw.get("ddns_updated")),
            "status_code": status.value, "status": status.name.lower(),
            "gaps": gaps}
