"""Nonsecret selected WAN contract from asusrouter 1.21.3.

Source: modules/endpoint/hook_const.py MAP_WAN and MAP_WAN_ITEM;
modules/data_finder.py ASUSDATA_REQUEST/NVRAM and slots 0/1 expansion.
Only MAP_WAN_ITEM_X timing integers are selected; no address/DNS fields or
realip_ip are requested. Native timing representations remain separate.
"""
from __future__ import annotations

import re
from typing import Any

from asusrouter.modules.endpoint.wan import AsusDualWAN
from asusrouter.modules.ip_address import IPAddressType, read_ip_address_type

from .errors import RouterError

_SLOT_KEYS = ("state_t", "sbstate_t", "auxstate_t", "primary", "proto")
_TIMING_KEYS = ("lease", "expires", "xlease", "xexpires")
WAN_HOOK = ("get_wan_unit();nvram_get(link_internet);nvram_get(link_wan);nvram_get(link_wan1);"
            "nvram_get(wans_mode);" + "".join(f"nvram_get(wan{i}_{key});" for i in (0, 1) for key in (*_SLOT_KEYS, *_TIMING_KEYS)))
_INTEGER = re.compile(r"-?[0-9]{1,10}\Z")


def _invalid() -> RouterError:
    return RouterError("malformed_response", "Native WAN selected state is missing or malformed.")


def _number(value: Any, minimum=-(2**31), maximum=2**31 - 1) -> int:
    if type(value) is int:
        number = value
    elif type(value) is str and _INTEGER.fullmatch(value):
        number = int(value)
    else:
        raise _invalid()
    if not minimum <= number <= maximum:
        raise _invalid()
    return number


def _optional_code(raw: dict, key: str, gaps: list[str]) -> int | None:
    if key not in raw:
        gaps.append(key + "_unavailable")
        return None
    return _number(raw[key])


def _timing_number(value: Any) -> int:
    """Preserve signed/unsigned native 32-bit timing representations.

    The pinned MAP_WAN_ITEM_X uses safe_int without a signed-32 restriction.
    Keep uint32 values (including 0xffffffff) without assigning sentinel or
    clock semantics, alongside signed native observations. Status-code bounds
    remain unchanged in _number.
    """
    return _number(value, minimum=-(2**31), maximum=2**32 - 1)


def normalize_wan(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _invalid()
    unit = _number(raw.get("get_wan_unit"), 0, 1)
    link = _number(raw.get("link_internet"), 0, 9)
    gaps = []
    slots = []
    for index in (0, 1):
        prefix = f"wan{index}_"
        slot = {"unit": index,
                "link_code": _optional_code(raw, "link_wan" if index == 0 else "link_wan1", gaps),
                "state_code": _optional_code(raw, prefix + "state_t", gaps),
                "sbstate_code": _optional_code(raw, prefix + "sbstate_t", gaps),
                "auxstate_code": _optional_code(raw, prefix + "auxstate_t", gaps)}
        for field in _TIMING_KEYS:
            value = raw.get(prefix + field)
            if value is None or value == "":
                slot[field + "_native"] = None
                gaps.append(prefix + field + "_unavailable")
            else:
                slot[field + "_native"] = _timing_number(value)
        primary_key = prefix + "primary"
        if primary_key not in raw:
            slot["primary"] = None
            gaps.append(primary_key + "_unavailable")
        else:
            value = raw[primary_key]
            if type(value) is bool:
                slot["primary"] = value
            else:
                slot["primary"] = bool(_number(value, 0, 1))
        protocol_key = prefix + "proto"
        if protocol_key not in raw:
            slot["protocol"] = "unknown"
            gaps.append(protocol_key + "_unavailable")
        else:
            value = raw[protocol_key]
            if type(value) is not str or len(value) > 64:
                raise _invalid()
            protocol = read_ip_address_type(value)
            slot["protocol"] = protocol.value
            if protocol == IPAddressType.UNKNOWN:
                gaps.append(protocol_key + "_unrecognised")
        slots.append(slot)
    if "wans_mode" not in raw:
        dualwan_mode = None
        gaps.append("dualwan_mode_unavailable")
    else:
        value = raw["wans_mode"]
        if type(value) is not str or value not in {mode.value for mode in AsusDualWAN}:
            raise _invalid()
        dualwan_mode = value
    gaps.extend(("native_timing_units_and_countdown_not_established", "addresses_dns_and_gateway_not_collected", "route_and_egress_not_verified", "slot_hardware_applicability_not_discovered"))
    return {"unit": unit, "link_code": link, "slots": slots, "dualwan_mode": dualwan_mode, "gaps": gaps}
