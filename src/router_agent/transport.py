"""Bounded native reads through the public asusrouter 1.21.3 API.

Do not use async_connect/async_get_data here: they discover every endpoint and
may restore LED state. Public init_connection + selected hooks avoids both.
Invocation time is deliberately never represented as source observation time.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import math
import re
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

import aiohttp
from yarl import URL

from .dsl_reads import DSL_PATH, DSL_HOOK, normalize_dsl, validate_dsl_probe
from .flags_reads import observe_flags
from .openvpn_reads import normalize_openvpn
from .errors import RouterError
from .vendor_logging import SUPPRESS_VENDOR as _SUPPRESS_VENDOR
from .snapshots import client_alias
from .tls import verified_session, ssl_context
from .wan_reads import WAN_HOOK, normalize_wan
from .network_reads import NETWORK_HOOK, normalize_network
from .ports_reads import normalize_ports
from .aimesh_reads import normalize_aimesh, read_onboarding_text, validate_aimesh_shape
from .sysinfo_reads import SYSINFO_PATH, normalize_sysinfo, read_sysinfo_text
from .firmware_reads import FIRMWARE_PATH, read_firmware_text, normalize_firmware
from .speedtest_reads import SPEEDTEST_HOOK, SPEEDTEST_CAPABILITY_HOOK, normalize_speedtest, normalize_speedtest_capability
from .node_info_reads import normalize_node_info
from .firmware_note_reads import FIRMWARE_NOTE_PATH, read_firmware_note_text, normalize_firmware_note
from .hardware_reads import AURA_HOOK, AURA_CAPABILITY_HOOK, normalize_aura, normalize_aura_capability
from .vpn_settings_reads import (OPENVPN_SERVER_HOOK, WIREGUARD_SERVER_HOOK, WIREGUARD_CLIENTS_HOOK, normalize_openvpn_server, normalize_wireguard_server, normalize_wireguard_clients, validate_vpn_settings_identity)
from .policy_reads import PARENTAL_HOOK, FORWARDING_HOOK, normalize_parental, normalize_forwarding
from .health_reads import (UPTIME_PATH, TEMPERATURE_PATH, read_uptime_text, read_temperature_text, normalize_uptime, normalize_temperature)
from .native_reads import (
    VPN_STATUS_HOOK, LED_STATE_HOOK, WLAN_STATE_HOOK, GUEST_STATE_HOOK, DDNS_STATE_HOOK,
    normalize_vpn_status, normalize_led_state, normalize_wlan_state,
    normalize_guest_state, normalize_ddns_state,
)

GROUPS = ("identity", "wan", "cpu", "ram", "clients", "vpn", "led", "wlan", "guest", "ddns", "ports", "aimesh", "network", "sysinfo", "uptime", "temperature", "parental", "forwarding", "firmware", "speedtest", "aura", "openvpn_server", "wireguard_server", "wireguard_clients", "node_info", "firmware_note", "dsl", "flags", "openvpn")
HOOKS = {
    "dsl": DSL_HOOK,
    "identity": "nvram_get(productid);nvram_get(firmver);nvram_get(buildno);nvram_get(extendno);nvram_get(label_mac);",
    "wan": WAN_HOOK,
    "cpu": "cpu_usage(appobj);",
    "ram": "memory_usage(appobj);",
    "clients": "get_clientlist();",
    "vpn": VPN_STATUS_HOOK,
    "led": LED_STATE_HOOK,
    "wlan": WLAN_STATE_HOOK,
    "guest": GUEST_STATE_HOOK,
    "ddns": DDNS_STATE_HOOK,
    "network": NETWORK_HOOK,
    "parental": PARENTAL_HOOK,
    "forwarding": FORWARDING_HOOK,
    "speedtest": SPEEDTEST_HOOK,
    "aura": AURA_HOOK,
    "openvpn_server": OPENVPN_SERVER_HOOK,
    "wireguard_server": WIREGUARD_SERVER_HOOK,
    "wireguard_clients": WIREGUARD_CLIENTS_HOOK,
}
_READ_LOCK = asyncio.Lock()
@dataclass(frozen=True)
class TransportConfig:
    hostname: str
    username: str
    use_ssl: bool = True
    allow_plain_http: bool = False
    port: int | None = None
    timeout: float = 10
    cleanup_timeout: float = 2
    max_requests: int = len(GROUPS) + 4
    ca_file: str | None = None

    def __post_init__(self) -> None:
        if not self.use_ssl and not self.allow_plain_http:
            raise RouterError("http_not_selected", "HTTP requires an explicit transport choice.")
        if (not self.hostname or any(c in self.hostname for c in "/@?#\\")
                or not self.username or self.timeout <= 0 or self.cleanup_timeout <= 0
                or self.max_requests < 2 or not math.isfinite(self.timeout)
                or not math.isfinite(self.cleanup_timeout)
                or self.port is not None and not 1 <= self.port <= 65535):
            raise RouterError("invalid_transport", "Invalid native transport configuration.")
        if self.ca_file is not None:
            if not self.use_ssl:
                raise RouterError("invalid_ca_file", "A CA file requires HTTPS.")
            ssl_context(self.ca_file)

    def require_secure_write(self) -> None:
        if not self.use_ssl:
            raise RouterError("https_required", "Live writes require authenticated HTTPS; HTTP is allowed only for explicit legacy reads.")

    @property
    def origin(self) -> URL:
        return URL.build(scheme="https" if self.use_ssl else "http", host=self.hostname,
                         port=self.port or (443 if self.use_ssl else 80)).origin()

    @classmethod
    def from_auth(cls, config: Any) -> TransportConfig:
        parsed = urlsplit(config.origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"}):
            raise RouterError("invalid_transport", "Invalid native transport origin.")
        return cls(parsed.hostname, config.username, use_ssl=parsed.scheme == "https",
                   allow_plain_http=bool(getattr(config, "allow_plain_http", False)), port=parsed.port, ca_file=getattr(config, "ca_file", None))


class RequestGuard:
    """Network-side guard: even upstream retries and post-read calls are bounded."""
    def __init__(self, config: TransportConfig, hooks: tuple[str, ...] = (), *, allow_ports: bool = False, allow_aimesh: bool = False, allow_sysinfo: bool = False, allow_uptime: bool = False, allow_temperature: bool = False, allow_firmware: bool = False, allow_firmware_note: bool = False, allow_dsl: bool = False):
        self.origin = config.origin
        self.max_requests = config.max_requests
        self.requests = 0
        self.logins = 0
        self.allow_ports = allow_ports
        self.port_reads = 0
        self.allow_aimesh = allow_aimesh
        self.aimesh_reads = 0
        self.allow_sysinfo = allow_sysinfo
        self.sysinfo_reads = 0
        self.health_paths = {path for path, enabled in ((DSL_PATH, allow_dsl), (UPTIME_PATH, allow_uptime), (TEMPERATURE_PATH, allow_temperature), (FIRMWARE_PATH, allow_firmware), (FIRMWARE_NOTE_PATH, allow_firmware_note)) if enabled}
        self.health_reads: dict[str, int] = {}
        self.allowed_bodies = {"hook=" + hook for hook in hooks}
        self.stopped = False
        self.authenticated = False
        self.request_tasks: set[asyncio.Task[Any]] = set()

    async def start(self, _session: Any, _ctx: Any, params: Any) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.request_tasks.add(task)
        url = URL(params.url)
        ports_request = (self.allow_ports and url.path == "/get_port_status.cgi"
                         and params.method == "GET" and url.raw_query_string == "node_mac=all")
        aimesh_request = (self.allow_aimesh and url.path == "/ajax_onboarding.asp"
                          and params.method == "POST" and not url.query_string)
        sysinfo_request = (self.allow_sysinfo and url.path == SYSINFO_PATH
                          and params.method == "POST" and not url.query_string)
        health_request = (url.path in self.health_paths and params.method == "POST" and not url.query_string)
        standard_request = (url.path in {"/login.cgi", "/Logout.asp", "/appGet.cgi"}
                            and params.method == "POST" and not url.query_string)
        if ((url.scheme, url.raw_host, url.port) != (self.origin.scheme, self.origin.raw_host, self.origin.port)
                or url.user or url.password or not (standard_request or ports_request or aimesh_request or sysinfo_request or health_request)):
            raise RouterError("read_boundary", "Native request rejected by the read boundary.")
        if url.path in {"/appGet.cgi", "/get_port_status.cgi", "/ajax_onboarding.asp", SYSINFO_PATH, UPTIME_PATH, TEMPERATURE_PATH, FIRMWARE_PATH, FIRMWARE_NOTE_PATH, DSL_PATH} and not self.authenticated:
            raise RouterError("auth_required", "Native reads require a successful authentication gate.")
        if health_request:
            self.health_reads[url.path] = self.health_reads.get(url.path, 0) + 1
            if self.health_reads[url.path] > 1:
                raise RouterError("read_boundary", "A repeated native health read was blocked.")
        if sysinfo_request:
            self.sysinfo_reads += 1
            if self.sysinfo_reads > 1:
                raise RouterError("read_boundary", "A repeated native SYSINFO read was blocked.")
        if aimesh_request:
            self.aimesh_reads += 1
            if self.aimesh_reads > 1:
                raise RouterError("read_boundary", "A repeated native AiMesh read was blocked.")
        if ports_request:
            self.port_reads += 1
            if self.port_reads > 1:
                raise RouterError("read_boundary", "A repeated native port read was blocked.")
        self.requests += 1
        if self.requests > self.max_requests:
            raise RouterError("request_budget", "Native request budget exhausted.")
        if self.stopped and url.path != "/Logout.asp":
            raise RouterError("auth_stopped", "Authentication stopped; no retry permitted.")
        if url.path == "/login.cgi":
            self.logins += 1
            if self.logins > 1:
                raise RouterError("login_budget", "A second login attempt was blocked.")

    async def middleware(self, request: aiohttp.ClientRequest, handler: Any) -> aiohttp.ClientResponse:
        if request.url.path in {"/get_port_status.cgi", "/ajax_onboarding.asp", SYSINFO_PATH, UPTIME_PATH, TEMPERATURE_PATH, FIRMWARE_PATH, FIRMWARE_NOTE_PATH, DSL_PATH} and request.body not in (None, b""):
            raise RouterError("read_boundary", "A named endpoint request body was rejected before transmission.")
        return await handler(request)

    async def chunk(self, _session: Any, _ctx: Any, params: Any) -> None:
        path = URL(params.url).path
        if path in {"/get_port_status.cgi", "/ajax_onboarding.asp", SYSINFO_PATH, UPTIME_PATH, TEMPERATURE_PATH, FIRMWARE_PATH, FIRMWARE_NOTE_PATH, DSL_PATH} and params.chunk:
            raise RouterError("read_boundary", "Unexpected native port request body rejected.")
        if path == "/appGet.cgi":
            try:
                payload = unquote(params.chunk.decode("ascii"), errors="strict")
            except (UnicodeError, ValueError):
                raise RouterError("read_boundary", "Native hook payload rejected.") from None
            if payload not in self.allowed_bodies:
                raise RouterError("read_boundary", "Native hook payload rejected.")
        elif path == "/Logout.asp" and params.chunk:
            raise RouterError("read_boundary", "Unexpected logout payload rejected.")

    async def redirect(self, _session: Any, _ctx: Any, _params: Any) -> None:
        raise RouterError("redirect_blocked", "Native redirects are forbidden.")

    async def end(self, _session: Any, _ctx: Any, params: Any) -> None:
        response = params.response
        if URL(params.url).path == DSL_PATH and response.status == 404:
            raise RouterError("unsupported_capability", "The native DSL availability endpoint is unavailable; no rates were requested.")
        if response.status != 200:
            raise RouterError("http_error", "The router returned an unsuccessful HTTP response.")
        if URL(params.url).path == DSL_PATH:
            validate_dsl_probe(await response.text())
            return
        health_reader = {UPTIME_PATH: read_uptime_text, TEMPERATURE_PATH: read_temperature_text, FIRMWARE_PATH: read_firmware_text, FIRMWARE_NOTE_PATH: read_firmware_note_text}.get(URL(params.url).path)
        if health_reader is not None:
            try:
                health_reader(await response.text())
            except RouterError as error:
                if error.code.startswith("auth_") or error.code == "native_status_failed":
                    self.stopped = True
                raise
            return
        if URL(params.url).path == SYSINFO_PATH:
            # Exact native text reader before upstream's JSON retry/auth paths.
            # JSON/native-text auth errors are fixed codes, never vendor text.
            try:
                read_sysinfo_text(await response.text())
            except RouterError as error:
                if error.code.startswith("auth_") or error.code == "native_status_failed":
                    self.stopped = True
                raise
            return
        # Inspect errors before upstream can recurse through reauthentication.
        # This is upstream JSON, never copied to output or logs.
        try:
            content = await response.json(content_type=None)
        except (ValueError, UnicodeError, aiohttp.ClientError):
            if URL(params.url).path == "/ajax_onboarding.asp":
                content = read_onboarding_text(await response.text())
            elif URL(params.url).path != "/Logout.asp":
                raise RouterError("malformed_response", "The router returned malformed JSON.") from None
            else:
                return
        if not isinstance(content, dict):
            raise RouterError("malformed_response", "The router returned a non-object response.")
        if "error_status" in content:
            try:
                code = int(content["error_status"])
            except (ValueError, TypeError):
                raise RouterError("malformed_response", "The router returned an invalid authentication status.") from None
            if code in {2, 3, 7, 9, 10, 11}:
                self.stopped = True
                raise RouterError(f"auth_{code}", "Router authentication stopped; local intervention is required.")
            if code not in {0, 200} and not (code == 8 and URL(params.url).path == "/Logout.asp"):
                self.stopped = True
                raise RouterError("native_status_failed", "The router returned an unsuccessful native status.")
        if URL(params.url).path == "/ajax_onboarding.asp":
            validate_aimesh_shape(content)
        if URL(params.url).path == "/login.cgi":
            if not isinstance(content.get("asus_token"), str) or not content["asus_token"]:
                raise RouterError("auth_failed", "The router did not authenticate the session.")
            self.authenticated = True

    def trace(self) -> aiohttp.TraceConfig:
        trace = aiohttp.TraceConfig()
        trace.on_request_start.append(self.start)
        trace.on_request_chunk_sent.append(self.chunk)
        trace.on_request_redirect.append(self.redirect)
        trace.on_request_end.append(self.end)
        return trace


def _upstream() -> tuple[Any, Any, dict[Any, Any], dict[Any, Any]]:
    from asusrouter import AsusRouter
    from asusrouter.connection import Connection
    from asusrouter.connection_config import ARConnectionConfigKey as K
    from asusrouter.config import ARConfig, ARConfigKey
    from asusrouter.tools.security import ARSecurityLevel
    ARConfig.set(ARConfigKey.DEBUG_PAYLOAD, ARSecurityLevel.STRICT)
    return AsusRouter, Connection, {
        K.ALLOW_FALLBACK: False, K.ALLOW_MULTIPLE_FALLBACKS: False,
        K.ALLOW_UPGRADE_HTTP_TO_HTTPS: False, K.STRICT_SSL: True, K.VERIFY_SSL: True,
    }, {ARConfigKey.DEBUG_PAYLOAD: ARSecurityLevel.STRICT, ARConfigKey.OPTIMISTIC_TEMPERATURE: False}


def _safe_exception(error: Exception) -> RouterError:
    if isinstance(error, RouterError):
        return error
    # Only enum/integer error codes are read; never stringify upstream errors.
    if len(error.args) > 1 and type(error.args[1]) is not str:
        try:
            code = int(error.args[1])
            if code in {2, 3, 7, 9, 10, 11}:
                return RouterError(f"auth_{code}", "Router authentication stopped; local intervention is required.")
        except (TypeError, ValueError):
            pass
    from asusrouter.error import AsusRouterTimeoutError
    if isinstance(error, (TimeoutError, asyncio.TimeoutError, AsusRouterTimeoutError)):
        return RouterError("timeout", "Native command deadline exceeded.")
    return RouterError("native_read_failed", "Native read failed; vendor details were suppressed.")


def _number(value: Any, minimum: int = 0, maximum: int = 2**63 - 1) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    try:
        number = int(value)
    except (ValueError, TypeError):
        return None
    return number if minimum <= number <= maximum else None


def _label(value: Any, pattern: str) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else None


def _normalize(group: str, raw: Any, key: bytes) -> Any:
    if group == "dsl":
        return normalize_dsl(raw)
    if group == "sysinfo":
        return normalize_sysinfo(raw)
    if group == "node_info":
        return normalize_node_info(raw, key)
    if group == "aura":
        return normalize_aura(raw)
    if group == "firmware":
        return normalize_firmware(raw)
    if group == "speedtest":
        return normalize_speedtest(raw)
    if group == "parental":
        return normalize_parental(raw, key)
    if group == "forwarding":
        return normalize_forwarding(raw, key)
    if group == "uptime":
        return normalize_uptime(raw)
    if group == "temperature":
        return normalize_temperature(raw)
    if group == "network":
        return normalize_network(raw)
    if group == "aimesh":
        return normalize_aimesh(raw, key)
    if group == "ports":
        return normalize_ports(raw, key)
    if not isinstance(raw, dict) or not raw:
        raise RouterError("malformed_response", "Selected native data is missing or malformed.")
    parsers = {"vpn": normalize_vpn_status, "led": normalize_led_state,
               "wlan": normalize_wlan_state, "guest": normalize_guest_state,
               "ddns": normalize_ddns_state, "wan": normalize_wan}
    if group in parsers:
        return parsers[group](raw)
    if group == "identity":
        model = _label(raw.get("productid"), r"[A-Za-z0-9_-]{1,40}")
        parts = [_label(raw.get(k), r"[A-Za-z0-9_.-]{1,40}") for k in ("firmver", "buildno", "extendno")]
        mac = _label(raw.get("label_mac"), r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
        if not model or not all(parts) or not mac:
            raise RouterError("malformed_response", "Native identity is incomplete.")
        return {"model": model, "firmware": f"{parts[0]}.{parts[1]}_{parts[2]}", "device_fingerprint": hmac.new(key, b"device:" + mac.upper().encode(), hashlib.sha256).hexdigest()[:24]}
    if group == "ram":
        memory = raw.get("memory_usage")
        if not isinstance(memory, dict):
            raise RouterError("malformed_response", "Native RAM data is malformed.")
        result = {out: _number(memory.get(inp)) for out, inp in (("total_kib", "mem_total"), ("used_kib", "mem_used"), ("free_kib", "mem_free"))}
        if any(v is None for v in result.values()) or result["total_kib"] == 0 or result["used_kib"] > result["total_kib"] or result["free_kib"] > result["total_kib"]:
            raise RouterError("malformed_response", "Native RAM counters are incomplete.")
        return result
    if group == "cpu":
        cpu = raw.get("cpu_usage")
        if not isinstance(cpu, dict):
            raise RouterError("malformed_response", "Native CPU data is malformed.")
        cores = []
        for i in range(1, 65):
            if f"cpu{i}_total" not in cpu:
                break
            total, used = _number(cpu[f"cpu{i}_total"]), _number(cpu.get(f"cpu{i}_usage"))
            if total is None or used is None or used > total:
                raise RouterError("malformed_response", "Native CPU counters are invalid.")
            cores.append({"core": i, "total_ticks": total, "used_ticks": used})
        if not cores:
            raise RouterError("malformed_response", "Native CPU counters are missing.")
        return {"cores": cores}
    if group == "clients":
        clients = raw.get("get_clientlist")
        if not isinstance(clients, dict) or len(clients) > 4097:
            raise RouterError("malformed_response", "Native clients are malformed.")
        result = []
        for mac, client in clients.items():
            # get_clientlist includes these two router API metadata entries.
            # Other non-MAC keys remain malformed; do not hide unknown rows.
            if mac == "maclist" and isinstance(client, list):
                continue
            if mac == "ClientAPILevel" and isinstance(client, str):
                continue
            if not _label(mac, r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}") or not isinstance(client, dict):
                raise RouterError("malformed_response", "Native client record is malformed.")
            online = client.get("isOnline")
            wireless = _number(client.get("isWL"), maximum=9)
            if online not in ("0", "1", 0, 1) or wireless is None:
                raise RouterError("malformed_response", "Native client state is incomplete.")
            result.append({"alias": client_alias(key, mac), "online": str(online) == "1", "connection": "wired" if wireless == 0 else "wireless", "signal_dbm": _number(client.get("rssi"), -150, 0) if wireless else None})
        return sorted(result, key=lambda row: row["alias"])
    raise RouterError("unsupported_group", "This native data group is unsupported.")


@asynccontextmanager
async def _serialized(timeout: float):
    try:
        async with asyncio.timeout(timeout):
            await _READ_LOCK.acquire()
    except TimeoutError:
        raise RouterError("timeout", "Native command serialization deadline exceeded.") from None
    try:
        yield
    finally:
        _READ_LOCK.release()


async def _cleanup(client: Any, session: aiohttp.ClientSession, timeout: float, guard: RequestGuard) -> bool:
    ok = True
    try:
        async with asyncio.timeout(timeout):
            # Upstream shields its connect task. Stop/cancel traced child tasks
            # before closing the session, otherwise upstream can replace a
            # closed external session with an unguarded one. One scheduling
            # turn also lets a newly queued connect task hit the stopped guard.
            guard.stopped = True
            await asyncio.sleep(0)
            children = [task for task in guard.request_tasks if task is not asyncio.current_task() and not task.done()]
            for task in children:
                task.cancel()
            if children:
                await asyncio.gather(*children, return_exceptions=True)
            ok = await client.async_disconnect() is not False
    except Exception:
        ok = False
    finally:
        # The external session is owned here, not by upstream. Closing it also
        # prevents upstream's shielded login task from completing new requests.
        await session.close()
    return ok


async def probe_auth(config: TransportConfig, password: str, *, connection_factory: Callable[..., Any] | None = None) -> dict[str, Any]:
    """One native login and bounded logout; does not collect identity/config."""
    async with _serialized(config.timeout):
        token = _SUPPRESS_VENDOR.set(True)
        session = None
        client = None
        cleanup_ok = True
        try:
            _, native_connection, connection_config, _ = _upstream()
            guard = RequestGuard(config)
            session = verified_session(config, timeout=aiohttp.ClientTimeout(total=config.timeout), trace_configs=[guard.trace()])
            client = (connection_factory or native_connection)(hostname=config.hostname, username=config.username, password=password, port=config.port, use_ssl=config.use_ssl, session=session, timeout=config.timeout, config=connection_config)
            async with asyncio.timeout(config.timeout):
                deadline = asyncio.get_running_loop().time() + config.timeout
                connected = await client.async_connect()
                if asyncio.get_running_loop().time() >= deadline:
                    raise RouterError("timeout", "Native command deadline exceeded.")
                if not connected:
                    raise RouterError("auth_failed", "The router did not authenticate the session.")
            result = {"schema_version": 1, "authenticated": True, "source": "native", "fetched_at": datetime.now(timezone.utc).isoformat(), "observed_at": None, "freshness": "unknown"}
        except Exception as error:
            raise _safe_exception(error) from None
        finally:
            if session is not None:
                if client is not None:
                    cleanup_ok = await _cleanup(client, session, config.cleanup_timeout, guard)
                else:
                    await session.close()
            _SUPPRESS_VENDOR.reset(token)
        if not cleanup_ok:
            result["warnings"] = ["logout_unconfirmed"]
        return result


async def collect_native(config: TransportConfig, password: str, groups: tuple[str, ...] = GROUPS, *, router_factory: Callable[..., Any] | None = None, fingerprint_key: bytes, note_offset: int = 0, note_limit: int = 2048, state_dir: Any = None) -> dict[str, Any]:
    """Select safe hooks only. No raw vendor objects or observation timestamps."""
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise RouterError("identity_key_required", "A private identity key of at least 32 bytes is required.")
    if type(note_offset) is not int or not 0 <= note_offset <= 131072 or type(note_limit) is not int or not 1 <= note_limit <= 4096:
        raise RouterError("invalid_arguments", "Release-note offset must be nonnegative and limit 1..4096.", 2)
    if "firmware_note" not in groups and (note_offset != 0 or note_limit != 2048):
        raise RouterError("invalid_arguments", "Release-note pagination requires the firmware_note group.", 2)
    if not groups or len(groups) != len(set(groups)) or any(g not in GROUPS for g in groups):
        raise RouterError("unsupported_group", "Only named native telemetry groups are accepted.")
    # Identity is a mandatory safe gate even for a single-subsystem command.
    groups = ("identity",) + tuple(g for g in groups if g != "identity")
    expected_requests = len(groups) + 2 + ("speedtest" in groups) + ("aura" in groups) + ("dsl" in groups) - ("ports" in groups and "node_info" in groups)
    expected_requests -= max(0, len(set(groups) & {"uptime", "flags", "openvpn"}) - 1)
    if config.max_requests < expected_requests:
        raise RouterError("request_budget", "The request budget cannot cover the selected groups and cleanup.")
    async with _serialized(config.timeout):
        token = _SUPPRESS_VENDOR.set(True)
        session = None
        router = None
        cleanup_ok = True
        result: dict[str, Any] = {"schema_version": 1, "data": {}, "source": "native", "observed_at": None, "freshness": "unknown", "sources": {}, "capability_gaps": []}
        try:
            native_router, _, connection_config, strict_config = _upstream()
            guard = RequestGuard(config, tuple(HOOKS[g] for g in groups if g in HOOKS) + ((SPEEDTEST_CAPABILITY_HOOK,) if "speedtest" in groups else ()) + ((AURA_CAPABILITY_HOOK,) if "aura" in groups else ()), allow_ports="ports" in groups or "node_info" in groups, allow_aimesh="aimesh" in groups, allow_sysinfo="sysinfo" in groups, allow_uptime=bool(set(groups) & {"uptime", "flags", "openvpn"}), allow_temperature="temperature" in groups, allow_firmware="firmware" in groups, allow_firmware_note="firmware_note" in groups, allow_dsl="dsl" in groups)
            guard.max_requests = min(config.max_requests, expected_requests)
            session = verified_session(config, timeout=aiohttp.ClientTimeout(total=config.timeout), trace_configs=[guard.trace()], middlewares=[guard.middleware])
            router = (router_factory or native_router)(hostname=config.hostname, username=config.username, password=password, port=config.port, use_ssl=config.use_ssl, session=session, config=strict_config, connection_config=connection_config)
            async with asyncio.timeout(config.timeout):
                await router.async_init_connection()
                endpoint_cache: dict[Any, Any] = {}
                endpoint_fetched_at: dict[Any, str] = {}
                for group in groups:
                    if group not in HOOKS and group not in {"ports", "aimesh", "sysinfo", "uptime", "temperature", "firmware", "node_info", "firmware_note", "flags", "openvpn"}:
                        result["data"][group] = None
                        result["capability_gaps"].append({"group": group, "reason": "unsupported_native_state_only_contract"})
                        continue
                    if group in {"wlan", "guest"} and result["data"]["identity"]["model"] != "RT-AX86U":
                        raise RouterError("unsupported_model", "This model lacks a reviewed radio slot contract.")
                    if group in {"openvpn_server", "wireguard_server", "wireguard_clients"}:
                        validate_vpn_settings_identity(result["data"]["identity"])
                    if group == "openvpn":
                        # Finite reviewed stock dispatch. Merlin requires a fresh
                        # native identity signal; no firmware-suffix inference.
                        validate_vpn_settings_identity(result["data"]["identity"])
                    if group == "dsl":
                        from asusrouter.modules.endpoint import Endpoint
                        await router.async_api_query(Endpoint.DSL)
                    if group == "aura":
                        capability = normalize_aura_capability(await router.async_api_hook(AURA_CAPABILITY_HOOK))
                        if capability["aura_flag_present"] is None:
                            raise RouterError("capability_unknown", "The native Aura marker was not returned; applicability is unknown.")
                        if not capability["aura_flag_present"]:
                            raise RouterError("unsupported_capability", "The native Aura marker is unavailable; no settings read was attempted.")
                    if group == "speedtest":
                        capability = normalize_speedtest_capability(await router.async_api_hook(SPEEDTEST_CAPABILITY_HOOK))
                        if not capability["ookla_supported"]:
                            raise RouterError("unsupported_capability", "The native Ookla capability flag is unavailable; no result read was attempted.")
                    if group in {"ports", "aimesh", "sysinfo", "uptime", "temperature", "firmware", "node_info", "firmware_note", "flags", "openvpn"}:
                        from asusrouter.modules.endpoint import Endpoint
                        endpoint = {"ports": Endpoint.PORT_STATUS, "node_info": Endpoint.PORT_STATUS, "aimesh": Endpoint.ONBOARDING, "sysinfo": Endpoint.SYSINFO, "uptime": Endpoint.DEVICEMAP, "flags": Endpoint.DEVICEMAP, "openvpn": Endpoint.DEVICEMAP, "temperature": Endpoint.TEMPERATURE, "firmware": Endpoint.FIRMWARE, "firmware_note": Endpoint.FIRMWARE_NOTE}[group]
                        if endpoint not in endpoint_cache:
                            endpoint_cache[endpoint] = await router.async_api_load(endpoint)
                            endpoint_fetched_at[endpoint] = datetime.now(timezone.utc).isoformat()
                        raw = endpoint_cache[endpoint]
                        fetched_at = endpoint_fetched_at[endpoint]
                    else:
                        raw = await router.async_api_hook(HOOKS[group])
                        fetched_at = datetime.now(timezone.utc).isoformat()
                    vpn_parsers = {"openvpn_server": normalize_openvpn_server, "wireguard_server": normalize_wireguard_server, "wireguard_clients": normalize_wireguard_clients}
                    if group == "flags":
                        value = observe_flags(raw, result["data"]["identity"], state_dir=state_dir)
                    elif group == "openvpn":
                        value = normalize_openvpn(raw, flavor="stock")
                    elif group == "firmware_note":
                        value = normalize_firmware_note(raw, offset=note_offset, limit=note_limit)
                    else:
                        value = vpn_parsers[group](raw, result["data"]["identity"]) if group in vpn_parsers else _normalize(group, raw, fingerprint_key)
                    if group == "speedtest":
                        value["gaps"] = [gap for gap in value["gaps"] if gap != "ookla_capability_not_discovered"] + ["ookla_capability_flag_is_not_job_authorization"]
                    result["data"][group] = value
                    if isinstance(value, dict) and "gaps" in value:
                        result["capability_gaps"].extend({"group": group, "reason": reason} for reason in value["gaps"])
                    result["fetched_at"] = max(result.get("fetched_at", fetched_at), fetched_at)
                    result["sources"][group] = {"fetched_at": fetched_at, "observed_at": None, "freshness": "unknown", "reason": "router_cached" if group == "clients" else "source_observation_time_unavailable"}
        except Exception as error:
            raise _safe_exception(error) from None
        finally:
            if session is not None:
                if router is not None:
                    cleanup_ok = await _cleanup(router, session, config.cleanup_timeout, guard)
                else:
                    await session.close()
            _SUPPRESS_VENDOR.reset(token)
        if not cleanup_ok:
            result["warnings"] = ["logout_unconfirmed"]
        return result


class TrafficGuard(RequestGuard):
    """One freshly resolved, typed native traffic request; static guard stays closed."""
    def __init__(self, config: TransportConfig):
        super().__init__(config, (HOOKS['identity'],), allow_aimesh=True)
        self.prepared = None
        self.traffic_url = None
        self.traffic_reads = 0

    def arm(self, prepared: Any) -> None:
        from asusrouter.modules.endpoint import EndpointTools
        from .traffic_reads import PreparedTrafficRead
        from urllib.parse import parse_qsl, quote
        endpoints = {'ethernet': EndpointTools.TRAFFIC_ETHERNET, 'wifi': EndpointTools.TRAFFIC_WIFI, 'backhaul': EndpointTools.TRAFFIC_BACKHAUL}
        if (self.prepared is not None or not isinstance(prepared, PreparedTrafficRead)
                or type(prepared.endpoint) is not EndpointTools or prepared.endpoint != endpoints.get(prepared.kind)):
            raise RouterError('read_boundary', 'The typed native traffic request was rejected.')
        try:
            pairs = parse_qsl(prepared.request, keep_blank_values=True, strict_parsing=True)
        except (ValueError, TypeError):
            raise RouterError('read_boundary', 'The typed native traffic query was rejected.') from None
        second = {'ethernet': 'is_bh', 'wifi': 'band_mac', 'backhaul': 'sta_mac'}[prepared.kind]
        if len(pairs) != 2 or [key for key, _ in pairs] != ['node_mac', second]:
            raise RouterError('read_boundary', 'The typed native traffic query was rejected.')
        node, towards = pairs[0][1], pairs[1][1]
        mac = r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}'
        invalid = {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}
        if (not re.fullmatch(mac, node) or node in invalid
                or prepared.kind == 'ethernet' and towards != str(int(prepared.backhaul))
                or prepared.kind != 'ethernet' and (not re.fullmatch(mac, towards) or towards in invalid)):
            raise RouterError('read_boundary', 'The typed native traffic identifiers were rejected.')
        expected = f'node_mac={quote(node, safe="")}&{second}={quote(towards, safe="")}'
        if prepared.request != expected:
            raise RouterError('read_boundary', 'The typed native traffic query encoding was rejected.')
        self.prepared = prepared
        self.traffic_url = URL(f'{self.origin}/{prepared.endpoint.value}?{prepared.request}')

    def matches(self, url: Any, method: str) -> bool:
        value = URL(url)
        expected = self.traffic_url
        return (expected is not None and method == 'GET' and not value.user and not value.password
                and (value.scheme, value.raw_host, value.port, value.path, value.raw_query_string)
                == (expected.scheme, expected.raw_host, expected.port, expected.path, expected.raw_query_string))

    async def start(self, session: Any, ctx: Any, params: Any) -> None:
        if self.traffic_url is None or URL(params.url).path != self.traffic_url.path:
            await super().start(session, ctx, params)
            return
        task = asyncio.current_task()
        if task is not None:
            self.request_tasks.add(task)
        if not self.matches(params.url, params.method) or not self.authenticated or self.stopped:
            raise RouterError('read_boundary', 'The typed native traffic request was rejected.')
        if self.traffic_reads >= 1 or self.requests >= self.max_requests:
            raise RouterError('read_boundary', 'A repeated or excess native traffic request was blocked.')
        self.traffic_reads += 1
        self.requests += 1

    async def middleware(self, request: aiohttp.ClientRequest, handler: Any) -> aiohttp.ClientResponse:
        if self.traffic_url is not None and request.url.path == self.traffic_url.path:
            if not self.matches(request.url, request.method) or request.body not in (None, b''):
                raise RouterError('read_boundary', 'The typed traffic request was rejected before transmission.')
        return await super().middleware(request, handler)

    async def chunk(self, session: Any, ctx: Any, params: Any) -> None:
        if self.traffic_url is not None and URL(params.url).path == self.traffic_url.path:
            if params.chunk:
                raise RouterError('read_boundary', 'A native traffic request body was rejected.')
            return
        await super().chunk(session, ctx, params)

    async def end(self, session: Any, ctx: Any, params: Any) -> None:
        if self.traffic_url is None or URL(params.url).path != self.traffic_url.path:
            await super().end(session, ctx, params)
            return
        from .traffic_reads import normalize_traffic
        response = params.response
        if response.status != 200:
            raise RouterError('http_error', 'The router returned an unsuccessful HTTP response.')
        try:
            if len(await response.read()) > 65536:
                raise ValueError
            raw = await response.json(content_type=None)
        except (ValueError, UnicodeError, aiohttp.ClientError):
            raise RouterError('malformed_response', 'Native selected traffic rates are missing or malformed.') from None
        # Check every nested status before upstream's top-level auth parser can
        # misclassify it or attempt a reconnect. Raw vendor fields never escape.
        visited = [0]
        def check(value: Any, depth: int = 0) -> None:
            visited[0] += 1
            if visited[0] > 512 or depth > 4:
                raise RouterError('malformed_response', 'Native selected traffic rates are missing or malformed.')
            if isinstance(value, dict):
                if len(value) > 128:
                    raise RouterError('malformed_response', 'Native selected traffic rates are missing or malformed.')
                if 'error_status' in value:
                    status = value['error_status']
                    if type(status) not in (str, int) or isinstance(status, str) and not re.fullmatch(r'[0-9]{1,3}', status):
                        raise RouterError('malformed_response', 'Native traffic status is malformed.')
                    code = int(status)
                    if code in {2, 3, 7, 9, 10, 11}:
                        self.stopped = True
                        raise RouterError(f'auth_{code}', 'Router authentication stopped; local intervention is required.')
                    if code not in {0, 200}:
                        self.stopped = True
                        raise RouterError('native_status_failed', 'The router returned an unsuccessful native status.')
                for item in value.values():
                    check(item, depth + 1)
            elif isinstance(value, list):
                if len(value) > 128:
                    raise RouterError('malformed_response', 'Native selected traffic rates are missing or malformed.')
                for item in value:
                    check(item, depth + 1)
        check(raw)
        normalize_traffic(raw, self.prepared)


async def collect_traffic(config: TransportConfig, password: str, kind: str, node_alias: str, *,
                          fingerprint_key: bytes, peer_alias: str | None = None, band: str | None = None,
                          backhaul: bool = False, router_factory: Callable[..., Any] | None = None) -> dict[str, Any]:
    """One native traffic read following fresh same-session private alias resolution."""
    from .traffic_reads import prepare_traffic_request, normalize_traffic
    alias_pattern = r'node-[0-9a-f]{16}'
    valid = (type(kind) is str and kind in {'ethernet', 'wifi', 'backhaul'} and type(node_alias) is str
             and re.fullmatch(alias_pattern, node_alias) and type(backhaul) is bool)
    if kind == 'ethernet':
        valid = valid and peer_alias is None and band is None
    elif kind == 'wifi':
        valid = valid and peer_alias is None and not backhaul and type(band) is str and band in {'2ghz', '5ghz', '5ghz2', '6ghz'}
    elif kind == 'backhaul':
        valid = valid and band is None and not backhaul and type(peer_alias) is str and re.fullmatch(alias_pattern, peer_alias) and peer_alias != node_alias
    if not valid:
        raise RouterError('invalid_arguments', 'Traffic reads require valid typed node aliases and mode-specific options.', 2)
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise RouterError('identity_key_required', 'A private identity key of at least 32 bytes is required.')
    if config.max_requests < 5:
        raise RouterError('request_budget', 'The request budget cannot cover the typed traffic read and cleanup.')
    async with _serialized(config.timeout):
        token = _SUPPRESS_VENDOR.set(True)
        session = None
        router = None
        guard = TrafficGuard(config)
        guard.max_requests = 5
        cleanup_ok = True
        try:
            native_router, _, connection_config, strict_config = _upstream()
            session = verified_session(config, timeout=aiohttp.ClientTimeout(total=config.timeout), trace_configs=[guard.trace()], middlewares=[guard.middleware])
            router = (router_factory or native_router)(hostname=config.hostname, username=config.username, password=password, port=config.port, use_ssl=config.use_ssl, session=session, config=strict_config, connection_config=connection_config)
            async with asyncio.timeout(config.timeout):
                await router.async_init_connection()
                identity = _normalize('identity', await router.async_api_hook(HOOKS['identity']), fingerprint_key)
                identity_fetched_at = datetime.now(timezone.utc).isoformat()
                from asusrouter.modules.endpoint import Endpoint
                inventory = await router.async_api_load(Endpoint.ONBOARDING)
                inventory_fetched_at = datetime.now(timezone.utc).isoformat()
                prepared = await prepare_traffic_request(kind, node_alias, inventory, fingerprint_key, peer_alias=peer_alias, band=band, backhaul=backhaul)
                guard.arm(prepared)
                raw = await router.async_api_load(prepared.endpoint, request=prepared.request)
                traffic_fetched_at = datetime.now(timezone.utc).isoformat()
                selected = normalize_traffic(raw, prepared)
                selected['gaps'] += ['target_stock_handler_and_hardware_applicability_unverified']
                result = {'schema_version': 1, 'source': 'native', 'fetched_at': traffic_fetched_at, 'observed_at': None, 'freshness': 'unknown',
                          'data': {'identity': identity, 'traffic': selected},
                          'sources': {group: {'fetched_at': fetched, 'observed_at': None, 'freshness': 'unknown', 'reason': 'source_observation_time_unavailable'} for group, fetched in (('identity', identity_fetched_at), ('aimesh', inventory_fetched_at), ('traffic', traffic_fetched_at))},
                          'capability_gaps': [{'group': 'traffic', 'reason': gap} for gap in selected['gaps']]}
        except Exception as error:
            raise _safe_exception(error) from None
        finally:
            if session is not None:
                if router is not None:
                    cleanup_ok = await _cleanup(router, session, config.cleanup_timeout, guard)
                else:
                    await session.close()
            _SUPPRESS_VENDOR.reset(token)
        if not cleanup_ok:
            result['warnings'] = ['logout_unconfirmed']
        return result
