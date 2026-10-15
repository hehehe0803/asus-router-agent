"""One firmware-bound native LED operation, using public upstream methods.

Transport is not authorization. Callers must independently validate the user's
approved scope and durably record uncertainty before invoking a write.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable
from urllib.parse import quote

import aiohttp
from yarl import URL

from .errors import RouterError
from .tls import verified_session
from .transport import (HOOKS, RequestGuard, TransportConfig, _SUPPRESS_VENDOR,
                        _cleanup, _normalize, _safe_exception, _serialized, _upstream)

SUPPORTED_MODEL = "RT-AX86U"
SUPPORTED_FIRMWARE = "3.0.0.4.388_24436-ge7c0b5e"


def validate_led_applicability(identity: dict[str, Any]) -> None:
    if identity.get("model") != SUPPORTED_MODEL or identity.get("firmware") != SUPPORTED_FIRMWARE:
        raise RouterError("unsupported_firmware", "The native LED operation lacks a reviewed model and firmware contract.")


def led_body(enabled: bool) -> bytes:
    """Exact upstream service.py command order and connection.py URL quoting."""
    return quote(str({"rc_service": "start_ctrl_led", "led_val": int(enabled),
                      "action_mode": "apply"})).encode("ascii")


class LEDGuard(RequestGuard):
    def __init__(self, config: TransportConfig, enabled: bool, *, authorization_check=None):
        super().__init__(config, (HOOKS["identity"], HOOKS["led"]))
        self.authorization_check = authorization_check
        self.expected_body = led_body(enabled)
        self.armed = False
        self.write_attempted = False

    async def start(self, session: Any, ctx: Any, params: Any) -> None:
        url = URL(params.url)
        if url.path != "/applyapp.cgi":
            await super().start(session, ctx, params)
            return
        task = asyncio.current_task()
        if task is not None:
            self.request_tasks.add(task)
        if ((url.scheme, url.raw_host, url.port) != (self.origin.scheme, self.origin.raw_host, self.origin.port)
                or url.user or url.password or url.query_string or params.method != "POST"
                or not self.armed or not self.authenticated or self.stopped):
            raise RouterError("write_boundary", "Native LED request rejected by the operation boundary.")
        self.requests += 1
        if self.requests > self.max_requests:
            raise RouterError("request_budget", "Native request budget exhausted.")

    async def middleware(self, request: aiohttp.ClientRequest, handler: Any) -> aiohttp.ClientResponse:
        if request.url.path == "/applyapp.cgi":
            # Client middleware wraps the send handler, before connection/request
            # transmission. Only the exact StringPayload bytes are admitted.
            body = request.body
            if (not self.armed or not self.authenticated or self.stopped
                    or self.write_attempted or not isinstance(body, aiohttp.payload.StringPayload)
                    or await body.as_bytes() != self.expected_body):
                raise RouterError("write_boundary", "Native LED payload rejected before transmission.")
            if not callable(self.authorization_check):
                raise RouterError("approval_window_required", "Write admission requires an independent authorization check.")
            self.authorization_check()
            self.write_attempted = True
        return await handler(request)

    async def chunk(self, session: Any, ctx: Any, params: Any) -> None:
        if URL(params.url).path == "/applyapp.cgi":
            if not self.write_attempted or params.chunk != self.expected_body:
                raise RouterError("write_boundary", "Native LED payload rejected.")
            return
        await super().chunk(session, ctx, params)


async def set_led(config: TransportConfig, password: str, *, expected_identity: dict[str, str],
                  expected_before: bool, enabled: bool, fingerprint_key: bytes,
                  router_factory: Callable[..., Any] | None = None, authorization_check=None) -> dict[str, Any]:
    """Bind one native LED request to identity and before-state; never retry."""
    config.require_secure_write()
    if (type(enabled) is not bool or type(expected_before) is not bool
            or not isinstance(expected_identity, dict)
            or set(expected_identity) != {"device_fingerprint", "model", "firmware"}
            or any(not isinstance(v, str) or not v for v in expected_identity.values())):
        raise RouterError("invalid_operation", "Native LED operation binding is invalid.")
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise RouterError("identity_key_required", "A private identity key of at least 32 bytes is required.")
    async with _serialized(config.timeout):
        token = _SUPPRESS_VENDOR.set(True)
        session = None
        router = None
        guard = LEDGuard(config, enabled, authorization_check=authorization_check)
        cleanup_ok = True
        try:
            native_router, _, connection_config, strict_config = _upstream()
            session = verified_session(config, timeout=aiohttp.ClientTimeout(total=config.timeout),
                                            trace_configs=[guard.trace()], middlewares=[guard.middleware])
            router = (router_factory or native_router)(hostname=config.hostname, username=config.username,
                        password=password, port=config.port, use_ssl=config.use_ssl, session=session,
                        config=strict_config, connection_config=connection_config)
            async with asyncio.timeout(config.timeout):
                await router.async_init_connection()
                identity = _normalize("identity", await router.async_api_hook(HOOKS["identity"]), fingerprint_key)
                if identity != expected_identity:
                    raise RouterError("identity_changed", "The router identity changed since the approved observation.")
                validate_led_applicability(identity)
                before = _normalize("led", await router.async_api_hook(HOOKS["led"]), fingerprint_key)["enabled"]
                if type(before) is not bool or before is not expected_before:
                    raise RouterError("state_changed", "The LED before-state changed or is unknown.")
                if before is enabled:
                    result = {"schema_version": 1, "source": "native", "freshness": "unknown",
                              "before": before, "after": enabled, "noop": True, "write_attempted": False}
                else:
                    from asusrouter.modules.led import AsusLED
                    guard.armed = True
                    success = await router.async_set_state(AsusLED.ON if enabled else AsusLED.OFF)
                    if success is not True or not guard.write_attempted:
                        raise RouterError("apply_uncertain", "The LED operation outcome is uncertain; verify without retrying.")
                    result = {"schema_version": 1, "source": "native", "freshness": "applied_unverified",
                              "before": before, "after": enabled, "noop": False, "write_attempted": True}
        except Exception as error:
            if guard.write_attempted:
                raise RouterError("apply_uncertain", "The LED operation outcome is uncertain; verify without retrying.") from None
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
