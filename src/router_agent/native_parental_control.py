"""Target-bound native parental operations; never authorization or a raw editor.

Caller must persist uncertainty before invoking a write and keep private policy
snapshots out of plans/output. Fresh full-policy fingerprints bind every field.
Native rule operations receive an explicit validated AsusDataState snapshot;
we never mutate AsusRouter._state or invoke its uninitialized rule setter.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
import re
from typing import Any, Callable
from urllib.parse import quote

import aiohttp
from yarl import URL

from .errors import RouterError
from .tls import verified_session
from .transport import (HOOKS, RequestGuard, TransportConfig, _SUPPRESS_VENDOR,
                        _cleanup, _normalize, _safe_exception, _serialized, _upstream)

SUPPORTED_MODEL = 'RT-AX86U'
SUPPORTED_FIRMWARE = '3.0.0.4.388_24436-ge7c0b5e'
from .parental_policy import PARENTAL_POLICY_HOOK
FULL_POLICY_HOOK = PARENTAL_POLICY_HOOK
RULE_KEYS = ('MULTIFILTER_MAC', 'MULTIFILTER_DEVICENAME', 'MULTIFILTER_MACFILTER_DAYTIME_V2', 'MULTIFILTER_ENABLE')


def validate_parental_applicability(identity: Any) -> None:
    if not isinstance(identity, dict) or identity.get('model') != SUPPORTED_MODEL or identity.get('firmware') != SUPPORTED_FIRMWARE:
        raise RouterError('unsupported_parental_target', 'Native parental operations require the reviewed model and firmware.')


def _binding(identity: Any, fingerprint: Any, key: bytes) -> None:
    if (not isinstance(identity, dict) or set(identity) != {'model', 'firmware', 'device_fingerprint'}
            or any(type(value) is not str or not value for value in identity.values())
            or type(fingerprint) is not str or not 1 <= len(fingerprint) <= 128):
        raise RouterError('invalid_operation', 'The native parental operation binding is invalid.')
    validate_parental_applicability(identity)
    if not isinstance(key, bytes) or len(key) < 32:
        raise RouterError('identity_key_required', 'A private identity key of at least 32 bytes is required.')


def parental_body(arguments: dict[str, Any]) -> bytes:
    """Exact public service.py construction; no configurable service name."""
    return quote(str({'rc_service': 'restart_firewall', **arguments, 'action_mode': 'apply'})).encode('ascii')


class ParentalGuard(RequestGuard):
    def __init__(self, config: TransportConfig, *, include_clients=False, authorization_check=None):
        super().__init__(config, (HOOKS['identity'], FULL_POLICY_HOOK) + ((HOOKS['clients'],) if include_clients else ()))
        self.authorization_check = authorization_check
        self.expected_body = None
        self.write_attempted = False

    def arm(self, arguments: dict[str, Any]) -> None:
        if self.expected_body is not None or not isinstance(arguments, dict):
            raise RouterError('write_boundary', 'Native parental operation arguments were rejected.')
        if set(arguments) in ({'MULTIFILTER_ALL'}, {'MULTIFILTER_BLOCK_ALL'}):
            value = next(iter(arguments.values()))
            valid = type(value) is int and value in (0, 1)
        else:
            valid = tuple(arguments) == RULE_KEYS and all(type(value) is str and len(value) <= 32768 and '\x00' not in value for value in arguments.values())
        if not valid:
            raise RouterError('write_boundary', 'Native parental operation arguments were rejected.')
        self.expected_body = parental_body(arguments)

    async def start(self, session: Any, ctx: Any, params: Any) -> None:
        url = URL(params.url)
        if url.path != '/applyapp.cgi':
            await super().start(session, ctx, params)
            return
        task = asyncio.current_task()
        if task is not None:
            self.request_tasks.add(task)
        if ((url.scheme, url.raw_host, url.port) != (self.origin.scheme, self.origin.raw_host, self.origin.port)
                or url.user or url.password or url.query_string or params.method != 'POST'
                or self.expected_body is None or not self.authenticated or self.stopped
                or self.write_attempted or self.requests >= self.max_requests):
            raise RouterError('write_boundary', 'The native parental write was rejected.')
        self.requests += 1

    async def middleware(self, request: aiohttp.ClientRequest, handler: Any) -> aiohttp.ClientResponse:
        if request.url.path == '/applyapp.cgi':
            body = request.body
            if (self.expected_body is None or not self.authenticated or self.stopped or self.write_attempted
                    or not isinstance(body, aiohttp.payload.StringPayload) or await body.as_bytes() != self.expected_body):
                raise RouterError('write_boundary', 'The native parental payload was rejected before transmission.')
            if not callable(self.authorization_check):
                raise RouterError('approval_window_required', 'Write admission requires an independent authorization check.')
            self.authorization_check()
            self.write_attempted = True
        return await super().middleware(request, handler)

    async def chunk(self, session: Any, ctx: Any, params: Any) -> None:
        if URL(params.url).path == '/applyapp.cgi':
            if not self.write_attempted or params.chunk != self.expected_body:
                raise RouterError('write_boundary', 'The native parental payload was rejected.')
            return
        await super().chunk(session, ctx, params)


def _client_inventory(raw: Any) -> dict[str, dict]:
    if not isinstance(raw, dict) or not isinstance(raw.get('get_clientlist'), dict) or len(raw['get_clientlist']) > 4098:
        raise RouterError('malformed_response', 'Native client inventory is missing or malformed.')
    selected = {}
    seen = set()
    for mac, record in raw['get_clientlist'].items():
        if mac == 'maclist' and isinstance(record, list):
            continue
        if mac == 'ClientAPILevel' and isinstance(record, str):
            continue
        if type(mac) is not str or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac) or not isinstance(record, dict):
            raise RouterError('malformed_response', 'Native client inventory is missing or malformed.')
        if mac.upper() in seen:
            raise RouterError('malformed_response', 'Native client inventory contains duplicate identifiers.')
        seen.add(mac.upper())
        selected[mac] = {}  # Alias resolution needs identifiers only, never names/IPs.
    return selected


async def read_parental_policy(config: TransportConfig, password: str, *, fingerprint_key: bytes,
                               router_factory: Callable[..., Any] | None = None, include_clients: bool = False) -> dict[str, Any]:
    """Private operation observation: caller must not emit/store this as public JSON."""
    from .parental_policy import read_policy_snapshot
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise RouterError('identity_key_required', 'A private identity key of at least 32 bytes is required.')
    if type(include_clients) is not bool:
        raise RouterError("invalid_arguments", "Private policy client inventory option must be boolean.", 2)
    budget = 5 if include_clients else 4
    if config.max_requests < budget:
        raise RouterError('request_budget', 'The request budget cannot cover a private policy observation and cleanup.')
    async with _serialized(config.timeout):
        token = _SUPPRESS_VENDOR.set(True)
        session = router = None
        guard = ParentalGuard(config, include_clients=include_clients)
        guard.max_requests = budget
        cleanup_ok = True
        try:
            native_router, _, connection_config, strict_config = _upstream()
            session = verified_session(config, timeout=aiohttp.ClientTimeout(total=config.timeout), trace_configs=[guard.trace()], middlewares=[guard.middleware])
            router = (router_factory or native_router)(hostname=config.hostname, username=config.username, password=password,
                        port=config.port, use_ssl=config.use_ssl, session=session, config=strict_config, connection_config=connection_config)
            async with asyncio.timeout(config.timeout):
                await router.async_init_connection()
                identity = _normalize('identity', await router.async_api_hook(HOOKS['identity']), fingerprint_key)
                validate_parental_applicability(identity)
                snapshot = read_policy_snapshot(await router.async_api_hook(FULL_POLICY_HOOK), fingerprint_key)
                result = {'identity': identity, 'policy': snapshot}
                if include_clients:
                    result['client_inventory'] = _client_inventory(await router.async_api_hook(HOOKS['clients']))
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


async def _apply_parental(config: TransportConfig, password: str, *, expected_identity: dict[str, str],
                          expected_policy_fingerprint: str, expected_after_policy_fingerprint: str, fingerprint_key: bytes, kind: str,
                          enabled: bool | None = None, client_alias: str | None = None,
                          rule_type: str | None = None, schedule: Any = None, restore_snapshot: Any = None,
                          router_factory: Callable[..., Any] | None = None, authorization_check=None) -> dict[str, Any]:
    config.require_secure_write()
    from .parental_policy import read_policy_snapshot, prepare_enable, prepare_block_all, prepare_rule, prepare_restore
    _binding(expected_identity, expected_policy_fingerprint, fingerprint_key)
    _binding(expected_identity, expected_after_policy_fingerprint, fingerprint_key)
    include_clients = kind == 'rule'
    budget = 6 if include_clients else 5
    if config.max_requests < budget:
        raise RouterError('request_budget', 'The request budget cannot cover the bound parental operation and cleanup.')
    async with _serialized(config.timeout):
        token = _SUPPRESS_VENDOR.set(True)
        session = router = None
        guard = ParentalGuard(config, include_clients=include_clients, authorization_check=authorization_check)
        guard.max_requests = budget
        cleanup_ok = True
        try:
            native_router, _, connection_config, strict_config = _upstream()
            session = verified_session(config, timeout=aiohttp.ClientTimeout(total=config.timeout), trace_configs=[guard.trace()], middlewares=[guard.middleware])
            router = (router_factory or native_router)(hostname=config.hostname, username=config.username, password=password,
                        port=config.port, use_ssl=config.use_ssl, session=session, config=strict_config, connection_config=connection_config)
            async with asyncio.timeout(config.timeout):
                await router.async_init_connection()
                identity = _normalize('identity', await router.async_api_hook(HOOKS['identity']), fingerprint_key)
                if identity != expected_identity:
                    raise RouterError('identity_changed', 'The router identity changed since the approved policy observation.')
                validate_parental_applicability(identity)
                before = read_policy_snapshot(await router.async_api_hook(FULL_POLICY_HOOK), fingerprint_key)
                if before.fingerprint != expected_policy_fingerprint:
                    raise RouterError('policy_changed', 'The complete parental policy changed since the approved observation.')
                if kind == 'enable':
                    prepared = await prepare_enable(before, enabled)
                elif kind == 'block_all':
                    prepared = await prepare_block_all(before, enabled)
                elif kind == 'rule':
                    inventory = _client_inventory(await router.async_api_hook(HOOKS['clients']))
                    prepared = await prepare_rule(before, client_alias, rule_type, client_inventory=inventory, schedule=schedule)
                else:
                    prepared = await prepare_restore(before, restore_snapshot)
                if prepared.after.fingerprint != expected_after_policy_fingerprint:
                    raise RouterError('after_policy_changed', 'The prepared parental policy differs from the approved exact result.')
                if not prepared.noop:
                    guard.arm(deepcopy(prepared.arguments))
                    from asusrouter.modules.parental_control import set_state, set_rule
                    if kind in {'enable', 'block_all'}:
                        success = await set_state(router.async_run_service, deepcopy(prepared.native_state))
                    elif kind == 'rule':
                        success = await set_rule(router.async_run_service, deepcopy(prepared.native_rule), router_state=deepcopy(prepared.router_state))
                    else:
                        # Maintained serializer generated the exact ordered four
                        # fields and the same service proven by native set_rule.
                        success = await router.async_run_service('restart_firewall', arguments=deepcopy(prepared.arguments), apply=True)
                    if success is not True or not guard.write_attempted:
                        raise RouterError('apply_uncertain', 'Parental operation outcome is uncertain; verify independently without retrying.')
                result = {'schema_version': 1, 'source': 'native', 'freshness': 'unknown' if prepared.noop else 'applied_unverified',
                          'noop': prepared.noop, 'write_attempted': guard.write_attempted,
                          'policy_fingerprint': prepared.after.fingerprint,
                          'before': prepared.public_before, 'after': prepared.public_after}
        except Exception as error:
            if guard.write_attempted:
                raise RouterError('apply_uncertain', 'Parental operation outcome is uncertain; verify independently without retrying.') from None
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


async def set_parental_global(config: TransportConfig, password: str, *, expected_identity: dict[str, str],
                              expected_policy_fingerprint: str, expected_after_policy_fingerprint: str, enabled: bool, fingerprint_key: bytes,
                              router_factory: Callable[..., Any] | None = None, authorization_check=None) -> dict[str, Any]:
    if type(enabled) is not bool:
        raise RouterError('invalid_operation', 'The parental global enabled value must be boolean.')
    return await _apply_parental(config, password, expected_identity=expected_identity, expected_policy_fingerprint=expected_policy_fingerprint, expected_after_policy_fingerprint=expected_after_policy_fingerprint,
                                 fingerprint_key=fingerprint_key, kind='enable', enabled=enabled, router_factory=router_factory, authorization_check=authorization_check)


async def set_parental_rule(config: TransportConfig, password: str, *, expected_identity: dict[str, str],
                            expected_policy_fingerprint: str, expected_after_policy_fingerprint: str, client_alias: str, rule_type: str,
                            fingerprint_key: bytes, schedule: Any = None,
                            router_factory: Callable[..., Any] | None = None, authorization_check=None) -> dict[str, Any]:
    if type(client_alias) is not str or not re.fullmatch(r'client-[0-9a-f]{16}', client_alias) or type(rule_type) is not str or rule_type not in {'disable', 'time', 'block', 'remove'}:
        raise RouterError('invalid_operation', 'The native parental rule intent is invalid.')
    return await _apply_parental(config, password, expected_identity=expected_identity, expected_policy_fingerprint=expected_policy_fingerprint, expected_after_policy_fingerprint=expected_after_policy_fingerprint,
                                 fingerprint_key=fingerprint_key, kind='rule', client_alias=client_alias, rule_type=rule_type, schedule=schedule, router_factory=router_factory, authorization_check=authorization_check)


async def restore_parental_rules(config: TransportConfig, password: str, *, expected_identity: dict[str, str],
                                 expected_policy_fingerprint: str, expected_after_policy_fingerprint: str, restore_snapshot: Any, fingerprint_key: bytes,
                                 router_factory: Callable[..., Any] | None = None, authorization_check=None) -> dict[str, Any]:
    from .parental_policy import PolicySnapshot
    if not isinstance(restore_snapshot, PolicySnapshot):
        raise RouterError('invalid_operation', 'A validated private policy snapshot is required for rule restoration.')
    return await _apply_parental(config, password, expected_identity=expected_identity, expected_policy_fingerprint=expected_policy_fingerprint, expected_after_policy_fingerprint=expected_after_policy_fingerprint,
                                 fingerprint_key=fingerprint_key, kind='restore', restore_snapshot=restore_snapshot, router_factory=router_factory, authorization_check=authorization_check)


async def set_parental_block_all(config: TransportConfig, password: str, *, expected_identity: dict[str, str],
                                 expected_policy_fingerprint: str, expected_after_policy_fingerprint: str, blocked: bool, fingerprint_key: bytes,
                                 router_factory: Callable[..., Any] | None = None, authorization_check=None) -> dict[str, Any]:
    """Distinct all-client operation; never implied by the global enabled toggle."""
    if type(blocked) is not bool:
        raise RouterError('invalid_operation', 'The parental block-all value must be boolean.')
    return await _apply_parental(config, password, expected_identity=expected_identity, expected_policy_fingerprint=expected_policy_fingerprint, expected_after_policy_fingerprint=expected_after_policy_fingerprint,
                                 fingerprint_key=fingerprint_key, kind='block_all', enabled=blocked, router_factory=router_factory, authorization_check=authorization_check)
