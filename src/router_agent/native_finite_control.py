"""Guarded native finite transport; admission must durably precede send.

Private snapshots never enter results or error messages. Production backup
admission belongs to the engine and remains required for effective writes.
"""
import asyncio
from copy import deepcopy
from urllib.parse import quote

import aiohttp
from yarl import URL

from .errors import RouterError
from .finite_controls import compile_native, prepare, settings_hook, validate_intent, validate_raw
from .hardware_reads import AURA_CAPABILITY_HOOK, normalize_aura_capability
from .tls import verified_session
from .transport import (HOOKS, RequestGuard, _SUPPRESS_VENDOR, _cleanup,
                        _normalize, _safe_exception, _serialized, _upstream)
from .vpn_settings_reads import validate_vpn_settings_identity


def finite_body(service, arguments):
    return quote(str({'rc_service': service, **arguments, 'action_mode': 'apply'})).encode('ascii')


class FiniteGuard(RequestGuard):
    def __init__(self, config, operation, intent=None, authorization_check=None):
        hooks = (HOOKS['identity'], settings_hook(operation, intent))
        if operation == 'state.aura':
            hooks += (AURA_CAPABILITY_HOOK,)
        super().__init__(config, hooks)
        self.operation, self.intent = operation, deepcopy(intent)
        self.expected_body = None
        self.write_attempted = False
        self.authorization_check = authorization_check

    async def arm(self, prepared):
        if self.expected_body is not None:
            raise RouterError('write_boundary', 'A native finite command was already armed.')
        expected = await prepare(self.operation, prepared.before, self.intent)
        if (prepared.after != expected.after or prepared.service != expected.service
                or prepared.arguments != expected.arguments):
            raise RouterError('write_boundary', 'The native finite command differs from its maintained compiler.')
        self.expected_body = finite_body(expected.service, expected.arguments)

    async def start(self, session, ctx, params):
        url = URL(params.url)
        if url.path != '/applyapp.cgi':
            return await super().start(session, ctx, params)
        task = asyncio.current_task()
        if task is not None:
            self.request_tasks.add(task)
        if ((url.scheme, url.raw_host, url.port) != (self.origin.scheme, self.origin.raw_host, self.origin.port)
                or url.user or url.password or url.query_string or params.method != 'POST'
                or self.expected_body is None or not self.authenticated or self.stopped
                or self.write_attempted or self.requests >= self.max_requests):
            raise RouterError('write_boundary', 'The native finite write was rejected.')
        self.requests += 1

    async def middleware(self, request, handler):
        if request.url.path == '/applyapp.cgi':
            body = request.body
            if (self.expected_body is None or not self.authenticated or self.stopped or self.write_attempted
                    or not isinstance(body, aiohttp.payload.StringPayload) or await body.as_bytes() != self.expected_body):
                raise RouterError('write_boundary', 'The exact native finite payload was rejected before transmission.')
            if not callable(self.authorization_check):
                raise RouterError('approval_window_required', 'Independent write admission is required.')
            self.authorization_check()
            self.write_attempted = True
        return await super().middleware(request, handler)

    async def chunk(self, session, ctx, params):
        if URL(params.url).path == '/applyapp.cgi':
            if not self.write_attempted or params.chunk != self.expected_body:
                raise RouterError('write_boundary', 'The native finite payload was rejected.')
            return
        await super().chunk(session, ctx, params)


async def _observe(router, operation, intent, key, expected_identity=None):
    identity = _normalize('identity', await router.async_api_hook(HOOKS['identity']), key)
    validate_vpn_settings_identity(identity)  # before any settings or credentials
    if expected_identity is not None and identity != expected_identity:
        raise RouterError('identity_changed', 'The router identity changed since approval.')
    if operation == 'state.aura':
        capability = normalize_aura_capability(await router.async_api_hook(AURA_CAPABILITY_HOOK))['aura_flag_present']
        if capability is not True:
            raise RouterError('unsupported_capability' if capability is False else 'capability_unknown', 'Native Aura capability is unavailable or unknown.')
    raw = validate_raw(operation, await router.async_api_hook(settings_hook(operation, intent)), intent)
    return identity, raw


async def _run(config, password, operation, *, fingerprint_key, intent=None,
               expected_identity=None, expected_before_raw=None, expected_after_raw=None,
               authorization_check=None, router_factory=None, writing=False):
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise RouterError('identity_key_required', 'A private identity binding key is required.')
    if writing:
        config.require_secure_write()
        validate_intent(operation, intent)
        validate_vpn_settings_identity(expected_identity)
        if not isinstance(expected_identity, dict) or set(expected_identity) != {'model', 'firmware', 'device_fingerprint'} or any(type(v) is not str or not v for v in expected_identity.values()):
            raise RouterError('invalid_operation', 'An exact expected device identity is required.')
        approved = await prepare(operation, expected_before_raw, intent, identity=expected_identity)
        if approved.after != expected_after_raw:
            raise RouterError('after_policy_changed', 'The approved exact finite result changed.')
    budget = (5 if writing else 4) + (operation == 'state.aura')
    if config.max_requests < budget:
        raise RouterError('request_budget', 'The request budget cannot cover finite observation and cleanup.')
    async with _serialized(config.timeout):
        token = _SUPPRESS_VENDOR.set(True)
        session = router = None
        guard = FiniteGuard(config, operation, intent, authorization_check)
        guard.max_requests = budget
        cleanup_ok = True
        try:
            native_router, _, connection_config, strict_config = _upstream()
            session = verified_session(config, timeout=aiohttp.ClientTimeout(total=config.timeout), trace_configs=[guard.trace()], middlewares=[guard.middleware])
            router = (router_factory or native_router)(hostname=config.hostname, username=config.username, password=password,
                        port=config.port, use_ssl=config.use_ssl, session=session, config=strict_config, connection_config=connection_config)
            async with asyncio.timeout(config.timeout):
                await router.async_init_connection()
                identity, raw = await _observe(router, operation, intent, fingerprint_key, expected_identity if writing else None)
                if not writing:
                    result = {'identity': identity, 'raw': raw}
                else:
                    if identity != expected_identity:
                        raise RouterError('identity_changed', 'The router identity changed since approval.')
                    if raw != expected_before_raw:
                        raise RouterError('policy_changed', 'Complete preserved finite settings changed since approval.')
                    prepared = await prepare(operation, raw, intent, identity=identity)
                    if prepared.after != expected_after_raw:
                        raise RouterError('after_policy_changed', 'The exact finite result changed since approval.')
                    if not prepared.noop:
                        await guard.arm(prepared)
                        success = await compile_native(operation, intent, router.async_run_service)
                        if success is not True or not guard.write_attempted:
                            raise RouterError('apply_uncertain', 'Native finite outcome is uncertain; independently verify without replay.')
                    result = {'noop': prepared.noop, 'write_attempted': guard.write_attempted, 'freshness': 'unknown' if prepared.noop else 'applied_unverified'}
        except Exception as error:
            if guard.write_attempted:
                raise RouterError('apply_uncertain', 'Native finite outcome is uncertain; independently verify without replay.') from None
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


async def read(config, password, operation, *, fingerprint_key, intent=None, router_factory=None):
    return await _run(config, password, operation, fingerprint_key=fingerprint_key, intent=intent, router_factory=router_factory)


async def write(config, password, operation, *, intent, expected_identity, expected_before_raw,
                expected_after_raw, fingerprint_key, authorization_check=None, router_factory=None):
    return await _run(config, password, operation, intent=intent, expected_identity=expected_identity,
                      expected_before_raw=deepcopy(expected_before_raw), expected_after_raw=deepcopy(expected_after_raw),
                      fingerprint_key=fingerprint_key, authorization_check=authorization_check,
                      router_factory=router_factory, writing=True)
