"""Bounded credential-private Fusion transport; not an authorization engine.

The application must pass its independent admission check and durably record
uncertainty before calling write_vpn. Production backup gating lives above this
transport. No writes are retried and private data never enters public results.
"""
from __future__ import annotations
import asyncio
from copy import deepcopy
from typing import Any
from urllib.parse import quote
import aiohttp
from yarl import URL
from .errors import RouterError
from .protected_vpn import VPN_HOOK, validate_identity, parse_snapshot, prepare, config_snapshot
from .tls import verified_session
from .transport import (HOOKS, RequestGuard, TransportConfig, _SUPPRESS_VENDOR,
                        _cleanup, _normalize, _safe_exception, _serialized, _upstream)


def vpn_body(command):
    return quote(str({'rc_service': command['service'], **command['arguments'], 'action_mode': 'apply'})).encode('ascii')


class VPNGuard(RequestGuard):
    def __init__(self, config, *, authorization_check=None):
        super().__init__(config, (HOOKS['identity'], VPN_HOOK))
        self.authorization_check = authorization_check
        self.expected_body = None
        self.write_attempted = False

    def arm(self, command):
        if (self.expected_body is not None or not isinstance(command, dict)
                or set(command) != {'service', 'arguments', 'apply', 'expect_modify'}
                or command['service'] not in {'restart_vpnc', 'stop_vpnc'}
                or command['apply'] is not True or command['expect_modify'] is not False):
            raise RouterError('write_boundary', 'Native VPN command rejected.')
        args = command['arguments']
        if (not isinstance(args, dict) or tuple(args) != ('vpnc_unit', 'vpnc_clientlist')
                or type(args['vpnc_unit']) is not int or not 0 <= args['vpnc_unit'] < 128
                or type(args['vpnc_clientlist']) is not str or len(args['vpnc_clientlist'].encode()) > 32768):
            raise RouterError('write_boundary', 'Native VPN arguments rejected.')
        self.expected_body = vpn_body(command)

    async def start(self, session: Any, ctx: Any, params: Any):
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
            raise RouterError('write_boundary', 'Native VPN write rejected.')
        self.requests += 1

    async def middleware(self, request, handler):
        if request.url.path == '/applyapp.cgi':
            body = request.body
            if (self.expected_body is None or not self.authenticated or self.stopped or self.write_attempted
                    or not isinstance(body, aiohttp.payload.StringPayload) or await body.as_bytes() != self.expected_body):
                raise RouterError('write_boundary', 'Native VPN payload rejected before transmission.')
            if not callable(self.authorization_check):
                raise RouterError('approval_window_required', 'Write admission requires an independent authorization check.')
            self.authorization_check()
            self.write_attempted = True
        return await super().middleware(request, handler)

    async def chunk(self, session, ctx, params):
        if URL(params.url).path == '/applyapp.cgi':
            if not self.write_attempted or params.chunk != self.expected_body:
                raise RouterError('write_boundary', 'Native VPN payload rejected.')
            return
        await super().chunk(session, ctx, params)


async def _run(config, password, *, fingerprint_key, router_factory=None, expected_identity=None,
               before_raw=None, after_raw=None, intent=None, authorization_check=None):
    writing = intent is not None
    if writing:
        config.require_secure_write()
        validate_identity(expected_identity)
        # Compile before opening any connection: reject lossy recovery and bad intent.
        approved = await prepare(before_raw, intent, fingerprint_key, expected_identity)
        if approved['after_raw'] != after_raw:
            raise RouterError('after_policy_changed', 'The protected VPN result differs from the approved state.')
    if type(fingerprint_key) is not bytes or len(fingerprint_key) < 32:
        raise RouterError('identity_key_required', 'A private identity key of at least 32 bytes is required.')
    budget = 5 if writing else 4
    if config.max_requests < budget:
        raise RouterError('request_budget', 'The request budget cannot cover the protected VPN operation and cleanup.')
    async with _serialized(config.timeout):
        token = _SUPPRESS_VENDOR.set(True)
        session = router = None
        guard = VPNGuard(config, authorization_check=authorization_check)
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
                validate_identity(identity)
                if writing and identity != expected_identity:
                    raise RouterError('identity_changed', 'The router identity changed since the approved observation.')
                raw = await router.async_api_hook(VPN_HOOK)
                snapshot = parse_snapshot(raw, fingerprint_key, identity)
                if not writing:
                    result = {'identity': identity, 'raw': raw}
                else:
                    if snapshot.raw_config != before_raw:
                        raise RouterError('policy_changed', 'The protected VPN configuration changed since the approved observation.')
                    prepared = await prepare(raw, intent, fingerprint_key, identity)
                    if prepared['after_raw'] != after_raw:
                        raise RouterError('after_policy_changed', 'The protected VPN result differs from the approved state.')
                    if not prepared['noop']:
                        guard.arm(prepared['commands'][0])
                        from asusrouter.modules.vpnc import set_state
                        success = await set_state(router.async_run_service, prepared['native_state'],
                                                  router_state=deepcopy(prepared['router_state']), **prepared['native_kwargs'])
                        if success is not True or not guard.write_attempted:
                            raise RouterError('apply_uncertain', 'VPN outcome is uncertain; verify independently without retrying.')
                    result = {'schema_version': 1, 'source': 'native', 'freshness': 'unknown' if prepared['noop'] else 'applied_unverified',
                              'noop': prepared['noop'], 'write_attempted': guard.write_attempted, **prepared['review']}
        except Exception as error:
            if guard.write_attempted:
                raise RouterError('apply_uncertain', 'VPN outcome is uncertain; verify independently without retrying.') from None
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


async def read_vpn(config: TransportConfig, password: str, *, fingerprint_key: bytes, router_factory=None):
    """Application-private observation; never serialize the returned raw hook."""
    return await _run(config, password, fingerprint_key=fingerprint_key, router_factory=router_factory)


async def write_vpn(config: TransportConfig, password: str, *, expected_identity, before_raw, after_raw, intent,
                    fingerprint_key: bytes, authorization_check=None, router_factory=None):
    return await _run(config, password, expected_identity=expected_identity, before_raw=before_raw, after_raw=after_raw,
                      intent=intent, fingerprint_key=fingerprint_key, authorization_check=authorization_check, router_factory=router_factory)
