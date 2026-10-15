"""Finite expansion contexts, sealed to public plans and kept in Secret Service.

No raw configuration is persisted in plan files. A vault failure blocks planning
or recovery rather than creating a plaintext fallback. The root state lock is
owned by the caller, as for existing native backends.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import hmac
import json
import re

from .catalog import canonical
from .errors import RouterError

VPN_OPERATIONS = frozenset({'state.vpnc', 'state.openvpn_client', 'state.wireguard_client'})
FINITE_OPERATIONS = frozenset({'state.port_forwarding', 'state.openvpn_server', 'state.wireguard_server', 'state.wlan'})
OPERATIONS = VPN_OPERATIONS | FINITE_OPERATIONS
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_PROFILE = re.compile(r'vpn-[0-9a-f]{24}\Z')
_TARGET = re.compile(r'(?:radio[01]|guest[01]\.[123])\Z')
_MAX_CONTEXT = 1024 * 1024


def validate_intent(operation, intent, *, recovery=False):
    if not isinstance(intent, dict):
        raise RouterError('invalid_operation', 'A finite native intent is required.')
    values = dict(intent)
    if recovery and 'source_plan' in values:
        source = values.pop('source_plan')
        if not isinstance(source, str) or _HASH.fullmatch(source) is None:
            raise RouterError('invalid_operation', 'The recovery source identifier is invalid.')
    required = {'enabled'}
    if operation in VPN_OPERATIONS:
        required.add('profile_ref')
    elif operation == 'state.wlan':
        required.add('target')
    elif operation not in FINITE_OPERATIONS:
        raise RouterError('unsupported_operation', 'This native operation has no enabled finite contract.')
    valid = set(values) == required and type(values.get('enabled')) is bool
    if 'profile_ref' in required:
        valid = valid and isinstance(values.get('profile_ref'), str) and _PROFILE.fullmatch(values['profile_ref']) is not None
    if 'target' in required:
        valid = valid and isinstance(values.get('target'), str) and _TARGET.fullmatch(values['target']) is not None
    if not valid:
        raise RouterError('invalid_operation', 'The native operation intent is invalid.')
    return values


def validate_public_context(data):
    """Validate the reviewable shape before a credential or router read."""
    validate_intent(data.get('operation'), data.get('intent'), recovery=True)
    if (data.get('fields') != ['policy_fingerprint']
            or not isinstance(data.get('context_binding'), str)
            or _HASH.fullmatch(data['context_binding']) is None
            or not isinstance(data.get('review'), dict)
            or set(data['review']) != {'before', 'after', 'preservation'}
            or not isinstance(data['review']['preservation'], str)
            or not isinstance(data['review']['before'], dict)
            or not isinstance(data['review']['after'], dict)
            or type(data['review']['before'].get('enabled')) is not bool
            or type(data['review']['after'].get('enabled')) is not bool
            or data['review']['after']['enabled'] != data['intent']['enabled']
            or not isinstance(data.get('side_effects'), list)
            or not data['side_effects']
            or any(not isinstance(item, str) or not item or len(item) > 256 for item in data['side_effects'])):
        raise RouterError('invalid_plan', 'The stored native review context is invalid.')
    for name in ('before', 'after', 'verification'):
        values = data.get(name)
        if (not isinstance(values, dict) or set(values) != {'policy_fingerprint'}
                or not isinstance(values['policy_fingerprint'], str)
                or _HASH.fullmatch(values['policy_fingerprint']) is None):
            raise RouterError('invalid_plan', 'The stored native policy scope is invalid.')


class SecretServiceContexts:
    """Vetted OS vault; account names and service labels contain no router data."""
    service = 'asus-router-agent:protected-native-recovery:v1'

    def __init__(self, backend=None):
        self._injected = backend

    def _backend(self):
        from .auth import _backend
        return _backend(self._injected)

    def put(self, plan_id, value):
        if not isinstance(plan_id, str) or _HASH.fullmatch(plan_id) is None:
            raise RouterError('invalid_policy_context', 'The native recovery identifier is invalid.')
        payload = canonical(value)
        if len(payload.encode()) > _MAX_CONTEXT:
            raise RouterError('invalid_policy_context', 'The native recovery context exceeds its bound.')
        try:
            vault = self._backend()
            previous = vault.get_password(self.service, plan_id)
            if previous is not None and previous != payload:
                raise RouterError('invalid_policy_context', 'An existing native recovery context differs.')
            if previous is None:
                vault.set_password(self.service, plan_id, payload)
            if vault.get_password(self.service, plan_id) != payload:
                raise RouterError('keyring_unavailable', 'Native recovery persistence could not be confirmed.')
        except RouterError:
            raise
        except Exception:
            raise RouterError('keyring_unavailable', 'Desktop Secret Service is unavailable or locked.') from None

    def get(self, plan_id):
        if not isinstance(plan_id, str) or _HASH.fullmatch(plan_id) is None:
            raise RouterError('invalid_policy_context', 'The native recovery identifier is invalid.')
        try:
            payload = self._backend().get_password(self.service, plan_id)
        except RouterError:
            raise
        except Exception:
            raise RouterError('keyring_unavailable', 'Desktop Secret Service is unavailable or locked.') from None
        try:
            if not isinstance(payload, str) or len(payload.encode()) > _MAX_CONTEXT:
                raise ValueError
            result = json.loads(payload)
            if not isinstance(result, dict):
                raise ValueError
            return result
        except (ValueError, TypeError, UnicodeError):
            raise RouterError('invalid_policy_context', 'The protected native recovery context is unavailable.') from None


class ExpansionBackend:
    live = True
    authorization_at_send = True
    live_operations = OPERATIONS

    def __init__(self, config, password, *, operation, fingerprint_key, vault=None,
                 reader=None, preparer=None, writer=None, backup_provider=None):
        if operation not in OPERATIONS:
            raise RouterError('unsupported_operation', 'This native operation has no enabled finite contract.')
        if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
            raise RouterError('identity_key_required', 'A private native context key is required.')
        self.config, self._password, self.operation, self._key = config, password, operation, fingerprint_key
        self.vault = vault if vault is not None else SecretServiceContexts()
        self._reader, self._preparer, self._writer = reader, preparer, writer
        self._backup_provider = backup_provider
        self._active = False
        self._clear()

    def _clear(self):
        self._identity = self._raw = self._pending = self._context = None
        self._requested_intent = None
        self._consumed = False

    @contextmanager
    def transaction(self):
        if self._active:
            raise RouterError('transaction_busy', 'A native operation transaction is already active.')
        self._active = True
        self._clear()
        try:
            yield
        finally:
            self._clear()
            self._active = False

    def _require(self):
        if not self._active:
            raise RouterError('transaction_required', 'A native operation transaction is required.')

    def fingerprint(self, raw):
        return hmac.new(self._key, b'expansion-state:' + self.operation.encode() + b':' + canonical(raw).encode(), hashlib.sha256).hexdigest()

    def _config(self, raw):
        if self.operation in VPN_OPERATIONS:
            # Status is volatile and never part of a configuration fingerprint.
            from .protected_vpn import config_snapshot
            return config_snapshot(self.operation, raw)
        if not isinstance(raw, dict) or not raw:
            raise RouterError('native_state_unknown', 'The protected native configuration is incomplete.')
        return deepcopy(raw)

    def _collect(self):
        if self._reader is not None:
            return asyncio.run(self._reader(self.config, self._password, operation=self.operation, fingerprint_key=self._key))
        if self.operation in VPN_OPERATIONS:
            from .native_vpn_control import read_vpn
            return asyncio.run(read_vpn(self.config, self._password, fingerprint_key=self._key))
        from .native_finite_control import read
        intent = self._requested_intent
        if intent is None and self._context is not None:
            intent = validate_intent(self.operation, self._context['public']['intent'], recovery=True)
        return asyncio.run(read(self.config, self._password, self.operation, fingerprint_key=self._key, intent=intent))

    def device_identity(self):
        self._require()
        if self._identity is not None:
            return {'device': self._identity['device_fingerprint'], 'firmware': self._identity['firmware']}
        result = self._collect()
        if not isinstance(result, dict) or result.get('warnings'):
            raise RouterError('native_cleanup_unconfirmed', 'Native read cleanup is unconfirmed.')
        identity = result.get('identity')
        if (not isinstance(identity, dict) or set(identity) != {'model', 'firmware', 'device_fingerprint'}
                or any(not isinstance(v, str) or not v for v in identity.values())):
            raise RouterError('native_state_unknown', 'Exact native target identity is required.')
        self._identity, self._raw = deepcopy(identity), self._config(result.get('raw'))
        self._consumed = False
        return {'device': identity['device_fingerprint'], 'firmware': identity['firmware']}

    def read(self, operation, fields):
        self._require()
        if operation != self.operation or list(fields) != ['policy_fingerprint'] or self._raw is None or self._consumed:
            raise RouterError('fresh_read_required', 'A fresh bound native configuration is required.')
        self._consumed = True
        return {'policy_fingerprint': self.fingerprint(self._raw)}

    def _prepare(self, raw, intent):
        values = validate_intent(self.operation, intent, recovery=True)
        if self._preparer is not None:
            result = asyncio.run(self._preparer(self.operation, raw, values, self._key, identity=self._identity))
        elif self.operation in VPN_OPERATIONS:
            from .protected_vpn import prepare
            native_intent = {'kind': self.operation.removeprefix('state.'), **values}
            result = asyncio.run(prepare(raw, native_intent, self._key, self._identity))
        else:
            from .finite_controls import prepare
            result = asyncio.run(prepare(self.operation, raw, values, self._key, identity=self._identity))
        if isinstance(result, dict):
            before, after, review, effects = result['before_raw'], result['after_raw'], result['review'], result['side_effects']
        else:
            before, after, review, effects = result.before, result.after, result.review, result.side_effects
        before, after = self._config(before), self._config(after)
        if before != raw:
            raise RouterError('invalid_policy_context', 'The native compiler changed its before-state.')
        return {'before': before, 'after': after, 'review': deepcopy(review), 'intent': deepcopy(intent), 'side_effects': list(effects)}

    def _description(self, prepared):
        return {'before': {'policy_fingerprint': self.fingerprint(prepared['before'])},
                'after': {'policy_fingerprint': self.fingerprint(prepared['after'])},
                'review': {'before': prepared['review']['before'], 'after': prepared['review']['after'], 'preservation': 'Complete selected native configuration, order and unknown fields are bound privately; only the reviewed finite intent changes. Settings do not establish effective behavior.'},
                'intent': prepared['intent'], 'side_effects': prepared['side_effects']}

    def prepare_plan(self, operation, intent):
        self._require()
        if operation != self.operation:
            raise RouterError('unsupported_operation', 'The native backend operation differs.')
        validate_intent(operation, intent)
        self._requested_intent = dict(intent)
        self.device_identity()
        self._pending = self._prepare(self._raw, intent)
        return self._description(self._pending)

    def seal_plan(self, data):
        if self._pending is None or any(data.get(k) != v for k, v in self._description(self._pending).items()):
            raise RouterError('invalid_policy_context', 'The native review differs from its private configuration.')
        self._pending = {'public': deepcopy(data), 'before': self._pending['before'], 'after': self._pending['after']}
        return hmac.new(self._key, b'expansion-context:' + canonical(self._pending).encode(), hashlib.sha256).hexdigest()

    def bind_plan(self, plan):
        if self._pending is None or self._binding(self._pending) != plan.data.get('context_binding'):
            raise RouterError('invalid_policy_context', 'The native context binding is invalid.')
        self.vault.put(plan.id, self._pending)

    def _binding(self, context):
        return hmac.new(self._key, b'expansion-context:' + canonical(context).encode(), hashlib.sha256).hexdigest()

    def attach_plan(self, plan):
        self._require()
        data = plan.data
        validate_public_context(data)
        if data['operation'] != self.operation:
            raise RouterError('invalid_policy_context', 'The native operation context differs.')
        context = self.vault.get(plan.id)
        if (not isinstance(context, dict) or set(context) != {'public', 'before', 'after'}
                or context['public'] != {k: v for k, v in data.items() if k not in {'hash', 'context_binding'}}
                or not hmac.compare_digest(self._binding(context), data['context_binding'])
                or data['before'] != {'policy_fingerprint': self.fingerprint(self._config(context['before']))}
                or data['after'] != {'policy_fingerprint': self.fingerprint(self._config(context['after']))}):
            raise RouterError('invalid_policy_context', 'The native public plan or private recovery context changed.')
        self._context = deepcopy(context)

    @property
    def backup_provider(self):
        return self._backup_provider

    def backup_request(self, plan, challenge):
        """Bind complete private context; never disclose this request publicly."""
        from .backup_admission import request_for
        self._require()
        self.attach_plan(plan)  # includes sealed context integrity checks
        if (self._identity is None or self._raw != self._context['before']
                or plan.data['device'] != self._identity['device_fingerprint']
                or plan.data['firmware'] != self._identity['firmware']):
            raise RouterError('invalid_policy_context', 'A complete unchanged private context is required.')
        return request_for(plan, self._identity, self._context['before'], self._context, challenge)

    def write(self, operation, values, *, authorization_check=None):
        self._require()
        if (operation != self.operation or self._context is None or self._raw is None or not self._consumed
                or values != self._context['public']['after']
                or self._raw != self._context['before']):
            raise RouterError('invalid_policy_context', 'A fresh complete native context is required before writing.')
        context, identity = deepcopy(self._context), deepcopy(self._identity)
        intent = validate_intent(operation, context['public']['intent'], recovery=True)
        self._consumed = False
        common = dict(intent=intent, expected_identity=identity, fingerprint_key=self._key, authorization_check=authorization_check)
        if self._writer is not None:
            result = asyncio.run(self._writer(self.config, self._password, operation=operation, expected_before_raw=context['before'], expected_after_raw=context['after'], **common))
        elif operation in VPN_OPERATIONS:
            from .native_vpn_control import write_vpn
            common['intent'] = {'kind': operation.removeprefix('state.'), **intent}
            result = asyncio.run(write_vpn(self.config, self._password, before_raw=context['before'], after_raw=context['after'], **common))
        else:
            from .native_finite_control import write
            result = asyncio.run(write(self.config, self._password, operation, expected_before_raw=context['before'], expected_after_raw=context['after'], **common))
        if not isinstance(result, dict) or result.get('warnings'):
            raise RouterError('apply_uncertain', 'The native write or cleanup is uncertain; verify without replay.')

    def prepare_reverse(self, plan):
        self._require()
        if self._context is None or self._raw != self._context['after']:
            raise RouterError('state_changed', 'Native recovery requires the exact source after-state.')
        intent = validate_intent(self.operation, plan.data['intent'], recovery=True)
        intent['enabled'] = plan.data['review']['before']['enabled']
        intent['source_plan'] = plan.id
        self._pending = self._prepare(self._raw, intent)
        if self._pending['after'] != self._context['before']:
            raise RouterError('exact_recovery_unavailable', 'The native inverse cannot reproduce the original configuration exactly.')
        return self._description(self._pending)
