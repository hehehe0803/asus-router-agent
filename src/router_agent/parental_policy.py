"""Private, bounded parental policy compiler using pristine asusrouter helpers.

Never serialize PolicySnapshot or PreparedParentalChange to public output. The
six selected raw strings belong only in protected recovery storage. Native rule
read/write delimiter conversion is compared losslessly before any rule edit.
Schedule literals follow weekSchedule PC_init_data's 12-character records;
structural validity does not establish schedule meaning or router timezone.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re

from asusrouter.modules import parental_control as pc
from asusrouter.modules.data import AsusData, AsusDataState
from .errors import RouterError

PARENTAL_POLICY_KEYS = tuple(pc.HOOK_PC)
PARENTAL_POLICY_HOOK = ''.join(f'nvram_get({key});' for key in PARENTAL_POLICY_KEYS)
_MAC = re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z')
_ALIAS = re.compile(r'client-[0-9a-f]{16}\Z')
_SEGMENT = re.compile(r'[WM][01][0-9A-Fa-f]{2}[0-9]{8}\Z')
_TYPES = {'disable': pc.PCRuleType.DISABLE, 'time': pc.PCRuleType.TIME,
          'block': pc.PCRuleType.BLOCK, 'remove': pc.PCRuleType.REMOVE}


def _error(code='malformed_response'):
    return RouterError(code, 'Native parental policy cannot be safely represented or recovered.')


def _digest(key, domain, value):
    return hmac.new(key, domain + value.encode(), hashlib.sha256).hexdigest()


def client_alias(key, mac):
    return 'client-' + _digest(key, b'client:', mac.upper())[:16]


def validate_schedule(value):
    """Validate native literal structure; no presets or semantic time encoder."""
    if not isinstance(value, str) or not value or len(value) > 512:
        raise _error('invalid_schedule')
    parts = value.split('<')
    modes = set()
    for part in parts:
        if not _SEGMENT.fullmatch(part):
            raise _error('invalid_schedule')
        modes.add(part[0])
        if int(part[2:4], 16) > 127:
            raise _error('invalid_schedule')
        for offset in (4, 8):
            hour, minute = int(part[offset:offset+2]), int(part[offset+2:offset+4])
            if hour > 24 or minute > 59 or (hour == 24 and minute != 0):
                raise _error('invalid_schedule')
    if len(modes) != 1:
        raise _error('invalid_schedule')
    return value


@dataclass(frozen=True, repr=False)
class PolicySnapshot:
    _encoded: str = field(repr=False)
    _key: bytes = field(repr=False)
    fingerprint: str
    enabled: bool | None
    block_all: bool | None
    rules_write_recoverable: bool

    @property
    def raw(self):
        return json.loads(self._encoded)

    @property
    def rules(self):
        return pc.read_pc_rules(self.raw)

    def __repr__(self):
        return 'PolicySnapshot(private)'


def _flag(value):
    if value in ('0', '1'):
        return value == '1'
    if value in ('', '-999'):
        return None
    raise _error()


def _payload(raw):
    result = {key: raw[key].replace('&#62', '>') for key in pc.PC_RULE_MAP}
    result[pc.KEY_PC_TIMEMAP] = result[pc.KEY_PC_TIMEMAP].replace('&#60', '<')
    return result


def read_policy_snapshot(raw, fingerprint_key):
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
        raise _error('identity_key_required')
    if not isinstance(raw, dict) or any(key not in raw for key in PARENTAL_POLICY_KEYS):
        raise _error()
    selected = {key: raw[key] for key in PARENTAL_POLICY_KEYS}
    for value in selected.values():
        if not isinstance(value, str) or len(value) > 32768 or any(ord(c) < 32 for c in value):
            raise _error()
    enabled, block_all = _flag(selected[pc.KEY_PC_STATE]), _flag(selected[pc.KEY_PC_BLOCK_ALL])
    if selected[pc.KEY_PC_MAC] == '' and selected[pc.KEY_PC_TYPE] == '':
        # Native parser deliberately ignores orphan name/schedule strings.
        pass
    else:
        parts = [selected[key].split('&#62') for key in pc.PC_RULE_MAP]
        if len({len(part) for part in parts}) != 1 or len(parts[0]) > 64:
            raise _error()
        macs, names, schedules, kinds = parts
        if any(not _MAC.fullmatch(mac) for mac in macs) or len({mac.upper() for mac in macs}) != len(macs):
            raise _error()
        if any(kind not in ('', '-999', '0', '1', '2') for kind in kinds):
            raise _error()
        if any(len(name) > 256 for name in names) or any(len(schedule) > 512 for schedule in schedules):
            raise _error()
        if any('>' in item or '<' in item for item in macs + names):
            raise _error()
    try:
        rules = pc.read_pc_rules(selected)
        serialized = pc.write_pc_rules(rules)
        recoverable = serialized == _payload(selected)
        # Hook read strings use encoded separators. Do not promise byte-exact
        # recovery for another observed spelling that our prediction cannot
        # reproduce through the maintained serializer.
        for key, value in serialized.items():
            encoded_value = value.replace('>', '&#62')
            if key == pc.KEY_PC_TIMEMAP:
                encoded_value = encoded_value.replace('<', '&#60')
            recoverable = recoverable and encoded_value == selected[key]
    except Exception:
        raise _error() from None
    encoded = json.dumps(selected, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return PolicySnapshot(encoded, fingerprint_key,
                          _digest(fingerprint_key, b'parental-policy:', encoded),
                          enabled, block_all, recoverable)


def policy_fingerprint(snapshot):
    return snapshot.fingerprint


def public_policy(snapshot):
    rules = []
    for mac, rule in snapshot.rules.items():
        rules.append({'alias': client_alias(snapshot._key, mac),
                      'rule_type': {0:'disable', 1:'time', 2:'block', -999:'unknown'}[int(rule.type)],
                      'name_fingerprint': _digest(snapshot._key, b'parental-name:', rule.name or ''),
                      'schedule_fingerprint': _digest(snapshot._key, b'parental-schedule:', rule.timemap or ''),
                      'schedule_present': bool(rule.timemap)})
    return {'enabled': snapshot.enabled, 'block_all': snapshot.block_all,
            'policy_fingerprint': snapshot.fingerprint, 'rules': rules,
            'rule_count': len(rules), 'rules_write_recoverable': snapshot.rules_write_recoverable,
            'gaps': ['settings_do_not_prove_parental_enforcement', 'schedule_semantics_and_timezone_unverified']}


@dataclass(repr=False)
class PreparedParentalChange:
    kind: str
    before: PolicySnapshot
    after: PolicySnapshot
    arguments: dict
    native_state: object = None
    native_rule: object = None
    router_state: dict = field(default_factory=dict, repr=False)
    intent: dict = field(default_factory=dict)

    @property
    def public_before(self):
        return public_policy(self.before)

    @property
    def public_after(self):
        return {**public_policy(self.after), 'intent': deepcopy(self.intent)}

    @property
    def noop(self):
        return self.before.fingerprint == self.after.fingerprint

    def __repr__(self):
        return 'PreparedParentalChange(private)'


def _after(snapshot, arguments):
    raw = snapshot.raw
    for key, value in arguments.items():
        if key not in PARENTAL_POLICY_KEYS:
            raise _error()
        value = str(value)
        if key in pc.PC_RULE_MAP:
            value = value.replace('>', '&#62')
            if key == pc.KEY_PC_TIMEMAP:
                value = value.replace('<', '&#60')
        raw[key] = value
    return read_policy_snapshot(raw, snapshot._key)


async def _compile(setter, *args, **kwargs):
    captured = []
    async def capture(**call):
        captured.append(call)
        return True
    if not await setter(capture, *args, **kwargs) or len(captured) != 1:
        raise _error('unsupported_policy_mutation')
    call = captured[0]
    if call.get('service') != 'restart_firewall' or call.get('apply') is not True:
        raise _error()
    return call['arguments']


async def prepare_enable(snapshot, enabled):
    if type(enabled) is not bool or snapshot.enabled is None:
        raise _error('unsupported_policy_mutation')
    state = pc.AsusParentalControl.ON if enabled else pc.AsusParentalControl.OFF
    arguments = await _compile(pc.set_state, state)
    return PreparedParentalChange('enable', snapshot, _after(snapshot, arguments), arguments,
                                  native_state=state, intent={'enabled': enabled})


async def prepare_block_all(snapshot, blocked):
    """Compile the distinct all-client firewall flag without touching rules."""
    if type(blocked) is not bool or snapshot.block_all is None:
        raise _error('unsupported_policy_mutation')
    state = pc.AsusBlockAll.ON if blocked else pc.AsusBlockAll.OFF
    arguments = await _compile(pc.set_state, state)
    return PreparedParentalChange('block_all', snapshot, _after(snapshot, arguments), arguments,
                                  native_state=state,
                                  intent={'blocked': blocked, 'impact': 'all_clients',
                                          'service': 'restart_firewall'})


async def prepare_rule(snapshot, alias, rule_type, client_inventory=None, schedule=None):
    if not snapshot.rules_write_recoverable:
        raise _error('policy_recovery_unavailable')
    if not isinstance(alias, str) or not _ALIAS.fullmatch(alias) or rule_type not in _TYPES:
        raise _error('invalid_rule_intent')
    rules = snapshot.rules
    candidates = list(rules)
    if client_inventory is not None and (not isinstance(client_inventory, dict) or len(client_inventory) > 4096):
        raise _error('malformed_client_inventory')
    if isinstance(client_inventory, dict):
        candidates.extend(mac for mac in client_inventory if isinstance(mac, str) and _MAC.fullmatch(mac))
    matches = {mac.upper(): mac for mac in candidates if client_alias(snapshot._key, mac) == alias}
    if len(matches) != 1:
        raise _error('client_alias_unresolved')
    mac = next(iter(matches.values()))
    existing = next((rule for key, rule in rules.items() if key.upper() == mac.upper()), None)
    if existing:
        mac = existing.mac
    if rule_type == 'remove':
        if schedule is not None:
            raise _error('invalid_rule_intent')
        rule = pc.ParentalControlRule(mac=mac, type=pc.PCRuleType.REMOVE)
    else:
        chosen = schedule if schedule is not None else (existing.timemap.replace('&#60', '<') if existing and existing.timemap else None)
        if schedule is not None or existing is None:
            validate_schedule(chosen)
        # An existing unknown native schedule is preserved, never interpreted.
        rule = pc.ParentalControlRule(mac=mac, name=existing.name if existing else alias,
                                      timemap=chosen, type=_TYPES[rule_type])
    state = {AsusData.PARENTAL_CONTROL: AsusDataState(data={'rules': deepcopy(rules)})}
    arguments = await _compile(pc.set_rule, deepcopy(rule), router_state=deepcopy(state))
    after = _after(snapshot, arguments)
    if not after.rules_write_recoverable:
        raise _error('policy_recovery_unavailable')
    intent = {'client_alias': alias, 'rule_type': rule_type}
    if schedule is not None:
        intent['schedule'] = schedule
    return PreparedParentalChange('rule', snapshot, after, arguments,
                                  native_rule=rule, router_state=state, intent=intent)


async def prepare_restore(current, original):
    if current._key != original._key or not current.rules_write_recoverable or not original.rules_write_recoverable:
        raise _error('policy_recovery_unavailable')
    for key in (pc.KEY_PC_STATE, pc.KEY_PC_BLOCK_ALL):
        if current.raw[key] != original.raw[key]:
            raise _error('policy_recovery_state_changed')
    arguments = pc.write_pc_rules(original.rules)
    after = _after(current, arguments)
    if after.fingerprint != original.fingerprint:
        raise _error('policy_recovery_unavailable')
    return PreparedParentalChange('rules_restore', current, after, arguments,
                                  intent={'restore_policy_fingerprint': original.fingerprint})
