"""Private finite native compilers. Never serialize Prepared.raw into public output."""
from copy import deepcopy
from dataclasses import dataclass
from types import SimpleNamespace

from .errors import RouterError
from .vpn_settings_reads import validate_vpn_settings_identity

OPERATIONS = frozenset({'state.port_forwarding', 'state.openvpn_server', 'state.wireguard_server', 'state.wlan', 'state.aura'})
TARGETS = tuple(f'radio{i}' for i in range(2)) + tuple(f'guest{i}.{j}' for i in range(2) for j in range(1, 4))


def validate_intent(operation, intent):
    if operation not in OPERATIONS or not isinstance(intent, dict):
        raise RouterError('invalid_operation', 'A finite native operation is required.')
    if operation == 'state.aura':
        if set(intent) - {'effect', 'color', 'brightness', 'zone'} or 'effect' not in intent:
            raise RouterError('invalid_operation', 'A finite Aura intent is required.')
        if intent['effect'] not in {'off', 'gradient', 'static', 'breathing', 'evolution', 'rainbow', 'wave', 'marquee'}:
            raise RouterError('invalid_operation', 'Unsupported Aura effect.')
        if 'color' in intent and (not isinstance(intent['color'], list) or len(intent['color']) != 3 or any(type(x) is not int or not 0 <= x <= 255 for x in intent['color'])):
            raise RouterError('invalid_operation', 'Aura color requires three finite RGB integers.')
        if 'brightness' in intent and (type(intent['brightness']) is not int or not 0 <= intent['brightness'] <= 100):
            raise RouterError('invalid_operation', 'Aura brightness must be a finite percentage.')
        if 'zone' in intent and (type(intent['zone']) is not int or not 0 <= intent['zone'] < 8):
            raise RouterError('invalid_operation', 'Unsupported Aura zone.')
        if intent['effect'] not in {'gradient', 'static', 'breathing', 'marquee'} and set(intent) & {'color', 'brightness', 'zone'}:
            raise RouterError('invalid_operation', 'The Aura effect does not support color arguments.')
        return
    wanted = {'target', 'enabled'} if operation == 'state.wlan' else {'enabled'}
    if set(intent) != wanted or type(intent.get('enabled')) is not bool or (operation == 'state.wlan' and intent.get('target') not in TARGETS):
        raise RouterError('invalid_operation', 'Only finite existing native toggle intent is supported.')


def settings_hook(operation, intent=None):
    """Use upstream maintained lists/request builders, including secret settings."""
    from asusrouter.modules.data_finder import ASUSDATA_NVRAM
    from asusrouter.modules.wlan import Wlan, wlan_nvram_request, gwlan_nvram_request
    from asusrouter.tools.writers import nvram
    if operation == 'state.wlan':
        validate_intent(operation, intent)
        guest = intent['target'].startswith('guest')
        index = int(intent['target'][5] if guest else intent['target'][5:])
        return (gwlan_nvram_request if guest else wlan_nvram_request)([Wlan.FREQ_2G if index == 0 else Wlan.FREQ_5G])
    name = {'state.port_forwarding': 'port_forwarding', 'state.openvpn_server': 'openvpn_server_388', 'state.wireguard_server': 'wireguard_server', 'state.aura': 'aura'}.get(operation)
    if name is None:
        raise RouterError('invalid_operation', 'Unknown finite native operation.')
    keys = list(ASUSDATA_NVRAM[name])
    if operation == 'state.wireguard_server':
        # wireguard.set_state writes f'{wg_unit}_unit' with server wg_unit='wgs'.
        # The data-finder map omits this auxiliary selected-unit setting.
        keys.append('wgs_unit')
    return nvram(keys)


def required_keys(operation, intent=None):
    import re
    return tuple(re.findall(r'nvram_get\(([^)]+)\);', settings_hook(operation, intent)))


def validate_raw(operation, raw, intent=None):
    keys = required_keys(operation, intent)
    if (not isinstance(raw, dict) or len(raw) > 256 or not set(keys) <= set(raw)
            or any(type(k) is not str or type(v) is not str or len(k) > 128 or len(v) > 32768 or any(ord(c) < 32 for c in v) for k, v in raw.items())
            or sum(len(k) + len(v) for k, v in raw.items()) > 262144):
        raise RouterError('native_state_unknown', 'Complete native selected settings are required for exact recovery.')
    return deepcopy(raw)


@dataclass(frozen=True, repr=False)
class Prepared:
    before: dict
    after: dict
    intent: dict
    review: dict
    side_effects: list
    service: str
    arguments: dict

    @property
    def noop(self):
        return self.before == self.after


async def compile_native(operation, intent, callback):
    """Only public maintained setters and explicit slot arguments."""
    from asusrouter.modules import port_forwarding, openvpn, wireguard, wlan
    from asusrouter.modules.firmware import Firmware
    validate_intent(operation, intent)
    on = intent.get('enabled')
    if operation == 'state.port_forwarding':
        return await port_forwarding.set_state(callback, port_forwarding.AsusPortForwarding.ON if on else port_forwarding.AsusPortForwarding.OFF)
    if operation == 'state.openvpn_server':
        identity = SimpleNamespace(merlin=False, firmware=Firmware(major='3.0.0.4', minor=388, build=24436))
        return await openvpn.set_state(callback, openvpn.AsusOVPNServer.ON if on else openvpn.AsusOVPNServer.OFF, id=1, identity=identity)
    if operation == 'state.wireguard_server':
        return await wireguard.set_state(callback, wireguard.AsusWireGuardServer.ON if on else wireguard.AsusWireGuardServer.OFF, id=1)
    if operation == 'state.wlan':
        guest = intent['target'].startswith('guest')
        target = intent['target'][5:]
        return await wlan.set_state(callback, wlan.AsusWLAN.ON if on else wlan.AsusWLAN.OFF, api_type='gwlan' if guest else 'wlan', api_id=target)
    raise RouterError('exact_recovery_unavailable', 'Native Aura complete forward/inverse recovery is not established.')


async def prepare(operation, raw, intent, key=None, *, identity=None):
    validate_intent(operation, intent)
    if identity is not None:
        validate_vpn_settings_identity(identity)
    before = validate_raw(operation, raw, intent)
    if operation == 'state.aura':
        # set_state writes only ledg_scheme and optional ledg_rgb. It has no
        # restoration input for ledg_scheme_old, AllLED or ledg_night_mode.
        raise RouterError('exact_recovery_unavailable', 'Native Aura complete scheme-history and RGB recovery is not established.')
    target = intent.get('target')
    flag = {'state.port_forwarding': 'vts_enable_x', 'state.openvpn_server': 'VPNServer_enable', 'state.wireguard_server': 'wgs_enable'}.get(operation)
    if operation == 'state.wlan':
        guest = target.startswith('guest')
        flag = f'wl{target[5:]}_' + ('bss_enabled' if guest else 'radio')
        if guest and (before[f'wl{target[5:]}_expire'] != '0' or before[f'wl{target[5:]}_expire_tmp'] != '0'):
            raise RouterError('exact_recovery_unavailable', 'Guest expiry must be known zero in both forward and inverse directions.')
    if before[flag] not in {'0', '1'}:
        raise RouterError('native_state_unknown', 'The selected native toggle must be known.')
    if operation == 'state.openvpn_server' and before['vpn_server_unit'] != '1':
        raise RouterError('unsupported_operation', 'Only existing native OpenVPN server unit 1 is supported.')
    if operation == 'state.wireguard_server' and before['wgs_unit'] != '1':
        raise RouterError('unsupported_operation', 'Only existing native WireGuard server unit 1 is recoverable.')
    calls = []
    async def capture(*args, **kwargs):
        service = args[0] if args else kwargs.pop('service')
        calls.append((service, deepcopy(kwargs)))
        return True
    if await compile_native(operation, intent, capture) is not True or len(calls) != 1:
        raise RouterError('write_boundary', 'Native finite compiler did not produce exactly one command.')
    service, kwargs = calls[0]
    if set(kwargs) != {'arguments', 'apply', 'expect_modify'} or kwargs['apply'] is not True or kwargs['expect_modify'] is not False:
        raise RouterError('write_boundary', 'Native finite command options changed.')
    after = deepcopy(before)
    after[flag] = str(int(intent['enabled']))
    effects = {'state.port_forwarding': ['firewall_restart', 'exposure_change'], 'state.openvpn_server': ['openvpn_restart_or_stop', 'chpass_on_enable', 'samba_restart', 'dnsmasq_restart', 'exposure_change'], 'state.wireguard_server': ['wireguard_restart', 'dnsmasq_restart', 'exposure_change'], 'state.wlan': ['wireless_restart', 'wireless_admin_access_loss_possible'] }[operation]
    if operation == 'state.wlan' and target.startswith('guest'):
        effects = effects + ['firewall_restart']
    review = {'before': {'enabled': before[flag] == '1'}, 'after': {'enabled': intent['enabled']}, 'preservation': 'complete selected native settings including unknown fields', 'settings_do_not_prove_effective_behavior': True}
    if target:
        review['target'] = target
    if operation == 'state.port_forwarding':
        review['preservation'] = 'complete raw forwarding rule list, order and unknown fields'
    return Prepared(before, after, deepcopy(intent), review, effects, service, kwargs['arguments'])
