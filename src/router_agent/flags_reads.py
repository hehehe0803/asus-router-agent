"""Comparable owner-only boot observations, never an unchecked reboot oracle."""
from datetime import datetime
import json
import math
from pathlib import Path
import time

from .errors import RouterError
from .health_reads import normalize_uptime, _auth
from .snapshots import atomic_write, private_dir, private_read, state_lock


def _bad():
    return RouterError('malformed_response', 'Selected boot observation is malformed.')


def observe_flags(raw, identity, *, state_dir=None, wall_time=None, monotonic_time=None, host_boot_id=None):
    from asusrouter.modules.endpoint.devicemap import read_uptime_string, process_boottime
    _auth(raw)
    seconds = normalize_uptime(raw)['uptime_seconds']
    boot, _ = read_uptime_string(raw['sys']['uptimeStr'])
    if boot is None:
        raise _bad()
    wall = time.time() if wall_time is None else wall_time
    mono = time.monotonic() if monotonic_time is None else monotonic_time
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in (wall, mono)):
        raise _bad()
    if host_boot_id is None:
        try:
            host_boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        except OSError:
            host_boot_id = None
    current = {'schema_version': 1, 'identity': {k: identity[k] for k in ('device_fingerprint', 'firmware')}, 'boot': boot.isoformat(), 'uptime': seconds, 'wall': wall, 'monotonic': mono, 'host_boot_id': host_boot_id}
    result = {'reboot': None, 'native_reboot_signal': None, 'boot_delta_seconds': None, 'uptime_delta_seconds': None, 'local_elapsed_seconds': None, 'router_elapsed_seconds': None, 'gaps': ['boot_change_is_not_reboot_proof', 'router_clock_not_source_freshness']}

    def compare(previous):
        if previous is None:
            result['gaps'].append('first_observation_or_history_unavailable')
            return
        try:
            if (not isinstance(previous, dict) or set(previous) != set(current) or previous['schema_version'] != 1
                    or not isinstance(previous['identity'], dict)
                    or type(previous['uptime']) is not int or not 0 <= previous['uptime'] <= 2**32 - 1
                    or any(type(previous[k]) not in (int, float) or not math.isfinite(previous[k]) for k in ('wall', 'monotonic'))):
                raise ValueError
            old_boot = datetime.fromisoformat(previous['boot'])
            if old_boot.tzinfo != boot.tzinfo:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            result['gaps'].append('history_malformed')
            return
        if previous['identity'] != current['identity']:
            result['gaps'].append('identity_or_firmware_changed')
            return
        delta = (boot - old_boot).total_seconds()
        uptime_delta = seconds - previous['uptime']
        elapsed = wall - previous['wall']
        router_elapsed = delta + uptime_delta
        _, signal = process_boottime(raw, {'datetime': old_boot, 'uptime': previous['uptime']})
        result.update(native_reboot_signal=signal, boot_delta_seconds=delta, uptime_delta_seconds=uptime_delta, local_elapsed_seconds=elapsed, router_elapsed_seconds=router_elapsed)
        if (host_boot_id is None or previous['host_boot_id'] != host_boot_id or mono < previous['monotonic']):
            result['gaps'].append('local_monotonic_history_unavailable')
            return
        monotonic_delta = mono - previous['monotonic']
        if elapsed < 0 or abs(elapsed - monotonic_delta) > 3:
            result['gaps'].append('local_clock_correction')
        elif elapsed > 86400:
            result['gaps'].append('observation_gap_exceeds_one_day')
        elif abs(router_elapsed - monotonic_delta) > 5:
            result['gaps'].append('router_clock_correction_or_counter_discontinuity')
        elif abs(delta) <= 1 and uptime_delta >= 0:
            result['reboot'] = False
        elif delta >= 2 and uptime_delta < 0:
            result['reboot'] = True
        else:
            result['gaps'].append('signed_boot_or_uptime_delta_ambiguous')
        if delta < 0:
            result['gaps'].append('negative_boot_delta_native_day_wrap_risk')

    if state_dir is None:
        compare(None)
        result['gaps'].append('history_persistence_not_configured')
    else:
        directory = private_dir(Path(state_dir) / 'boot-history')
        with state_lock(directory):
            path = directory / 'observation.json'
            previous = None
            if path.exists() or path.is_symlink():
                payload = private_read(path)
                if len(payload) > 4096:
                    result['gaps'].append('history_malformed')
                else:
                    try:
                        previous = json.loads(payload)
                    except (ValueError, UnicodeError):
                        result['gaps'].append('history_malformed')
            compare(previous)
            atomic_write(path, json.dumps(current, separators=(',', ':')).encode())
    return result
