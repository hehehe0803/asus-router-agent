"""Finite LED backend; caller owns the cross-process root state lock.

The engine's transaction context limits the selected-read cache lifetime.
No credentials are loaded here and no request occurs during construction.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from copy import deepcopy

from .errors import RouterError


class NativeLEDBackend:
    live = True
    authorization_at_send = True
    live_operations = frozenset({"led.set"})

    def __init__(self, config, password, *, fingerprint_key, collector=None, writer=None):
        self.config, self._password = config, password
        self._key = fingerprint_key
        self._collector, self._writer = collector, writer
        self._active = False
        self._clear()

    def _clear(self):
        self._identity = None
        self._before = None
        self._read_pending = False
        self._read_consumed = False

    @contextmanager
    def transaction(self):
        if self._active:
            raise RouterError("transaction_busy", "A native operation transaction is already active.")
        self._active = True
        self._clear()
        try:
            yield
        finally:
            self._clear()
            self._active = False

    def _require_transaction(self):
        if not self._active:
            raise RouterError("transaction_required", "Native operation reads require an engine transaction.")

    def device_identity(self):
        self._require_transaction()
        self._clear()
        if self._collector is None:
            from .transport import collect_native
            collector = collect_native
        else:
            collector = self._collector
        result = asyncio.run(collector(self.config, self._password, groups=("identity", "led"), fingerprint_key=self._key))
        if isinstance(result, dict) and result.get("warnings"):
            raise RouterError("native_cleanup_unconfirmed", "Native read cleanup is unconfirmed; local intervention is required before an operation.")
        data = result.get("data", {}) if isinstance(result, dict) else {}
        identity, led = data.get("identity"), data.get("led")
        if (not isinstance(identity, dict) or set(identity) != {"model", "firmware", "device_fingerprint"}
                or not all(type(v) is str and v for v in identity.values())
                or not isinstance(led, dict) or type(led.get("enabled")) is not bool):
            raise RouterError("native_state_unknown", "Exact identity and known LED state are required.")
        from .native_control import validate_led_applicability
        validate_led_applicability(identity)
        self._identity = deepcopy(identity)
        self._before = {"enabled": led["enabled"]}
        self._read_pending = True
        return {"device": identity["device_fingerprint"], "firmware": identity["firmware"]}

    def read(self, operation, fields):
        self._require_transaction()
        if operation != "led.set" or list(fields) != ["enabled"]:
            raise RouterError("unsupported_operation", "Only the native LED enabled operation is supported.")
        if not self._read_pending or self._before is None:
            raise RouterError("fresh_read_required", "A fresh identity and LED read is required.")
        self._read_pending = False
        self._read_consumed = True
        return dict(self._before)

    def write(self, operation, values, *, authorization_check=None):
        self._require_transaction()
        if (operation != "led.set" or not isinstance(values, dict)
                or set(values) != {"enabled"} or type(values["enabled"]) is not bool):
            raise RouterError("unsupported_operation", "Only the native LED enabled operation is supported.")
        if not self._read_consumed or self._identity is None or self._before is None:
            raise RouterError("fresh_read_required", "A fresh identity and LED read is required.")
        identity, before = deepcopy(self._identity), self._before["enabled"]
        # Consume the binding before invoking a possibly uncertain write.
        self._clear()
        if self._writer is None:
            from .native_control import set_led
            writer = set_led
        else:
            writer = self._writer
        result = asyncio.run(writer(self.config, self._password, enabled=values["enabled"],
                                    expected_identity=identity, expected_before=before, fingerprint_key=self._key,
                                    authorization_check=authorization_check))
        if not isinstance(result, dict) or result.get("warnings"):
            raise RouterError("apply_uncertain", "Native LED outcome or cleanup is uncertain; verify independently without retrying the write.")
        return result
