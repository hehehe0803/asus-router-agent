"""Scoped vendor namespace boundary using public logging APIs.

The pinned vendor creates loggers, not child handlers. Lazy children inherit
this boundary. A host attaching its own child handler during a command would
bypass it and must not do so. Root and unrelated logger settings are untouched.
"""
from contextvars import ContextVar
import logging
import threading


class VendorSuppression:
    def __init__(self):
        self._context = ContextVar('router_agent_suppress_vendor', default=False)
        self._lock = threading.RLock()
        self._users = 0
        self._saved = []
        self._boundary = logging.NullHandler()

    def set(self, value):
        if value is not True:
            raise ValueError('Vendor suppression must be enabled.')
        with self._lock:
            if self._users == 0:
                parent = logging.getLogger('asusrouter')
                loggers = [parent] + [logger for name, logger in list(logging.Logger.manager.loggerDict.items())
                                      if name.startswith('asusrouter.') and isinstance(logger, logging.Logger)]
                self._saved = [(logger, list(logger.handlers), logger.propagate) for logger in loggers]
                for logger, handlers, _ in self._saved:
                    for handler in handlers:
                        logger.removeHandler(handler)
                    logger.propagate = logger is not parent
                parent.addHandler(self._boundary)
            self._users += 1
            return self._context.set(True)

    def reset(self, token):
        with self._lock:
            self._context.reset(token)
            self._users -= 1
            if self._users == 0:
                logging.getLogger('asusrouter').removeHandler(self._boundary)
                for logger, handlers, propagate in self._saved:
                    for handler in handlers:
                        logger.addHandler(handler)
                    logger.propagate = propagate
                self._saved = []


SUPPRESS_VENDOR = VendorSuppression()
