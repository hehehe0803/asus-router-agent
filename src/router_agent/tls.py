"""Verified TLS through documented aiohttp connector configuration.

https://docs.aiohttp.org/en/stable/client_advanced.html#ssl-control-for-tcp-sockets
asusrouter 1.21.3 passes request ssl=True; aiohttp 3.14.5 uses the
connector's SSLContext for that value, including hostname verification.
"""
from pathlib import Path
import ssl

import aiohttp

from .errors import RouterError


def ssl_context(ca_file: str | None = None) -> ssl.SSLContext:
    try:
        if ca_file is not None:
            if not isinstance(ca_file, str) or not ca_file or len(ca_file) > 4096:
                raise ValueError
            path = Path(ca_file)
            if not path.is_file() or path.stat().st_size > 1024 * 1024:
                raise ValueError
        return ssl.create_default_context(cafile=ca_file)
    except (OSError, ValueError, TypeError, ssl.SSLError):
        raise RouterError("invalid_ca_file", "Provide a readable valid PEM CA certificate file of at most 1 MiB.") from None


def verified_session(config, **kwargs) -> aiohttp.ClientSession:
    """All project sessions share authenticated TLS; HTTP remains explicit reads."""
    context = ssl_context(config.ca_file)
    return aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=context), **kwargs)
