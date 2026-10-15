"""Interactive password input, persisted only in desktop Secret Service."""
from dataclasses import dataclass, asdict
import getpass
import json
import sys
import warnings
from urllib.parse import urlsplit
from pathlib import Path
from .errors import RouterError
from .tls import ssl_context
from .snapshots import default_state_dir, state_lock, atomic_write, private_read


@dataclass(frozen=True)
class AuthConfig:
    origin: str
    username: str
    allow_plain_http: bool = False
    ca_file: str | None = None


def validate_config(origin, username, allow_plain_http=False, ca_file=None):
    try:
        url = urlsplit(origin)
        port = url.port
        if url.scheme not in {"http", "https"} or not url.hostname or url.username is not None or url.password is not None or url.path not in {"", "/"} or url.query or url.fragment:
            raise ValueError
        if not username or len(username) > 128 or any(ord(c) < 32 for c in username + origin) or any(c.isspace() for c in url.netloc):
            raise ValueError
        if url.scheme == "http" and not allow_plain_http:
            raise RouterError("plaintext_confirmation_required", "HTTP authentication requires --allow-plain-http.")
        host = url.hostname.lower()
        if ":" in host:
            host = "[" + host + "]"
        if port is not None and port != (443 if url.scheme == "https" else 80):
            host += ":" + str(port)
        if ca_file is not None:
            if url.scheme != "https":
                raise RouterError("invalid_ca_file", "A CA file requires an HTTPS origin.")
            ssl_context(ca_file)
            ca_file = str(Path(ca_file).resolve())
        return AuthConfig(url.scheme + "://" + host, username, bool(allow_plain_http), ca_file)
    except (ValueError, TypeError) as exc:
        raise RouterError("invalid_config", "Provide a valid HTTP(S) origin and username.") from exc


def _backend(backend=None):
    if backend is not None:  # Test injection only; production always instantiates SecretService.
        return backend
    try:
        from keyring.backends.SecretService import Keyring
        result = Keyring()
        if result.priority <= 0:
            raise RuntimeError
        return result
    except Exception as exc:
        raise RouterError("keyring_unavailable", "Desktop Secret Service is unavailable or locked.") from exc


def _service(config):
    return "asus-router-agent:" + config.origin


def load_config(state_dir=None):
    directory = Path(state_dir) if state_dir is not None else default_state_dir()
    with state_lock(directory):
        path = directory / "config.json"
        if not path.exists() and not path.is_symlink():
            raise RouterError("auth_required", "Run router-agent auth init in an interactive terminal.")
        try:
            raw = json.loads(private_read(path))
            if set(raw) not in ({"origin", "username", "allow_plain_http"}, {"origin", "username", "allow_plain_http", "ca_file"}) or not isinstance(raw["allow_plain_http"], bool):
                raise ValueError
            return validate_config(**raw)
        except (ValueError, TypeError, KeyError) as exc:
            raise RouterError("invalid_config", "Local authentication configuration is invalid.") from exc


def init_auth(origin, username, state_dir=None, backend=None, password_reader=None, allow_plain_http=False, ca_file=None):
    config = validate_config(origin, username, allow_plain_http, ca_file)
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise RouterError("tty_required", "Authentication initialization requires an interactive terminal.")
    secret_service = _backend(backend)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = (password_reader or getpass.getpass)("Router password: ")
    except (getpass.GetPassWarning, EOFError) as exc:
        raise RouterError("tty_required", "Secure hidden password input is unavailable.") from exc
    if not password:
        raise RouterError("invalid_credential", "Password must not be empty.")
    directory = Path(state_dir) if state_dir is not None else default_state_dir()
    with state_lock(directory):
        try:
            secret_service.set_password(_service(config), config.username, password)
        except Exception as exc:
            raise RouterError("keyring_unavailable", "Desktop Secret Service is unavailable or locked.") from exc
        atomic_write(directory / "config.json", json.dumps(asdict(config)).encode())
    return {"configured": True, "backend": "SecretService", "transport": urlsplit(config.origin).scheme, "router_auth": "not_tested"}


def get_credentials(state_dir=None, backend=None):
    config = load_config(state_dir)
    try:
        password = _backend(backend).get_password(_service(config), config.username)
    except RouterError:
        raise
    except Exception as exc:
        raise RouterError("keyring_unavailable", "Desktop Secret Service is unavailable or locked.") from exc
    if not password:
        raise RouterError("auth_required", "Router credential is missing from Secret Service.")
    return config, password


def auth_status(state_dir=None, backend=None):
    config, password = get_credentials(state_dir, backend)
    del password
    return {"configured": True, "backend": "SecretService", "transport": urlsplit(config.origin).scheme, "router_auth": "not_tested"}
