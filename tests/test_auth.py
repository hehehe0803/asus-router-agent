import json
import os
import pytest
from router_agent.auth import init_auth, auth_status, get_credentials, validate_config
from router_agent.errors import RouterError

class FakeKeyring:
    def __init__(self): self.values = {}
    def set_password(self,s,u,p): self.values[s,u] = p
    def get_password(self,s,u): return self.values.get((s,u))

def tty(monkeypatch):
    monkeypatch.setattr('sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('sys.stderr.isatty', lambda: True)

def test_secret_service_and_config_boundary(tmp_path, monkeypatch):
    tty(monkeypatch)
    backend = FakeKeyring()
    state = tmp_path / 'state'
    init_auth('https://ROUTER.local:443/', 'admin', state, backend, lambda _: 'fake-secret')
    assert get_credentials(state, backend)[1] == 'fake-secret'
    assert 'fake-secret' not in (state/'config.json').read_text()
    assert (state.stat().st_mode & 0o777) == 0o700
    assert ((state/'config.json').stat().st_mode & 0o777) == 0o600
    assert auth_status(state, backend)['router_auth'] == 'not_tested'
    assert list(backend.values) == [('asus-router-agent:https://router.local','admin')]

def test_noninteractive_never_reads_password(tmp_path, monkeypatch):
    monkeypatch.setattr('sys.stdin.isatty', lambda: False)
    with pytest.raises(RouterError, match='interactive'):
        init_auth('https://router', 'admin', tmp_path/'state', FakeKeyring(), lambda _: pytest.fail())

@pytest.mark.parametrize('origin', ['http://router','https://admin:password@router','https://router/path','https://router?query=secret','ftp://router','https://router:99999'])
def test_invalid_origins(origin):
    with pytest.raises(RouterError): validate_config(origin,'admin')

def test_locked_backend_is_sanitized(tmp_path, monkeypatch):
    tty(monkeypatch)
    class Locked(FakeKeyring):
        def set_password(self,*args): raise RuntimeError('fake-secret')
    with pytest.raises(RouterError) as error:
        init_auth('https://router','admin',tmp_path/'state',Locked(),lambda _: 'fake-secret')
    assert error.value.code == 'keyring_unavailable'
    assert 'fake-secret' not in error.value.public_message

def test_getpass_echo_fallback_is_refused(tmp_path, monkeypatch):
    import warnings, getpass
    tty(monkeypatch)
    def fallback(_):
        warnings.warn('echo fallback', getpass.GetPassWarning)
        return 'fake-secret'
    monkeypatch.setattr(getpass, 'getpass', fallback)
    backend=FakeKeyring()
    with pytest.raises(RouterError) as error:
        init_auth('https://router','admin',tmp_path/'state',backend)
    assert error.value.code == 'tty_required'
    assert not backend.values
