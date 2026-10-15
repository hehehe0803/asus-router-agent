import json
import os
from types import SimpleNamespace
import pytest

from router_agent import approval_window as window
from router_agent.errors import RouterError
from test_approval import make_plan


def grant(monkeypatch, plan=None):
    plan = plan or make_plan()
    data = window.approval_request(plan)
    monkeypatch.setattr(window, '_read_grant', lambda _: data)
    return plan, data


def test_exact_scope_and_public_request(monkeypatch):
    plan, data = grant(monkeypatch)
    scope = window.validate_window(plan, plan.id, clock=lambda: 101)
    assert scope.plan_hash == scope.window_id == plan.id
    assert scope.expires_at == 400
    for key in ('device', 'operation', 'after_json', 'plan_hash'):
        original = data[key]
        data[key] = 'wrong'
        with pytest.raises(RouterError) as error:
            window.validate_window(plan, plan.id, clock=lambda: 101)
        assert error.value.code == 'approval_scope_mismatch'
        data[key] = original


@pytest.mark.parametrize('change', [{'expires_at': 401}, {'expires_at': 100}, {'issued_at': 102}, {'issued_at': 99}, {'expires_at': float('nan')}, {'expires_at': True}, {'extra': 1}])
def test_reject_invalid_window(monkeypatch, change):
    plan, data = grant(monkeypatch)
    data.update(change)
    with pytest.raises(RouterError):
        window.validate_window(plan, plan.id, clock=lambda: 101)


def test_reference_missing_or_wrong_never_reads(monkeypatch):
    monkeypatch.setattr(window, '_read_grant', lambda _: pytest.fail('must not read'))
    for value in (None, '', '../grant', 'a' * 64):
        with pytest.raises(RouterError):
            window.validate_window(make_plan(), value, clock=lambda: 101)


def test_root_agent_refused(monkeypatch):
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    with pytest.raises(RouterError) as error:
        window._read_grant(make_plan().id)
    assert error.value.code == 'approval_authority_unsafe'


@pytest.mark.parametrize('mode,uid,links,size,directory', [(0o40777, 0, 1, 0, True), (0o40755, 1000, 1, 0, True), (0o120644, 0, 1, 100, False), (0o100664, 0, 1, 100, False), (0o100644, 0, 2, 100, False), (0o100644, 0, 1, 16385, False), (0o010644, 0, 1, 100, False)])
def test_ownership_type_modes_and_size(mode,uid,links,size,directory):
    with pytest.raises(RouterError):
        window._check_owner(SimpleNamespace(st_uid=uid,st_mode=mode,st_nlink=links,st_size=size),directory=directory)


def test_safe_owned_types():
    window._check_owner(SimpleNamespace(st_uid=0,st_mode=0o40755),directory=True)
    window._check_owner(SimpleNamespace(st_uid=0,st_mode=0o100644,st_nlink=1,st_size=100),directory=False)


def test_missing_authority_fail_closed(monkeypatch):
    monkeypatch.setattr(os,'geteuid',lambda:1000)
    def missing(*args, **kwargs): raise FileNotFoundError
    monkeypatch.setattr(os,'open',missing)
    with pytest.raises(RouterError) as error: window._read_grant(make_plan().id)
    assert error.value.code == 'approval_window_required'


def test_descriptor_traversal_requires_no_follow_and_checks_every_node(monkeypatch):
    monkeypatch.setattr(os,'geteuid',lambda:1000)
    calls=[]
    def opened(path, flags, **kwargs):
        calls.append((path, flags, kwargs))
        return len(calls)
    monkeypatch.setattr(os,'open',opened)
    monkeypatch.setattr(os,'close',lambda _:None)
    monkeypatch.setattr(os,'fstat',lambda fd:SimpleNamespace(st_uid=0,st_mode=0o40755 if fd <5 else 0o100644,st_nlink=1,st_size=100))
    monkeypatch.setattr(os,'read',lambda *args:json.dumps(window.approval_request(make_plan())).encode())
    result=window._read_grant(make_plan().id)
    assert result['plan_hash']==make_plan().id
    assert [c[0] for c in calls]==['/','etc','asus-router-agent','approvals',make_plan().id+'.json']
    assert all(flags & os.O_NOFOLLOW for _,flags,_ in calls)
    assert all(flags & os.O_DIRECTORY for _,flags,_ in calls[:-1])
    assert all(calls[index][2]['dir_fd']==index for index in range(1,5))
