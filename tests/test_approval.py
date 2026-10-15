import hashlib
import pytest
from router_agent.approval import confirm_plan
from router_agent.catalog import canonical
from router_agent.errors import RouterError
from router_agent.operations import Plan


def make_plan(now=100):
    data={'device':'fixture-fingerprint','firmware':'fixture','catalog_hash':'fixture','operation':'led.set','fields':['enabled'],'before':{'enabled':False},'after':{'enabled':True},'verification':{'enabled':True},'created_at':now,'expires_at':now+300,'risk':'low','backup_required':False}
    data['hash']=hashlib.sha256(canonical(data).encode()).hexdigest()
    return Plan(canonical(data))


@pytest.fixture(autouse=True)
def administrator_grant(monkeypatch):
    from router_agent.approval_window import approval_request
    monkeypatch.setattr('router_agent.approval_window._read_grant', lambda window: approval_request(make_plan()))


def tty(monkeypatch,value=True):
    monkeypatch.setattr('sys.stdin.isatty',lambda:value)
    monkeypatch.setattr('sys.stderr.isatty',lambda:value)


def test_exact_human_reply_and_display(monkeypatch,capsys):
    tty(monkeypatch)
    plan=make_plan()
    approval=confirm_plan(plan,window_id=plan.id,clock=lambda:101,input_reader=lambda _: 'apply '+plan.id)
    assert approval.plan_hash == plan.id
    out=capsys.readouterr()
    assert not out.out
    assert all(field in out.err for field in ('device','firmware','before','after','risk','expires_at',plan.id))

@pytest.mark.parametrize('reply',['yes','', 'apply wrong'])
def test_no_positive_exact_confirmation(monkeypatch,reply):
    tty(monkeypatch)
    with pytest.raises(RouterError) as error:
        confirm_plan(make_plan(),window_id=make_plan().id,clock=lambda:101,input_reader=lambda _:reply)
    assert error.value.code == 'approval_cancelled'


def test_non_tty_eof_and_expiry(monkeypatch):
    tty(monkeypatch,False)
    with pytest.raises(RouterError,match='human'):
        confirm_plan(make_plan(),window_id=make_plan().id,clock=lambda:101,input_reader=lambda _:pytest.fail())
    tty(monkeypatch)
    def eof(_):raise EOFError
    with pytest.raises(RouterError) as error: confirm_plan(make_plan(),window_id=make_plan().id,clock=lambda:101,input_reader=eof)
    assert error.value.code == 'approval_cancelled'
    with pytest.raises(RouterError) as error: confirm_plan(make_plan(),window_id=make_plan().id,clock=lambda:401,input_reader=lambda _:pytest.fail())
    assert error.value.code == 'expired_plan'


def test_expiry_during_confirmation(monkeypatch):
    tty(monkeypatch)
    plan=make_plan()
    now=[101]
    def reply(_):
        now[0]=401
        return 'apply '+plan.id
    with pytest.raises(RouterError) as error:confirm_plan(plan,window_id=plan.id,clock=lambda:now[0],input_reader=reply)
    assert error.value.code == 'expired_plan'


def test_window_expiry_during_confirmation(monkeypatch):
    from router_agent.approval_window import approval_request
    tty(monkeypatch)
    plan = make_plan()
    grant = approval_request(plan)
    grant['expires_at'] = 102
    monkeypatch.setattr('router_agent.approval_window._read_grant', lambda _: grant)
    now = [101]
    def reply(_):
        now[0] = 103
        return 'apply ' + plan.id
    with pytest.raises(RouterError) as error:
        confirm_plan(plan, window_id=plan.id, clock=lambda: now[0], input_reader=reply)
    assert error.value.code == 'approval_window_expired'
