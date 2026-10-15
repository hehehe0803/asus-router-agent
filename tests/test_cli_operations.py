import json
import pytest
from router_agent.cli import main
from router_agent.errors import RouterError
from router_agent.auth import AuthConfig


@pytest.fixture(autouse=True)
def configured_https(monkeypatch):
    monkeypatch.setattr("router_agent.cli.load_config",lambda:AuthConfig("https://router.example:443","synthetic"))
from router_agent.operations import FilePlanStore
from router_agent.snapshots import private_dir, state_lock
from test_approval import make_plan


class FakeEngine:
    def __init__(self): self.writes=0; self.verifies=0; self.phase='apply_unverified'; self.verify_phase='verified'
    def apply(self,plan_id,approval):
        self.writes+=1
        return {'phase':self.phase}
    def verify(self,plan_id):
        self.verifies+=1
        return {'phase':self.verify_phase}
    def rollback_plan(self,plan_id):return make_plan()
    def plan(self,operation,after):return make_plan()


def setup_cli(tmp_path,monkeypatch):
    directory=private_dir(tmp_path/'state')
    store=FilePlanStore(directory/'plans')
    plan=make_plan()
    with store.lock():store.put(plan,{'phase':'planned'})
    engine=FakeEngine()
    monkeypatch.setattr('router_agent.cli._plan_store',lambda:(directory,store))
    monkeypatch.setattr('router_agent.cli._engine',lambda:(directory,engine))
    return directory,store,plan,engine


def test_apply_confirm_then_independent_verify(tmp_path,monkeypatch,capsys):
    directory,store,plan,engine=setup_cli(tmp_path,monkeypatch)
    def confirm(p, **kwargs):
        # The root lock must be available during confirmation.
        with state_lock(directory):pass
        return object()
    monkeypatch.setattr('router_agent.approval.confirm_plan',confirm)
    assert main(['apply',plan.id]) == 0
    assert engine.writes == 1 and engine.verifies == 1
    assert json.loads(capsys.readouterr().out)['data']['phase'] == 'verified'


@pytest.mark.parametrize('code',['approval_cancelled','expired_plan','human_confirmation_required'])
def test_failed_confirmation_never_fetches_credentials_or_writes(tmp_path,monkeypatch,capsys,code):
    _,_,plan,engine=setup_cli(tmp_path,monkeypatch)
    def reject(_, **kwargs):raise RouterError(code,'Fixed rejection.')
    monkeypatch.setattr('router_agent.approval.confirm_plan',reject)
    monkeypatch.setattr('router_agent.cli._engine',lambda:pytest.fail('credential/backend setup before confirmation'))
    assert main(['apply',plan.id]) == 1
    assert engine.writes == 0
    assert json.loads(capsys.readouterr().out)['error']['code'] == code


def test_unknown_outcome_verified_once_and_failure_nonzero(tmp_path,monkeypatch,capsys):
    _,_,plan,engine=setup_cli(tmp_path,monkeypatch)
    monkeypatch.setattr('router_agent.approval.confirm_plan',lambda _, **kwargs:object())
    engine.phase='outcome_unknown';engine.verify_phase='verification_failed'
    assert main(['apply',plan.id]) == 1
    assert engine.writes == 1 and engine.verifies == 1
    assert json.loads(capsys.readouterr().out)['data']['phase'] == 'verification_failed'


def test_rollback_preview_never_applies_and_plan_show_is_local(tmp_path,monkeypatch,capsys):
    _,_,plan,engine=setup_cli(tmp_path,monkeypatch)
    assert main(['rollback',plan.id]) == 0
    assert json.loads(capsys.readouterr().out)['data']['phase'] == 'planned'
    assert engine.writes == 0
    monkeypatch.setattr('router_agent.cli._engine',lambda:pytest.fail())
    assert main(['plan-show',plan.id]) == 0
    assert json.loads(capsys.readouterr().out)['data']['plan']['hash'] == plan.id


def test_no_argv_approval_or_replay(tmp_path,monkeypatch,capsys):
    _,store,plan,engine=setup_cli(tmp_path,monkeypatch)
    assert main(['apply',plan.id,'--yes']) == 2
    capsys.readouterr()
    with store.lock():store.put(plan,{'phase':'outcome_unknown'})
    monkeypatch.setattr('router_agent.approval.confirm_plan',lambda _:pytest.fail())
    assert main(['apply',plan.id]) == 1
    assert json.loads(capsys.readouterr().out)['error']['code'] == 'replay_blocked_verify_first'
    assert engine.writes == 0

def test_cli_protocol_integrates_real_engine_with_synthetic_backend(tmp_path,monkeypatch,capsys):
    from router_agent.catalog import Catalog, load_catalog
    from router_agent.operations import OperationEngine
    directory=private_dir(tmp_path/'state')
    store=FilePlanStore(directory/'plans')
    catalog_data=load_catalog().manifest()
    synthetic=next(op for op in catalog_data['operations'] if op['name']=='synthetic.led')
    synthetic['name']='led.set'
    catalog_data['operations']=[synthetic]
    from backup_fixtures import SyntheticBackupBackend
    class Backend(SyntheticBackupBackend):
        live=False
        def __init__(self):self.enabled=False;self.writes=0;self.reads=0
        def device_identity(self):return {'device':'fixture','firmware':'fixture'}
        def read(self,operation,fields):self.reads+=1;return {'enabled':self.enabled}
        def write(self,operation,values):self.enabled=values['enabled'];self.writes+=1
    backend=Backend()
    engine=OperationEngine(Catalog(catalog_data),backend,store)
    monkeypatch.setattr('router_agent.cli._engine',lambda:(directory,engine))
    monkeypatch.setattr('router_agent.cli._plan_store',lambda:(directory,store))
    monkeypatch.setattr('sys.stdin.isatty',lambda:True)
    monkeypatch.setattr('sys.stderr.isatty',lambda:True)
    assert main(['plan','led','--enabled','on']) == 0
    preview=json.loads(capsys.readouterr().out)['data']['plan']
    assert preview['before']=={'enabled':False} and preview['after']=={'enabled':True}
    assert backend.writes==0
    monkeypatch.setattr('builtins.input',lambda _:'apply '+preview['hash'])
    monkeypatch.setattr('router_agent.approval_window._read_grant',lambda _: {'schema_version':1,'plan_hash':preview['hash'],'device':preview['device'],'operation':preview['operation'],'after_json':json.dumps(preview['after'],sort_keys=True,separators=(',',':')),'issued_at':preview['created_at'],'expires_at':preview['expires_at']})
    assert main(['apply',preview['hash'],'--window',preview['hash']]) == 0
    result=json.loads(capsys.readouterr().out)
    assert result['data']['phase']=='verified'
    assert backend.writes==1 and backend.reads==3
    assert main(['apply',preview['hash'],'--window',preview['hash']]) == 1
    assert json.loads(capsys.readouterr().out)['error']['code']=='replay_blocked_verify_first'
    assert backend.writes==1


def test_plaintext_apply_rejected_before_prompt_credentials_or_network(tmp_path,monkeypatch,capsys):
    _,_,plan,_ = setup_cli(tmp_path,monkeypatch)
    monkeypatch.setattr('router_agent.cli.load_config',lambda:AuthConfig('http://router.example:80','synthetic',allow_plain_http=True))
    monkeypatch.setattr('router_agent.approval.confirm_plan',lambda _:pytest.fail('HTTP reached prompt'))
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:pytest.fail('HTTP read credentials'))
    monkeypatch.setattr('router_agent.cli._engine',lambda:pytest.fail('HTTP reached backend'))
    assert main(['apply',plan.id]) == 1
    assert json.loads(capsys.readouterr().out)['error']['code'] == 'https_required'


def test_approval_request_is_local_public_scope_without_authority(tmp_path,monkeypatch,capsys):
    _,_,plan,_ = setup_cli(tmp_path,monkeypatch)
    monkeypatch.setattr('router_agent.cli.load_config',lambda:pytest.fail('local request touched auth config'))
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:pytest.fail('local request touched credentials'))
    monkeypatch.setattr('router_agent.cli._engine',lambda:pytest.fail('local request reached backend'))
    monkeypatch.setattr('router_agent.cli.validate_local_plan',lambda _:None,raising=False)
    # This synthetic fixture has an old clock; use current-time validation injection only.
    monkeypatch.setattr('router_agent.approval.validate_local_plan',lambda _:plan.data)
    assert main(['approval-request',plan.id]) == 0
    data = json.loads(capsys.readouterr().out)['data']
    assert data['status'] == 'not_authorized'
    assert data['approval_request']['plan_hash'] == plan.id
    assert '300 seconds (five minutes) after creation' in data['reason']
    assert 'new plan with a new hash' in data['reason']
    assert 'new grant' in data['reason']
    assert data['approval_request']['expires_at'] == plan.data['expires_at']
    assert data['plan']['expires_at'] == plan.data['expires_at']
    assert data['plan']['before'] == plan.data['before']
    assert data['plan']['after'] == plan.data['after']
