import json
import pytest
from router_agent.cli import main
from router_agent.approval import confirm_plan,validate_local_plan
from router_agent.errors import RouterError
from router_agent.snapshots import SnapshotStore,state_lock
from test_native_parental_backend import setup,State,approve,KEY,MACS,SCHEDULE,client_alias


@pytest.mark.parametrize('arguments',[
    ['parental'],['parental','--enabled','on','--blocked','on'],
    ['parental-block-all','--enabled','on'],['parental-block-all','--blocked','on','--alias','client-0000000000000001'],
    ['parental-rule','--alias','AA:BB:CC:DD:EE:FF','--type','block'],
    ['parental-rule','--alias','client-0000000000000001'],
    ['parental-rule','--alias','client-0000000000000001','--type','remove','--schedule',SCHEDULE],
    ['parental-rule','--alias','client-0000000000000001','--type','time','--schedule','invalid-private-value'],
    ['led','--enabled','on','--blocked','on'],
])
def test_parental_bad_intent_rejected_before_credentials(arguments,monkeypatch,capsys):
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:pytest.fail('must reject before keyring'))
    assert main(['plan',*arguments])!=0
    result=json.loads(capsys.readouterr().out)
    assert result['error']['code'] in {'invalid_arguments','invalid_parental_intent','invalid_schedule'}
    assert 'invalid-private-value' not in str(result)


def test_parental_approval_shows_meaningful_scope_and_explicit_user_schedule_only(tmp_path,monkeypatch,capsys):
    engine,state,store,backend,clock=setup(tmp_path)
    alias=client_alias(KEY,MACS[1])
    plan=engine.plan('parental.rule',{'client_alias':alias,'rule_type':'time','schedule':SCHEDULE})
    monkeypatch.setattr('sys.stdin.isatty',lambda:True)
    monkeypatch.setattr('sys.stderr.isatty',lambda:True)
    from router_agent.approval_window import approval_request
    monkeypatch.setattr('router_agent.approval_window._read_grant', lambda window: approval_request(store.get(window)[0]))
    approval=confirm_plan(plan,window_id=plan.id,clock=lambda:101,input_reader=lambda _:'apply '+plan.id)
    assert approval.plan_hash==plan.id
    output=capsys.readouterr()
    assert not output.out
    assert alias in output.err and SCHEDULE in output.err
    assert 'firewall_restart' in output.err and 'schedule_semantics_and_timezone_unverified' in output.err
    for private in ('private-middle',*MACS,'fake-router-password'):assert private not in output.err
    block=engine.plan('parental.block_all',{'blocked':True})
    confirm_plan(block,window_id=block.id,clock=lambda:101,input_reader=lambda _:'apply '+block.id)
    assert 'all_client_internet_blocking_setting' in capsys.readouterr().err


def test_parental_cancel_eof_and_expiry_produce_no_writes(tmp_path,monkeypatch):
    engine,state,store,backend,clock=setup(tmp_path)
    plan=engine.plan('parental.enable',{'enabled':True})
    monkeypatch.setattr('sys.stdin.isatty',lambda:True)
    monkeypatch.setattr('sys.stderr.isatty',lambda:True)
    from router_agent.approval_window import approval_request
    monkeypatch.setattr('router_agent.approval_window._read_grant', lambda window: approval_request(store.get(window)[0]))
    def eof(_):raise EOFError
    for reader in (lambda _:'yes',eof):
        with pytest.raises(RouterError) as error:confirm_plan(plan,window_id=plan.id,clock=lambda:101,input_reader=reader)
        assert error.value.code=='approval_cancelled'
    with pytest.raises(RouterError) as error:confirm_plan(plan,window_id=plan.id,clock=lambda:9999,input_reader=lambda _:pytest.fail())
    assert error.value.code=='expired_plan' and state.writes==0


def test_cli_context_prevalidation_runs_before_review_keyring_or_native_action(tmp_path,monkeypatch,capsys):
    engine,state,store,backend,clock=setup(tmp_path)
    directory=tmp_path
    # Use the exact bound key for local-only context authentication.
    directory.chmod(0o700);(directory/'alias.key').write_bytes(KEY);(directory/'alias.key').chmod(0o600)
    plan=engine.plan('parental.enable',{'enabled':True})
    (backend.directory/(plan.id+'.json')).write_text('null')
    from router_agent.auth import AuthConfig
    monkeypatch.setattr('router_agent.cli.load_config',lambda:AuthConfig('https://router.example:443','synthetic'))
    monkeypatch.setattr('router_agent.cli._plan_store',lambda:(directory,store))
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:pytest.fail('invalid context before credentials'))
    monkeypatch.setattr('router_agent.approval.confirm_plan',lambda _:pytest.fail('invalid context before operator review'))
    before=state.reads
    assert main(['apply',plan.id,'--window',plan.id])==1
    assert json.loads(capsys.readouterr().out)['error']['code']=='invalid_policy_context'
    assert state.reads==before and state.writes==0


def test_parental_approval_requires_finite_metadata_and_explicit_block_scope(tmp_path):
    import hashlib
    from router_agent.catalog import canonical
    from router_agent.operations import Plan
    engine,state,store,backend,clock=setup(tmp_path)
    plan=engine.plan('parental.block_all',{'blocked':True})
    data=plan.data;data['side_effects']=['firewall_restart'];data.pop('hash');data['hash']=hashlib.sha256(canonical(data).encode()).hexdigest()
    with pytest.raises(RouterError) as error:validate_local_plan(Plan(canonical(data)),clock=lambda:101)
    assert error.value.code=='invalid_plan'
