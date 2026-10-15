import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import pytest
from router_agent.catalog import canonical,load_catalog
from router_agent.errors import RouterError
from router_agent.operations import OperationEngine,MemoryPlanStore,ApprovedScope,Plan,PLAN_KEYS,PARENTAL_PLAN_KEYS
from router_agent.native_parental_backend import NativeParentalBackend
from router_agent.parental_policy import (PARENTAL_POLICY_KEYS,read_policy_snapshot,prepare_enable,prepare_block_all,prepare_rule,prepare_restore,client_alias)

ACTIVE_STORE = None

@pytest.fixture(autouse=True)
def synthetic_authority(monkeypatch):
    from router_agent.approval_window import approval_request
    monkeypatch.setattr('router_agent.approval_window._read_grant', lambda window: approval_request(ACTIVE_STORE.get(window)[0]))


KEY=b'k'*32
IDENTITY={'model':'RT-AX86U','firmware':'3.0.0.4.388_24436-ge7c0b5e','device_fingerprint':'fixture-device'}
MACS=['AA:BB:CC:DD:EE:01','AA:BB:CC:DD:EE:02','AA:BB:CC:DD:EE:03']
SCHEDULE='W03E21000700<W04122000800'


def raw_policy(orphan=False):
    if orphan:return {'MULTIFILTER_ALL':'0','MULTIFILTER_BLOCK_ALL':'0','MULTIFILTER_MAC':'','MULTIFILTER_DEVICENAME':'','MULTIFILTER_MACFILTER_DAYTIME_V2':'private-orphan-schedule','MULTIFILTER_ENABLE':''}
    return {'MULTIFILTER_ALL':'0','MULTIFILTER_BLOCK_ALL':'0','MULTIFILTER_MAC':'&#62'.join(MACS),'MULTIFILTER_DEVICENAME':'private-first&#62private-middle&#62private-last','MULTIFILTER_MACFILTER_DAYTIME_V2':'&#62'.join(SCHEDULE.replace('<','&#60') for _ in MACS),'MULTIFILTER_ENABLE':'0&#621&#622'}


class State:
    def __init__(self,raw=None):self.raw=raw or raw_policy();self.writes=0;self.reads=0;self.fail=False;self.store=None;self.plan_id=None;self.inventory={mac:{} for mac in [*MACS,'AA:BB:CC:DD:EE:04']}
    def snapshot(self):return read_policy_snapshot(self.raw,KEY)
    async def reader(self,config,password,*,fingerprint_key,include_clients=False):
        self.reads+=1
        assert fingerprint_key==KEY
        result={'identity':IDENTITY,'policy':self.snapshot()}
        if include_clients:result['client_inventory']=self.inventory
        return result
    async def writer(self,config,password,*,expected_identity,expected_policy_fingerprint,expected_after_policy_fingerprint,fingerprint_key,**intent):
        assert expected_identity==IDENTITY and fingerprint_key==KEY
        assert self.snapshot().fingerprint==expected_policy_fingerprint
        assert self.store.get(self.plan_id)[1]['phase']=='outcome_unknown'
        if 'enabled' in intent:prepared=await prepare_enable(self.snapshot(),intent['enabled'])
        elif 'blocked' in intent:prepared=await prepare_block_all(self.snapshot(),intent['blocked'])
        elif 'restore_snapshot' in intent:prepared=await prepare_restore(self.snapshot(),intent['restore_snapshot'])
        else:prepared=await prepare_rule(self.snapshot(),intent['client_alias'],intent['rule_type'],client_inventory=self.inventory,schedule=intent.get('schedule'))
        assert prepared.after.fingerprint==expected_after_policy_fingerprint
        intent['authorization_check']()
        self.writes+=1;self.raw=prepared.after.raw
        if self.fail:raise TimeoutError('private-error-value')
        return {'freshness':'applied_unverified'}


def setup(tmp_path,state=None):
    state=state or State()
    global ACTIVE_STORE
    store=MemoryPlanStore();state.store=store
    ACTIVE_STORE=store
    backend=NativeParentalBackend(None,'fake-router-password',fingerprint_key=KEY,state_dir=tmp_path,reader=state.reader,writers={name:state.writer for name in ('enable','block_all','rule','restore')})
    clock=[100.0]
    return OperationEngine(load_catalog(),backend,store,clock=lambda:clock[0]),state,store,backend,clock


def approve(plan):return ApprovedScope(plan.id,plan.data['device'],plan.data['operation'],canonical(plan.data['after']),plan.data['expires_at'],plan.id)


def apply(engine,state,plan):
    state.plan_id=plan.id
    return engine.apply(plan.id,approve(plan))


@pytest.mark.parametrize('operation,intent,flag',[('parental.enable',{'enabled':True},'MULTIFILTER_ALL'),('parental.block_all',{'blocked':True},'MULTIFILTER_BLOCK_ALL')])
def test_global_flag_full_binding_preserves_orphan_and_faithful_inverse(tmp_path,operation,intent,flag):
    original=raw_policy(orphan=True)
    engine,state,store,backend,clock=setup(tmp_path,State(deepcopy(original)))
    plan=engine.plan(operation,intent)
    assert set(plan.data)==PARENTAL_PLAN_KEYS
    assert plan.data['review']['before']['rules_write_recoverable'] is False
    assert plan.data['side_effects'][0]=='firewall_restart'
    if operation=='parental.block_all':assert 'all_client_internet_blocking_setting' in plan.data['side_effects']
    assert apply(engine,state,plan)['phase']=='apply_unverified'
    assert state.raw[flag]=='1'
    assert all(state.raw[k]==v for k,v in original.items() if k!=flag)
    assert engine.verify(plan.id)['phase']=='verified'
    clock[0]+=1;reverse=engine.rollback_plan(plan.id)
    assert reverse.data['intent']['source_plan']==plan.id
    apply(engine,state,reverse)
    assert engine.verify(reverse.id)['phase']=='verified'
    assert state.raw==original and state.writes==2


def test_middle_rule_removal_and_reverse_restore_exact_order_names_schedules(tmp_path):
    engine,state,store,backend,clock=setup(tmp_path)
    original=deepcopy(state.raw)
    alias=client_alias(KEY,MACS[1])
    plan=engine.plan('parental.rule',{'client_alias':alias,'rule_type':'remove'})
    assert plan.data['review']['before']['alias']==alias and plan.data['review']['after'] is None
    assert apply(engine,state,plan)['phase']=='apply_unverified'
    assert engine.verify(plan.id)['phase']=='verified'
    assert state.raw['MULTIFILTER_MAC']=='&#62'.join([MACS[0],MACS[2]])
    clock[0]+=1;reverse=engine.rollback_plan(plan.id)
    assert reverse.data['review']['before'] is None
    assert reverse.data['review']['after']['alias']==alias
    assert 'original order' in reverse.data['review']['preservation']
    apply(engine,state,reverse)
    assert engine.verify(reverse.id)['phase']=='verified'
    assert state.raw==original


def test_rule_add_update_remove_last_and_explicit_schedule_review(tmp_path):
    engine,state,store,backend,clock=setup(tmp_path,State({'MULTIFILTER_ALL':'0','MULTIFILTER_BLOCK_ALL':'0',**{key:'' for key in PARENTAL_POLICY_KEYS if key not in ('MULTIFILTER_ALL','MULTIFILTER_BLOCK_ALL')}}))
    alias=client_alias(KEY,'AA:BB:CC:DD:EE:04')
    plan=engine.plan('parental.rule',{'client_alias':alias,'rule_type':'time','schedule':SCHEDULE})
    assert plan.data['intent']['schedule']==SCHEDULE
    assert apply(engine,state,plan)['phase']=='apply_unverified'
    assert engine.verify(plan.id)['phase']=='verified'
    assert state.raw['MULTIFILTER_DEVICENAME']==alias
    clock[0]+=1;changed=engine.plan('parental.rule',{'client_alias':alias,'rule_type':'block'})
    preserved=state.raw['MULTIFILTER_MACFILTER_DAYTIME_V2']
    apply(engine,state,changed);assert engine.verify(changed.id)['phase']=='verified'
    assert state.raw['MULTIFILTER_MACFILTER_DAYTIME_V2']==preserved
    clock[0]+=1;removed=engine.plan('parental.rule',{'client_alias':alias,'rule_type':'remove'})
    apply(engine,state,removed);assert engine.verify(removed.id)['phase']=='verified'
    assert state.raw['MULTIFILTER_MAC']==state.raw['MULTIFILTER_DEVICENAME']==state.raw['MULTIFILTER_MACFILTER_DAYTIME_V2']==state.raw['MULTIFILTER_ENABLE']==''
    clock[0]+=1;reverse=engine.rollback_plan(removed.id)
    apply(engine,state,reverse);assert engine.verify(reverse.id)['phase']=='verified'
    assert state.raw['MULTIFILTER_MAC']=='AA:BB:CC:DD:EE:04'


def test_noop_zero_writes_and_rule_only_drift_blocks_global_enable(tmp_path):
    engine,state,store,backend,clock=setup(tmp_path)
    noop=engine.plan('parental.enable',{'enabled':False})
    assert apply(engine,state,noop)['phase']=='verified_noop'
    assert engine.verify(noop.id)['phase']=='verified_noop' and state.writes==0
    clock[0]+=1;plan=engine.plan('parental.enable',{'enabled':True})
    state.raw['MULTIFILTER_DEVICENAME']='changed-unrelated-name&#62private-middle&#62private-last'
    with pytest.raises(ValueError,match='before_drift'):apply(engine,state,plan)
    assert state.writes==0


def test_uncertain_write_durable_replay_blocked_verify_after_expiry(tmp_path):
    engine,state,store,backend,clock=setup(tmp_path)
    plan=engine.plan('parental.enable',{'enabled':True});state.fail=True
    assert apply(engine,state,plan)['phase']=='outcome_unknown'
    with pytest.raises(ValueError,match='replay'):apply(engine,state,plan)
    assert state.writes==1
    clock[0]=5000
    assert engine.verify(plan.id)['phase']=='verified'
    state.raw['MULTIFILTER_DEVICENAME']='other-drift&#62private-middle&#62private-last'
    with pytest.raises(ValueError,match='rollback_drift'):engine.rollback_plan(plan.id)


def test_private_context_protected_bound_and_public_plan_excludes_existing_data(tmp_path):
    engine,state,store,backend,clock=setup(tmp_path)
    plan=engine.plan('parental.rule',{'client_alias':client_alias(KEY,MACS[1]),'rule_type':'block'})
    path=backend.directory/(plan.id+'.json')
    assert path.stat().st_mode&0o777==0o600 and backend.directory.stat().st_mode&0o777==0o700
    public=canonical(plan.data)
    for private in [*MACS,'private-middle',SCHEDULE,'fake-router-password']:assert private not in public
    private=path.read_text()
    assert 'private-middle' in private and 'fake-router-password' not in private
    state.raw['MULTIFILTER_ALL']='1'
    with pytest.raises(ValueError,match='before_drift'):apply(engine,state,plan)


@pytest.mark.parametrize('damage',['missing','null','scalar','tamper','swap','rehashed_review'])
def test_context_damage_fails_before_router_read_or_write(tmp_path,damage):
    engine,state,store,backend,clock=setup(tmp_path)
    plan=engine.plan('parental.enable',{'enabled':True})
    path=backend.directory/(plan.id+'.json');before_reads=state.reads
    if damage=='missing':path.unlink()
    elif damage in {'null','scalar'}:path.write_text('null' if damage=='null' else '42')
    elif damage=='tamper':
        record=json.loads(path.read_text());record['context']['before']['MULTIFILTER_ALL']='1';path.write_text(json.dumps(record))
    elif damage=='swap':
        record=json.loads(path.read_text());record['plan_hash']='f'*64;path.write_text(json.dumps(record))
    else:
        data=plan.data;data['review']['after']['enabled']=False;data.pop('hash');data['hash']=hashlib.sha256(canonical(data).encode()).hexdigest();plan=Plan(canonical(data));store.put(plan,{'phase':'planned'})
        record=json.loads(path.read_text());record['plan_hash']=plan.id
        (backend.directory/(plan.id+'.json')).write_text(json.dumps(record));(backend.directory/(plan.id+'.json')).chmod(0o600)
    with pytest.raises(RouterError) as error:apply(engine,state,plan)
    assert error.value.code=='invalid_policy_context'
    assert state.reads==before_reads and state.writes==0


def test_rule_native_loss_branches_reject_without_plan_or_write(tmp_path):
    engine,state,store,backend,clock=setup(tmp_path,State(raw_policy(orphan=True)))
    with pytest.raises(RouterError) as error:engine.plan('parental.rule',{'client_alias':client_alias(KEY,MACS[0]),'rule_type':'block','schedule':SCHEDULE})
    assert error.value.code=='policy_recovery_unavailable' and not store._records and state.writes==0
    engine,state,store,backend,clock=setup(tmp_path/'second')
    state.raw['MULTIFILTER_DEVICENAME']='&#62private-middle&#62private-last'
    with pytest.raises(RouterError):engine.plan('parental.rule',{'client_alias':client_alias(KEY,MACS[0]),'rule_type':'block'})
    assert state.writes==0
