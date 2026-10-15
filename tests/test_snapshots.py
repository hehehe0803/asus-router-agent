import os
import pytest
from router_agent.snapshots import SnapshotStore, private_dir, atomic_write, private_read
from router_agent.errors import RouterError

IDENTITY = {'schema':1,'device':'private-fingerprint','firmware':'fixture','catalog':'fixture-hash'}

def test_alias_is_private_stable_and_local(tmp_path):
    a,b = SnapshotStore(tmp_path/'a'),SnapshotStore(tmp_path/'b')
    assert a.alias('fixture-device') == a.alias('fixture-device')
    assert a.alias('fixture-device') != b.alias('fixture-device')
    assert (a.state_dir/'alias.key').stat().st_mode & 0o777 == 0o600

def test_diff_keeps_freshness_and_ignores_counters(tmp_path):
    store = SnapshotStore(tmp_path/'state')
    a = store.save({'freshness':'fresh','ram':{'used':4},'uptime':1},IDENTITY)
    b = store.save({'freshness':'fresh','ram':{'used':4},'uptime':2},IDENTITY)
    c = store.save({'freshness':'stale','ram':{'used':4},'uptime':3},IDENTITY)
    assert not store.diff(a['snapshot_id'],b['snapshot_id'])['changed']
    assert store.diff(b['snapshot_id'],c['snapshot_id'])['changes'] == [{'path':'/freshness','before':'fresh','after':'stale'}]

def test_compatibility_and_redaction(tmp_path):
    store=SnapshotStore(tmp_path/'state')
    a=store.save({'password':'fake-secret','model':'fixture'},IDENTITY)
    assert 'fake-secret' not in str(a)
    b=store.save({'model':'fixture'},{**IDENTITY,'firmware':'changed'})
    with pytest.raises(RouterError) as error: store.diff(a['snapshot_id'],b['snapshot_id'])
    assert error.value.code == 'baseline_reset'

def test_retention_does_not_delete_unrelated_files(tmp_path):
    store=SnapshotStore(tmp_path/'state')
    store.save({'model':'fixture'},IDENTITY)
    unrelated=store.directory/'notes.json'; unrelated.write_text('keep');unrelated.chmod(0o600)
    for _ in range(22): store.save({'model':'fixture'},IDENTITY)
    assert len(store.list()) == 20
    assert unrelated.read_text() == 'keep'

def test_unsafe_paths_and_hardlinks(tmp_path):
    target=tmp_path/'target';target.mkdir(mode=0o700)
    link=tmp_path/'link';link.symlink_to(target)
    with pytest.raises(RouterError):private_dir(link/'state')
    unsafe=tmp_path/'unsafe';unsafe.mkdir(mode=0o755)
    with pytest.raises(RouterError):private_dir(unsafe)
    p=target/'file';atomic_write(p,b'fixture')
    os.link(p,target/'copy')
    with pytest.raises(RouterError):private_read(p)

def test_seven_day_snapshot_retention(tmp_path):
    import time
    store=SnapshotStore(tmp_path/'state')
    old=store.save({'model':'fixture'},IDENTITY)
    path=store.directory/(old['snapshot_id']+'.json')
    os.utime(path,(time.time()-8*86400,time.time()-8*86400))
    current=store.save({'model':'fixture'},IDENTITY)
    assert [r['snapshot_id'] for r in store.list()] == [current['snapshot_id']]

def test_state_lock_contention_has_bounded_error(tmp_path):
    from router_agent.snapshots import state_lock
    with state_lock(tmp_path/'state'):
        with pytest.raises(RouterError) as error:
            with state_lock(tmp_path/'state'): pass
        assert error.value.code == 'state_busy'

def test_diff_leaf_records_do_not_repeat_unrelated_payload(tmp_path):
    from router_agent.output import envelope
    store=SnapshotStore(tmp_path/'state')
    base={'data':{'wan':{'link_code':1},'clients':[{'alias':'client-fixture','online':True}],'cpu':{'cores':[{'core':0,'total_ticks':123}]}},'freshness':'unknown'}
    old=store.save(base,IDENTITY)
    newer=store.save({**base,'data':{**base['data'],'wan':{'link_code':2}}},IDENTITY)
    diff=store.diff(old['snapshot_id'],newer['snapshot_id'])
    assert diff['changes'] == [{'path':'/data/wan/link_code','before':1,'after':2}]
    rendered=envelope(diff)
    assert rendered['data']['changes'] == diff['changes']
    assert 'client-fixture' not in str(rendered)
    assert 'total_ticks' not in str(rendered)

def test_snapshot_list_metadata_only(tmp_path):
    store=SnapshotStore(tmp_path/'state')
    saved=store.save({'clients':[{'alias':'client-fixture'}]},IDENTITY)
    listed=store.list()
    assert listed == [{k:saved[k] for k in ('snapshot_id','created_at','kind','identity')}]
    assert 'client-fixture' not in str(listed)

def test_added_client_delta_is_leaf_bounded(tmp_path):
    store=SnapshotStore(tmp_path/'state')
    old=store.save({'clients':[]},IDENTITY)
    new=store.save({'clients':[{'alias':f'client-{i}','online':True} for i in range(50)]},IDENTITY)
    diff=store.diff(old['snapshot_id'],new['snapshot_id'])
    assert len(diff['changes']) == 20
    assert diff['total_changes'] == 100
    assert diff['truncated']
    assert all(isinstance(c['after'], (str,bool)) for c in diff['changes'])

def test_diff_missing_and_null_presence_is_visible(tmp_path):
    from router_agent.output import envelope
    store=SnapshotStore(tmp_path/'state')
    old=store.save({'clients':[]},IDENTITY)
    new=store.save({'clients':[None],'wan':None},IDENTITY)
    changes=store.diff(old['snapshot_id'],new['snapshot_id'])
    assert changes['total_changes'] == 2
    assert changes['changes'] == [
        {'path':'/clients/0','before':None,'after':None,'before_present':False,'after_present':True},
        {'path':'/wan','before':None,'after':None,'before_present':False,'after_present':True},
    ]
    assert envelope(changes)['data']['changes'] == changes['changes']
    reverse=store.diff(new['snapshot_id'],old['snapshot_id'])
    assert all(c['before_present'] and not c['after_present'] for c in reverse['changes'])

@pytest.mark.parametrize('empty',[{},[]])
def test_empty_container_add_remove_and_null_transition(tmp_path,empty):
    store=SnapshotStore(tmp_path/'state')
    missing=store.save({},IDENTITY)
    null=store.save({'wan':None},IDENTITY)
    container=store.save({'wan':empty},IDENTITY)
    added=store.diff(missing['snapshot_id'],container['snapshot_id'])
    assert added['total_changes'] == 1
    assert added['changes'] == [{'path':'/wan','before':None,'after':empty,'before_present':False,'after_present':True}]
    removed=store.diff(container['snapshot_id'],missing['snapshot_id'])
    assert removed['changes'] == [{'path':'/wan','before':empty,'after':None,'before_present':True,'after_present':False}]
    transitioned=store.diff(null['snapshot_id'],container['snapshot_id'])
    assert transitioned['changes'] == [{'path':'/wan','before':None,'after':empty}]

def test_cpu_counter_changes_do_not_mask_freshness_or_wan_change(tmp_path):
    store=SnapshotStore(tmp_path/'state')
    base={'data':{'cpu':{'cores':[{'core':0,'total_ticks':100,'used_ticks':10}]},'wan':{'link_code':1}},'freshness':'unknown'}
    first=store.save(base,IDENTITY)
    counters={**base,'data':{**base['data'],'cpu':{'cores':[{'core':0,'total_ticks':200,'used_ticks':20}]}}}
    second=store.save(counters,IDENTITY)
    assert not store.diff(first['snapshot_id'],second['snapshot_id'])['changed']
    changed=store.save({**counters,'freshness':'stale','data':{**counters['data'],'wan':{'link_code':2}}},IDENTITY)
    delta=store.diff(second['snapshot_id'],changed['snapshot_id'])
    assert delta['changes'] == [
        {'path':'/data/wan/link_code','before':1,'after':2},
        {'path':'/freshness','before':'unknown','after':'stale'},
    ]

def test_diff_pagination_recovers_all_leaf_changes_in_stable_order(tmp_path):
    store=SnapshotStore(tmp_path/'state')
    old_data={'clients':[{'alias':f'client-{i:016x}','online':False} for i in range(25)],'wan':None,'ram':{'used':3}}
    new_data={'clients':[{'alias':f'client-{i:016x}','online':True} for i in range(24)]+[None],'cpu':None}
    old=store.save(old_data,IDENTITY)['snapshot_id']
    new=store.save(new_data,IDENTITY)['snapshot_id']
    first=store.diff(old,new)
    assert len(first['changes']) == 20
    assert first['total_changes'] > 20 and first['truncated']
    assert first['pagination'] == {'offset':0,'limit':20,'next_offset':20}
    assert first == store.diff(old,new)
    collected=[];offset=0
    while offset is not None:
        page=store.diff(old,new,offset=offset,limit=7)
        assert len(page['changes']) <= 7
        assert page['total_changes'] == first['total_changes']
        collected.extend(page['changes'])
        offset=page['pagination']['next_offset']
    assert len(collected) == first['total_changes']
    assert len({change['path'] for change in collected}) == len(collected)
    assert collected[:20] == first['changes']
    by_path={change['path']:change for change in collected}
    assert by_path['/cpu']['before_present'] is False and by_path['/cpu']['after_present'] is True
    assert by_path['/wan']['before_present'] is True and by_path['/wan']['after_present'] is False
    assert by_path['/ram/used']['before'] == 3 and by_path['/ram/used']['after_present'] is False
    beyond=store.diff(old,new,offset=1000)
    assert beyond['changes'] == [] and beyond['pagination']['next_offset'] is None


@pytest.mark.parametrize('options',[{'offset':-1},{'limit':0},{'limit':21},{'offset':True},{'limit':True}])
def test_diff_invalid_pagination_rejected_without_state_access(tmp_path,options):
    store=SnapshotStore(tmp_path/'absent')
    with pytest.raises(RouterError) as error:store.diff('invalid','invalid',**options)
    assert error.value.code == 'invalid_arguments'
    assert not store.state_dir.exists()


def test_explicit_key_initialization_and_alias_matches_live(tmp_path):
    import hashlib
    import hmac
    from router_agent.snapshots import atomic_write, private_dir, client_alias
    store = SnapshotStore(tmp_path/'state')
    private_dir(store.state_dir)
    existing_key = b'k' * 32
    atomic_write(store.state_dir/'alias.key', existing_key)
    assert store.ensure_key() == existing_key
    mac = 'aa:bb:cc:dd:ee:ff'
    expected = 'client-' + hmac.new(existing_key, b'client:'+mac.upper().encode(), hashlib.sha256).hexdigest()[:16]
    assert store.alias(mac) == client_alias(existing_key, mac) == expected
    assert store.ensure_key() == existing_key


def test_fetch_timestamp_alone_is_not_a_semantic_snapshot_change(tmp_path):
    store = SnapshotStore(tmp_path/'state')
    old = store.save({'fetched_at':'2026-10-13T01:00:00+00:00','data':{'wan':{'link_code':1}},'observed_at':None,'freshness':'unknown'}, IDENTITY)
    new = store.save({'fetched_at':'2026-10-13T01:01:00+00:00','data':{'wan':{'link_code':1}},'observed_at':None,'freshness':'unknown'}, IDENTITY)
    assert old['data']['fetched_at'] != new['data']['fetched_at']
    assert store.diff(old['snapshot_id'],new['snapshot_id'])['changed'] is False
