import asyncio
import json
import pytest
from asusrouter.modules import parental_control as pc
from router_agent.errors import RouterError
from router_agent.parental_policy import (read_policy_snapshot, public_policy, prepare_enable,
    prepare_rule, prepare_restore, client_alias, validate_schedule, PARENTAL_POLICY_KEYS)

KEY = b'x'*32
MACS = ['AA:BB:CC:DD:EE:01','AA:BB:CC:DD:EE:02','AA:BB:CC:DD:EE:03']
SCHEDULE = pc.DEFAULT_PC_TIMEMAP


def raw(count=0):
    data = dict.fromkeys(PARENTAL_POLICY_KEYS, '')
    data.update({pc.KEY_PC_STATE:'0', pc.KEY_PC_BLOCK_ALL:'0'})
    for key, values in [(pc.KEY_PC_MAC,MACS[:count]),
                        (pc.KEY_PC_NAME,[f'private-name-{i}' for i in range(count)]),
                        (pc.KEY_PC_TIMEMAP,[SCHEDULE.replace('<','&#60')]*count),
                        (pc.KEY_PC_TYPE,['1']*count)]:
        data[key] = '&#62'.join(values)
    return data


def run(coro): return asyncio.run(coro)


def test_full_snapshot_private_and_public():
    snap = read_policy_snapshot(raw(3), KEY)
    assert snap.rules_write_recoverable
    assert 'private-name' not in json.dumps(public_policy(snap))
    assert MACS[0] not in repr(snap)
    copy = snap.raw
    copy[pc.KEY_PC_MAC] = ''
    assert len(snap.rules) == 3


@pytest.mark.parametrize('key',list(pc.PC_RULE_MAP))
def test_reject_zip_truncation(key):
    data = raw(2)
    data[key] = data[key].split('&#62')[0]
    with pytest.raises(RouterError): read_policy_snapshot(data, KEY)


def test_duplicate_and_unknown_numeric_rejected():
    data=raw(2); data[pc.KEY_PC_MAC]='&#62'.join([MACS[0]]*2)
    with pytest.raises(RouterError): read_policy_snapshot(data, KEY)
    data=raw(1); data[pc.KEY_PC_TYPE]='8'
    with pytest.raises(RouterError): read_policy_snapshot(data, KEY)


@pytest.mark.parametrize('key,value',[(pc.KEY_PC_NAME,''),(pc.KEY_PC_NAME,' name '),
    (pc.KEY_PC_TIMEMAP,''),(pc.KEY_PC_TYPE,'')])
def test_native_loss_rejects_rule_only(key,value):
    data=raw(1); data[key]=value
    snap=read_policy_snapshot(data,KEY)
    assert not snap.rules_write_recoverable
    change=run(prepare_enable(snap,True))
    assert change.arguments == {pc.KEY_PC_STATE:1}
    assert all(change.after.raw[k]==data[k] for k in pc.PC_RULE_MAP)
    with pytest.raises(RouterError,match='recovered'):
        run(prepare_rule(snap,client_alias(KEY,MACS[0]),'block'))


def test_orphan_schedule_enable_preserved_rule_rejected():
    data=raw(); data[pc.KEY_PC_TIMEMAP]=SCHEDULE
    snap=read_policy_snapshot(data,KEY)
    assert len(snap.rules)==0 and not snap.rules_write_recoverable
    assert run(prepare_enable(snap,True)).after.raw[pc.KEY_PC_TIMEMAP]==SCHEDULE
    with pytest.raises(RouterError):
        run(prepare_rule(snap,client_alias(KEY,MACS[0]),'time',{MACS[0]:{}},SCHEDULE))


def test_add_update_remove_and_exact_ordered_restore():
    before=read_policy_snapshot(raw(3),KEY)
    alias=client_alias(KEY,MACS[1])
    removed=run(prepare_rule(before,alias,'remove'))
    assert list(removed.after.rules)==[MACS[0],MACS[2]]
    restored=run(prepare_restore(removed.after,before))
    assert restored.after.raw == before.raw
    assert list(restored.after.rules)==MACS
    updated=run(prepare_rule(before,alias,'block'))
    assert list(updated.after.rules)==MACS
    assert updated.after.rules[MACS[1]].name==before.rules[MACS[1]].name
    assert updated.after.raw[pc.KEY_PC_TIMEMAP]==before.raw[pc.KEY_PC_TIMEMAP]


def test_add_explicit_schedule_approved_literal():
    before=read_policy_snapshot(raw(),KEY)
    alias=client_alias(KEY,MACS[0])
    with pytest.raises(RouterError): run(prepare_rule(before,alias,'time',{MACS[0]:{}}))
    prepared=run(prepare_rule(before,alias,'time',{MACS[0]:{}},SCHEDULE))
    assert prepared.public_after['intent']['schedule']==SCHEDULE
    assert prepared.after.rules[MACS[0]].name==alias
    assert run(prepare_restore(prepared.after,before)).after.raw==before.raw
    with pytest.raises(RouterError): run(prepare_rule(before,MACS[0],'time',{MACS[0]:{}},SCHEDULE))


def test_unknown_existing_type_preserved_by_full_restore():
    data=raw(1); data[pc.KEY_PC_TYPE]='-999'
    before=read_policy_snapshot(data,KEY)
    assert before.rules_write_recoverable
    updated=run(prepare_rule(before,client_alias(KEY,MACS[0]),'block'))
    assert run(prepare_restore(updated.after,before)).after.raw==data


def test_noop_and_flag_drift_restore_rejection():
    before=read_policy_snapshot(raw(1),KEY)
    assert run(prepare_enable(before,False)).noop
    assert run(prepare_rule(before,client_alias(KEY,MACS[0]),'time')).noop
    changed=run(prepare_enable(before,True)).after
    with pytest.raises(RouterError): run(prepare_restore(changed,before))


@pytest.mark.parametrize('value',[SCHEDULE,'M17F00002400','W03E21000700'])
def test_native_schedule_literals(value): assert validate_schedule(value)==value


@pytest.mark.parametrize('value',['','yes','W03E25000700','W03E23600700','W08000002400',
    'W03E21000700<M04122000800','W03E21000700>bad','W03E21000700&#60W04122000800'])
def test_invalid_schedule_literals(value):
    with pytest.raises(RouterError): validate_schedule(value)


def test_existing_unknown_schedule_preserved_not_interpreted():
    data=raw(1); data[pc.KEY_PC_TIMEMAP]='opaque-existing-native-value'
    before=read_policy_snapshot(data,KEY)
    assert before.rules_write_recoverable
    updated=run(prepare_rule(before,client_alias(KEY,MACS[0]),'block'))
    assert updated.after.raw[pc.KEY_PC_TIMEMAP]==data[pc.KEY_PC_TIMEMAP]
    assert run(prepare_restore(updated.after,before)).after.raw==data


def test_alternate_read_encoding_no_false_exact_recovery():
    data=raw(1); data[pc.KEY_PC_TIMEMAP]=SCHEDULE
    before=read_policy_snapshot(data,KEY)
    assert not before.rules_write_recoverable
    assert run(prepare_enable(before,True)).after.raw[pc.KEY_PC_TIMEMAP]==SCHEDULE


def test_no_private_values_in_fixed_failures():
    data=raw(1); data[pc.KEY_PC_MAC]='private-invalid-identifier'
    with pytest.raises(RouterError) as failure: read_policy_snapshot(data,KEY)
    assert 'private-invalid' not in str(failure.value)


@pytest.mark.parametrize('blocked',[False,True])
def test_block_all_native_single_flag_and_faithful_inverse(blocked):
    from router_agent.parental_policy import prepare_block_all
    data=raw(); data[pc.KEY_PC_TIMEMAP]='unused-private-native-schedule'
    before=read_policy_snapshot(data,KEY)
    change=run(prepare_block_all(before,blocked))
    assert change.kind=='block_all'
    assert change.arguments=={pc.KEY_PC_BLOCK_ALL:int(blocked)}
    assert change.public_after['intent']['impact']=='all_clients'
    assert change.public_after['intent']['service']=='restart_firewall'
    assert all(change.after.raw[k]==data[k] for k in PARENTAL_POLICY_KEYS if k!=pc.KEY_PC_BLOCK_ALL)
    assert run(prepare_block_all(change.after,before.block_all)).after.raw==data
