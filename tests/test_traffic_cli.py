import json
import pytest
from router_agent.cli import main
from router_agent.errors import RouterError

NODE='node-0000000000000001'
PEER='node-0000000000000002'


@pytest.mark.parametrize('arguments,expected',[
    (['ethernet','--node',NODE],('ethernet',NODE,{'peer_alias':None,'band':None,'backhaul':False})),
    (['ethernet','--node',NODE,'--backhaul'],('ethernet',NODE,{'peer_alias':None,'band':None,'backhaul':True})),
    (['wifi','--node',NODE,'--band','5ghz'],('wifi',NODE,{'peer_alias':None,'band':'5ghz','backhaul':False})),
    (['backhaul','--node',NODE,'--peer',PEER],('backhaul',NODE,{'peer_alias':PEER,'band':None,'backhaul':False})),
])
def test_typed_traffic_dispatch_preserves_every_selected_field(arguments,expected,monkeypatch,capsys):
    calls=[]
    value={'schema_version':1,'source':'native','observed_at':None,'freshness':'unknown','data':{'identity':{'model':'fixture'},'traffic':{'kind':expected[0],'node_alias':NODE,'peer_alias':expected[2]['peer_alias'],'band':expected[2]['band'],'backhaul':expected[2]['backhaul'],'rx_bps':None,'tx_bps':4.0,'gaps':['native_rates_are_not_throughput_or_egress_verification']}},'sources':{'aimesh':{'freshness':'unknown','observed_at':None},'traffic':{'freshness':'unknown','observed_at':None}},'capability_gaps':[{'group':'traffic','reason':'observation_window_and_source_time_unavailable'}]}
    async def collect(kind,node_alias,**kwargs):calls.append((kind,node_alias,kwargs));return value
    monkeypatch.setattr('router_agent.cli._collect_traffic',collect)
    assert main(['traffic',*arguments])==0
    assert calls==[expected]
    assert json.loads(capsys.readouterr().out)==value


@pytest.mark.parametrize('arguments',[
    ['ethernet','--node','AA:BB:CC:DD:EE:FF'],['ethernet','--node','client-0000000000000001'],
    ['ethernet','--node','node-ABCDEF0123456789'],['ethernet','--node','node-123'],
    ['ethernet','--node',NODE,'--peer',PEER],['ethernet','--node',NODE,'--band','5ghz'],
    ['wifi','--node',NODE],['wifi','--node',NODE,'--band','5ghz','--backhaul'],
    ['wifi','--node',NODE,'--band','5ghz','--peer',PEER],['wifi','--node',NODE,'--band','arbitrary'],
    ['backhaul','--node',NODE],['backhaul','--node',NODE,'--peer',NODE],
    ['backhaul','--node',NODE,'--peer',PEER,'--band','5ghz'],
    ['backhaul','--node',NODE,'--peer',PEER,'--backhaul'],
])
def test_bad_aliases_and_option_combinations_fail_before_credentials(arguments,monkeypatch,capsys):
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:pytest.fail('must validate before keyring'))
    async def collect(*args,**kwargs):pytest.fail('must validate before collection')
    monkeypatch.setattr('router_agent.cli._collect_traffic',collect)
    assert main(['traffic',*arguments])==2
    value=json.loads(capsys.readouterr().out)
    assert value['error']['code']=='invalid_arguments'
    assert 'AA:BB:CC:DD:EE:FF' not in str(value)


def test_fresh_alias_resolution_failure_stays_error_without_partial_success(monkeypatch,capsys):
    async def collect(*args,**kwargs):raise RouterError('traffic_target_unavailable','The requested native traffic alias or band is unavailable in the fresh node inventory.')
    monkeypatch.setattr('router_agent.cli._collect_traffic',collect)
    assert main(['traffic','wifi','--node',NODE,'--band','6ghz'])==1
    assert set(json.loads(capsys.readouterr().out))=={'error'}

def test_traffic_private_plumbing_uses_keyring_config_and_cross_process_lock(tmp_path,monkeypatch,capsys):
    from router_agent.auth import AuthConfig
    from router_agent.snapshots import state_lock,private_read
    from router_agent import transport
    directory=tmp_path/'state'
    monkeypatch.setattr('router_agent.snapshots.default_state_dir',lambda:directory)
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:(AuthConfig('https://router.invalid','synthetic-admin'),'synthetic-private-password'))
    calls=[]
    async def native(config,password,kind,node_alias,*,fingerprint_key,peer_alias=None,band=None,backhaul=False):
        assert config.hostname=='router.invalid' and config.use_ssl
        assert password=='synthetic-private-password'
        assert fingerprint_key==private_read(directory/'alias.key') and len(fingerprint_key)==32
        with pytest.raises(RouterError) as busy:
            with state_lock(directory):pass
        assert busy.value.code=='state_busy'
        calls.append((kind,node_alias,peer_alias,band,backhaul))
        return {'schema_version':1,'source':'native','freshness':'unknown','observed_at':None,'data':{'traffic':{'node_alias':node_alias,'rx_bps':None,'tx_bps':1.0}},'capability_gaps':[]}
    monkeypatch.setattr(transport,'collect_traffic',native)
    assert main(['traffic','ethernet','--node',NODE,'--backhaul'])==0
    assert calls==[('ethernet',NODE,None,None,True)]
    out=capsys.readouterr()
    assert json.loads(out.out)['data']['traffic']['rx_bps'] is None
    assert 'synthetic-private-password' not in out.out+out.err
    assert directory.stat().st_mode&0o777==0o700
    assert (directory/'alias.key').stat().st_mode&0o777==0o600
