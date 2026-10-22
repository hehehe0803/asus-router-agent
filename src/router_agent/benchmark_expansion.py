"""Frozen expansion CLI tasks; synthetic evidence and tokenizer proxy only."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stdout, redirect_stderr
from copy import deepcopy
import hashlib
import io
import json
from importlib.metadata import version
from pathlib import Path
import tempfile
from unittest.mock import patch

from . import cli
from .benchmark_batch import answer, measure
from .benchmark_contract import FETCHED_AT

CORPUS = Path(__file__).resolve().parents[2] / 'benchmarks/corpus-expansion-v2.json'
KEY = b'e' * 32
IDENTITY = {'model':'RT-AX86U', 'firmware':'3.0.0.4.388_24436-ge7c0b5e', 'device_fingerprint':'synthetic-expansion-device'}
INSTRUCTIONS = ('Retain every selected fact, false/null distinction, identity, fetched_at receipt time, unknown source observation time, privacy statement, capability gap, error and follow-up. '
                'Native settings/status do not verify VPN egress, effective exposure or physical WLAN behavior. Plans are previews, grants and confirmation remain separate, plans expire after 300 seconds. '
                'Every apply, inverse and no-op needs its own administrator exact-plan grant and human personally typing apply HASH. Agents issue no grants or confirmations. '
                'A missing verified native backup/restore provider blocks effective exposure/disruptive changes; a status snapshot is not a backup. '
                'Do not retry an uncertain send. Blocked apply means no restoration or successful inverse is established.\n')


def capture(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try: code = cli.main(argv)
        except SystemExit as error: code = error.code
    return {'command':'router-agent ' + ' '.join(argv) + '\n', 'stdout':out.getvalue(), 'stderr':err.getvalue(), 'exit_code':code}


def selected(group):
    from .protected_vpn import parse_snapshot, select_profiles
    from .dsl_reads import normalize_dsl
    from .openvpn_reads import normalize_openvpn
    from .flags_reads import observe_flags
    if group in {'openvpn_client','vpnc_clientlist'}:
        # Transient synthetic credentials are intentionally absent from corpus.
        private = {'vpnc_clientlist':'private-name-sentinel>OpenVPN>1>private-login-sentinel>private-password-sentinel>0>1<private-name-2>WireGuard>2>unused>unused>1>2', 'get_vpnc_status':'2>0>1'}
        snapshot = parse_snapshot(private,KEY,IDENTITY)
        value = select_profiles(snapshot, 'openvpn' if group=='openvpn_client' else None)
        value['gaps'] = ['selected_settings_and_native_status_do_not_prove_tunnel_or_egress','profile_credentials_are_application_private','source_observation_time_unavailable']
        return value
    if group == 'dsl':return normalize_dsl({'dsllog_dataratedown':'0 kbps','dsllog_datarateup':None})
    if group == 'openvpn':return normalize_openvpn({'vpn':{'client1_state':'0','client1_errno':None,'server1_state':None}},flavor='stock')
    if group == 'flags':return observe_flags({'sys':{'uptimeStr':'Thu, 15 Oct 2026 00:00:00 +0000(100 secs since boot)'}},IDENTITY,wall_time=100,monotonic_time=100,host_boot_id='synthetic-host')
    raise AssertionError('Unexpected synthetic group')


def read_fixture(groups):
    data = {'identity':deepcopy(IDENTITY)}
    gaps=[]
    for group in groups:
        if group=='identity':continue
        data[group]=selected(group)
        gaps.extend({'group':group,'reason':gap} for gap in data[group].get('gaps',[]))
    source={'fetched_at':FETCHED_AT,'observed_at':None,'freshness':'unknown','reason':'source_observation_time_unavailable'}
    return {'schema_version':1,'source':'native','fetched_at':FETCHED_AT,'observed_at':None,'freshness':'unknown',
            'data':data,'sources':{group:deepcopy(source) for group in data},'capability_gaps':gaps,'warnings':['synthetic_fixture_not_live_evidence']}


def read_steps(groups, grouped):
    async def collect(actual,probe=False,**kwargs):
        assert not probe
        return read_fixture(actual)
    with patch.object(cli,'_collect',collect):
        return [capture(['get',*groups])] if grouped else [capture(['get',group]) for group in groups]


def lifecycle_steps(operation):
    """Actual CLI/engine/backend, in-memory vault, intentionally blocked backup.

    A synthetic scope replaces human/grant machinery only to exercise backup
    refusal. No writer, network, real vault or real approval is reachable.
    """
    from . import approval, expansion_backend
    from .auth import AuthConfig
    from .catalog import load_catalog, canonical
    from .finite_controls import required_keys
    from .expansion_backend import ExpansionBackend
    from .operations import ApprovedScope, MemoryPlanStore, OperationEngine
    intent={'enabled':True}
    raw=dict.fromkeys(required_keys(operation,intent),'')
    flag={'state.port_forwarding':'vts_enable_x','state.wireguard_server':'wgs_enable'}[operation]
    raw[flag]='0'
    if operation=='state.port_forwarding':raw['vts_rulelist']='private-rule-sentinel>private-address-sentinel>unknown'
    else:
        raw['wgs_priv']='private-key-sentinel'
        raw['wgs_unit']='1'
    original=deepcopy(raw)
    class Vault:
        def __init__(self):self.records={}
        def put(self,key,value):self.records[key]=deepcopy(value)
        def get(self,key):return deepcopy(self.records[key])
    vault=Vault()
    async def reader(*args,**kwargs):return {'identity':deepcopy(IDENTITY),'raw':deepcopy(raw)}
    async def writer(*args,**kwargs):raise AssertionError('Backup-blocked benchmark must never invoke a writer')
    backend=ExpansionBackend(None,None,operation=operation,fingerprint_key=KEY,vault=vault,reader=reader,writer=writer)
    store=MemoryPlanStore()
    engine=OperationEngine(load_catalog(),backend,store,clock=lambda:100.0)
    validate=approval.validate_local_plan
    def scope(plan,window_id=None):
        return ApprovedScope(plan.id,plan.data['device'],operation,canonical(plan.data['after']),400.0,'synthetic-not-a-grant')
    with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
        directory=Path(temporary);directory.chmod(0o700)
        (directory/'alias.key').write_bytes(KEY);(directory/'alias.key').chmod(0o600)
        for item in [patch.object(cli,'_engine',lambda *args:(directory,engine)),patch.object(cli,'_plan_store',lambda:(directory,store)),
                     patch.object(cli,'load_config',lambda:AuthConfig('https://router.invalid','synthetic')),
                     patch.object(expansion_backend,'SecretServiceContexts',lambda:vault),
                     patch.object(approval,'validate_local_plan',lambda plan,**kwargs:validate(plan,clock=lambda:100.0)),
                     patch.object(approval,'confirm_plan',scope)]:stack.enter_context(item)
        name={'state.port_forwarding':'forwarding','state.wireguard_server':'wireguard-server'}[operation]
        steps=[capture(['plan',name,'--enabled','on'])]
        if steps[0]['exit_code']:raise ValueError(steps[0]['stdout'])
        plan=json.loads(steps[0]['stdout'])['data']['plan']
        steps += [capture([command,plan['hash']]) for command in ('plan-show','approval-request','apply','verify','rollback')]
        if [step['exit_code'] for step in steps] != [0,0,0,1,1,1]:raise ValueError('Unexpected blocked lifecycle exit codes')
        codes=[json.loads(step['stdout'])['error']['code'] for step in steps[3:]]
        if codes != ['backup_required','not_applied','not_applied']:raise ValueError('Backup/inverse failure semantics changed')
        if raw!=original:raise ValueError('Blocked lifecycle changed synthetic configuration')
        return steps


def build_corpus():
    """Task splits/required answers fixed before tokenizer is imported."""
    tasks=[]
    for name,split,groups in [('protected_profiles','train',['openvpn_client','vpnc_clientlist']),('passive_observations','heldout',['dsl','flags','openvpn'])]:
        separate=read_steps(groups,False);grouped=read_steps(groups,True)
        required=answer(groups,separate)
        if answer(groups,grouped)!=required:raise ValueError('Grouped selected evidence differs')
        tasks.append({'id':name,'split':split,'kind':'reads','groups':groups,'required_answer':required,'savings_eligible':True,
                      'transcripts':{'separate_reads':separate,'grouped_read':grouped}})
    for operation,split in [('state.port_forwarding','train'),('state.wireguard_server','heldout')]:
        steps=lifecycle_steps(operation)
        tasks.append({'id':operation+'_backup_inverse_followup','split':split,'kind':'blocked_lifecycle','savings_eligible':False,
                      'required_answer':deepcopy(steps),'transcripts':{'separate_reads':deepcopy(steps),'grouped_read':deepcopy(steps)}})
    return {'schema_version':2,'fixture_fetched_at':FETCHED_AT,'instructions':INSTRUCTIONS,
            'provenance':'Actual CLI parser/output and normalizers with injected synthetic collectors; actual operation engine and ExpansionBackend with in-memory vault and backup refusal. No router, keyring, real authority or writes.',
            'split_policy':'Fixed protected read/forwarding training and passive read/WireGuard held-out tasks before scoring; held-out never selects candidate.',
            'sampling_limit':'Independent sequential groups are not simultaneous; synthetic fixed readings do not establish live consistency or safety.',
            'discovery':[capture(['--help']),capture(['get','--help']),capture(['plan','--help']),capture(['capabilities','--help']),capture(['rollback','--help']),capture(['apply','--help'])],
            'tasks':tasks}


def validate(task,steps):
    actual=answer(task['groups'],steps) if task['kind']=='reads' else steps
    if json.dumps(actual,sort_keys=True)!=json.dumps(task['required_answer'],sort_keys=True):
        raise ValueError('Required facts, privacy, approval, gaps or error follow-ups changed')


def run(path=CORPUS, historical_transcript=False):
    import tiktoken
    from .benchmark_contract import validate_historical_transcript
    raw=Path(path).read_bytes();corpus=json.loads(raw)
    if historical_transcript:
        validate_historical_transcript(raw)
    elif build_corpus()!=corpus:raise ValueError('Current CLI differs from frozen expansion corpus')
    encoding=tiktoken.get_encoding('o200k_base');rows=[]
    for task in corpus['tasks']:
        scores={}
        for name,steps in task['transcripts'].items():
            validate(task,steps)
            scores[name]=measure(steps,corpus['discovery'],corpus['instructions'],encoding)
        rows.append({'task':task['id'],'split':task['split'],'required_answer_valid':True,'savings_eligible':task['savings_eligible'],'candidates':scores,
                     'saved_tokens':scores['separate_reads']['tokens']-scores['grouped_read']['tokens'] if task['savings_eligible'] else None})
    train=next(row for row in rows if row['split']=='train' and row['savings_eligible'])
    selected='grouped_read' if train['saved_tokens']>0 else 'separate_reads'
    heldout=next(row for row in rows if row['split']=='heldout' and row['savings_eligible'])
    gate='passed' if selected=='separate_reads' or heldout['saved_tokens']>=0 else 'rejected_token_regression'
    return {'schema_version':corpus['schema_version'],'corpus_sha256':hashlib.sha256(raw).hexdigest(),
            'tokenizer':{'package':'tiktoken','version':version('tiktoken'),'encoding':'o200k_base','claim':'proxy only; not Fable/model-native tokens, billing or browser savings'},
            'selected_on_training':selected,'heldout_gate':gate,'retained':selected if gate=='passed' else 'separate_reads',
            'errors_counted_but_excluded_from_savings':True,'tasks':rows}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--freeze',action='store_true');parser.add_argument('--corpus',type=Path,default=CORPUS)
    args=parser.parse_args(argv)
    if args.freeze:
        if args.corpus.exists():raise ValueError('Frozen corpus already exists; use a new versioned path')
        args.corpus.write_text(json.dumps(build_corpus(),indent=2)+'\n')
    else:print(json.dumps(run(args.corpus),indent=2))


if __name__=='__main__':main()
