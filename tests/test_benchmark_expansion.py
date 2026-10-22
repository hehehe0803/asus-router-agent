from copy import deepcopy
import json
from pathlib import Path

import pytest
import tiktoken

from router_agent.benchmark_expansion import CORPUS, INSTRUCTIONS, build_corpus, run, validate
from router_agent.benchmark_batch import measure


def test_expansion_actual_cli_preserves_private_aliases_and_all_selected_evidence(monkeypatch):
    import router_agent.cli as cli
    monkeypatch.setattr(cli,'get_credentials',lambda *a,**k:(_ for _ in ()).throw(AssertionError('Real credentials forbidden')))
    corpus=build_corpus()
    serialized=json.dumps(corpus)
    for secret in ('private-name-sentinel','private-login-sentinel','private-password-sentinel','private-rule-sentinel','private-address-sentinel','private-key-sentinel','vpnc_clientlist=','wgs_priv'):
        assert secret not in serialized
    for task in corpus['tasks']:
        for steps in task['transcripts'].values():validate(task,steps)
    protected=corpus['tasks'][0]['required_answer']
    assert protected['data']['openvpn_client']['profiles'][0]['enabled'] is False
    assert protected['data']['vpnc_clientlist']['profiles'][1]['status_code'] is None
    assert protected['metadata']['fetched_at']==corpus['fixture_fetched_at']
    assert protected['sources']['openvpn_client']['observed_at'] is None
    assert 'profile_credentials_are_application_private' in protected['data']['openvpn_client']['gaps']
    assert 'Agents issue no grants or confirmations' in INSTRUCTIONS


@pytest.mark.parametrize('damage',['null_to_false','remove_gap','receipt_time','source_age','privacy'])
def test_lossy_protected_output_rejected(damage):
    task=build_corpus()['tasks'][0]
    steps=deepcopy(task['transcripts']['grouped_read'])
    payload=json.loads(steps[0]['stdout'])
    if damage=='null_to_false':payload['data']['vpnc_clientlist']['profiles'][1]['status_code']=False
    elif damage=='remove_gap':payload['capability_gaps']=[]
    elif damage=='receipt_time':payload['fetched_at']=None
    elif damage=='source_age':payload['sources']['openvpn_client']['observed_at']='invented'
    else:payload['data']['openvpn_client']['gaps'].remove('profile_credentials_are_application_private')
    steps[0]['stdout']=json.dumps(payload)
    with pytest.raises(ValueError):validate(task,steps)


def test_backup_block_inverse_followup_counted_without_claiming_restoration():
    corpus=build_corpus()
    for task in corpus['tasks'][2:]:
        steps=task['transcripts']['grouped_read']
        assert not task['savings_eligible']
        assert [step['exit_code'] for step in steps]==[0,0,0,1,1,1]
        plan=json.loads(steps[0]['stdout'])['data']['plan']
        assert plan['backup_required'] is True
        assert plan['expires_at']-plan['created_at']==300
        request=json.loads(steps[2]['stdout'])['data']
        assert request['status']=='not_authorized'
        assert [json.loads(step['stdout'])['error']['code'] for step in steps[3:]]==['backup_required','not_applied','not_applied']
        lost=deepcopy(steps);lost.pop()
        with pytest.raises(ValueError):validate(task,lost)
        score=measure(steps,corpus['discovery'],corpus['instructions'],tiktoken.get_encoding('o200k_base'))
        assert score['response_calls']==6 and score['discovery_calls']==6
        assert score['tokens']==sum(score['component_tokens'].values())
        assert score['component_tokens']['stdout']>0 and score['component_tokens']['task_instructions']>0


def test_frozen_expansion_corpus_and_report_replay():
    result=run(CORPUS)
    assert result==json.loads(CORPUS.with_name('results-expansion-v2.json').read_text())
    assert result['selected_on_training']=='grouped_read'
    assert result['heldout_gate']=='passed'
    assert result['errors_counted_but_excluded_from_savings'] is True
    assert all(row['saved_tokens'] is None for row in result['tasks'] if not row['savings_eligible'])
    assert 'proxy only' in result['tokenizer']['claim']


def test_modified_corpus_rejected(tmp_path):
    corpus=build_corpus();corpus['instructions']='Missing approval and privacy facts'
    path=tmp_path/'changed.json';path.write_text(json.dumps(corpus))
    with pytest.raises(ValueError,match='differs from frozen'):run(path)
