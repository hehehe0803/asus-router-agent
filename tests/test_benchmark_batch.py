import copy
import json
from pathlib import Path

import pytest
import tiktoken

from router_agent.benchmark_batch import answer, capture, execute_task, freeze, measure, run, validate, validate_failure

CORPUS = Path(__file__).resolve().parents[1] / 'benchmarks/corpus-batch-v8.json'


def test_actual_grouped_cli_preserves_all_selected_facts_sources_gaps_and_unknowns():
    corpus = freeze()
    for task in corpus['tasks']:
        for steps in task['transcripts'].values():
            validate(task, steps)
        assert answer(task['groups'], task['transcripts']['separate_reads']) == answer(task['groups'], task['transcripts']['grouped_read'])
    network = corpus['tasks'][1]['required_answer']['data']['network']
    assert network['interfaces'][0]['tx_bytes'] is None
    assert corpus['tasks'][0]['required_answer']['data']['wlan']['slots'][1]['enabled'] is None


@pytest.mark.parametrize('damage', ['unknown_false', 'remove_gap', 'remove_source', 'change_identity'])
def test_required_fact_validation_rejects_optimizations_that_lose_evidence(damage):
    task = freeze()['tasks'][0]
    damaged = copy.deepcopy(task['transcripts']['grouped_read'])
    value = json.loads(damaged[0]['stdout'])
    if damage == 'unknown_false':
        value['data']['wlan']['slots'][1]['enabled'] = False
    elif damage == 'remove_gap':
        value['capability_gaps'] = []
    elif damage == 'remove_source':
        del value['sources']['guest']
    else:
        value['data']['identity']['device_fingerprint'] = 'different'
    damaged[0]['stdout'] = json.dumps(value)
    with pytest.raises(ValueError):
        validate(task, damaged)


def test_failed_group_returns_only_error_and_is_not_scored_as_equivalent():
    case = freeze()['failure_cases'][0]
    validate_failure(case)
    separate = case['transcripts']['separate_reads']
    grouped = case['transcripts']['grouped_read']
    assert separate[0]['exit_code'] == 0 and separate[-1]['exit_code'] == 1
    assert grouped[0]['exit_code'] == 1
    assert set(json.loads(grouped[0]['stdout'])) == {'error'}
    assert case['equivalence_claim'] is False
    with pytest.raises(ValueError):
        answer(case['groups'], grouped)


def test_partial_failure_or_false_success_breaks_failure_gate():
    case = copy.deepcopy(freeze()['failure_cases'][0])
    value = json.loads(case['transcripts']['grouped_read'][0]['stdout'])
    value['data'] = {'wlan': {'enabled': True}}
    case['transcripts']['grouped_read'][0]['stdout'] = json.dumps(value)
    with pytest.raises(ValueError):
        validate_failure(case)


def test_help_commands_outputs_errors_and_followups_counted_separately():
    corpus = freeze()
    task = corpus['tasks'][1]
    steps = task['transcripts']['separate_reads']
    encoding = tiktoken.get_encoding('o200k_base')
    measured = measure(steps, corpus['discovery'], task['query'], encoding)
    assert measured['response_calls'] == 3 and measured['discovery_calls'] == 2
    assert measured['component_tokens']['commands'] == sum(len(encoding.encode(step['command'])) for step in corpus['discovery'] + steps)
    assert measured['tokens'] == sum(measured['component_tokens'].values())
    assert measured['bytes'] == sum(measured['component_bytes'].values())
    error = corpus['failure_cases'][0]['transcripts']['grouped_read']
    error_score = measure(error, corpus['discovery'], 'Observe failure.\n', encoding)
    assert error_score['component_tokens']['stdout'] >= len(encoding.encode(error[0]['stdout'])) > 0
    assert [step['command'] for step in corpus['discovery']] == ['router-agent --help\n', 'router-agent get --help\n']


def test_corpus_and_current_cli_replay_are_reproducible():
    result = run(CORPUS)
    assert result == run(CORPUS)
    assert result == json.loads(CORPUS.with_name('results-batch-v8.json').read_text())
    assert result['selected_on_training'] == 'grouped_read'
    assert result['heldout_gate'] == 'passed'
    assert all(task['required_answer_valid'] for task in result['tasks'])
    assert result['failure_cases'][0]['equivalence_claim'] is False
    assert 'not simultaneous' in result['sampling_limit']


def test_modified_frozen_fixture_or_cli_transcript_is_rejected(tmp_path):
    corpus = json.loads(CORPUS.read_text())
    corpus['tasks'][0]['transcripts']['grouped_read'][0]['stdout'] = '{}\n'
    changed = tmp_path / 'changed.json'
    changed.write_text(json.dumps(corpus))
    with pytest.raises(ValueError, match='differs from frozen'):
        run(changed)


def test_current_normalizers_preserve_independent_synthetic_wire_facts():
    from router_agent.benchmark_batch import fixture
    data = fixture(['wlan', 'guest', 'network', 'wan', 'cpu'])['data']
    assert data['wlan']['slots'][0]['channel_code'] == 36
    assert data['wlan']['slots'][0]['bandwidth_code'] == 1
    assert data['wlan']['slots'][1]['enabled'] is None
    assert data['wlan']['slots'][1]['bandwidth_code'] is None
    assert all(slot['expire_seconds'] == 600 and slot['expire_remaining_seconds'] is None for slot in data['guest']['slots'])
    assert all(slot['lan_access_enabled'] is False and slot['ap_isolation_code'] == 0 for slot in data['guest']['slots'])
    assert data['wan']['slots'][0]['primary'] is True
    assert data['wan']['slots'][1]['primary'] is False
    assert data['wan']['slots'][0]['sbstate_code'] is None
    assert data['network']['interfaces'][0]['rx_bytes'] == 123456
    assert data['network']['interfaces'][0]['tx_bytes'] is None
    assert data['network']['interfaces'][1]['tx_bytes'] == 654321
    assert data['cpu']['cores'][1]['total_ticks'] == 900

@pytest.mark.parametrize("archive_version",[1,2,3,4])
def test_registered_historical_transcripts_preserve_dated_facts_without_current_parity(tmp_path,archive_version):
    archived=CORPUS.with_name(f'corpus-batch-v{archive_version}.json')
    with pytest.raises(ValueError,match='differs from frozen'):
        run(archived)
    result=run(archived,historical_help=True,historical_schema=True)
    assert result == json.loads(archived.with_name(f'results-batch-v{archive_version}.json').read_text())
    corrupted=json.loads(archived.read_text())
    corrupted['tasks'][0]['transcripts']['grouped_read'][0]['stdout']='{}\n'
    path=tmp_path/'corrupted.json';path.write_text(json.dumps(corrupted))
    with pytest.raises(ValueError,match='differs from frozen'):
        run(path,historical_help=True,historical_schema=True)


def test_freeze_cannot_hide_new_help_with_historical_flag():
    from router_agent.benchmark_batch import main
    with pytest.raises(SystemExit) as error:main(['--freeze','--historical-help'])
    assert error.value.code == 2

def test_named_group_help_hillclimb_preserves_same_tasks_and_improves_heldout():
    baseline_path=CORPUS.with_name('corpus-batch-v4-help-baseline.json')
    baseline=json.loads(baseline_path.read_text())
    candidate_path=CORPUS.with_name('corpus-batch-v4.json')
    current=json.loads(candidate_path.read_text())
    assert baseline['tasks']==current['tasks']
    assert baseline['failure_cases']==current['failure_cases']
    assert baseline['discovery'][0]==current['discovery'][0]  # Same traffic-aware top-level help.
    old=run(baseline_path,historical_help=True,historical_schema=True)
    assert old==json.loads(baseline_path.with_name('results-batch-v4-help-baseline.json').read_text())
    new=run(candidate_path,historical_help=True,historical_schema=True)
    assert new['heldout_gate']=='passed'
    for a,b in zip(old['tasks'],new['tasks'],strict=True):
        for candidate in a['candidates']:
            assert a['candidates'][candidate]['tokens']-b['candidates'][candidate]['tokens']==126
            assert a['candidates'][candidate]['component_tokens']['stdout']-b['candidates'][candidate]['component_tokens']['stdout']==126
