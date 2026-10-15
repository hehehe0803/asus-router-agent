"""Remaining-task proxy measurements must preserve evidence and authority text."""
import copy
import json
from pathlib import Path

import pytest

from router_agent import benchmark_validation as validation
from router_agent.benchmark_contract import FETCHED_AT

BENCHMARKS = Path(__file__).resolve().parents[1] / 'benchmarks'


@pytest.fixture(scope='module')
def corpus():
    return json.loads(validation.CORPUS.read_text())


def task(corpus, name):
    return next(item for item in corpus['tasks'] if item['id'] == name)


def test_frozen_corpus_and_report_replay_without_credentials_or_live_state(corpus, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Benchmark must never access credentials or the user state')
    monkeypatch.setattr(validation.cli, 'get_credentials', forbidden)
    monkeypatch.setattr(validation.cli, 'load_config', forbidden)
    monkeypatch.setattr('router_agent.snapshots.default_state_dir', forbidden)
    monkeypatch.setattr('router_agent.approval_window._read_grant', forbidden)
    assert corpus == validation.build_corpus()
    emitted = (json.dumps(validation.run(), indent=2) + '\n').encode()
    assert emitted == (BENCHMARKS / 'results-validation-v2.json').read_bytes()


def test_capability_traversal_reconstructs_all_rows_and_metadata(corpus):
    for name, row_field, expected_count in [('discovery_train', 'capabilities', 54), ('discovery_heldout', 'pages', 8)]:
        case = task(corpus, name)
        for candidate, limit in zip(validation.CANDIDATES, (5, 20), strict=True):
            steps, answer = validation.capability_pages(case['selector'], limit)
            assert steps == case['transcripts'][candidate]
            assert answer == case['required_answer']
            assert len(answer[row_field]) == expected_count
            assert answer['metadata']['observed_at'] is None
            assert answer['metadata']['capability_gaps']
            assert json.loads(steps[-1]['stdout'])['data']['pagination']['next_offset'] is None


def test_normalized_rates_empty_result_and_failure_preserve_uncertainty(corpus):
    traffic = task(corpus, 'traffic_ethernet')['required_answer'][0]['stdout']
    rates = traffic['data']['traffic']
    assert rates['rx_bps'] == 0.0 and rates['phy_rx_bps'] == 0.0
    assert rates['tx_bps'] == 12800.0 and rates['phy_tx_bps'] is None
    assert rates['backhaul'] is False
    assert traffic['fetched_at'] == FETCHED_AT
    assert all(source['fetched_at'] == FETCHED_AT and source['observed_at'] is None and source['freshness'] == 'unknown' for source in traffic['sources'].values())
    empty = task(corpus, 'empty_speedtest')['required_answer'][0]['stdout']['data']['speedtest']
    assert empty['native_completed_result'] is False
    assert empty['download_bps'] is None and empty['result_timestamp_utc'] is None
    failed = task(corpus, 'unavailable_sysinfo_followup')
    assert failed['savings_eligible'] is False
    assert failed['required_answer'][0]['exit_code'] == 1
    assert set(failed['required_answer'][0]['stdout']) == {'error'}
    assert failed['required_answer'][0]['stdout']['error']['code'] == 'http_error'
    assert failed['transcripts']['small_pages'] == failed['transcripts']['bounded_large_pages']


def test_complete_parental_inverse_charges_separate_approval_and_human_input(corpus):
    for name in ('parental_enable_inverse', 'parental_block_all_inverse'):
        steps = task(corpus, name)['required_answer']
        assert [step['command'].split()[1] for step in steps] == ['plan', 'plan-show', 'approval-request', 'apply', 'verify', 'rollback', 'plan-show', 'approval-request', 'apply', 'verify']
        forward, inverse = steps[0]['stdout']['data']['plan'], steps[5]['stdout']['data']['plan']
        assert forward['hash'] != inverse['hash']
        assert inverse['intent']['source_plan'] == forward['hash']
        assert forward['review']['before']['enabled'] is False
        for index, plan in [(3, forward), (8, inverse)]:
            assert steps[index]['human_input'] == 'apply ' + plan['hash'] + '\n'
            assert 'Review exact native plan:' in steps[index]['stderr']
            assert 'firewall_restart' in steps[index]['stderr']
            assert steps[index]['stdout']['data']['phase'] == 'verified'
        for index in (2, 7):
            assert steps[index]['stdout']['data']['status'] == 'not_authorized'
            assert '300 seconds' in steps[index]['stdout']['data']['reason']
        assert steps[9]['stdout']['data']['phase'] == 'verified'
        if name == 'parental_block_all_inverse':
            assert 'all_client_internet_blocking_setting' in steps[3]['stderr']


@pytest.mark.parametrize('damage', ['fetch', 'false_to_null', 'approval_text', 'human_phrase', 'error_code', 'missing_page'])
def test_corrupted_evidence_is_rejected_before_scoring(corpus, tmp_path, damage):
    altered = copy.deepcopy(corpus)
    if damage in {'fetch', 'false_to_null'}:
        step = task(altered, 'traffic_ethernet')['transcripts']['bounded_large_pages'][0]
        value = json.loads(step['stdout'])
        if damage == 'fetch':
            del value['fetched_at']
        else:
            value['data']['traffic']['backhaul'] = None
        step['stdout'] = json.dumps(value)
    elif damage in {'approval_text', 'human_phrase'}:
        step = task(altered, 'parental_enable_inverse')['transcripts']['bounded_large_pages'][8]
        step['stderr' if damage == 'approval_text' else 'human_input'] = ''
    elif damage == 'error_code':
        task(altered, 'unavailable_sysinfo_followup')['transcripts']['bounded_large_pages'][0]['exit_code'] = 0
    else:
        task(altered, 'discovery_train')['transcripts']['bounded_large_pages'].pop()
    path = tmp_path / 'damaged.json'
    path.write_text(json.dumps(altered))
    with pytest.raises(ValueError, match='differs from frozen'):
        validation.run(path)


def test_any_heldout_regression_rejects_training_winner(monkeypatch):
    original = validation.measure
    def regress(steps, corpus, encoding):
        score = original(steps, corpus, encoding)
        if '--group Logs --limit 20' in steps[0]['command']:
            score['tokens'] += 10000
        return score
    monkeypatch.setattr(validation, 'measure', regress)
    result = validation.run()
    assert result['selected_on_training'] == 'bounded_large_pages'
    assert result['heldout_gate'] == 'rejected_token_regression'
    assert result['retained'] == 'small_pages'


def test_four_existing_current_reports_replay_byte_identically():
    assert set(validation.replay_current_reports()) == {'v2', 'v7-clients', 'batch-v7', 'diff-v6'}


def test_original_v1_bytes_are_immutable_historical_not_current_parity():
    import hashlib
    original_corpus = BENCHMARKS / 'corpus-validation-v1.json'
    original_report = BENCHMARKS / 'results-validation-v1.json'
    assert hashlib.sha256(original_corpus.read_bytes()).hexdigest() == validation.HISTORICAL_V1['corpus_sha256']
    assert hashlib.sha256(original_report.read_bytes()).hexdigest() == validation.HISTORICAL_V1['report_sha256']
    assert json.loads(original_corpus.read_text())['schema_version'] == 1
    assert 'not current CLI replay' in validation.HISTORICAL_V1['claim']
    with pytest.raises(ValueError, match='Historical validation corpus'):
        validation.run(original_corpus)


def test_v2_current_schema_binding_and_limits(corpus):
    assert corpus['schema_version'] == 2
    assert corpus['historical_v1'] == validation.HISTORICAL_V1
    report = validation.run()
    assert report['schema_version'] == 2
    assert report['historical_v1'] == validation.HISTORICAL_V1
    assert 'Proxy only' in report['tokenizer']['claim']
    assert 'Synthetic authority never proves' in report['limits']
