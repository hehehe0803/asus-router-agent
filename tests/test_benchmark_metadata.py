"""Current metadata is never hidden to reproduce historical score reports."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from router_agent import benchmark, benchmark_clients, benchmark_batch, benchmark_diff
from router_agent.benchmark_contract import FETCHED_AT

BENCHMARKS = Path(__file__).resolve().parents[1] / 'benchmarks'


@pytest.mark.parametrize('module,stem',[(benchmark_clients,'v7-clients'),(benchmark_batch,'batch-v7')])
def test_current_collectors_charge_and_preserve_all_fetch_metadata(module,stem,tmp_path):
    corpus = json.loads((BENCHMARKS/f'corpus-{stem}.json').read_text())
    required = corpus['tasks'][0]['required_answer']
    metadata = required['metadata']
    assert metadata['fetched_at'] == FETCHED_AT
    sources = required['sources'] if module is benchmark_batch else metadata['sources']
    assert all(source['fetched_at'] == FETCHED_AT and source['observed_at'] is None and source['freshness'] == 'unknown' for source in sources.values())
    damaged = copy.deepcopy(corpus)
    transcripts = damaged['tasks'][0]['transcripts']
    for steps in transcripts.values():
        payload = json.loads(steps[0]['stdout'])
        del payload['fetched_at']
        steps[0]['stdout'] = json.dumps(payload)
    path = tmp_path/'missing-metadata.json'
    path.write_text(json.dumps(damaged))
    with pytest.raises(ValueError,match='differs from frozen'):
        module.run(path,historical_help=True)
    with pytest.raises(ValueError,match='registered corpus'):
        module.run(BENCHMARKS/f'corpus-{stem}.json',historical_schema=True,historical_help=True)


def test_current_diff_and_formatter_required_facts_cover_fetch_field(tmp_path):
    corpus = benchmark_diff.freeze_actual()
    for task in corpus['tasks']:
        assert all('fetched_at' in step['stdout'] and step['stdout']['fetched_at'] is None for step in task['steps'])
        assert any(fact['path'].endswith('/stdout/fetched_at') for fact in task['required_facts'])
    generic = benchmark.freeze()
    for task in generic['tasks']:
        for index,step in enumerate(task['steps']):
            if 'error' not in step['stdout']:
                assert 'fetched_at' in step['stdout']
                assert any(fact['path'] == f'/{index}/stdout/fetched_at' for fact in task['required_facts'])


def test_all_fifteen_registered_archives_replay_exact_reports():
    manifest = json.loads((BENCHMARKS/'archive-contract.json').read_text())
    assert len(manifest['archives']) == 15
    assert 'not current CLI response parity' in manifest['contract']
    for archive in manifest['archives']:
        corpus = BENCHMARKS/Path(archive['corpus']).name
        report = BENCHMARKS/Path(archive['report']).name
        assert hashlib.sha256(corpus.read_bytes()).hexdigest() == archive['corpus_sha256']
        assert hashlib.sha256(report.read_bytes()).hexdigest() == archive['report_sha256']
        if corpus.name == 'corpus-v1.json':
            actual = benchmark.run(corpus,help_file=BENCHMARKS/'help-v1-v2.txt')
        elif corpus.name == 'corpus-diff-v1.json':
            actual = benchmark_diff.run(corpus,historical_format_study=True)
        else:
            runner = benchmark_batch.run if 'batch-' in corpus.name else benchmark_diff.run_actual if 'diff-' in corpus.name else benchmark_clients.run
            actual = runner(corpus,historical_help=True,historical_schema=True)
        assert actual == json.loads(report.read_text())
        emitted = (json.dumps(actual, indent=2) + "\n").encode()
        assert emitted == report.read_bytes()
        assert hashlib.sha256(emitted).hexdigest() == archive["report_sha256"]


@pytest.mark.parametrize('module',[benchmark_clients,benchmark_batch,benchmark_diff])
def test_archive_mode_requires_explicit_corpus_and_cannot_freeze(module):
    with pytest.raises(SystemExit) as error:
        module.main(['--historical-schema'])
    assert error.value.code == 2
    with pytest.raises(SystemExit) as error:
        module.main(['--historical-schema','--freeze','--corpus','somewhere.json'])
    assert error.value.code == 2


def test_archive_cli_reports_dated_schema_without_current_parity_claim(capsys):
    benchmark_clients.main(['--corpus',str(BENCHMARKS/'corpus-v5-clients.json'),'--historical-help','--historical-schema'])
    captured = capsys.readouterr()
    assert 'No current CLI response parity' in captured.err
    assert json.loads(captured.out)['schema_version'] == 5


@pytest.mark.parametrize('runner,corpus_name,report_name',[
    (benchmark_batch.run,'corpus-batch-v6.json','results-batch-v6.json'),
    (benchmark_clients.run,'corpus-v6-clients.json','results-v6-clients.json'),
    (benchmark_diff.run_actual,'corpus-diff-v5.json','results-diff-v5.json'),
])
def test_prior_fetch_metadata_corpora_keep_current_response_validation(runner,corpus_name,report_name):
    """Only prior help is archived; fetched_at and actual outputs remain current."""
    corpus=BENCHMARKS/corpus_name
    actual=runner(corpus,historical_help=True)
    assert actual==json.loads((BENCHMARKS/report_name).read_text())
    assert (json.dumps(actual,indent=2)+'\n').encode()==(BENCHMARKS/report_name).read_bytes()
    with pytest.raises(ValueError,match='registered corpus'):
        runner(corpus,historical_help=True,historical_schema=True)


@pytest.mark.parametrize('runner,corpus_name,report_name',[
    (benchmark_batch.run,'corpus-batch-v7.json','results-batch-v7.json'),
    (benchmark_clients.run,'corpus-v7-clients.json','results-v7-clients.json'),
    (benchmark_diff.run_actual,'corpus-diff-v6.json','results-diff-v6.json'),
])
def test_refreshed_current_help_reports_replay_byte_exact(runner,corpus_name,report_name):
    actual=runner(BENCHMARKS/corpus_name)
    assert (json.dumps(actual,indent=2)+'\n').encode()==(BENCHMARKS/report_name).read_bytes()
