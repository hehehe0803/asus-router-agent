"""Actual synthetic CLI benchmark: separate named reads versus grouped reads."""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
from importlib.metadata import version
import io
import json
from pathlib import Path
from unittest.mock import patch

from . import cli
from .benchmark_contract import FETCHED_AT, fixture_contract, archive_contract, validate_registered, archival_notice, validate_historical_transcript
from .errors import RouterError

# Bounded synthetic wire fields are normalized through current application
# parsers, so this benchmark cannot silently omit implemented diagnostics/gaps.
RAW_FIXTURES = {
    'identity': {'productid': 'RT-AX86U', 'firmver': '3.0.0.4', 'buildno': '388', 'extendno': 'synthetic-batch', 'label_mac': '00:00:00:00:00:11'},
    'wlan': {'wl0_radio': '1', 'wl0_channel': '36', 'wl0_bw': '1', 'wl1_radio': None, 'wl1_channel': '0'},
    'guest': {key: value for i in (0, 1) for j in (1, 2, 3) for key, value in (
        (f'wl{i}.{j}_bss_enabled', '0' if j != 3 else None),
        (f'wl{i}.{j}_expire', '600'), (f'wl{i}.{j}_lanaccess', 'off'),
        (f'wl{i}.{j}_ap_isolate', '0'))},
    'network': {'netdev': {'INTERNET_rx': '0x1e240', 'INTERNET_tx': None, 'WIRED_rx': '0x0', 'WIRED_tx': '0x9fbf1'}},
    'wan': {'get_wan_unit': '0', 'link_internet': '2', 'link_wan': '1', 'link_wan1': '0', 'wans_mode': 'fb',
            'wan0_primary': '1', 'wan0_state_t': '2', 'wan0_auxstate_t': '0', 'wan0_proto': 'dhcp',
            'wan1_primary': '0', 'wan1_state_t': '4', 'wan1_sbstate_t': '0', 'wan1_proto': 'dhcp'},
    'cpu': {'cpu_usage': {'cpu1_total': '1000', 'cpu1_usage': '20', 'cpu2_total': '900', 'cpu2_usage': '10'}},
}


def selected(group):
    from .transport import _normalize
    return _normalize(group, copy.deepcopy(RAW_FIXTURES[group]), b'b' * 32)


def fixture(groups, *, fail_group=None):
    """Deterministic selected collector; raises without exposing partial reads."""
    ordered = ('identity',) + tuple(g for g in groups if g != 'identity')
    result = {'schema_version': 1, 'source': 'native', 'freshness': 'unknown', 'observed_at': None,
              'data': {}, 'sources': {}, 'capability_gaps': [], 'warnings': ['logout_unconfirmed']}
    for group in ordered:
        if group == fail_group:
            raise RouterError('timeout', 'Native command deadline exceeded.')
        result['data'][group] = selected(group)
        result['sources'][group] = {'observed_at': None, 'freshness': 'unknown', 'reason': 'source_observation_time_unavailable'}
        if group != 'identity':
            result['capability_gaps'].extend({'group': group, 'reason': reason} for reason in result['data'][group].get('gaps', []))
    result['fetched_at'] = FETCHED_AT
    for source in result['sources'].values():
        source['fetched_at'] = FETCHED_AT
    return fixture_contract(result)


def capture(argv, *, fail_group=None):
    async def collect(groups, probe=False):
        if probe:
            raise AssertionError('Unexpected auth probe')
        return fixture(groups, fail_group=fail_group)
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.object(cli, '_collect', collect), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = cli.main(argv)
        except SystemExit as error:
            code = error.code
    return {'command': 'router-agent ' + ' '.join(argv) + '\n', 'stdout': stdout.getvalue(), 'stderr': stderr.getvalue(), 'exit_code': code}


def answer(groups, steps):
    data, sources, gaps, metadata = {}, {}, [], None
    for step in steps:
        if step['exit_code'] != 0 or step['stderr']:
            raise ValueError('A failed CLI read cannot be scored as successful equivalence')
        value = json.loads(step['stdout'])
        current = {k: v for k, v in value.items() if k not in {'data', 'sources', 'capability_gaps'}}
        if metadata is not None and current != metadata:
            raise ValueError('Read metadata differs across responses')
        metadata = current
        for group, selected in value['data'].items():
            if group in data and data[group] != selected:
                raise ValueError('Selected data differs across responses')
            data[group] = selected
        for group, source in value['sources'].items():
            if group in sources and sources[group] != source:
                raise ValueError('Source metadata differs across responses')
            sources[group] = source
        for gap in value['capability_gaps']:
            if gap not in gaps:
                gaps.append(gap)
    if set(data) != {'identity', *groups} or set(sources) != set(data):
        raise ValueError('Required groups or per-source metadata are missing')
    return {'metadata': metadata, 'data': data, 'sources': sources, 'capability_gaps': gaps}


def validate(task, steps):
    actual = answer(task['groups'], steps)
    # Serialized structural comparison preserves bool/int and null distinctions.
    if json.dumps(actual, sort_keys=True) != json.dumps(task['required_answer'], sort_keys=True):
        raise ValueError('Required selected facts or uncertainty were lost')


def execute_task(task):
    return {'separate_reads': [capture(['get', group]) for group in task['groups']],
            'grouped_read': [capture(['get', *task['groups']])]}


def validate_failure(case):
    separate, grouped = case['transcripts']['separate_reads'], case['transcripts']['grouped_read']
    if separate[-1]['exit_code'] == 0 or grouped[0]['exit_code'] == 0:
        raise ValueError('Failed group was incorrectly treated as success')
    error = {'error': {'code': 'timeout', 'message': 'Native command deadline exceeded.'}}
    if json.loads(separate[-1]['stdout']) != error or json.loads(grouped[0]['stdout']) != error:
        raise ValueError('Failure semantics differ from the frozen timeout')
    if len(grouped) != 1 or 'data' in json.loads(grouped[0]['stdout']):
        raise ValueError('Grouped failure exposed partial success')
    # Separate first read succeeded; this is intentionally not equivalent data.
    if separate[0]['exit_code'] != 0 or case['equivalence_claim'] is not False:
        raise ValueError('Failure comparison must explicitly deny partial-result equivalence')


def _freeze(schema_version=8):
    if schema_version not in {1,2,3,4,5,6,7,8}:
        raise ValueError("Unsupported grouped-read benchmark corpus")
    # Task goals, splits, fixtures and required answers fixed before token scoring.
    tasks = [{'id': 'radio_guest_training', 'split': 'train', 'groups': ['wlan', 'guest'], 'query': 'Read selected radio and guest slot settings; preserve unknown settings, identity, source metadata, all capability gaps and cleanup warnings.\n'},
             {'id': 'traffic_wan_cpu_heldout', 'split': 'heldout', 'groups': ['network', 'wan', 'cpu'], 'query': 'Read selected cumulative interface counters, WAN state and CPU counters; preserve null counters, unknown freshness, identity, source metadata, gaps and cleanup warnings without claiming rates or verified egress.\n'}]
    for task in tasks:
        source = fixture(task['groups'])
        task['required_answer'] = {'metadata': {k: v for k, v in source.items() if k not in {'data', 'sources', 'capability_gaps'}}, 'data': source['data'], 'sources': source['sources'], 'capability_gaps': source['capability_gaps']}
        task['transcripts'] = execute_task(task)
        for steps in task['transcripts'].values():
            validate(task, steps)
    failure = {'id': 'second_group_timeout', 'groups': ['wlan', 'guest'], 'equivalence_claim': False,
               'transcripts': {'separate_reads': [capture(['get', 'wlan'], fail_group='guest'), capture(['get', 'guest'], fail_group='guest')], 'grouped_read': [capture(['get', 'wlan', 'guest'], fail_group='guest')]}}
    validate_failure(failure)
    return {'schema_version': schema_version, 'provenance': 'Actual CLI main with current normalizers over bounded synthetic raw fields; no router, browser or credentials.',
            'sampling_limit': 'Independent sequential reads are not simultaneous; synthetic fixed observations do not prove real-time equivalence.',
            'discovery': [capture(['--help']), capture(['get', '--help'])], 'tasks': tasks, 'failure_cases': [failure]}


def freeze(schema_version=8, historical_schema=False):
    with archive_contract(historical_schema):
        return _freeze(schema_version)


def measure(steps, discovery, query, encoding):
    streams = {'commands': [s['command'] for s in discovery + steps], 'stdout': [s['stdout'] for s in discovery + steps],
               'stderr': [s['stderr'] for s in discovery + steps], 'task_instructions': [query]}
    tokens = {key: sum(len(encoding.encode(part)) for part in parts) for key, parts in streams.items()}
    sizes = {key: sum(len(part.encode()) for part in parts) for key, parts in streams.items()}
    return {'tokens': sum(tokens.values()), 'bytes': sum(sizes.values()), 'response_calls': len(steps), 'discovery_calls': len(discovery), 'component_tokens': tokens, 'component_bytes': sizes}


def run(path, encoding_name='o200k_base', historical_help=False, historical_schema=False, historical_transcript=False):
    import tiktoken
    raw = Path(path).read_bytes()
    corpus = json.loads(raw)
    if historical_schema:
        validate_registered(raw)
    if historical_transcript:
        validate_historical_transcript(raw)
    if historical_schema or historical_transcript:
        if not historical_help:
            raise ValueError('Historical transcripts require explicit historical help')
        # Check dated required facts and failure semantics below. Current runtime
        # equivalence belongs exclusively to the newly versioned corpus.
    else:
        current = freeze(schema_version=corpus.get('schema_version'))
        if historical_help:
            if [(step['command'], step['exit_code']) for step in corpus['discovery']] != [(step['command'], step['exit_code']) for step in current['discovery']]:
                raise ValueError('Historical discovery commands differ from current CLI')
            current['discovery'] = copy.deepcopy(corpus['discovery'])
        if corpus != current:
            raise ValueError('Current CLI behavior differs from frozen grouped-read corpus')
    encoding = tiktoken.get_encoding(encoding_name)
    rows = []
    for task in corpus['tasks']:
        scores = {}
        for candidate, steps in task['transcripts'].items():
            validate(task, steps)
            scores[candidate] = measure(steps, corpus['discovery'], task['query'], encoding)
        base, grouped = scores['separate_reads'], scores['grouped_read']
        rows.append({'task': task['id'], 'split': task['split'], 'required_answer_valid': True, 'candidates': scores,
                     'saved_tokens': base['tokens'] - grouped['tokens'], 'saved_percent': round(100 * (base['tokens'] - grouped['tokens']) / base['tokens'], 2)})
    train = next(row for row in rows if row['split'] == 'train')
    selected = 'grouped_read' if train['saved_tokens'] > 0 else 'separate_reads'
    heldout = next(row for row in rows if row['split'] == 'heldout')
    gate = 'passed' if selected == 'separate_reads' or heldout['saved_tokens'] >= 0 else 'rejected_token_regression'
    failure_scores = []
    for case in corpus['failure_cases']:
        validate_failure(case)
        failure_scores.append({'task': case['id'], 'equivalence_claim': False, 'failure_semantics_valid': True,
                               'candidates': {c: measure(steps, corpus['discovery'], 'Observe a failed second group; do not claim partial-result equivalence.\n', encoding) for c, steps in case['transcripts'].items()}})
    return {'schema_version': corpus['schema_version'], 'corpus_sha256': hashlib.sha256(raw).hexdigest(), 'tokenizer': {'package': 'tiktoken', 'version': version('tiktoken'), 'encoding': encoding_name, 'claim': 'proxy only; not GPT-6/GPT-6.1 tokens or billing'},
            'browser_baseline': 'unavailable; no browser savings claim', 'selected_on_training': selected, 'retained': selected if gate == 'passed' else 'separate_reads', 'heldout_gate': gate,
            'sampling_limit': corpus['sampling_limit'], 'tasks': rows, 'failure_cases': failure_scores}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', default=None)
    parser.add_argument('--freeze', action='store_true')
    parser.add_argument('--historical-help', action='store_true', help='Archive help only unless paired with an explicit dated schema/transcript contract')
    parser.add_argument('--historical-schema', action='store_true', help='Registered pre-fetched_at contract; no current response parity')
    parser.add_argument('--historical-transcript', action='store_true', help='Pinned superseded transcript; no current CLI parity claim')
    args = parser.parse_args(argv)
    if args.historical_transcript and (args.corpus is None or args.freeze):
        parser.error('Historical transcript requires explicit corpus and cannot freeze')
    if args.historical_schema and (args.corpus is None or args.freeze):
        parser.error('Historical schema requires explicit corpus and cannot freeze')
    if args.freeze:
        if args.historical_help:
            parser.error('--freeze cannot be combined with historical help')
        Path(args.corpus or 'benchmarks/corpus-batch-v8.json').write_text(json.dumps(freeze(), indent=2) + '\n')
    else:
        if args.historical_schema or args.historical_transcript:
            import sys
            print('Immutable historical transcript and archived help; dated facts and scores are checked. No current CLI response parity or current help-cost claim.' if args.historical_transcript else archival_notice(), file=sys.stderr)
        elif args.historical_help:
            import sys
            print('Historical discovery help replay; current response/fact/failure behavior is still checked.', file=sys.stderr)
        print(json.dumps(run(args.corpus or 'benchmarks/corpus-batch-v8.json', historical_help=args.historical_help, historical_schema=args.historical_schema, historical_transcript=args.historical_transcript), indent=2))


if __name__ == '__main__':
    main()
