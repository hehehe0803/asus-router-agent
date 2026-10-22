"""Frozen synthetic remaining-task transcripts; never live authorization evidence."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import copy
import hashlib
from importlib.metadata import version
import json
import io
from pathlib import Path
import tempfile
from unittest.mock import patch

from . import cli
from .benchmark_batch import fixture
from .benchmark_contract import FETCHED_AT
from .errors import RouterError

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / 'benchmarks/corpus-validation-v3.json'
REPORT = ROOT / 'benchmarks/results-validation-v3.json'
HISTORICAL_V1 = {
    'corpus_sha256': '6f39ef3d01c6189affdff030f9ecaf10c97bafb7b45301092dfcd924d6e5e20d',
    'report_sha256': '336c9bd2c3a6fcb580a62f95a67293e22a4a4dd3e7e3d0d0434e76a3dfa8acd1',
    'claim': 'Immutable historical synthetic evidence; not current CLI replay or migration validation.'}
CANDIDATES = ('small_pages', 'bounded_large_pages')
INSTRUCTIONS = ('Preserve all selected fields, false/null distinctions, fetched_at, unknown source age, '
                'gaps and errors. Inventory is dated evidence, rates are not throughput or egress proof. '
                'Requests and inverse previews grant no authority. Every apply, including inverse/no-op, '
                'requires a separate administrator exact-plan grant within the 300-second plan lifetime '
                'and a human personally typing apply HASH over verified HTTPS. Agents never install '
                'grants or type confirmations. Firewall restart and all-client blocking are distinct '
                'effects. Verify uncertainty without repeating writes.\n')
DECODER = 'Decode each single JSON stdout; retain stderr and exit code. Follow next_offset until null. Reassemble ordered rows with unchanged non-pagination metadata; pagination is traversal evidence, not omitted selected data.\n'


def capture(argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = cli.main(argv)
        except SystemExit as error:
            code = error.code
    return {'command': 'router-agent ' + ' '.join(argv) + '\n', 'stdout': stdout.getvalue(),
            'stderr': stderr.getvalue(), 'exit_code': code}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def capability_pages(selector, limit):
    steps, offset, rows, metadata = [], 0, [], None
    field = 'capabilities' if '--native' in selector else 'pages'
    while True:
        step = capture(['capabilities', *selector, '--limit', str(limit), '--offset', str(offset)])
        if step['exit_code'] or step['stderr']:
            raise ValueError('Capability discovery failed')
        payload = json.loads(step['stdout'])
        data = payload['data']
        current = copy.deepcopy(payload)
        del current['data'][field]
        del current['data']['pagination']
        if metadata is not None and canonical(metadata) != canonical(current):
            raise ValueError('Capability metadata changed between pages')
        metadata = current
        rows.extend(data[field])
        steps.append(step)
        next_offset = data['pagination']['next_offset']
        if next_offset is None:
            if len(rows) != data['pagination']['total']:
                raise ValueError('Capability traversal is incomplete')
            break
        if next_offset <= offset or len(steps) > 100:
            raise ValueError('Capability pagination did not advance')
        offset = next_offset
    return steps, {'metadata': metadata, field: rows}


def read_fixture(groups, *, failure=None):
    from .speedtest_reads import normalize_speedtest
    value = fixture(['identity'])
    for group in groups:
        if group == 'identity':
            continue
        if group == failure:
            raise RouterError('http_error', 'Native request returned an unsuccessful HTTP response.')
        if group != 'speedtest':
            raise AssertionError('Unexpected fixture group')
        value['data'][group] = normalize_speedtest({'ookla_state': '0', 'ookla_speedtest_get_result': []})
        value['sources'][group] = {'fetched_at': FETCHED_AT, 'observed_at': None, 'freshness': 'unknown', 'reason': 'source_observation_time_unavailable'}
        value['capability_gaps'].extend({'group': group, 'reason': gap} for gap in value['data'][group]['gaps'])
    return value


def read_steps(unavailable=False):
    async def collect(groups, probe=False):
        assert not probe
        return read_fixture(groups, failure='sysinfo' if unavailable else None)
    with patch.object(cli, '_collect', collect):
        return [capture(['get', 'sysinfo' if unavailable else 'speedtest']),
                capture(['get', '--help'])] if unavailable else [capture(['get', 'speedtest'])]


def traffic_steps(kind):
    from .traffic_reads import PreparedTrafficRead, normalize_traffic
    node = 'node-0000000000000001'
    async def collect(actual_kind, actual_node, **kwargs):
        assert (actual_kind, actual_node) == (kind, node)
        prepared = PreparedTrafficRead(kind, node, kwargs['peer_alias'], kwargs['band'], kwargs['backhaul'], None, '')
        raw = {'data_rx': '0', 'data_tx': '12.5', 'phy_rx': '0', 'phy_tx': None, 'error_status': '0'}
        value = fixture(['identity'])
        selected = normalize_traffic(raw, prepared)
        value['data']['traffic'] = selected
        for source in ('aimesh', 'traffic'):
            value['sources'][source] = {'fetched_at': FETCHED_AT, 'observed_at': None, 'freshness': 'unknown', 'reason': 'source_observation_time_unavailable'}
        value['capability_gaps'] = [{'group': 'traffic', 'reason': gap} for gap in selected['gaps']]
        return value
    argv = ['traffic', kind, '--node', node]
    if kind == 'wifi':
        argv += ['--band', '5ghz']
    with patch.object(cli, '_collect_traffic', collect):
        return [capture(argv)]


def parental_steps(block_all=False):
    """Real CLI/engine/backend over temporary synthetic policy; no real grants."""
    from . import approval, approval_window
    from .auth import AuthConfig
    from .catalog import load_catalog
    from .native_parental_backend import NativeParentalBackend
    from .operations import MemoryPlanStore, OperationEngine
    from .parental_policy import PARENTAL_POLICY_KEYS, read_policy_snapshot, prepare_enable, prepare_block_all
    key = b'v' * 32
    clock = lambda: 100.0
    raw = {field: '' for field in PARENTAL_POLICY_KEYS}
    raw.update(MULTIFILTER_ALL='0', MULTIFILTER_BLOCK_ALL='0')
    original = copy.deepcopy(raw)
    identity = {'model': 'RT-AX86U', 'firmware': '3.0.0.4.388_24436-ge7c0b5e', 'device_fingerprint': 'synthetic-validation-device'}
    writes = []
    class SyntheticTerminal(io.StringIO):
        def isatty(self):
            return True
    async def reader(*args, **kwargs):
        return {'identity': identity, 'policy': read_policy_snapshot(raw, key)}
    async def writer(*args, **kwargs):
        snapshot = read_policy_snapshot(raw, key)
        assert snapshot.fingerprint == kwargs['expected_policy_fingerprint']
        prepared = await (prepare_enable(snapshot, kwargs['enabled']) if 'enabled' in kwargs else prepare_block_all(snapshot, kwargs['blocked']))
        assert prepared.after.fingerprint == kwargs['expected_after_policy_fingerprint']
        kwargs['authorization_check']()
        writes.append(prepared.after.fingerprint)
        raw.clear(); raw.update(prepared.after.raw)
        return {'freshness': 'applied_unverified'}
    with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
        directory = Path(temporary)
        directory.chmod(0o700)
        (directory / 'alias.key').write_bytes(key)
        (directory / 'alias.key').chmod(0o600)
        store = MemoryPlanStore()
        backend = NativeParentalBackend(None, None, fingerprint_key=key, state_dir=directory, reader=reader,
                                        writers={'enable': writer, 'block_all': writer})
        engine = OperationEngine(load_catalog(), backend, store, clock=clock)
        validate_window = approval_window.validate_window
        validate_plan = approval.validate_local_plan
        confirm = approval.confirm_plan
        human = []
        def confirmation(plan, window_id=None):
            phrase = 'apply ' + plan.id
            human.append(phrase + '\n')
            return confirm(plan, window_id=window_id, clock=clock, input_reader=lambda _: phrase)
        patches = [patch.object(cli, '_engine', lambda *args: (directory, engine)),
                   patch.object(cli, '_plan_store', lambda: (directory, store)),
                   patch.object(cli, 'load_config', lambda: AuthConfig('https://router.invalid', 'synthetic')),
                   patch.object(approval, 'validate_local_plan', lambda plan, **kw: validate_plan(plan, clock=clock)),
                   patch.object(approval, 'confirm_plan', confirmation),
                   patch.object(approval_window, 'validate_window', lambda plan, window, **kw: validate_window(plan, window, clock=clock)),
                   patch.object(approval_window, '_read_grant', lambda window: approval_window.approval_request(store.get(window)[0])),
                   patch('sys.stdin.isatty', return_value=True), patch('router_agent.benchmark_validation.io.StringIO', SyntheticTerminal)]
        for item in patches:
            stack.enter_context(item)
        steps = []
        def command(argv):
            step = capture(argv)
            if step['exit_code']:
                raise ValueError('Synthetic parental conversation failed: ' + step['stdout'])
            step['human_input'] = human.pop() if human else ''
            steps.append(step)
            return json.loads(step['stdout'])
        args = ['parental-block-all', '--blocked', 'on'] if block_all else ['parental', '--enabled', 'on']
        plan = command(['plan', *args])['data']['plan']
        for command_name in ('plan-show', 'approval-request', 'apply', 'verify'):
            command([command_name, plan['hash'], *(['--window', plan['hash']] if command_name == 'apply' else [])])
        inverse = command(['rollback', plan['hash']])['data']['plan']
        for command_name in ('plan-show', 'approval-request', 'apply', 'verify'):
            command([command_name, inverse['hash'], *(['--window', inverse['hash']] if command_name == 'apply' else [])])
        if raw != original or len(writes) != 2:
            raise ValueError('Synthetic policy was not exactly restored')
        return steps


def decoded(steps):
    return [{**step, 'stdout': json.loads(step['stdout']) if step['stdout'].startswith('{') else step['stdout']} for step in steps]


def build_corpus():
    """Build fixed cases with no tokenizer access; freeze these bytes before run."""
    tasks = []
    for split, selector in [('train', ['--native']), ('heldout', ['--group', 'Logs'])]:
        transcripts, required = {}, None
        for candidate, limit in zip(CANDIDATES, (5, 20), strict=True):
            steps, answer = capability_pages(selector, limit)
            if required is not None and canonical(required) != canonical(answer):
                raise ValueError('Page-size candidate lost complete inventory')
            required = answer
            transcripts[candidate] = steps
        tasks.append({'id': 'discovery_' + split, 'split': split, 'kind': 'pagination', 'selector': selector,
                      'required_answer': required, 'transcripts': transcripts, 'savings_eligible': True})
    cases = [('traffic_ethernet', 'train', traffic_steps('ethernet')),
             ('traffic_wifi', 'heldout', traffic_steps('wifi')),
             ('empty_speedtest', 'train', read_steps()),
             ('unavailable_sysinfo_followup', 'heldout', read_steps(True)),
             ('parental_enable_inverse', 'train', parental_steps()),
             ('parental_block_all_inverse', 'heldout', parental_steps(True))]
    for name, split, steps in cases:
        expected_codes = [1, 0] if name == 'unavailable_sysinfo_followup' else [0] * len(steps)
        if [step['exit_code'] for step in steps] != expected_codes:
            raise ValueError('Unexpected CLI outcome: ' + name)
        if name == 'unavailable_sysinfo_followup' and json.loads(steps[0]['stdout'])['error']['code'] != 'http_error':
            raise ValueError('Unavailable read changed error semantics')
        tasks.append({'id': name, 'split': split, 'kind': 'conversation', 'required_answer': decoded(steps),
                      'transcripts': {candidate: copy.deepcopy(steps) for candidate in CANDIDATES},
                      'savings_eligible': not any(step['exit_code'] for step in steps)})
    helps = ['capabilities', 'traffic', 'get', 'plan', 'plan-show', 'approval-request', 'apply', 'verify', 'rollback']
    return {'schema_version': 3, 'historical_v1': HISTORICAL_V1, 'fixture_fetched_at': FETCHED_AT, 'provenance': 'Actual CLI main, packaged offline ledgers, current selected traffic/speedtest normalizers, real operation engine/native parental backend over bounded synthetic temporary policy. Collectors and authority are synthetic, not live transport or approval validation.',
            'split_policy': 'Fixed training and held-out selectors/traffic kinds/operations before token scoring; held-out does not select the candidate.',
            'instructions': INSTRUCTIONS, 'decoder': DECODER,
            'discovery': [capture(['--help']), *[capture([name, '--help']) for name in helps]], 'tasks': tasks}


def measure(steps, corpus, encoding):
    components = {'commands': [], 'stdout': [], 'stderr': [], 'human_input': [],
                  'instructions': [corpus['instructions'], corpus['decoder']]}
    for step in corpus['discovery'] + steps:
        for field in ('commands', 'stdout', 'stderr', 'human_input'):
            components[field].append(step.get('command' if field == 'commands' else field, ''))
    tokens = {key: sum(len(encoding.encode(part)) for part in parts) for key, parts in components.items()}
    return {'tokens': sum(tokens.values()), 'component_tokens': tokens, 'calls': len(steps),
            'discovery_calls': len(corpus['discovery'])}


def validate_task(task, steps):
    """Reconstruct dated required evidence independently of token accounting."""
    if task['kind'] == 'conversation':
        actual = decoded(steps)
    else:
        field = 'capabilities' if '--native' in task['selector'] else 'pages'
        rows, metadata, expected_offset = [], None, 0
        for index, step in enumerate(steps):
            if step['exit_code'] or step['stderr']:
                raise ValueError('Capability discovery failed')
            payload = json.loads(step['stdout'])
            pagination = payload['data']['pagination']
            arguments = step['command'].split()
            offset = int(arguments[arguments.index('--offset') + 1])
            if offset != expected_offset or pagination.get('offset', offset) != offset:
                raise ValueError('Capability traversal offset changed')
            current = copy.deepcopy(payload)
            del current['data'][field]
            del current['data']['pagination']
            if metadata is not None and canonical(metadata) != canonical(current):
                raise ValueError('Capability metadata changed between pages')
            metadata = current
            rows.extend(payload['data'][field])
            expected_offset = pagination['next_offset']
            if expected_offset is None:
                if index != len(steps) - 1 or len(rows) != pagination['total']:
                    raise ValueError('Capability traversal is incomplete')
            elif expected_offset <= offset:
                raise ValueError('Capability pagination did not advance')
        if not steps or expected_offset is not None:
            raise ValueError('Capability traversal is incomplete')
        actual = {'metadata': metadata, field: rows}
    if canonical(actual) != canonical(task['required_answer']):
        raise ValueError('Required facts, prompts, human input or failure follow-ups changed')


def run(path=CORPUS, historical_transcript=False):
    import tiktoken
    from .benchmark_contract import validate_historical_transcript
    raw = Path(path).read_bytes()
    corpus = json.loads(raw)
    if historical_transcript:
        validate_historical_transcript(raw)
    elif corpus.get('schema_version') != 3:
        raise ValueError('Historical validation corpus is not current CLI replay evidence')
    # Full reconstructed answers, prompts, errors and traversal bytes must replay.
    if not historical_transcript and canonical(corpus) != canonical(build_corpus()):
        raise ValueError('Current CLI differs from frozen validation corpus')
    encoding = tiktoken.get_encoding('o200k_base')
    rows = []
    for task in corpus['tasks']:
        for steps in task['transcripts'].values():
            validate_task(task, steps)
        scores = {candidate: measure(steps, corpus, encoding) for candidate, steps in task['transcripts'].items()}
        saved = scores[CANDIDATES[0]]['tokens'] - scores[CANDIDATES[1]]['tokens']
        if not task['savings_eligible'] and saved:
            raise ValueError('Failure cannot count as token savings')
        rows.append({'task': task['id'], 'split': task['split'], 'required_answer_valid': True,
                     'savings_eligible': task['savings_eligible'], 'candidates': scores, 'saved_tokens': saved})
    totals = {split: {candidate: sum(row['candidates'][candidate]['tokens'] for row in rows if row['split'] == split) for candidate in CANDIDATES} for split in ('train', 'heldout')}
    selected = CANDIDATES[1] if totals['train'][CANDIDATES[1]] < totals['train'][CANDIDATES[0]] else CANDIDATES[0]
    passed = all(row['candidates'][selected]['tokens'] <= row['candidates'][CANDIDATES[0]]['tokens'] for row in rows if row['split'] == 'heldout')
    return {'schema_version': corpus['schema_version'], 'historical_v1': HISTORICAL_V1, 'corpus_sha256': hashlib.sha256(raw).hexdigest(),
            'tokenizer': {'package': 'tiktoken', 'version': version('tiktoken'), 'encoding': 'o200k_base', 'claim': 'Proxy only; not Fable-native tokens, billing or equivalent-browser savings.'},
            'selected_on_training': selected, 'retained': selected if passed else CANDIDATES[0],
            'heldout_gate': 'passed' if passed else 'rejected_token_regression', 'totals': totals,
            'savings_percent': {split: round(100 * (values[CANDIDATES[0]] - values[selected]) / values[CANDIDATES[0]], 2) for split, values in totals.items()},
            'tasks': rows, 'limits': 'Small fixed synthetic corpus. Only capability page size is optimized; unchanged traffic/read/parental costs remain charged. Synthetic authority never proves human, root-grant, transport, enforcement or live recovery behavior.'}


def replay_current_reports():
    from . import benchmark, benchmark_clients, benchmark_batch, benchmark_diff
    runners = [('v3', benchmark.run), ('v8-clients', benchmark_clients.run), ('batch-v8', benchmark_batch.run), ('diff-v7', benchmark_diff.run_actual)]
    results = {}
    for stem, runner in runners:
        report = ROOT / f'benchmarks/results-{stem}.json'
        emitted = (json.dumps(runner(ROOT / f'benchmarks/corpus-{stem}.json'), indent=2) + '\n').encode()
        if emitted != report.read_bytes():
            raise ValueError('Existing report changed: ' + stem)
        results[stem] = hashlib.sha256(emitted).hexdigest()
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=CORPUS)
    parser.add_argument('--replay-current', action='store_true')
    args = parser.parse_args(argv)
    if args.replay_current:
        print(json.dumps(replay_current_reports(), indent=2))
    else:
        print(json.dumps(run(args.corpus), indent=2))


if __name__ == '__main__':
    main()
