"""JSON compatibility flags preserve the default CLI contract without runtime I/O."""
import json

import pytest

from router_agent import __version__, cli


COMMANDS = [
    ['capabilities'], ['status'], ['get', 'identity'],
    ['traffic', 'ethernet', '--node', 'node-' + 'a' * 16], ['clients'],
    ['snapshot', '--list'], ['diff', '--since', 'before', '--to', 'after'],
    ['plan', 'led', '--enabled', 'off'], ['plan-show', 'plan-id'],
    ['approval-request', 'plan-id'], ['apply', 'plan-id'], ['verify', 'plan-id'],
    ['rollback', 'plan-id'], ['auth', 'init', '--host', 'https://router.invalid',
                             '--username', 'synthetic'],
    ['auth', 'status'], ['auth', 'probe'],
]


@pytest.mark.parametrize('argv', COMMANDS)
def test_json_accepted_at_root_and_every_command_level(argv):
    expected = vars(cli.parser().parse_args(argv))
    variants = [['--json', *argv], [*argv, '--json'], ['--json', *argv, '--json']]
    if argv[0] == 'auth':
        variants += [['auth', '--json', *argv[1:]],
                     ['--json', 'auth', '--json', *argv[1:], '--json']]
    for flagged in variants:
        actual = vars(cli.parser().parse_args(flagged))
        assert actual.pop('json') is True
        assert actual == expected


@pytest.fixture
def no_runtime(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail('offline command touched credentials or router runtime')
    for name in ('get_credentials', 'load_config', 'auth_status', 'init_auth',
                 '_collect', '_collect_traffic', '_engine'):
        monkeypatch.setattr(cli, name, forbidden)
    monkeypatch.setattr('router_agent.snapshots.default_state_dir', lambda: tmp_path)
    for name in ('collect_native', 'collect_traffic', 'probe_auth'):
        monkeypatch.setattr('router_agent.transport.' + name, forbidden)


@pytest.mark.parametrize('argv', [
    ['capabilities'], ['capabilities', '--native'], ['capabilities', '--expansion'],
    ['capabilities', '--webui'], ['snapshot', '--list'],
])
def test_offline_json_output_unchanged(argv, no_runtime, capsys):
    assert cli.main(argv) == 0
    expected = json.loads(capsys.readouterr().out)
    for flagged in (['--json', *argv], [*argv, '--json']):
        assert cli.main(flagged) == 0
        captured = capsys.readouterr()
        assert json.loads(captured.out) == expected
        assert captured.err == ''


@pytest.mark.parametrize('argv', [
    [], ['unknown'], ['capabilities', '--unknown'], ['capabilities', '--limit', '0'],
    ['get'], ['auth'], ['auth', 'init'], ['status', '--version'],
    ['capabilities', '--json=true'],
])
def test_json_keeps_argument_error_envelope_and_exit_code(argv, no_runtime, capsys):
    assert cli.main(argv) == 2
    expected = json.loads(capsys.readouterr().out)
    assert expected['error']['code'] == 'invalid_arguments'
    assert cli.main(['--json', *argv]) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out) == expected
    assert captured.err == ''


@pytest.mark.parametrize('argv', [
    ['--json', '--help'], ['--help', '--json'],
    *[[command[0], '--json', '--help'] for command in COMMANDS if command[0] != 'auth'],
    ['auth', '--json', '--help'],
    *[['auth', command, '--json', '--help'] for command in ('init', 'status', 'probe')],
])
def test_help_remains_standard_argparse_text(argv, no_runtime, capsys):
    with pytest.raises(SystemExit) as exited:
        cli.main(argv)
    assert exited.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.startswith('usage: router-agent')
    assert '--json' in captured.out
    assert 'JSON is already the default' in captured.out
    assert captured.err == ''


@pytest.mark.parametrize('argv', [['--json', '--version'], ['--version', '--json']])
def test_version_remains_standard_argparse_text(argv, no_runtime, capsys):
    with pytest.raises(SystemExit) as exited:
        cli.main(argv)
    assert exited.value.code == 0
    captured = capsys.readouterr()
    assert captured.out == 'router-agent ' + __version__ + '\n'
    assert captured.err == ''
