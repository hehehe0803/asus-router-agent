import pytest
from router_agent.cli import main, parser
from router_agent import __version__


def test_version_and_all_command_help_are_local(monkeypatch,capsys):
    monkeypatch.setattr('router_agent.cli.get_credentials',lambda:pytest.fail('help touched credentials'))
    with pytest.raises(SystemExit) as exit:
        main(['--version'])
    assert exit.value.code == 0
    assert capsys.readouterr().out.strip() == 'router-agent ' + __version__
    commands = ['auth','capabilities','status','get','traffic','clients','snapshot','diff','plan','plan-show','approval-request','apply','verify','rollback']
    for command in commands:
        with pytest.raises(SystemExit) as exit:
            main([command,'--help'])
        assert exit.value.code == 0
        assert parser()._subparsers._group_actions[0].choices[command].description
        help_text = capsys.readouterr().out
        assert 'usage:' in help_text
        if command == 'apply':
            assert 'zero writes' in help_text and 'reads' in help_text
    for command in ('init','status','probe'):
        with pytest.raises(SystemExit):
            main(['auth',command,'--help'])
        assert 'usage:' in capsys.readouterr().out
