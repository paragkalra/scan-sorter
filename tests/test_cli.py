import pytest

from scan_sorter import __version__
from scan_sorter.cli import main


def test_version_flag_prints_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_args_prints_help(capsys):
    assert main([]) == 0
    assert "usage: scan-sorter" in capsys.readouterr().out
