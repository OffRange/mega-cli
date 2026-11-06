"""Smoke tests: verify the package imports and the CLI runs end to end."""

from typer.testing import CliRunner

from mega_cli import CLI_NAME, __version__
from mega_cli.cli import app

runner = CliRunner()


def test_package_version_is_set() -> None:
    assert __version__
    assert __version__ != "0.0.0+unknown"


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert CLI_NAME in result.output
    assert __version__ in result.output


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code != 0
    assert "Usage" in result.output
