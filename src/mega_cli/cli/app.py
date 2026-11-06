"""
MEGA CLI as part of the "Software Project" module at Mittweida University of Applied Sciences
"""

import typer

from mega_cli import CLI_NAME, __version__

app = typer.Typer(no_args_is_help=True, help=__doc__)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{CLI_NAME} {__version__}")
        raise typer.Exit()


@app.callback()
def root(
        version: bool = typer.Option(
            False,
            "--version",
            "-v",
            help="Show the version",
            callback=_version_callback,
            is_eager=True
        ),
) -> None:
    pass


def main() -> None:
    app()
