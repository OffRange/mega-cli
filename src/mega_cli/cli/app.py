"""
MEGA CLI as part of the "Software Project" module at Mittweida University of Applied Sciences
"""

import logging

import typer
from rich.console import Console
from rich.logging import RichHandler

from mega_cli import CLI_NAME, __version__

app = typer.Typer(no_args_is_help=True, help=__doc__)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{CLI_NAME} {__version__}")
        raise typer.Exit()


def _setup_logger(verbose: bool) -> None:
    handler = RichHandler(
        console=Console(stderr=True),
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
        show_path=verbose,
        markup=False,
        log_time_format="[%X]",
    )
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(name)s: %(message)s",
        handlers=[handler],
        force=True,
    )
    # third-party HTTP libraries are chatty at DEBUG
    for noisy in ("httpx2", "httpcore2"):
        logging.getLogger(noisy).setLevel(logging.INFO if verbose else logging.WARNING)


@app.callback()
def root(
        version: bool = typer.Option(
            False,
            "--version",
            "-v",
            help="Show the version",
            callback=_version_callback,
            is_eager=True,
        ),
        verbose: bool = typer.Option(
            False,
            "--verbose",
            help="Show more detailed logs"
        )
) -> None:
    _setup_logger(verbose)


def main() -> None:
    app()
