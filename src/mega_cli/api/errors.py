import traceback
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

import typer
from rich.console import Console
from rich.text import Text
from typer import _click
from typer.core import TyperGroup

from mega_cli import CLI_NAME
from mega_cli.api import BaseCommand
from mega_cli.logging import redact
from mega_cli.session import (
    KEYRING_TIMEOUT_ENV,
    InsecureSessionFileError,
    KeyringTimeoutError,
    KeyringUnavailableError,
    SessionError,
    SessionNotFoundError,
)


class MegaErrorCode(IntEnum):
    """
    Selection of error codes gathered from the official MEGA SDK
    https://github.com/meganz/sdk/blob/2c95a487b4b297dba1d792c88189d432c3452694/include/mega/types.h#L191-L245
    """

    EINTERNAL = -1
    EARGS = -2
    EAGAIN = -3
    ERATELIMIT = -4
    EFAILED = -5
    ENOENT = -9
    EACCESS = -11
    ESID = -15
    EOVERQUOTA = -17
    EMFAREQUIRED = -26

    @property
    def description(self) -> str:
        return _DESCRIPTIONS[self]

    @property
    def is_retryable(self) -> bool:
        return self in _RETRYABLE


_DESCRIPTIONS: dict[MegaErrorCode, str] = {
    MegaErrorCode.EINTERNAL: "Internal error",
    MegaErrorCode.EARGS: "Bad arguments",
    MegaErrorCode.EAGAIN: "Request failed, retry with exponential backoff",
    MegaErrorCode.ERATELIMIT: "Too many requests",
    MegaErrorCode.EFAILED: "Request failed permanently. Per command (not batch level)",
    MegaErrorCode.ENOENT: "Resource does not exist",
    MegaErrorCode.EACCESS: "Access denied",
    MegaErrorCode.ESID: "Bad session ID",
    MegaErrorCode.EOVERQUOTA: "Quota exceeded",
    MegaErrorCode.EMFAREQUIRED: "MFA required",
}

_RETRYABLE = frozenset({MegaErrorCode.EAGAIN, MegaErrorCode.ERATELIMIT})


def command_labels(commands: Sequence[type[BaseCommand]]) -> str:
    """E.g. ``Login ('us'), Ping ('ping')``"""
    return ", ".join(f"{cmd.__name__} ('{cmd.name}')" for cmd in commands)


class MegaClientError(Exception):
    """Base exception for everything this package raises."""


class MegaTransportError(MegaClientError):
    """Exception for the client's transport layer"""


class MegaProtocolError(MegaClientError):
    """Exception for the client's protocol layer"""


class MegaApiError(MegaClientError):
    """Exception for MEGA specific errors"""

    def __init__(self, code: int, commands: Sequence[type[BaseCommand]] = ()):
        super().__init__(code, tuple(commands))
        self.code = code
        self.commands = tuple(commands)
        """Command classes the error belongs to. More than one for a batch-level error"""

        try:
            known: MegaErrorCode | None = MegaErrorCode(code)
        except ValueError:
            known = None
        self.error = known

    def __str__(self) -> str:
        name = self.error.name if self.error else "UNKNOWN"
        msg = self.error.description if self.error else "Unknown error"
        where = ""
        if self.commands:
            where = f" in command {command_labels(self.commands)}"
        return f"{name} ({self.code}){where}: {msg}"

    @property
    def is_retryable(self) -> bool:
        return self.error is not None and self.error.is_retryable


class ExitCode(IntEnum):
    OK = 0
    GENERAL = 1
    USAGE = 2  # Click already uses this for bad arguments and options
    AUTH = 3
    NOT_FOUND = 4
    QUOTA = 5
    NETWORK = 6


@dataclass(frozen=True)
class UserError:
    message: str
    exit_code: ExitCode


_LOGIN_HINT = f"Run `{CLI_NAME} login` to sign in."
API_ERRORS: dict[MegaErrorCode | None, UserError] = {
    MegaErrorCode.EINTERNAL: UserError(
        "MEGA reported an internal error. Try later again.", ExitCode.GENERAL
    ),
    MegaErrorCode.EARGS: UserError(
        f"MEGA rejected the request. This is likely a bug in {CLI_NAME}", ExitCode.GENERAL
    ),
    MegaErrorCode.EAGAIN: UserError(
        "MEGA is temporarily unavailable. Try later again.", ExitCode.NETWORK
    ),
    MegaErrorCode.ERATELIMIT: UserError(
        "Too many requests to MEGA. try later again.", ExitCode.NETWORK
    ),
    MegaErrorCode.EFAILED: UserError("The request failed on MEGA's side", ExitCode.GENERAL),
    MegaErrorCode.ENOENT: UserError("Not found.", ExitCode.NOT_FOUND),
    MegaErrorCode.EACCESS: UserError("Access denied", ExitCode.AUTH),
    MegaErrorCode.ESID: UserError(f"Your session has expired. {_LOGIN_HINT}", ExitCode.AUTH),
    MegaErrorCode.EOVERQUOTA: UserError(
        "Quota exceeded: your storage is full. Free up space.",
        ExitCode.QUOTA,
    ),
    MegaErrorCode.EMFAREQUIRED: UserError("Two-factor authentication is required.", ExitCode.AUTH),
    None: UserError("MEGA returned an unknown error code: <code>.", ExitCode.GENERAL),
}

COMMAND_OVERRIDES: dict[tuple[str, MegaErrorCode | None], UserError] = {
    ("us", MegaErrorCode.ENOENT): UserError("Wrong email or password.", ExitCode.AUTH),
}

VERBOSE_KEY = "mega_cli.verbose"


def _sentence(e: Exception) -> str:
    """The exception message as the start of a sentence."""
    msg = str(e)
    return msg[:1].upper() + msg[1:]


def _describe_session_error(e: SessionError) -> UserError:
    if isinstance(e, SessionNotFoundError):
        return UserError(f"You are not logged in. {_LOGIN_HINT}", ExitCode.AUTH)

    if isinstance(e, InsecureSessionFileError):
        return UserError(
            f"Refusing to use the saved session: {e}. "
            f"Make the file private (chmod 600) or delete it. {_LOGIN_HINT}",
            ExitCode.GENERAL,
        )

    if isinstance(e, KeyringTimeoutError):
        return UserError(
            f"The OS keyring did not respond ({e}). Unlock it if a prompt is open and try again, "
            f"or set {KEYRING_TIMEOUT_ENV} to wait longer.",
            ExitCode.GENERAL,
        )

    if isinstance(e, KeyringUnavailableError):
        return UserError(
            f"{_sentence(e)}. Make sure the OS keyring is running and unlocked.",
            ExitCode.GENERAL,
        )

    return UserError(f"The saved session could not be used: {e}. {_LOGIN_HINT}", ExitCode.GENERAL)


def _describe_mega_client_error(e: MegaClientError) -> UserError:
    if isinstance(e, MegaApiError):
        for cmd in e.commands:
            if override := COMMAND_OVERRIDES.get((cmd.name, e.error)):
                return override

        user_error = API_ERRORS[e.error]
        user_error = UserError(
            user_error.message.replace("<code>", str(e.code)), user_error.exit_code
        )
        return user_error

    elif isinstance(e, MegaTransportError):
        return UserError(f"{e}. Check your internet connection.", ExitCode.NETWORK)

    elif isinstance(e, MegaProtocolError):
        return UserError("MEGA sent an unexpected response.", ExitCode.GENERAL)

    return UserError("An unexpected error occurred.", ExitCode.GENERAL)


def _describe(e: MegaClientError | SessionError) -> UserError:
    if isinstance(e, SessionError):
        return _describe_session_error(e)

    elif isinstance(e, MegaClientError):
        return _describe_mega_client_error(e)


def report(e: MegaClientError | SessionError, *, verbose: bool, console: Console) -> ExitCode:
    user_error = _describe(e)
    if verbose:
        _print_stacktrace(e, console)

    _print_error_line(user_error.message, console)
    return user_error.exit_code


def report_unexpected(exc: Exception, *, verbose: bool, console: Console) -> ExitCode:
    if verbose:
        _print_stacktrace(exc, console)

    hint = "" if verbose else " Re-run with --verbose to see further information."
    _print_error_line(
        f"Unexpected error ({type(exc).__name__}).{hint}",
        console,
    )
    return ExitCode.GENERAL


def _print_stacktrace(e: BaseException, console: Console) -> None:
    tb = "".join(traceback.format_exception(e))  # stdlib: never includes locals
    console.print(redact(tb), markup=False, highlight=False, soft_wrap=True)


def _print_error_line(message: str, console: Console) -> None:
    console.print(Text.assemble(("Error: ", "bold red"), redact(message)), soft_wrap=True)


class MegaErrorHandlerGroup(TyperGroup):
    def invoke(self, ctx: _click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except (typer.TyperException, typer.Exit, typer.Abort):
            raise  # Click's own control flow and usage errors: leave untouched
        except (MegaClientError, SessionError) as e:
            verbose = bool(ctx.meta.get(VERBOSE_KEY, False))
            raise typer.Exit(report(e, verbose=verbose, console=Console(stderr=True))) from None
        except Exception as e:
            verbose = bool(ctx.meta.get(VERBOSE_KEY, False))
            raise typer.Exit(
                report_unexpected(e, verbose=verbose, console=Console(stderr=True))
            ) from None
