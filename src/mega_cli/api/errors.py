from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum

from mega_cli import CLI_NAME
from mega_cli.api import BaseCommand


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
            labels = ", ".join(f"{cmd.__name__} ('{cmd.name}')" for cmd in self.commands)
            where = f" in command {labels}"
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


_LOGIN_HINT = f"Run `{CLI_NAME} login` to sign in again."
API_ERRORS: dict[MegaErrorCode, UserError] = {
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
}
