from enum import IntEnum


class MegaErrorCode(IntEnum):
    """
    Selection of error codes gathered from the official MEGA SDK
    https://github.com/meganz/sdk/blob/2c95a487b4b297dba1d792c88189d432c3452694/include/mega/types.h#L191-L245
    """

    EINTERNAL = -1
    """Internal error"""

    EARGS = -2
    """Bad Arguments"""

    EAGAIN = -3
    """Request failed, retry with exponential backoff"""

    ERATELIMIT = -4
    """Too many requests"""

    EFAILED = -5
    """Request failed permanently. Per command (not- batch level)"""

    ENOENT = -9
    """Resource does not exist"""

    EACCESS = -11
    """Access denied"""

    ESID = -15
    """Bad session ID"""

    EOVERQUOTA = -17
    """Quota exceeded"""

    EMFAREQUIRED = -26
    """MFA required"""


class MegaClientError(Exception):
    """Base exception for everything this package raises."""


class MegaApiError(MegaClientError):
    """Exception for MEGA specific errors"""

    def __init__(self, code: int, command: str | None):
        self.code = code
        self.command = command

        try:
            known: MegaErrorCode | None = MegaErrorCode(code)
        except ValueError:
            known = None
        self.error = known

        name = known.name if known else "UNKNOWN"
        msg = known.__doc__ if known else "Unknown error"
        where = f" in command '{command}'" if command else ""

        super().__init__(f"{name} ({code}){where}: {msg}")
