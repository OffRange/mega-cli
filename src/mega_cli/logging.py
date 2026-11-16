import logging
import re

# API field names whose values are secret: session IDs, user handle, password and key material
_SENSITIVE = ("sid", "csid", "tsid", "uh", "k", "privk", "password")
_ALTS = "|".join(_SENSITIVE)

# ?sid=... / &uh=... in URLs
_QUERY_PARAM = re.compile(rf"([?&](?:{_ALTS})=)[^&\s\"']*")
# 'sid': '...' / "k": "..." in dict reprs and JSON
_MAPPING_VALUE = re.compile(rf"""(["'](?:{_ALTS})["']\s*:\s*)(["'])(?:\\.|(?!\2).)*\2""")


def redact(msg: str) -> str:
    """Replace values of sensitive API fields in ``msg`` with ``<redacted>``.

    A fallback only: secrets should be kept out of messages in the first place.
    """
    msg = _QUERY_PARAM.sub(r"\1<redacted>", msg)
    return _MAPPING_VALUE.sub(r"\1\2<redacted>\2", msg)


class RedactSidFilter(logging.Filter):
    """Removes sensitive values (e.g. the ``sid`` query parameter) from log messages.

    httpx2 logs every request URL at INFO, and the session ID travels as ``?sid=``.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = redact(message)
        if redacted != message:
            record.msg, record.args = redacted, None
        return True


def install_sid_redaction(logger_name: str = "httpx2") -> None:
    """Attach :class:`RedactSidFilter` to a logger. Safe to call more than once."""
    logger = logging.getLogger(logger_name)
    if not any(isinstance(f, RedactSidFilter) for f in logger.filters):
        logger.addFilter(RedactSidFilter())
