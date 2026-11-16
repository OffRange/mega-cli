import logging
import re

_SID_PARAM = re.compile(r"([?&]sid=)[^&\s\"']*")


class RedactSidFilter(logging.Filter):
    """Removes the ``sid`` query parameter from log messages.

    httpx2 logs every request URL at INFO, and the session ID travels as ``?sid=``.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = _SID_PARAM.sub(r"\1<redacted>", message)
        if redacted != message:
            record.msg, record.args = redacted, None
        return True


def install_sid_redaction(logger_name: str = "httpx2") -> None:
    """Attach :class:`RedactSidFilter` to a logger. Safe to call more than once."""
    logger = logging.getLogger(logger_name)
    if not any(isinstance(f, RedactSidFilter) for f in logger.filters):
        logger.addFilter(RedactSidFilter())
