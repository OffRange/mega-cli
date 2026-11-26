"""MEGA base64url encoding helpers.

Encode binary API values as unpadded URL-safe base64 and decode them.
"""

import base64
import binascii


def base64url_encode(data: bytes) -> str:
    """Encode bytes as MEGA base64url (URL alphabet, no trailing '=')."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(value: str) -> bytes:
    """Decode padded or unpadded base64url, rejecting malformed input."""
    if not isinstance(value, str):
        raise TypeError("value must be str")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("base64url must contain only ASCII characters") from exc

    # A remainder of one is impossible for correctly encoded base64.
    unpadded = raw.rstrip(b"=")
    if b"=" in unpadded or len(unpadded) % 4 == 1:
        raise ValueError("invalid base64url padding or length")
    if len(raw) - len(unpadded) > 2:
        raise ValueError("too much base64url padding")
    if len(raw) != len(unpadded) and len(raw) % 4 != 0:
        raise ValueError("invalid base64url padding")
    padded = unpadded + b"=" * (-len(unpadded) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise ValueError("invalid base64url input") from exc
    # Avoid accepting non-canonical trailing bits in final sextet.
    if base64url_encode(decoded).encode("ascii") != unpadded:
        raise ValueError("non-canonical base64url input")
    return decoded
