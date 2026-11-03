import base64
import hashlib
import logging

SLOT_SIZE = 48
PREFIX_LENGTH = 4
REPLICATIONS = 262144

log = logging.getLogger(__name__)


def _threshold_from_easiness(easiness: int) -> int:
    """Based on https://github.com/meganz/sdk/blob/2c95a487b4b297dba1d792c88189d432c3452694/src/hashcash.cpp#L53"""
    return (((easiness & 63) << 1) + 1) << ((easiness >> 6) * 7 + 3)


def _buffer(token: bytes) -> bytearray:
    """
    Build the ~12 MB hashcash input buffer:

        [ 4-byte nonce slot ][ token ][ token ] ... [ token ]

    The nonce slot is zero-filled; the caller writes each candidate nonce there.
    The token is repeated so every hash attempt must process the full buffer.
    Raises if ``token`` is not SLOT_SIZE bytes.
    """
    if len(token) != SLOT_SIZE:
        raise Exception(f"Invalid token length: {len(token)}, expected {SLOT_SIZE}")

    buf = bytearray(PREFIX_LENGTH + SLOT_SIZE * REPLICATIONS)
    buf[PREFIX_LENGTH:] = token * REPLICATIONS
    return buf


def solve_hashcash_challenge(challenge: str) -> str:
    """Simplified version of MEGA SDK's implementation: https://github.com/meganz/sdk/blob/2c95a487b4b297dba1d792c88189d432c3452694/src/hashcash.cpp#L236"""
    (_, easiness, _, token) = challenge.split(":")
    token_b = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))

    threshold = _threshold_from_easiness(int(easiness))
    buffer = _buffer(token_b)

    # Try every possible 4-byte nonce: write it into the nonce slot, hash the full
    # buffer, and accept it if the first 4 bytes of the hash (big-endian) are <= threshold.
    for n in range(2**32):
        nonce = n.to_bytes(PREFIX_LENGTH, "little")
        buffer[:PREFIX_LENGTH] = nonce
        hash_value = hashlib.sha256(buffer).digest()
        value = int.from_bytes(hash_value[:PREFIX_LENGTH], "big")
        if value <= threshold:
            log.debug(f"Hashcash solved: nonce={n}, value={value}")
            pow = base64.urlsafe_b64encode(nonce).rstrip(b"=").decode()
            return f"1:{token}:{pow}"

    raise Exception("Challenge not solved")
