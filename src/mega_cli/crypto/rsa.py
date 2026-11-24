"""MEGA login RSA primitives: AES-wrapped MPI private keys and raw RSA SID.

Raw RSA is required for compatibility with MEGA's existing login protocol;
never use it for new encryption designs.
"""

from dataclasses import dataclass, field

from mega_cli.crypto.encoding import base64url_decode, base64url_encode, unwrap_key

SID_LENGTH = 43


class MegaRSAError(ValueError):
    """Invalid MEGA RSA login material."""


class MPIFormatError(MegaRSAError):
    """An MPI is truncated or malformed."""


class PrivateKeyError(MegaRSAError):
    """An encrypted MEGA RSA private key is invalid."""


class SessionDecryptionError(MegaRSAError):
    """A MEGA encrypted session ID is invalid."""


@dataclass(frozen=True)
class MegaPrivateKey:
    """Private components needed for the MEGA login; never expose in repr."""

    p: int = field(repr=False)
    q: int = field(repr=False)
    d: int = field(repr=False)

    def __repr__(self) -> str:
        return "MegaPrivateKey(<redacted>)"


def parse_mpis(data: bytes, count: int) -> tuple[int, ...]:
    """Decode exactly *count* big-endian, bit-length-prefixed MEGA MPIs.

    The AES-decrypted private key may have up to 15 zero padding bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError("MPI data must be bytes")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise ValueError("MPI count must be a positive integer")
    offset = 0
    values: list[int] = []
    for index in range(count):
        if len(data) - offset < 2:
            raise MPIFormatError(f"truncated MPI {index + 1} header")
        bits = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        byte_count = (bits + 7) // 8
        if len(data) - offset < byte_count:
            raise MPIFormatError(f"truncated MPI {index + 1} value")
        value = int.from_bytes(data[offset : offset + byte_count], "big")
        offset += byte_count
        if value.bit_length() != bits:
            raise MPIFormatError(f"invalid MPI {index + 1} bit length")
        values.append(value)

    trailing = data[offset:]
    if len(trailing) >= 16 or any(trailing):
        raise MPIFormatError("unexpected nonzero or excessive MPI trailing data")
    return tuple(values)


def decrypt_private_key(encrypted_privk: str, master_key: bytes) -> MegaPrivateKey:
    """Decrypt API `privk` (base64url AES-ECB ciphertext) and parse p, q, d, u.

    u is intentionally parsed but not interpreted; p, q and d suffice.
    """
    try:
        plaintext = unwrap_key(base64url_decode(encrypted_privk), master_key)
        p, q, d, _u = parse_mpis(plaintext, 4)
    except (ValueError, TypeError) as exc:
        raise PrivateKeyError("invalid encrypted MEGA private key") from exc
    if p <= 1 or q <= 1 or p == q or d <= 0:
        raise PrivateKeyError("invalid RSA private key components")
    return MegaPrivateKey(p=p, q=q, d=d)


def decrypt_session_id(encrypted_csid: str, private_key: MegaPrivateKey) -> str:
    """Decrypt MEGA's single-MPI raw-RSA `csid` to 43-byte base64url `sid`.

    Protocol width is reconstructed before slicing, preserving leading zeroes.
    """
    if not isinstance(private_key, MegaPrivateKey):
        raise TypeError("private_key must be MegaPrivateKey")
    try:
        (ciphertext,) = parse_mpis(base64url_decode(encrypted_csid), 1)
        n = private_key.p * private_key.q
        if ciphertext >= n:
            raise SessionDecryptionError("RSA ciphertext is outside the modulus")
        plaintext_int = pow(ciphertext, private_key.d, n)
        # The -2 is MEGA's legacy RSA decoding width convention.
        width = max(
            (private_key.p.bit_length() + 7) // 8 + (private_key.q.bit_length() + 7) // 8 - 2,
            (plaintext_int.bit_length() + 7) // 8,
        )
        if width < SID_LENGTH:
            raise SessionDecryptionError("RSA plaintext is too short for a session ID")
        sid_bytes = plaintext_int.to_bytes(width, "big")[:SID_LENGTH]
        return base64url_encode(sid_bytes)
    except SessionDecryptionError:
        raise
    except (ValueError, OverflowError, TypeError) as exc:
        raise SessionDecryptionError("invalid encrypted MEGA session ID") from exc
