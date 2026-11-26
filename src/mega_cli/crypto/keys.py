"""AES-128 key wrapping and MEGA v2 password-key derivation."""

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .encoding import base64url_encode

AES_BLOCK_SIZE = 16
PBKDF2_ITERATIONS = 100_000


def wrap_key(plaintext_key: bytes, wrapping_key: bytes) -> bytes:
    """MEGA key wrapping: AES-128-ECB, no padding, arbitrary full blocks."""
    if not plaintext_key:
        raise ValueError("key data must not be empty")
    encryptor = Cipher(algorithms.AES128(wrapping_key), modes.ECB()).encryptor()
    return encryptor.update(plaintext_key) + encryptor.finalize()


def unwrap_key(wrapped_key: bytes, wrapping_key: bytes) -> bytes:
    """Undo MEGA AES-128-ECB key wrapping (no padding)."""
    if not wrapped_key:
        raise ValueError("key data must not be empty")
    decryptor = Cipher(algorithms.AES128(wrapping_key), modes.ECB()).decryptor()
    return decryptor.update(wrapped_key) + decryptor.finalize()


@dataclass(frozen=True)
class V2LoginKeys:
    password_key: bytes  # 16 bytes for decrypting the encrypted master key
    user_hash: str  # unpadded base64url to send as `uh` in API `us`


def derive_v2_login_keys(password: str, salt: bytes) -> V2LoginKeys:
    """Derive MEGA v2 login credentials from the password and us0 salt."""
    if not salt:
        raise ValueError("salt must not be empty")

    derived = hashlib.pbkdf2_hmac(
        "sha512",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return V2LoginKeys(
        password_key=derived[:16],
        user_hash=base64url_encode(derived[16:]),
    )
