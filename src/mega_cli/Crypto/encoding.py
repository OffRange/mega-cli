"""Shared binary encoding and cryptographic helpers for MEGA API v2.

All cryptographic functions operate on bytes. Only API-facing base64url
functions return/accept text. AES-ECB is used solely for encrypting key
material as required by the MEGA protocol, never for encrypting file data.
"""

import base64
import binascii
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK_SIZE = 16
PBKDF2_ITERATIONS = 100_000


def base64url_encode(data: bytes) -> str:
    """Encode bytes as MEGA base64url (URL alphabet, no trailing '=')."""
    if not isinstance(data, bytes):
        raise TypeError('data must be bytes')
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def base64url_decode(value: str) -> bytes:
    """Decode padded or unpadded base64url, rejecting malformed input."""
    if not isinstance(value, str):
        raise TypeError('value must be str')
    try:
        raw = value.encode('ascii')
    except UnicodeEncodeError as exc:
        raise ValueError('base64url must contain only ASCII characters') from exc

    # A remainder of one is impossible for correctly encoded base64.
    unpadded = raw.rstrip(b'=')
    if b'=' in unpadded or len(unpadded) % 4 == 1:
        raise ValueError('invalid base64url padding or length')
    if len(raw) - len(unpadded) > 2:
        raise ValueError('too much base64url padding')
    if len(raw) != len(unpadded) and len(raw) % 4 != 0:
        raise ValueError('invalid base64url padding')
    padded = unpadded + b'=' * (-len(unpadded) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b'-_', validate=True)
    except binascii.Error as exc:
        raise ValueError('invalid base64url input') from exc
    # Avoid accepting non-canonical trailing bits in final sextet.
    if base64url_encode(decoded).encode('ascii') != unpadded:
        raise ValueError('non-canonical base64url input')
    return decoded


def _validate_aes_inputs(data: bytes, key: bytes) -> None:
    if not isinstance(data, bytes) or not isinstance(key, bytes):
        raise TypeError('data and key must be bytes')
    if len(key) != AES_BLOCK_SIZE:
        raise ValueError('AES-128 key must be exactly 16 bytes')
    if not data or len(data) % AES_BLOCK_SIZE != 0:
        raise ValueError('wrapped data must be a nonempty multiple of 16 bytes')


def wrap_key(plaintext_key: bytes, wrapping_key: bytes) -> bytes:
    """MEGA key wrapping: AES-128-ECB, no padding, arbitrary full blocks."""
    _validate_aes_inputs(plaintext_key, wrapping_key)
    encryptor = Cipher(algorithms.AES(wrapping_key), modes.ECB()).encryptor()
    return encryptor.update(plaintext_key) + encryptor.finalize()


def unwrap_key(wrapped_key: bytes, wrapping_key: bytes) -> bytes:
    """Undo MEGA AES-128-ECB key wrapping (no padding)."""
    _validate_aes_inputs(wrapped_key, wrapping_key)
    decryptor = Cipher(algorithms.AES(wrapping_key), modes.ECB()).decryptor()
    return decryptor.update(wrapped_key) + decryptor.finalize()


@dataclass(frozen=True)
class V2LoginKeys:
    password_key: bytes  # 16 bytes for decrypting the encrypted master key
    user_hash: str       # unpadded base64url to send as `uh` in API `us`


def derive_v2_login_keys(password: str, salt: bytes) -> V2LoginKeys:
    """Derive MEGA v2 login credentials from the password and us0 salt."""
    if not isinstance(password, str):
        raise TypeError('password must be str')
    if not isinstance(salt, bytes):
        raise TypeError('salt must be bytes')
    if not salt:
        raise ValueError('salt must not be empty')

    derived = hashlib.pbkdf2_hmac(
        'sha512', password.encode('utf-8'), salt,
        PBKDF2_ITERATIONS, dklen=32,
    )
    return V2LoginKeys(
        password_key=derived[:16],
        user_hash=base64url_encode(derived[16:]),
    )
