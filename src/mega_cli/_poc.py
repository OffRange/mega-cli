"""Proof of concept for MEGA's login flow.

Walks through MEGA's authentication end to end.
Credentials are read from the ``EMAIL`` and ``PASSWORD`` environment variables.

Run it with:

- uv:    ``uv run --env-file .env python -m mega_cli._poc``
- plain: ``python -m mega_cli._poc``
"""

import base64
import json
import logging
import math
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mega_cli.api import BaseCommand, Field, MegaClient
from mega_cli.crypto.encoding import (
    base64url_decode,
    base64url_encode,
    unwrap_key,
    wrap_key,
)
from mega_cli.crypto.rsa import (
    decrypt_private_key,
    decrypt_session_id,
    parse_mpis,
)

SID_LENGTH = 43

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

log = logging.getLogger(__name__)


@dataclass
class PreLoginResponse:
    salt: str = Field(api_alias="s", default=None)


class PreLogin(BaseCommand[PreLoginResponse], name="us0"):
    email: str = Field(api_alias="user")


@dataclass
class LoginResponse:
    master_key: str = Field(api_alias="k")
    """Master key, encrypted with the password key"""
    private_key: str = Field(api_alias="privk")
    """RSA private key, encrypted with the master key"""
    encrypted_sid: str = Field(api_alias="csid")
    """Session ID, encrypted with the RSA public key"""
    user_handle: str = Field(api_alias="u")


class Login(BaseCommand[LoginResponse], name="us"):
    email: str = Field(api_alias="user")
    user_handle: str = Field(api_alias="uh")
    mfa: str | None = None


class UserData(BaseCommand, name="ug"):
    v: int = 1


EMAIL = os.environ["EMAIL"]
PASSWORD = os.environ["PASSWORD"]


def b64dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


SHORT_PRIVATE_KEY = 3


def read_mpis(data: bytes, count: int) -> list[int]:
    """
    Based on https://github.com/meganz/sdk/blob/2c95a487b4b297dba1d792c88189d432c3452694/src/crypto/cryptopp.cpp#L1283
    Read MEGA's multi-precision integers: a 2-byte bit length, then the bytes.
    """
    data_len = len(data)
    values = []
    pos = 0
    for _ in range(count):
        if pos + 2 > data_len:
            raise ValueError("truncated MPI header")

        bits = int.from_bytes(data[pos : pos + 2], "big")
        length = (bits + 7) // 8
        pos += 2
        if pos + length > data_len:
            raise ValueError("truncated MPI value")

        values.append(int.from_bytes(data[pos : pos + length], "big"))
        pos += length

    if data_len - pos >= 16:
        raise ValueError("too much trailing data (wrong key or malformed input)")

    if count == 3:
        # u missing: calculate using inverse mod
        p, q, _ = values
        u = pow(p, -1, q)
        values.append(u)

    return values


def byte_length(n: int) -> int:
    return math.ceil(n.bit_length() / 8)


def main() -> None:
    with MegaClient() as api:
        salt = api.request(PreLogin(email=EMAIL)).salt
        salt = base64.urlsafe_b64decode(salt + "=" * (-len(salt) % 4))

        kdf = PBKDF2HMAC(hashes.SHA512(), 32, salt, 100_000)
        key = kdf.derive(PASSWORD.encode("utf-8"))
        password_key = key[:16]
        auth_key = key[16:]
        user_handle = base64.urlsafe_b64encode(auth_key).rstrip(b"=").decode()

        resp = api.request(Login(email=EMAIL, user_handle=user_handle))
        cipher = Cipher(algorithms.AES128(password_key), modes.ECB()).decryptor()
        master_key = cipher.update(b64dec(resp.master_key)) + cipher.finalize()

        cipher = Cipher(algorithms.AES128(master_key), modes.ECB()).decryptor()
        rsa_priv = cipher.update(b64dec(resp.private_key)) + cipher.finalize()
        prime1, prime2, d, _u = read_mpis(rsa_priv, 4)

        (ciphertext,) = read_mpis(b64dec(resp.encrypted_sid), 1)
        plain = pow(ciphertext, d, prime1 * prime2)

        # https://github.com/meganz/sdk/blob/2c95a487b4b297dba1d792c88189d432c3452694/src/crypto/cryptopp.cpp#L1147-L1159
        width = max(
            byte_length(prime1) + byte_length(prime2) - 2,
            byte_length(plain),
        )
        sid = plain.to_bytes(width, "big")[:SID_LENGTH]

        # Check user handle
        if sid[16:27].decode("ascii", "replace") != resp.user_handle:
            raise SystemExit("Session check failed: wrong password or unexpected server response.")

        sid = b64enc(sid)
        api.sid = sid

        resp = api.request(UserData())
        print(json.dumps(resp, indent=2))


def crypto_rsa_poc() -> None:
    # 1. Encoding testen
    original = b"MEGA Encoding Test"
    encoded = base64url_encode(original)
    decoded = base64url_decode(encoded)

    assert decoded == original
    print("[1] Base64url Round-Trip")

    # 2. AES-Key-Wrapping testen
    master_key = bytes(range(16))
    key = bytes(range(16, 32))

    wrapped = wrap_key(key, master_key)
    unwrapped = unwrap_key(wrapped, master_key)

    assert unwrapped == key
    print("[2] AES-128 Key-Wrapping")

    # 3. RSA-Key erzeugen
    test_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    numbers = test_key.private_numbers()

    # MEGA MPI-Format erzeugen
    def mpi_encode(value: int) -> bytes:
        bits = value.bit_length()
        data = value.to_bytes((bits + 7) // 8, "big")
        return bits.to_bytes(2, "big") + data

    # MPI-Parsing überprüfen
    values = (numbers.p, numbers.q, numbers.d, 1)
    encoded_mpis = b"".join(mpi_encode(v) for v in values)

    assert parse_mpis(encoded_mpis, 4) == values
    print("[3] RSA MPI-Parsing")

    # 4. Privaten RSA-Key mit AES verschlüsseln
    padding = (-len(encoded_mpis)) % 16
    encrypted_privk = wrap_key(
        encoded_mpis + bytes(padding),
        master_key,
    )

    private_key = decrypt_private_key(
        base64url_encode(encrypted_privk),
        master_key,
    )
    print("[4] RSA Private-Key entschlüsselt")

    # 5. Synthetische Session-ID mit führenden Nullbytes
    sid = b"\x00\x00" + bytes(range(41))

    # MEGA legt die SID im linken Teil des RSA-Klartexts ab
    width = (numbers.p.bit_length() + 7) // 8 + (numbers.q.bit_length() + 7) // 8 - 2

    plaintext = sid.ljust(width, b"\x00")
    plaintext_int = int.from_bytes(plaintext, "big")

    # 6. Raw-RSA-Verschlüsselung
    ciphertext_int = pow(
        plaintext_int,
        numbers.public_numbers.e,
        numbers.public_numbers.n,
    )

    csid = base64url_encode(mpi_encode(ciphertext_int))

    decrypted_sid = decrypt_session_id(
        csid,
        private_key,
    )

    assert base64url_decode(decrypted_sid) == sid
    print("[5] Führende Nullbytes erhalten")
    print("[6] RSA Session-ID entschlüsselt")


if __name__ == "__main__":
    crypto_rsa_poc()
    main()
