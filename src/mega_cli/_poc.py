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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mega_cli.api import BaseCommand, Field, MegaClient

SID_LENGTH = 43

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

log = logging.getLogger(__name__)


class PreLogin(BaseCommand, name="us0"):
    email: str = Field(api_alias="user")


class Login(BaseCommand, name="us"):
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
        salt = api.request(PreLogin(email=EMAIL))["s"]
        salt = base64.urlsafe_b64decode(salt + "=" * (-len(salt) % 4))

        kdf = PBKDF2HMAC(hashes.SHA512(), 32, salt, 100_000)
        key = kdf.derive(PASSWORD.encode("utf-8"))
        password_key = key[:16]
        auth_key = key[16:]
        user_handle = base64.urlsafe_b64encode(auth_key).rstrip(b"=").decode()

        resp = api.request(Login(email=EMAIL, user_handle=user_handle))
        cipher = Cipher(algorithms.AES128(password_key), modes.ECB()).decryptor()
        master_key = cipher.update(b64dec(resp["k"])) + cipher.finalize()

        cipher = Cipher(algorithms.AES128(master_key), modes.ECB()).decryptor()
        rsa_priv = cipher.update(b64dec(resp["privk"])) + cipher.finalize()
        prime1, prime2, d, _u = read_mpis(rsa_priv, 4)

        (ciphertext,) = read_mpis(b64dec(resp["csid"]), 1)
        plain = pow(ciphertext, d, prime1 * prime2)

        # https://github.com/meganz/sdk/blob/2c95a487b4b297dba1d792c88189d432c3452694/src/crypto/cryptopp.cpp#L1147-L1159
        width = max(
            byte_length(prime1) + byte_length(prime2) - 2,
            byte_length(plain),
        )
        sid = plain.to_bytes(width, "big")[:SID_LENGTH]

        # Check user handle
        if sid[16:27].decode("ascii", "replace") != resp["u"]:
            raise SystemExit("Session check failed: wrong password or unexpected server response.")

        sid = b64enc(sid)
        api.sid = sid

        resp = api.request(UserData())
        print(json.dumps(resp, indent=2))


if __name__ == "__main__":
    main()
