"""Proof of concept for MEGA's login flow.

Walks through MEGA's authentication end to end.
Credentials are read from the ``EMAIL`` and ``PASSWORD`` environment variables.

Run it with:

- uv:    ``uv run --env-file .env python -m mega_cli._poc``
- plain: ``python -m mega_cli._poc``
"""

import json
import logging
import math
import os
from dataclasses import dataclass


from mega_cli.api import BaseCommand, Field, MegaClient
from mega_cli.crypto import base64url_decode, base64url_encode, derive_v2_login_keys, unwrap_key

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
    email = os.environ["EMAIL"]
    password = os.environ["PASSWORD"]
    with MegaClient() as api:
        salt = base64url_decode(api.request(PreLogin(email=email)).salt)
        login_keys = derive_v2_login_keys(password, salt)

        resp = api.request(Login(email=email, user_handle=login_keys.user_hash))
        master_key = unwrap_key(base64url_decode(resp.master_key), login_keys.password_key)
        rsa_priv = unwrap_key(base64url_decode(resp.private_key), master_key)
        prime1, prime2, d, _u = read_mpis(rsa_priv, 4)

        (ciphertext,) = read_mpis(base64url_decode(resp.encrypted_sid), 1)
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

        sid = base64url_encode(sid)
        api.sid = sid

        resp = api.request(UserData())
        print(json.dumps(resp, indent=2))


if __name__ == "__main__":
    main()
