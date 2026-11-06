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
from types import TracebackType
from typing import Any, Self

import httpx2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mega_cli import hashcash

DEFAULT_BASE_URL = "https://g.api.mega.co.nz"
MAX_HASHCASH_ROUNDS = 3
SID_LENGTH = 43

type Command = dict[str, Any]

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

log = logging.getLogger(__name__)


def prelogin(email: str) -> Command:
    """Ask for the account version and salt. Response: ``{"v": 2, "s": "<salt>"}``."""
    return {"a": "us0", "user": email}


def login(email: str, user_hash: str, mfa_code: str | None = None) -> Command:
    """Log in. ``user_hash`` is base64url(authKey).

    Response has ``k``, ``privk``, ``csid`` and ``u``.
    """
    command: Command = {"a": "us", "user": email, "uh": user_hash}
    if mfa_code:
        command["mfa"] = mfa_code
    return command


def user_data() -> Command:
    return {"a": "ug", "v": 1}


class Client:
    def __init__(self, base_url: str = DEFAULT_BASE_URL):
        self.base_url = base_url
        self._http = httpx2.Client(base_url=base_url)

        self.sid: str | None = None

    def close(self) -> None:
        self._http.close()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __enter__(self) -> Self:
        return self

    def _params(self) -> dict[str, str]:
        params = {}
        if self.sid:
            params["sid"] = self.sid

        return params

    def send(self, command: Command) -> Any:
        headers = {"Content-Type": "application/json"}
        params = self._params()
        for _ in range(MAX_HASHCASH_ROUNDS):
            response = self._http.post(
                "/cs", content=json.dumps([command]), params=params, headers=headers
            )

            if response.status_code != 402:
                return self._decode(response)[0]

            challenge = response.headers.get("x-hashcash")
            if not challenge:
                raise Exception("Request failed with 402")

            log.debug("Solving hashcash challenge")
            headers["x-hashcash"] = hashcash.solve_hashcash_challenge(challenge)

        raise Exception("Server refused hashcat solution")

    @staticmethod
    def _decode(response: httpx2.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            raise Exception(f"Response is not JSON: {response.text[:200]!r}") from None


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
    with Client(base_url=DEFAULT_BASE_URL) as api:
        salt = api.send(prelogin(EMAIL))["s"]
        salt = base64.urlsafe_b64decode(salt + "=" * (-len(salt) % 4))

        kdf = PBKDF2HMAC(hashes.SHA512(), 32, salt, 100_000)
        key = kdf.derive(PASSWORD.encode("utf-8"))
        password_key = key[:16]
        auth_key = base64.urlsafe_b64encode(key[16:]).rstrip(b"=").decode()

        resp = api.send(login(EMAIL, auth_key))
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
            raise SystemExit(
                "Session check failed: wrong password or unexpected server response."
            )

        sid = b64enc(sid)
        api.sid = sid

        resp = api.send(user_data())
        print(json.dumps(resp, indent=2))


if __name__ == "__main__":
    main()
