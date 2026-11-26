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

from mega_cli.api import BaseCommand, Field, MegaClient
from mega_cli.crypto import (
    base64url_decode,
    decrypt_private_key,
    decrypt_session_id,
    derive_v2_login_keys,
    unwrap_key,
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


def byte_length(n: int) -> int:
    return math.ceil(n.bit_length() / 8)


def main() -> None:
    email = os.environ["EMAIL"]
    password = os.environ["PASSWORD"]

    with MegaClient() as api:
        # 1. Pre-Login: Salt abrufen
        prelogin = api.request(PreLogin(email=email))
        salt = base64url_decode(prelogin.salt)

        # 2. Passwort-Key und User-Hash ableiten
        login_keys = derive_v2_login_keys(password, salt)

        # 3. MEGA-Login
        response = api.request(Login(email=email, user_handle=login_keys.user_hash))

        # 4. Master-Key mit AES-128-ECB entschlüsseln
        master_key = unwrap_key(
            base64url_decode(response.master_key),
            login_keys.password_key,
        )

        # 5. RSA-Private-Key entschlüsseln und MPIs parsen
        private_key = decrypt_private_key(
            response.private_key,
            master_key,
        )

        # 6. Verschlüsselte Session-ID mit Raw-RSA entschlüsseln
        sid = decrypt_session_id(
            response.encrypted_sid,
            private_key,
        )

        # 7. Session-ID überprüfen
        sid_bytes = base64url_decode(sid)

        if (
            len(sid_bytes) != 43
            or sid_bytes[16:27].decode("ascii", "replace") != response.user_handle
        ):
            raise SystemExit("Session check failed: wrong password or unexpected server response.")

        # 8. Session verwenden und Benutzerdaten abrufen
        api.sid = sid
        user_data = api.request(UserData())

        print(json.dumps(user_data, indent=2))


if __name__ == "__main__":
    main()
