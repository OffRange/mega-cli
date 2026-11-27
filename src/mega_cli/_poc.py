"""Proof of concept for MEGA's login flow.

Walks through MEGA's authentication end to end.
Credentials are read from the ``EMAIL`` and ``PASSWORD`` environment variables.

Run it with:

- uv:    ``uv run --env-file .env python -m mega_cli._poc``
- plain: ``python -m mega_cli._poc``
"""

import json
import logging
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


def main() -> None:
    email = os.environ["EMAIL"]
    password = os.environ["PASSWORD"]

    with MegaClient() as api:
        prelogin = api.request(PreLogin(email=email))
        salt = base64url_decode(prelogin.salt)
        login_keys = derive_v2_login_keys(password, salt)

        response = api.request(Login(email=email, user_handle=login_keys.user_hash))
        master_key = unwrap_key(base64url_decode(response.master_key), login_keys.password_key)
        private_key = decrypt_private_key(response.private_key, master_key)
        sid = decrypt_session_id(response.encrypted_sid, private_key)

        # Verify the expected user handle without exposing session material.
        sid_bytes = base64url_decode(sid)
        if (
            len(sid_bytes) != 43
            or sid_bytes[16:27].decode("ascii", "replace") != response.user_handle
        ):
            raise SystemExit("Session check failed: wrong password or unexpected server response.")

        api.sid = sid
        user_data = api.request(UserData())
        print(json.dumps(user_data, indent=2))


if __name__ == "__main__":
    main()
