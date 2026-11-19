from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx2
import pytest
import typer
from typer.testing import CliRunner, Result

from mega_cli import hashcash
from mega_cli.api import BaseCommand, Field, MegaClient
from mega_cli.api.errors import (
    API_ERRORS,
    ExitCode,
    MegaApiError,
    MegaClientError,
    MegaErrorCode,
    MegaErrorHandlerGroup,
    MegaProtocolError,
    MegaTransportError,
)
from mega_cli.cli.app import root
from mega_cli.session import (
    InsecureSessionFileError,
    KeyringTimeoutError,
    KeyringUnavailableError,
    SessionError,
    SessionNotFoundError,
)

BASE_URL = "https://test.example.mega"
SECRET_SID = "SeCrEtSiD-do-not-leak-0123456789abcdef"
SECRET_UH = "SeCrEtUserHash-do-not-leak"
SECRET_PASSWORD = "SeCrEtPassword-do-not-leak"
SECRET_KEY = "SeCrEtMasterKey-do-not-leak"
SECRETS = (SECRET_SID, SECRET_UH, SECRET_PASSWORD, SECRET_KEY)

runner = CliRunner()


class Ping(BaseCommand, name="ping"):
    pass


@dataclass
class LoginResponse:
    session_id: str = Field(api_alias="csid")


class Login(BaseCommand[LoginResponse], name="us"):
    email: str = Field(api_alias="user")
    user_handle: str = Field(api_alias="uh")


def make_app(action: Callable[[], None]) -> typer.Typer:
    """An app wired like ``mega_cli.cli.app``, with one subcommand ``run`` executing ``action``."""
    app = typer.Typer(cls=MegaErrorHandlerGroup, pretty_exceptions_show_locals=False)
    app.callback()(root)
    app.command("run")(action)
    return app


def run(action: Callable[[], None], *, verbose: bool = False) -> Result:
    args = ["--verbose", "run"] if verbose else ["run"]
    return runner.invoke(make_app(action), args)


def raising(exc: BaseException) -> Callable[[], None]:
    def action() -> None:
        raise exc

    return action


def make_client(handler: Callable[[httpx2.Request], httpx2.Response], **kwargs: Any) -> MegaClient:
    http = httpx2.Client(base_url=BASE_URL, transport=httpx2.MockTransport(handler))
    return MegaClient(http_client=http, sleep=lambda _: None, **kwargs)


def replying(reply: Any) -> Callable[[httpx2.Request], httpx2.Response]:
    def handler(_: httpx2.Request) -> httpx2.Response:
        return reply if isinstance(reply, httpx2.Response) else httpx2.Response(200, json=reply)

    return handler


def squashed(result: Result) -> str:
    """Output without whitespace: Rich wraps long lines, which could split a secret."""
    return "".join(result.output.split())


def assert_no_secrets(result: Result) -> None:
    for secret in SECRETS:
        assert secret not in squashed(result)


def error_lines(result: Result) -> list[str]:
    return [line for line in result.output.splitlines() if line.startswith("Error: ")]


# --- documented exit codes -------------------------------------------------------------------
def test_exit_code_values_are_stable() -> None:
    # Scripts rely on these numbers: changing one is a breaking change
    assert {c.name: c.value for c in ExitCode} == {
        "OK": 0,
        "GENERAL": 1,
        "USAGE": 2,
        "AUTH": 3,
        "NOT_FOUND": 4,
        "QUOTA": 5,
        "NETWORK": 6,
    }


def test_every_known_error_code_has_a_message() -> None:
    assert set(MegaErrorCode) <= set(API_ERRORS)


# --- one message + exit code per MEGA error code ----------------------------------------------
@pytest.mark.parametrize(
    ("code", "exit_code"),
    [
        (MegaErrorCode.EINTERNAL, ExitCode.GENERAL),
        (MegaErrorCode.EARGS, ExitCode.GENERAL),
        (MegaErrorCode.EAGAIN, ExitCode.NETWORK),
        (MegaErrorCode.ERATELIMIT, ExitCode.NETWORK),
        (MegaErrorCode.EFAILED, ExitCode.GENERAL),
        (MegaErrorCode.ENOENT, ExitCode.NOT_FOUND),
        (MegaErrorCode.EACCESS, ExitCode.AUTH),
        (MegaErrorCode.ESID, ExitCode.AUTH),
        (MegaErrorCode.EOVERQUOTA, ExitCode.QUOTA),
        (MegaErrorCode.EMFAREQUIRED, ExitCode.AUTH),
    ],
)
def test_api_error_code_maps_to_message_and_exit_code(
    code: MegaErrorCode, exit_code: ExitCode
) -> None:
    result = run(raising(MegaApiError(code, [Ping])))

    assert result.exit_code == exit_code
    assert error_lines(result) == [f"Error: {API_ERRORS[code].message}"]


def test_session_expired_tells_user_to_log_in() -> None:
    result = run(raising(MegaApiError(MegaErrorCode.ESID, [Ping])))
    assert "mega-cli login" in result.output


def test_overquota_mentions_quota() -> None:
    result = run(raising(MegaApiError(MegaErrorCode.EOVERQUOTA, [Ping])))
    assert "quota" in result.output.lower()


def test_unknown_error_code_shows_the_code() -> None:
    result = run(raising(MegaApiError(-999, [Ping])))

    assert result.exit_code == ExitCode.GENERAL
    assert error_lines(result) == ["Error: MEGA returned an unknown error code: -999."]


def test_enoent_on_login_means_wrong_credentials() -> None:
    result = run(raising(MegaApiError(MegaErrorCode.ENOENT, [Login])))

    assert result.exit_code == ExitCode.AUTH
    assert error_lines(result) == ["Error: Wrong email or password."]


def test_api_error_end_to_end_through_client() -> None:
    def action() -> None:
        with make_client(replying(MegaErrorCode.ESID)) as client:
            client.request(Ping())

    result = run(action)
    assert result.exit_code == ExitCode.AUTH
    assert "session has expired" in result.output


# --- no traceback without --verbose -----------------------------------------------------------
@pytest.mark.parametrize(
    "exc",
    [
        MegaApiError(MegaErrorCode.EACCESS, [Ping]),
        MegaTransportError("Network error: boom"),
        MegaProtocolError("Response is not JSON"),
        MegaClientError("base"),
        RuntimeError("unexpected"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_no_traceback_without_verbose(exc: Exception) -> None:
    result = run(raising(exc))

    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert len(error_lines(result)) == 1


def test_unexpected_error_hints_at_verbose() -> None:
    result = run(raising(RuntimeError("boom")))

    assert result.exit_code == ExitCode.GENERAL
    assert "--verbose" in result.output


def test_verbose_shows_traceback_without_hint() -> None:
    result = run(raising(RuntimeError("boom")), verbose=True)

    assert result.exit_code == ExitCode.GENERAL
    assert "Traceback" in result.output
    assert "Re-run with --verbose" not in result.output


def test_verbose_shows_api_command_name_for_api_error() -> None:
    result = run(raising(MegaApiError(MegaErrorCode.EACCESS, [Login])), verbose=True)
    assert "'us'" in result.output


def test_verbose_shows_api_command_name_for_network_error() -> None:
    # The issue: --verbose shows the traceback *and the name of the API command*
    def action() -> None:
        with make_client(_refuse_connection, max_retries=0) as client:
            client.request(Ping())

    result = run(action, verbose=True)
    assert "While sending: Ping ('ping')" in result.output


def test_api_command_name_hidden_without_verbose() -> None:
    def action() -> None:
        with make_client(_refuse_connection, max_retries=0) as client:
            client.request(Ping())

    result = run(action)
    assert "While sending" not in result.output


# --- Click's own errors are left alone --------------------------------------------------------
def test_usage_error_keeps_click_exit_code() -> None:
    result = runner.invoke(make_app(lambda: None), ["run", "--no-such-option"])
    assert result.exit_code == ExitCode.USAGE


def test_typer_exit_is_passed_through() -> None:
    result = run(raising(typer.Exit(42)))
    assert result.exit_code == 42
    assert "Error" not in result.output


# --- network errors ---------------------------------------------------------------------------
def _refuse_connection(request: httpx2.Request) -> httpx2.Response:
    raise httpx2.ConnectError("Connection refused", request=request)


@pytest.mark.parametrize("verbose", [False, True])
def test_network_error_is_one_line_with_network_exit_code(verbose: bool) -> None:
    def action() -> None:
        with make_client(_refuse_connection, max_retries=1) as client:
            client.request(Ping())

    result = run(action, verbose=verbose)

    assert result.exit_code == ExitCode.NETWORK
    assert len(error_lines(result)) == 1
    if not verbose:
        assert len(result.output.strip().splitlines()) == 1
    assert "Connection refused" in result.output
    assert "internet connection" in result.output


def test_permanent_server_error_has_network_exit_code() -> None:
    def action() -> None:
        with make_client(replying(httpx2.Response(503)), max_retries=0) as client:
            client.request(Ping())

    result = run(action)
    assert result.exit_code == ExitCode.NETWORK
    assert error_lines(result) == ["Error: Server error: HTTP 503. Check your internet connection."]


# --- secrets never in the output, even with --verbose -----------------------------------------
@pytest.mark.parametrize("verbose", [False, True])
def test_login_failure_never_shows_secrets(verbose: bool) -> None:
    def action() -> None:
        password = SECRET_PASSWORD  # noqa: F841 - must not show up as a traceback local
        master_key = SECRET_KEY  # noqa: F841
        with make_client(replying([MegaErrorCode.ENOENT])) as client:
            client.sid = SECRET_SID
            client.request(Login(email="user@example.com", user_handle=SECRET_UH))

    result = run(action, verbose=verbose)

    assert result.exit_code == ExitCode.AUTH
    assert_no_secrets(result)
    if verbose:
        assert "Traceback" in result.output
        assert "sid=<redacted>" in squashed(result)  # httpx2 request log, sid redacted


@pytest.mark.parametrize(
    "reply",
    [
        {"csid": SECRET_SID, "k": SECRET_KEY, "uh": SECRET_UH, "privk": SECRET_PASSWORD},
        [{"tsid": SECRET_SID}, {"k": SECRET_KEY}],
        [{"k": SECRET_KEY}],
        httpx2.Response(200, text=f"<html>sid={SECRET_SID} k={SECRET_KEY}</html>"),
    ],
    ids=["object", "wrong-length-list", "non-object-item", "non-json"],
)
@pytest.mark.parametrize("verbose", [False, True])
def test_protocol_error_never_shows_secrets(reply: Any, verbose: bool) -> None:
    def action() -> None:
        with make_client(replying(reply)) as client:
            client.sid = SECRET_SID
            client.request(Login(email="user@example.com", user_handle=SECRET_UH))

    result = run(action, verbose=verbose)

    assert result.exit_code == ExitCode.GENERAL
    assert error_lines(result) == ["Error: MEGA sent an unexpected response."]
    assert_no_secrets(result)


@pytest.mark.parametrize("verbose", [False, True])
def test_unexpected_error_redacts_secrets_in_message(verbose: bool) -> None:
    # Fallback: even a careless exception message must not leak secrets
    def action() -> None:
        params = {"sid": SECRET_SID, "uh": SECRET_UH, "password": SECRET_PASSWORD, "k": SECRET_KEY}
        url = f"{BASE_URL}/cs?id=1&sid={SECRET_SID}&uh={SECRET_UH}"
        raise RuntimeError(f"bad state {params} at {url}")

    result = run(action, verbose=verbose)

    assert result.exit_code == ExitCode.GENERAL
    assert_no_secrets(result)


# --- session storage errors -------------------------------------------------------------------
@pytest.mark.parametrize(
    ("exc", "exit_code", "expected"),
    [
        (
            SessionNotFoundError("no saved session found"),
            ExitCode.AUTH,
            "Error: You are not logged in. Run `mega-cli login` to sign in.",
        ),
        (
            InsecureSessionFileError(
                "refusing to load /cfg/session.secrets.json: expected permissions 0600, found 0644"
            ),
            ExitCode.GENERAL,
            "Error: Refusing to use the saved session: refusing to load "
            "/cfg/session.secrets.json: expected permissions 0600, found 0644. "
            "Make the file private (chmod 600) or delete it. "
            "Run `mega-cli login` to sign in.",
        ),
        (
            KeyringTimeoutError("operation timed out after 60 seconds"),
            ExitCode.GENERAL,
            "Error: The OS keyring did not respond (operation timed out after 60 seconds). "
            "Unlock it if a prompt is open and try again, "
            "or set MEGA_CLI_KEYRING_TIMEOUT to wait longer.",
        ),
        (
            KeyringUnavailableError("OS keyring operation failed"),
            ExitCode.GENERAL,
            "Error: OS keyring operation failed. Make sure the OS keyring is running and unlocked.",
        ),
        (
            SessionError("invalid JSON in /cfg/session.json"),
            ExitCode.GENERAL,
            "Error: The saved session could not be used: invalid JSON in /cfg/session.json. "
            "Run `mega-cli login` to sign in.",
        ),
    ],
    ids=lambda v: type(v).__name__ if isinstance(v, Exception) else None,
)
def test_session_error_maps_to_message_and_exit_code(
    exc: SessionError, exit_code: ExitCode, expected: str
) -> None:
    result = run(raising(exc))

    assert result.exit_code == exit_code
    assert " ".join(result.output.split()) == expected
    assert "Traceback" not in result.output


def test_keyring_delete_failure_says_local_files_were_removed() -> None:
    exc = KeyringUnavailableError(
        "local session files were removed, but the OS keyring entry could not be removed: "
        "OS keyring operation failed"
    )
    result = run(raising(exc))

    assert result.exit_code == ExitCode.GENERAL
    assert squashed(result).startswith("Error:Localsessionfileswereremoved")


def test_session_error_verbose_shows_cause() -> None:
    def action() -> None:
        try:
            raise RuntimeError("dbus: org.freedesktop.secrets not provided")
        except RuntimeError as cause:
            raise KeyringUnavailableError("OS keyring operation failed") from cause

    result = run(action, verbose=True)

    assert result.exit_code == ExitCode.GENERAL
    assert "Traceback" in result.output
    assert "org.freedesktop.secrets" in result.output
    assert len(error_lines(result)) == 1
