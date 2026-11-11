import json
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx2
import pytest

from mega_cli.api import BaseCommand, Field, MegaClient
from mega_cli.api.errors import MegaApiError, MegaErrorCode

BASE_URL = "https://test.example.mega"
SECRET_SID = "SeCrEtSiD-do-not-log-0123456789abcdef"
SECRET_UH = "SeCrEtUserHash-do-not-leak"


class Ping(BaseCommand, name="ping"):
    pass


class Login(BaseCommand, name="us"):
    email: str = Field(api_alias="user")
    user_handle: str = Field(api_alias="uh")


@dataclass
class FakeServer:
    replies: list[Any]
    requests: list[httpx2.Request] = field(default_factory=list)

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return httpx2.Response(200, json=self.replies.pop(0))

    @property
    def ids(self) -> list[str | None]:
        return [req.url.params.get("id") for req in self.requests]


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def make_client(sleeps: list[float]) -> Iterator[Callable[..., tuple[MegaClient, FakeServer]]]:
    clients: list[MegaClient] = []

    def factory(*replies: Any, **kwargs: Any) -> tuple[MegaClient, FakeServer]:
        server = FakeServer(list(replies))
        http = httpx2.Client(base_url=BASE_URL, transport=httpx2.MockTransport(server))
        # Never really sleep: record the requested delays instead
        client = MegaClient(http_client=http, sleep=sleeps.append, **kwargs)
        clients.append(client)
        return client, server

    yield factory
    for c in clients:
        c._http_client.close()


# --- request id & sid -------------------------------------------------------------------------
def test_request_id_increments_per_call(make_client: Callable[..., Any]) -> None:
    client, server = make_client([0], [0], [0])
    for _ in range(3):
        client.request(Ping())

    first = int(server.ids[0])
    assert server.ids == [str(first), str(first + 1), str(first + 2)]


def test_body_is_command_array(make_client: Callable[..., Any]) -> None:
    client, server = make_client([0])
    client.request(Login(email="a@b.c", user_handle="uh"))

    assert json.loads(server.requests[0].content) == [{"a": "us", "user": "a@b.c", "uh": "uh"}]


# --- error codes ------------------------------------------------------------------------------
def test_error_code_as_whole_response_raises(make_client: Callable[..., Any]) -> None:
    client, _ = make_client(MegaErrorCode.EARGS)  # -3
    with pytest.raises(MegaApiError) as exc:
        client.request(Ping())

    assert exc.value.error is MegaErrorCode.EARGS
    assert exc.value.commands == (Ping,)


def test_error_code_in_result_array_raises(make_client: Callable[..., Any]) -> None:
    client, _ = make_client([MegaErrorCode.ENOENT])  # -9
    with pytest.raises(MegaApiError) as exc:
        client.request(Ping())

    assert exc.value.error is MegaErrorCode.ENOENT


def test_batch_returns_per_command_errors(make_client: Callable[..., Any]) -> None:
    client, _ = make_client([{"ok": 1}, -11])
    first, second = client.request_batch([Ping(), Ping()])

    assert first == {"ok": 1}
    assert isinstance(second, MegaApiError)
    assert second.error is MegaErrorCode.EACCESS


def test_unknown_error_code_is_kept(make_client: Callable[..., Any]) -> None:
    client, _ = make_client(-999)
    with pytest.raises(MegaApiError) as exc:
        client.request(Ping())

    assert exc.value.code == -999
    assert exc.value.error is None


# --- EAGAIN retries ---------------------------------------------------------------------------
def test_eagain_twice_then_success(make_client: Callable[..., Any], sleeps: list[float]) -> None:
    client, server = make_client(-3, -3, [{"ok": 1}])

    assert client.request(Ping()) == {"ok": 1}
    assert len(server.requests) == 3  # 3 calls in total
    assert len(sleeps) == 2  # 2 retries


def test_retries_reuse_request_id(make_client: Callable[..., Any]) -> None:
    client, server = make_client(-3, -3, [0])
    client.request(Ping())

    assert len(set(server.ids)) == 1


def test_permanent_eagain_raises_after_max_retries(
    make_client: Callable[..., Any], sleeps: list[float]
) -> None:
    client, server = make_client(*[-3] * 4, max_retries=3)
    with pytest.raises(MegaApiError) as exc:
        client.request(Ping())

    assert exc.value.error is MegaErrorCode.EAGAIN
    assert len(server.requests) == 4  # first attempt + 3 retries
    assert len(sleeps) == 3


def test_backoff_is_exponential_and_capped(
    make_client: Callable[..., Any], sleeps: list[float]
) -> None:
    client, _ = make_client(*[-3] * 6, max_retries=5, initial_backoff=0.5, max_backoff=3)
    with pytest.raises(MegaApiError):
        client.request(Ping())

    assert sleeps == [0.5, 1, 2, 3, 3]


@pytest.mark.parametrize("code", [code for code in MegaErrorCode if code != MegaErrorCode.EAGAIN])
def test_non_eagain_raises_immediately(
    make_client: Callable[..., Any], sleeps: list[float], code: int
) -> None:
    client, server = make_client(code)
    with pytest.raises(MegaApiError) as exc:
        client.request(Ping())

    assert exc.value.code == code
    assert len(server.requests) == 1
    assert sleeps == []


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"max_retries": -1}, "max_retries"),
        ({"initial_backoff": -1}, "initial_backoff"),
        ({"initial_backoff": 5, "max_backoff": 1}, "max_backoff"),
    ],
)
def test_invalid_config_rejected(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        MegaClient(**kwargs)


# --- secrets ----------------------------------------------------------------------------------
def test_error_str_and_repr_hide_secrets(make_client: Callable[..., Any]) -> None:
    client, _ = make_client([-9])
    client.sid = SECRET_SID
    with pytest.raises(MegaApiError) as exc:
        client.request(Login(email="a@b.c", user_handle=SECRET_UH))

    for text in (str(exc.value), repr(exc.value)):
        assert SECRET_UH not in text
        assert SECRET_SID not in text


def test_sid_never_logged(
    make_client: Callable[..., Any], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    client, _ = make_client(-3, [0])
    client.sid = SECRET_SID
    client.request(Ping())

    # httpx2's request log line must still be there, just without the sid
    assert any(r.name == "httpx2" for r in caplog.records)
    assert "sid=<redacted>" in caplog.text
    assert SECRET_SID not in caplog.text
