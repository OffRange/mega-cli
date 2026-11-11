import json
import logging
import secrets
import time
from collections.abc import Callable, Sequence
from types import TracebackType
from typing import Any, Self, TypeGuard

import httpx2

from mega_cli import __version__, hashcash
from mega_cli.api import BaseCommand
from mega_cli.api.errors import (
    MegaApiError,
    MegaClientError,
    MegaProtocolError,
    MegaTransportError,
)

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://g.api.mega.co.nz"
USER_AGENT = f"megacli/{__version__}"

MAX_HASHCASH_ROUNDS = 3

type BatchResult = list[MegaApiError | httpx2.Response]


def _is_error_code(v: object) -> TypeGuard[int]:
    return isinstance(v, int) and v < 0


class MegaClient:
    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30,
        max_retries: int = 7,
        initial_backoff: float = 1,
        max_backoff: float = 30,
        http_client: httpx2.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_retries < 0:
            raise ValueError(f"max_retries must not be negative, got {max_retries}")
        if initial_backoff < 0:
            raise ValueError(f"initial_backoff must not be negative, got {initial_backoff}")
        if max_backoff < initial_backoff:
            raise ValueError(
                f"max_backoff ({max_backoff}) must not be smaller than "
                f"initial_backoff ({initial_backoff})"
            )

        self.base_url = base_url.rstrip("/")
        self._http_client = http_client or httpx2.Client(
            base_url=self.base_url, timeout=timeout, headers={"User-Agent": USER_AGENT}
        )
        self._owns_transport = http_client is None
        self._max_retries = max_retries
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._sleep = sleep

        # The request id only has to be unique per session. So we take a random one so two CLI calls dont reuse one
        self._seq = secrets.randbelow(2**32)

        self._sid: str | None = None
        """Session ID, set after login"""

    @property
    def sid(self) -> str | None:
        return self._sid

    @sid.setter
    def sid(self, value: str | None) -> None:
        self._sid = value

    def close(self) -> None:
        if self._owns_transport:
            self._http_client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def request[R](self, command: BaseCommand[R]) -> R:
        (result,) = self.request_batch([command])
        if isinstance(result, MegaApiError):
            raise result

        # parsed by command.parse_response in request_batch
        return result  # type: ignore[return-value]

    def request_batch(self, commands: Sequence[BaseCommand]) -> BatchResult:
        if not commands:
            return []

        data = self._post(commands)
        if isinstance(data, list) and len(data) == len(commands):
            return [
                MegaApiError(item, [type(cmd)])
                if _is_error_code(item)
                else cmd.parse_response(item)
                for item, cmd in zip(data, commands, strict=True)
            ]

        names = [cmd.name for cmd in commands]
        raise MegaProtocolError(
            f"Expected a list of {len(commands)} results for {names}, got {data!r:.200}"
        )

    def _params(self) -> dict[str, str]:
        params = {"id": str(self._seq)}
        if self._sid:
            params["sid"] = self._sid

        return params

    def _post(self, commands: Sequence[BaseCommand]) -> Any:
        body = json.dumps([cmd.to_dict() for cmd in commands])
        classes = [type(cmd) for cmd in commands]

        self._seq += 1
        params = self._params()

        delay = self._initial_backoff
        last_error: MegaClientError | None = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                log.debug(
                    "Retry %d/%d in %.2fs: %s",
                    attempt,
                    self._max_retries,
                    delay,
                    last_error,
                )
                self._sleep(delay)
                delay = min(delay * 2, self._max_backoff)

            try:
                response = self._send(body, params)
            except httpx2.TransportError as e:
                last_error = MegaTransportError(f"Network error: {e}")
                last_error.__cause__ = e
                continue

            if response.status_code >= 500:
                last_error = MegaTransportError(f"Server error: HTTP {response.status_code}")
                continue

            if response.status_code != 200:
                raise MegaTransportError(f"Unexpected HTTP {response.status_code}")

            data = self._decode(response)

            if _is_error_code(data):  # Entire response got an error
                error = MegaApiError(data, classes)
                if error.is_retryable:
                    last_error = error
                    continue

                raise error

            return data

        # At this point we exhausted all retries and could not get a successful state -> fail
        assert last_error is not None  # the loop always runs at least once
        raise last_error

    def _send(self, body: str, params: dict[str, str]) -> httpx2.Response:
        headers = {"Content-Type": "application/json"}

        for _ in range(MAX_HASHCASH_ROUNDS):
            response = self._http_client.post("/cs", content=body, params=params, headers=headers)

            if response.status_code != 402:
                return response

            challenge = response.headers.get("x-hashcash")
            if not challenge:
                raise MegaProtocolError("HTTP 402 without an X-Hashcash challenge")

            log.debug("Solving hashcash challenge")
            headers["x-hashcash"] = hashcash.solve_hashcash_challenge(challenge)

        raise MegaTransportError("Server kept rejecting hashcash solution")

    @staticmethod
    def _decode(response: httpx2.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            raise MegaProtocolError(f"Response is not JSON: {response.text[:200]!r}") from None
