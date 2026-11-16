"""Secure persistence for a single MEGA session."""

import base64
import json
import os
import queue
import secrets
import stat
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast

import keyring

from mega_cli.config import config_dir

KEYRING_SERVICE = "mega-cli"
KEYRING_ACCOUNT = "session"
DEFAULT_KEYRING_TIMEOUT = 3.0

_T = TypeVar("_T")
_KEYRING_LOCK = threading.Lock()


class SessionStorage(StrEnum):
    """Location from which a session was loaded."""

    KEYRING = "keyring"
    FILE = "file"


@dataclass(frozen=True, slots=True)
class Session:
    """Credentials and metadata for one authenticated MEGA account."""

    email: str
    sid: str = field(repr=False)
    master_key: bytes = field(repr=False)
    user_handle: str | None = None
    storage: SessionStorage | None = None


class KeyringBackend(Protocol):
    """Subset of the keyring API used by the session store."""

    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class SessionError(Exception):
    """Base class for session persistence errors."""


class SessionNotFoundError(SessionError):
    """Raised when no saved session exists."""


class InsecureSessionFileError(SessionError):
    """Raised when a fallback file is readable by other users."""


class KeyringUnavailableError(SessionError):
    """Raised when the OS keyring fails or does not answer in time."""


class SessionStore:
    """Store one session in the OS keyring or a protected fallback file."""

    def __init__(
        self,
        directory: Path | None = None,
        *,
        keyring_backend: KeyringBackend | None = None,
        keyring_timeout: float = DEFAULT_KEYRING_TIMEOUT,
    ) -> None:
        if keyring_timeout <= 0:
            raise ValueError("keyring timeout must be positive")

        self.directory = directory or config_dir()
        self.metadata_path = self.directory / "session.json"
        self.fallback_path = self.directory / "session.secrets.json"
        self._keyring = (
            keyring_backend if keyring_backend is not None else cast(KeyringBackend, keyring)
        )
        self._keyring_timeout = keyring_timeout

    def save(self, session: Session) -> SessionStorage:
        """Save a session, preferring the OS keyring."""
        keyring_payload = json.dumps(
            {
                "write_id": secrets.token_hex(16),
                "sid": session.sid,
                "master_key": _encode_bytes(session.master_key),
            }
        )

        try:
            previous = self._call_keyring(
                self._keyring.get_password, KEYRING_SERVICE, KEYRING_ACCOUNT
            )
            self._call_keyring(
                self._keyring.set_password,
                KEYRING_SERVICE,
                KEYRING_ACCOUNT,
                keyring_payload,
                on_late_success=lambda _: self._remove_keyring_value(keyring_payload),
            )
        except KeyringUnavailableError:
            print(
                "Warning: OS keyring unavailable or timed out; "
                "saving the session in a protected local file.",
                file=sys.stderr,
            )
            _write_json_secure(
                self.fallback_path,
                {
                    "email": session.email,
                    "sid": session.sid,
                    "master_key": _encode_bytes(session.master_key),
                    "user_handle": session.user_handle,
                },
            )
            self._delete_keyring(ignore_errors=True)
            self.metadata_path.unlink(missing_ok=True)
            return SessionStorage.FILE

        try:
            _write_json_secure(
                self.metadata_path,
                {"email": session.email, "user_handle": session.user_handle},
            )
        except OSError:
            try:
                if previous is None:
                    self._delete_keyring(ignore_errors=False)
                else:
                    self._call_keyring(
                        self._keyring.set_password,
                        KEYRING_SERVICE,
                        KEYRING_ACCOUNT,
                        previous,
                    )
            except KeyringUnavailableError:
                raise SessionError(
                    "metadata write failed and keyring rollback failed; log in again"
                ) from None
            raise
        self.fallback_path.unlink(missing_ok=True)
        return SessionStorage.KEYRING

    def load(self) -> Session:
        """Load the saved session and report its storage location."""
        if self.fallback_path.exists():
            payload = _read_private_json(self.fallback_path)
            return Session(
                email=_require_string(payload, "email"),
                sid=_require_string(payload, "sid"),
                master_key=_decode_bytes(_require_string(payload, "master_key")),
                user_handle=_optional_string(payload, "user_handle"),
                storage=SessionStorage.FILE,
            )

        if not self.metadata_path.exists():
            raise SessionNotFoundError("no saved session found")

        metadata = _read_json(self.metadata_path)
        secret_payload = self._call_keyring(
            self._keyring.get_password,
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
        )
        if secret_payload is None:
            raise SessionNotFoundError("session metadata exists, but keyring secrets are missing")

        secrets_payload = _parse_json(secret_payload, "keyring session")
        return Session(
            email=_require_string(metadata, "email"),
            sid=_require_string(secrets_payload, "sid"),
            master_key=_decode_bytes(_require_string(secrets_payload, "master_key")),
            user_handle=_optional_string(metadata, "user_handle"),
            storage=SessionStorage.KEYRING,
        )

    def delete(self) -> None:
        """Remove the session from both possible storage locations."""
        keyring_error: KeyringUnavailableError | None = None
        try:
            self._delete_keyring(ignore_errors=False)
        except KeyringUnavailableError as exc:
            keyring_error = exc
        finally:
            self.metadata_path.unlink(missing_ok=True)
            self.fallback_path.unlink(missing_ok=True)

        if keyring_error is not None:
            raise KeyringUnavailableError(
                "local session files were removed, but the OS keyring entry "
                f"could not be removed: {keyring_error}"
            ) from keyring_error

    def _delete_keyring(self, *, ignore_errors: bool) -> None:
        try:
            existing = self._call_keyring(
                self._keyring.get_password, KEYRING_SERVICE, KEYRING_ACCOUNT
            )
            if existing is not None:
                self._call_keyring(
                    self._keyring.delete_password,
                    KEYRING_SERVICE,
                    KEYRING_ACCOUNT,
                )
        except KeyringUnavailableError:
            if not ignore_errors:
                raise
            print(
                "Warning: could not remove the old OS keyring entry; "
                "the fallback is active, but secrets may remain in the keyring.",
                file=sys.stderr,
            )

    def _remove_keyring_value(self, expected: str) -> None:
        """Best-effort cleanup for a write that completed after its timeout."""
        try:
            current = self._keyring.get_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
            if current == expected:
                self._keyring.delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
        except Exception:
            # This runs in a daemon thread after the caller has already fallen back
            # to a local file, so there is nowhere useful to report backend errors.
            return

    def _call_keyring(
        self,
        function: Callable[..., _T],
        *args: object,
        on_late_success: Callable[[_T], None] | None = None,
    ) -> _T:
        result: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)
        state_lock = threading.Lock()
        timed_out = False

        def run() -> None:
            try:
                outcome: tuple[bool, object] = (True, function(*args))
            except Exception as exc:  # keyring backends use backend-specific exceptions
                outcome = (False, exc)

            with state_lock:
                if timed_out:
                    succeeded, value = outcome
                    if succeeded and on_late_success is not None:
                        on_late_success(cast(_T, value))
                    return
                result.put(outcome)

        def serialized_run() -> None:
            # Late writes and their cleanup finish before a newer operation starts.
            with _KEYRING_LOCK:
                with state_lock:
                    if timed_out:
                        return
                run()

        threading.Thread(target=serialized_run, daemon=True).start()
        try:
            succeeded, value = result.get(timeout=self._keyring_timeout)
        except queue.Empty as exc:
            with state_lock:
                try:
                    succeeded, value = result.get_nowait()
                except queue.Empty:
                    timed_out = True
                    raise KeyringUnavailableError(
                        f"operation timed out after {self._keyring_timeout:g} seconds"
                    ) from exc

        if not succeeded:
            error = cast(Exception, value)
            raise KeyringUnavailableError("OS keyring operation failed") from error
        return cast(_T, value)


def _write_json_secure(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            json.dump(payload, file)
            file.write("\n")
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _read_private_json(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise InsecureSessionFileError("session file must be a regular file")
            mode = stat.S_IMODE(info.st_mode)
            if os.name == "posix" and mode & ~0o600:
                raise InsecureSessionFileError(
                    f"refusing to load {path}: expected permissions 0600, found {mode:04o}"
                )
            return _parse_json(file.read(), str(path))
    except OSError as exc:
        raise SessionError(f"could not safely open session file {path}") from exc


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return _parse_json(path.read_text(encoding="utf-8"), str(path))
    except OSError as exc:
        raise SessionError(f"could not read session file {path}: {exc}") from exc


def _parse_json(value: str, source: str) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise SessionError(f"invalid JSON in {source}") from exc
    if not isinstance(payload, dict):
        raise SessionError(f"invalid session data in {source}")
    return payload


def _require_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise SessionError(f"session field {key!r} must be a non-empty string")
    return value


def _optional_string(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is not None and not isinstance(value, str):
        raise SessionError(f"session field {key!r} must be a string or null")
    return value


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode_bytes(value: str) -> bytes:
    try:
        return base64.b64decode(value, altchars=b"-_", validate=True)
    except ValueError as exc:
        raise SessionError("invalid master key encoding") from exc
