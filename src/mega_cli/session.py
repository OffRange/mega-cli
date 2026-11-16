"""Secure persistence for a single MEGA session."""

import base64
import json
import logging
import os
import queue
import secrets
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast

import keyring

from mega_cli import CLI_NAME
from mega_cli.config import config_dir

KEYRING_ACCOUNT = "session"
KEYRING_TIMEOUT_ENV = "MEGA_CLI_KEYRING_TIMEOUT"
DEFAULT_KEYRING_TIMEOUT = 60.0
DEFAULT_KEYRING_NOTICE_AFTER = 2.0
_KEYRING_LOCK_GRACE = 0.5

_T = TypeVar("_T")
_KEYRING_LOCK = threading.Lock()
log = logging.getLogger(__name__)


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
    """Raised when the OS keyring fails."""


class KeyringTimeoutError(KeyringUnavailableError):
    """Raised when the OS keyring does not answer in time or is still busy."""


class SessionStore:
    """Store one session in the OS keyring or a protected fallback file."""

    def __init__(
        self,
        directory: Path | None = None,
        *,
        keyring_backend: KeyringBackend | None = None,
        keyring_timeout: float | None = None,
    ) -> None:
        if keyring_timeout is None:
            keyring_timeout = _default_keyring_timeout()
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
            previous = self._call_keyring(self._keyring.get_password, CLI_NAME, KEYRING_ACCOUNT)
            self._call_keyring(
                self._keyring.set_password,
                CLI_NAME,
                KEYRING_ACCOUNT,
                keyring_payload,
                on_late_success=lambda _: self._remove_keyring_value(keyring_payload),
            )
        except KeyringTimeoutError:
            log.warning("OS keyring timed out; saving the session in a protected local file")
            _write_json_secure(
                self.fallback_path,
                {
                    "email": session.email,
                    "sid": session.sid,
                    "master_key": _encode_bytes(session.master_key),
                    "user_handle": session.user_handle,
                },
            )
            log.warning("The fallback is active, but old secrets may remain in the OS keyring")
            self.metadata_path.unlink(missing_ok=True)
            return SessionStorage.FILE
        except KeyringUnavailableError:
            log.warning("OS keyring unavailable; saving the session in a protected local file")
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
                        CLI_NAME,
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
            CLI_NAME,
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
            existing = self._call_keyring(self._keyring.get_password, CLI_NAME, KEYRING_ACCOUNT)
            if existing is not None:
                self._call_keyring(
                    self._keyring.delete_password,
                    CLI_NAME,
                    KEYRING_ACCOUNT,
                )
        except KeyringUnavailableError:
            if not ignore_errors:
                raise
            log.warning(
                "Could not remove the old OS keyring entry; the fallback is active, "
                "but secrets may remain in the keyring"
            )

    def _remove_keyring_value(self, expected: str) -> None:
        """Best-effort cleanup for a write that completed after its timeout."""
        try:
            current = self._keyring.get_password(CLI_NAME, KEYRING_ACCOUNT)
            if current == expected:
                self._keyring.delete_password(CLI_NAME, KEYRING_ACCOUNT)
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
        result: queue.Queue[_T | Exception] = queue.Queue(maxsize=1)
        state_lock = threading.Lock()
        timed_out = False

        def mark_timeout(cause: queue.Empty) -> _T | Exception:
            nonlocal timed_out
            with state_lock:
                try:
                    return result.get_nowait()
                except queue.Empty:
                    timed_out = True
                    raise KeyringTimeoutError(
                        f"operation timed out after {self._keyring_timeout:g} seconds"
                    ) from cause

        def run() -> None:
            try:
                value: _T | Exception = function(*args)
            except Exception as exc:  # keyring backends use backend-specific exceptions
                value = exc

            with state_lock:
                if timed_out:
                    if not isinstance(value, Exception) and on_late_success is not None:
                        on_late_success(value)
                    return
                result.put(value)

        def serialized_run() -> None:
            # The caller owns the process-wide lock. The worker releases it only
            # after the backend call and any late cleanup have finished.
            try:
                run()
            finally:
                _KEYRING_LOCK.release()

        # state_lock protects this call's timeout flag and queue handoff. The
        # process-wide lock prevents a late write from overtaking a newer call.
        lock_timeout = min(_KEYRING_LOCK_GRACE, self._keyring_timeout)
        if not _KEYRING_LOCK.acquire(timeout=lock_timeout):
            raise KeyringTimeoutError("a previous OS keyring operation is still pending")
        try:
            threading.Thread(target=serialized_run, daemon=True).start()
        except BaseException:
            _KEYRING_LOCK.release()
            raise

        notice_after = min(DEFAULT_KEYRING_NOTICE_AFTER, self._keyring_timeout)
        try:
            value = result.get(timeout=notice_after)
        except queue.Empty as exc:
            remaining = self._keyring_timeout - notice_after
            if remaining > 0:
                log.warning("OS keyring is still waiting; an unlock prompt may be open")
                try:
                    value = result.get(timeout=remaining)
                except queue.Empty as final_exc:
                    value = mark_timeout(final_exc)
            else:
                value = mark_timeout(exc)

        if isinstance(value, Exception):
            raise KeyringUnavailableError("OS keyring operation failed") from value
        return value


def _default_keyring_timeout() -> float:
    raw = os.environ.get(KEYRING_TIMEOUT_ENV)
    if raw is None:
        return DEFAULT_KEYRING_TIMEOUT
    try:
        timeout = float(raw)
    except ValueError as exc:
        raise ValueError(f"{KEYRING_TIMEOUT_ENV} must be a number") from exc
    if timeout <= 0:
        raise ValueError(f"{KEYRING_TIMEOUT_ENV} must be positive")
    return timeout


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
