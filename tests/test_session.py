import json
import os
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from mega_cli.session import (
    InsecureSessionFileError,
    KeyringTimeoutError,
    KeyringUnavailableError,
    Session,
    SessionError,
    SessionStorage,
    SessionStore,
)


class FakeKeyring:
    def __init__(self) -> None:
        self.password: str | None = None
        self.fail_set = False
        self.fail_delete = False
        self.get_delay = 0.0
        self.set_delay = 0.0
        self.delete_delay = 0.0

    def get_password(self, service: str, username: str) -> str | None:
        self._wait(self.get_delay)
        return self.password

    def set_password(self, service: str, username: str, password: str) -> None:
        self._wait(self.set_delay)
        if self.fail_set:
            raise RuntimeError("keyring unavailable")
        self.password = password

    def delete_password(self, service: str, username: str) -> None:
        self._wait(self.delete_delay)
        if self.fail_delete:
            raise RuntimeError("keyring delete failed")
        self.password = None

    @staticmethod
    def _wait(delay: float) -> None:
        if delay:
            time.sleep(delay)


@pytest.fixture
def session() -> Session:
    return Session(
        email="alice@example.com",
        sid="secret-session-id",
        master_key=bytes.fromhex("00112233445566778899aabbccddeeff"),
        user_handle="abcdefghijk",
    )


def test_keyring_round_trip(tmp_path: Path, session: Session) -> None:
    backend = FakeKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend)

    assert store.save(session) is SessionStorage.KEYRING
    assert store.load() == Session(
        email=session.email,
        sid=session.sid,
        master_key=session.master_key,
        user_handle=session.user_handle,
        storage=SessionStorage.KEYRING,
    )

    metadata = store.metadata_path.read_text(encoding="utf-8")
    assert session.sid not in metadata
    assert session.master_key.hex() not in metadata


def test_keyring_failure_uses_private_fallback(
    tmp_path: Path,
    session: Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("WARNING", logger="mega_cli.session")
    backend = FakeKeyring()
    backend.fail_set = True
    store = SessionStore(tmp_path, keyring_backend=backend)

    assert store.save(session) is SessionStorage.FILE

    assert "OS keyring unavailable" in caplog.text
    if os.name == "posix":
        assert store.fallback_path.stat().st_mode & 0o777 == 0o600
    assert store.load().storage is SessionStorage.FILE


def test_keyring_timeout_uses_fallback(
    tmp_path: Path,
    session: Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("WARNING", logger="mega_cli.session")
    backend = FakeKeyring()
    backend.set_delay = 0.05
    store = SessionStore(tmp_path, keyring_backend=backend, keyring_timeout=0.01)

    assert store.save(session) is SessionStorage.FILE

    assert "timed out" in caplog.text
    assert "old secrets may remain" in caplog.text
    assert store.fallback_path.exists()
    time.sleep(0.06)


def test_slow_keyring_logs_unlock_hint(
    tmp_path: Path,
    session: Session,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level("WARNING", logger="mega_cli.session")
    monkeypatch.setattr("mega_cli.session.DEFAULT_KEYRING_NOTICE_AFTER", 0.01)
    backend = FakeKeyring()
    backend.set_delay = 0.03

    store = SessionStore(tmp_path, keyring_backend=backend, keyring_timeout=0.1)

    assert store.save(session) is SessionStorage.KEYRING
    assert "unlock prompt may be open" in caplog.text


def test_timeout_can_be_set_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEGA_CLI_KEYRING_TIMEOUT", "12.5")
    store = SessionStore(tmp_path, keyring_backend=FakeKeyring())

    assert store._keyring_timeout == 12.5


def test_late_keyring_write_is_removed_after_timeout(
    tmp_path: Path,
    session: Session,
) -> None:
    backend = FakeKeyring()
    backend.set_delay = 0.05
    store = SessionStore(tmp_path, keyring_backend=backend, keyring_timeout=0.01)

    assert store.save(session) is SessionStorage.FILE
    time.sleep(0.1)

    assert backend.password is None
    assert store.fallback_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_insecure_fallback_file_is_rejected(tmp_path: Path, session: Session) -> None:
    backend = FakeKeyring()
    backend.fail_set = True
    store = SessionStore(tmp_path, keyring_backend=backend)
    store.save(session)
    store.fallback_path.chmod(0o644)

    with pytest.raises(InsecureSessionFileError, match="expected permissions 0600, found 0644"):
        store.load()


def test_delete_removes_keyring_and_fallback(tmp_path: Path, session: Session) -> None:
    backend = FakeKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend)
    store.save(session)
    store.fallback_path.write_text("obsolete", encoding="utf-8")

    store.delete()

    assert backend.password is None
    assert not store.metadata_path.exists()
    assert not store.fallback_path.exists()


def test_delete_reports_keyring_failure_after_removing_local_files(
    tmp_path: Path,
    session: Session,
) -> None:
    backend = FakeKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend)
    store.save(session)
    store.fallback_path.write_text("obsolete", encoding="utf-8")
    backend.fail_delete = True

    with pytest.raises(KeyringUnavailableError, match="keyring entry could not be removed"):
        store.delete()

    assert backend.password is not None
    assert not store.metadata_path.exists()
    assert not store.fallback_path.exists()


def test_saving_in_keyring_removes_existing_fallback(tmp_path: Path, session: Session) -> None:
    backend = FakeKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend)
    store.fallback_path.write_text("obsolete", encoding="utf-8")

    assert store.save(session) is SessionStorage.KEYRING

    assert not store.fallback_path.exists()
    assert backend.password is not None


def test_saving_in_fallback_removes_keyring_and_metadata(tmp_path: Path, session: Session) -> None:
    backend = FakeKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend)
    store.save(session)
    backend.fail_set = True

    assert store.save(session) is SessionStorage.FILE

    assert backend.password is None
    assert not store.metadata_path.exists()


def test_session_repr_does_not_expose_secrets(session: Session) -> None:
    representation = repr(session)

    assert session.sid not in representation
    assert session.master_key.hex() not in representation
    assert "sid=" not in representation
    assert "master_key=" not in representation


def test_keyring_metadata_contains_no_secrets(tmp_path: Path, session: Session) -> None:
    backend = FakeKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend)
    store.save(session)

    metadata = json.loads(store.metadata_path.read_text(encoding="utf-8"))
    assert metadata == {
        "email": session.email,
        "user_handle": session.user_handle,
    }


def test_fallback_round_trip_without_optional_handle(tmp_path: Path, session: Session) -> None:
    backend = FakeKeyring()
    backend.fail_set = True
    store = SessionStore(tmp_path, keyring_backend=backend)
    original = replace(session, user_handle=None)
    store.save(original)
    assert store.load() == replace(original, storage=SessionStorage.FILE)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_read_only_private_file_is_accepted(tmp_path: Path, session: Session) -> None:
    backend = FakeKeyring()
    backend.fail_set = True
    store = SessionStore(tmp_path, keyring_backend=backend)
    store.save(session)
    store.fallback_path.chmod(0o400)
    assert store.load().sid == session.sid


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink protection")
def test_fallback_symlink_is_rejected(tmp_path: Path, session: Session) -> None:
    backend = FakeKeyring()
    backend.fail_set = True
    store = SessionStore(tmp_path, keyring_backend=backend)
    store.save(session)
    target = tmp_path / "other.json"
    store.fallback_path.rename(target)
    store.fallback_path.symlink_to(target)
    with pytest.raises(SessionError):
        store.load()


def test_repeated_delete_is_allowed(tmp_path: Path) -> None:
    store = SessionStore(tmp_path, keyring_backend=FakeKeyring())
    store.delete()
    store.delete()


@pytest.mark.parametrize("existing", [False, True])
def test_metadata_failure_rolls_back_keyring(
    tmp_path: Path, session: Session, monkeypatch: pytest.MonkeyPatch, existing: bool
) -> None:
    backend = FakeKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend)
    if existing:
        store.save(session)
    previous = backend.password

    def fail_write(path: Path, payload: dict[str, object]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("mega_cli.session._write_json_secure", fail_write)
    with pytest.raises(OSError, match="disk full"):
        store.save(replace(session, email="new@example.com", sid="new-secret"))
    assert backend.password == previous
    if existing:
        assert store.load() == replace(session, storage=SessionStorage.KEYRING)
    else:
        assert not store.metadata_path.exists()


def test_failed_fallback_write_preserves_old_session(
    tmp_path: Path, session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = FakeKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend)
    store.save(session)
    backend.fail_set = True

    def fail_write(path: Path, payload: dict[str, object]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("mega_cli.session._write_json_secure", fail_write)
    with pytest.raises(OSError, match="disk full"):
        store.save(replace(session, email="new@example.com", sid="new-secret"))
    assert store.load() == replace(session, storage=SessionStorage.KEYRING)


def test_late_write_cannot_overwrite_new_session(tmp_path: Path, session: Session) -> None:
    release = threading.Event()
    finished = threading.Event()

    class BlockingKeyring(FakeKeyring):
        def set_password(self, service: str, username: str, password: str) -> None:
            if not release.wait(timeout=2):
                raise RuntimeError("test did not release worker")
            super().set_password(service, username, password)

        def delete_password(self, service: str, username: str) -> None:
            super().delete_password(service, username)
            finished.set()

    backend = BlockingKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend, keyring_timeout=0.01)
    try:
        assert store.save(session) is SessionStorage.FILE
    finally:
        release.set()
    assert finished.wait(timeout=2)
    newer = replace(session, sid="new-session")
    assert store.save(newer) is SessionStorage.KEYRING
    assert store.load() == replace(newer, storage=SessionStorage.KEYRING)


def test_pending_keyring_call_fails_fast_without_starting_more_calls(
    tmp_path: Path,
    session: Session,
) -> None:
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class BlockingGetKeyring(FakeKeyring):
        def __init__(self) -> None:
            super().__init__()
            self.block_get = False
            self.get_calls = 0

        def get_password(self, service: str, username: str) -> str | None:
            self.get_calls += 1
            if self.block_get:
                started.set()
                release.wait(timeout=2)
                finished.set()
            return super().get_password(service, username)

    backend = BlockingGetKeyring()
    store = SessionStore(tmp_path, keyring_backend=backend, keyring_timeout=0.05)
    store.save(session)
    backend.block_get = True

    try:
        with pytest.raises(KeyringTimeoutError):
            store.load()
        assert started.is_set()
        calls_after_timeout = backend.get_calls

        with pytest.raises(KeyringTimeoutError, match="previous OS keyring operation"):
            store.load()
        with pytest.raises(KeyringTimeoutError, match="previous OS keyring operation"):
            store.load()

        assert backend.get_calls == calls_after_timeout
    finally:
        backend.block_get = False
        release.set()

    assert finished.wait(timeout=2)
    assert store.load() == replace(session, storage=SessionStorage.KEYRING)
