import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sysadmin_mcp.auth import MAX_LOGIN_FAILURES, AuthStore, LoginThrottled


def test_default_admin_is_hashed_and_forced_to_change(tmp_path: Path):
    path = tmp_path / "auth.db"
    store = AuthStore(path)
    result = store.login("admin", "admin")
    assert result is not None
    token, session = result
    assert session.must_change_password is True
    assert store.authenticate(token) is not None
    with sqlite3.connect(path) as db:
        encoded = db.execute("SELECT password_hash FROM app_users WHERE username='admin'").fetchone()[0]
    assert encoded.startswith("scrypt$") and encoded != "admin"


def test_password_change_validation_and_first_login_completion(tmp_path: Path):
    store = AuthStore(tmp_path / "auth.db")
    with pytest.raises(ValueError):
        store.change_password("admin", "wrong", "a-secure-password")
    with pytest.raises(ValueError):
        store.change_password("admin", "admin", "short")
    store.change_password("admin", "admin", "a-secure-password")
    result = store.login("admin", "a-secure-password")
    assert result is not None and result[1].must_change_password is False
    assert store.login("admin", "admin") is None


def test_session_tokens_are_hashed_and_revocable(tmp_path: Path):
    path = tmp_path / "auth.db"
    store = AuthStore(path)
    result = store.login("admin", "admin")
    assert result is not None
    token, _ = result
    with sqlite3.connect(path) as db:
        stored = db.execute("SELECT token_hash FROM app_sessions").fetchone()[0]
    assert token != stored
    store.logout(token)
    assert store.authenticate(token) is None


def test_existing_auth_schema_is_migrated_without_resetting_password(tmp_path: Path):
    path = tmp_path / "auth.db"
    stamp = datetime.now(UTC).isoformat()
    with sqlite3.connect(path) as db:
        db.executescript("""
        CREATE TABLE app_users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
          must_change_password INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE app_sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
          csrf_token TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, expires_at TEXT NOT NULL);
        """)
        db.execute("INSERT INTO app_users VALUES ('existing','invalid-hash',0,?,?)", (stamp, stamp))
    AuthStore(path)
    with sqlite3.connect(path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(app_users)")}
        assert {"role"}.issubset(columns)
        assert db.execute("SELECT password_hash FROM app_users WHERE username='existing'").fetchone()[0] == "invalid-hash"


def test_login_throttle_is_persistent_bounded_and_does_not_store_raw_ip(tmp_path: Path):
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    path = tmp_path / "auth.db"
    store = AuthStore(path, now=lambda: current[0])
    for _ in range(MAX_LOGIN_FAILURES):
        assert store.login("admin", "wrong", client_ip="192.0.2.55") is None
    with pytest.raises(LoginThrottled) as error:
        store.login("admin", "admin", client_ip="192.0.2.55")
    assert 1 <= error.value.retry_after_seconds <= int(timedelta(minutes=15).total_seconds()) + 1
    with sqlite3.connect(path) as db:
        stored = db.execute("SELECT client_key_hash FROM auth_login_attempts LIMIT 1").fetchone()[0]
    assert stored != "192.0.2.55" and len(stored) == 64
    current[0] += timedelta(minutes=16)
    assert store.login("admin", "admin", client_ip="192.0.2.55") is not None


def test_sessions_can_only_be_listed_and_revoked_for_the_owner(tmp_path: Path):
    store = AuthStore(tmp_path / "auth.db")
    first = store.login("admin", "admin", user_agent="Mozilla Firefox Windows")
    second = store.login("admin", "admin", user_agent="Chrome Linux")
    assert first and second
    rows = store.sessions("admin", first[1].session_id)
    assert len(rows) == 2 and sum(bool(row["current"]) for row in rows) == 1
    assert store.revoke_session("another-user", second[1].session_id) is False
    assert store.authenticate(second[0]) is not None
    assert store.revoke_session("admin", second[1].session_id) is True
    assert store.authenticate(second[0]) is None


def test_auth_event_requests_are_bounded(tmp_path: Path):
    store = AuthStore(tmp_path / "auth.db")
    for _ in range(110):
        store.events("admin", 10)
    assert store.login("admin", "admin") is not None
    assert len(store.events("admin", 100_000)) <= 100
