import sqlite3
from pathlib import Path

import pytest

from sysadmin_mcp.auth import AuthStore


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
