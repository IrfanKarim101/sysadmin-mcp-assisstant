"""Local operator authentication with bounded, revocable SQLite sessions."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

SESSION_COOKIE = "sentinel_session"
IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_TIMEOUT = timedelta(hours=8)


@dataclass(frozen=True)
class AuthSession:
    username: str
    csrf_token: str
    must_change_password: bool


class AuthStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS app_users (
              username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
              must_change_password INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS app_sessions (
              token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES app_users(username),
              csrf_token TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
              expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_app_sessions_username ON app_sessions(username);
            """)
            now = datetime.now(UTC).isoformat()
            db.execute(
                "INSERT OR IGNORE INTO app_users VALUES (?, ?, 1, ?, ?)",
                ("admin", _hash_password("admin"), now, now),
            )

    def login(self, username: str, password: str) -> tuple[str, AuthSession] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT password_hash, must_change_password FROM app_users WHERE username = ?",
                (username,),
            ).fetchone()
        candidate = row[0] if row else _hash_password("not-the-password")
        if not _verify_password(password, candidate) or row is None:
            return None
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        now = datetime.now(UTC)
        with self._connect() as db:
            db.execute(
                "INSERT INTO app_sessions VALUES (?, ?, ?, ?, ?, ?)",
                (_token_hash(token), username, csrf, now.isoformat(), now.isoformat(),
                 (now + ABSOLUTE_TIMEOUT).isoformat()),
            )
        return token, AuthSession(username, csrf, bool(row[1]))

    def authenticate(self, token: str | None) -> AuthSession | None:
        if not token:
            return None
        now = datetime.now(UTC)
        with self._connect() as db:
            row = db.execute("""SELECT s.username, s.csrf_token, s.created_at, s.last_seen_at,
                s.expires_at, u.must_change_password FROM app_sessions s
                JOIN app_users u ON u.username=s.username WHERE s.token_hash=?""",
                (_token_hash(token),)).fetchone()
            if not row:
                return None
            expired = now >= datetime.fromisoformat(row[4]) or now - datetime.fromisoformat(row[3]) >= IDLE_TIMEOUT
            if expired:
                db.execute("DELETE FROM app_sessions WHERE token_hash=?", (_token_hash(token),))
                return None
            db.execute("UPDATE app_sessions SET last_seen_at=? WHERE token_hash=?",
                       (now.isoformat(), _token_hash(token)))
        return AuthSession(row[0], row[1], bool(row[5]))

    def change_password(self, username: str, current: str, new: str) -> None:
        if len(new) < 12 or len(new) > 256 or new.lower() == username.lower() or new == "admin":
            raise ValueError("Use 12–256 characters and do not reuse the username or default password.")
        with self._connect() as db:
            row = db.execute("SELECT password_hash FROM app_users WHERE username=?", (username,)).fetchone()
            if not row or not _verify_password(current, row[0]):
                raise ValueError("Current password is incorrect.")
            db.execute("UPDATE app_users SET password_hash=?, must_change_password=0, updated_at=? WHERE username=?",
                       (_hash_password(new), datetime.now(UTC).isoformat(), username))

    def logout(self, token: str | None) -> None:
        if token:
            with self._connect() as db:
                db.execute("DELETE FROM app_sessions WHERE token_hash=?", (_token_hash(token),))

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        return db


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def _verify_password(password: str, encoded: str) -> bool:
    try:
        _, n, r, p, salt, expected = encoded.split("$")
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
