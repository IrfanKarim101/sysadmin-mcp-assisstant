"""Local operator authentication with durable throttling and revocable sessions."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

SESSION_COOKIE = "sentinel_session"
IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_TIMEOUT = timedelta(hours=8)
LOGIN_WINDOW = timedelta(minutes=15)
MAX_LOGIN_FAILURES = 5
ROLES = frozenset({"administrator", "operator", "viewer"})


class LoginThrottled(Exception):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Too many login attempts. Try again later.")
        self.retry_after_seconds = max(1, retry_after_seconds)


@dataclass(frozen=True)
class AuthSession:
    username: str
    csrf_token: str
    must_change_password: bool
    role: str
    session_id: str


class AuthStore:
    def __init__(self, path: Path, *, now: Callable[[], datetime] | None = None) -> None:
        self.path, self._now = path, now or (lambda: datetime.now(UTC))
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS app_users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
              must_change_password INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS app_sessions (token_hash TEXT PRIMARY KEY,
              username TEXT NOT NULL REFERENCES app_users(username), csrf_token TEXT NOT NULL,
              created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, expires_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_app_sessions_username ON app_sessions(username);
            CREATE TABLE IF NOT EXISTS auth_login_attempts (id INTEGER PRIMARY KEY, attempted_at TEXT NOT NULL,
              username TEXT NOT NULL, client_key_hash TEXT NOT NULL, success INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_key_time
              ON auth_login_attempts(username, client_key_hash, attempted_at);
            CREATE TABLE IF NOT EXISTS auth_events (id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL,
              username TEXT, event_type TEXT NOT NULL, session_id TEXT);
            CREATE INDEX IF NOT EXISTS idx_auth_events_user_time ON auth_events(username, occurred_at DESC);
            """)
            self._add_column(db, "app_users", "role", "TEXT NOT NULL DEFAULT 'administrator'")
            self._add_column(db, "app_sessions", "session_id", "TEXT")
            self._add_column(db, "app_sessions", "client_label", "TEXT NOT NULL DEFAULT 'Browser'")
            for (token_hash,) in db.execute("SELECT token_hash FROM app_sessions WHERE session_id IS NULL"):
                db.execute("UPDATE app_sessions SET session_id=? WHERE token_hash=?", (str(uuid4()), token_hash))
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_app_sessions_session_id ON app_sessions(session_id)")
            stamp = self._utc_now().isoformat()
            db.execute("""INSERT OR IGNORE INTO app_users
              (username,password_hash,must_change_password,created_at,updated_at,role)
              VALUES (?, ?, 1, ?, ?, 'administrator')""", ("admin", _hash_password("admin"), stamp, stamp))
            db.execute("PRAGMA optimize")

    def login(self, username: str, password: str, *, client_ip: str = "local",
              user_agent: str = "Browser") -> tuple[str, AuthSession] | None:
        username, now = username.strip().lower(), self._utc_now()
        key, oldest = _client_key(username, client_ip), now - LOGIN_WINDOW
        with self._connect() as db:
            failures = db.execute("""SELECT attempted_at FROM auth_login_attempts WHERE username=?
              AND client_key_hash=? AND success=0 AND attempted_at>=? ORDER BY attempted_at""",
              (username, key, oldest.isoformat())).fetchall()
            if len(failures) >= MAX_LOGIN_FAILURES:
                retry = int((datetime.fromisoformat(failures[0][0]) + LOGIN_WINDOW - now).total_seconds()) + 1
                self._event(db, now, username or None, "login_throttled")
                raise LoginThrottled(retry)
            row = db.execute("SELECT password_hash,must_change_password,role FROM app_users WHERE username=?",
                             (username,)).fetchone()
            candidate = row[0] if row else _hash_password("not-the-password")
            valid = row is not None and _verify_password(password, candidate)
            db.execute("INSERT INTO auth_login_attempts(attempted_at,username,client_key_hash,success) VALUES (?,?,?,?)",
                       (now.isoformat(), username, key, int(valid)))
            db.execute("DELETE FROM auth_login_attempts WHERE attempted_at<?", ((now-timedelta(days=1)).isoformat(),))
            if not valid:
                self._event(db, now, username or None, "login_failure")
                return None
            db.execute("DELETE FROM auth_login_attempts WHERE username=? AND client_key_hash=? AND success=0",
                       (username, key))
            token, csrf, session_id = secrets.token_urlsafe(32), secrets.token_urlsafe(24), str(uuid4())
            db.execute("""INSERT INTO app_sessions(token_hash,username,csrf_token,created_at,last_seen_at,
              expires_at,session_id,client_label) VALUES (?,?,?,?,?,?,?,?)""",
              (_token_hash(token), username, csrf, now.isoformat(), now.isoformat(),
               (now+ABSOLUTE_TIMEOUT).isoformat(), session_id, _client_label(user_agent)))
            self._event(db, now, username, "login_success", session_id)
        return token, AuthSession(username, csrf, bool(row[1]), _role(row[2]), session_id)

    def authenticate(self, token: str | None) -> AuthSession | None:
        if not token: return None
        now, digest = self._utc_now(), _token_hash(token)
        with self._connect() as db:
            row = db.execute("""SELECT s.username,s.csrf_token,s.last_seen_at,s.expires_at,
              u.must_change_password,u.role,s.session_id FROM app_sessions s JOIN app_users u
              ON u.username=s.username WHERE s.token_hash=?""", (digest,)).fetchone()
            if not row: return None
            if now >= datetime.fromisoformat(row[3]) or now-datetime.fromisoformat(row[2]) >= IDLE_TIMEOUT:
                db.execute("DELETE FROM app_sessions WHERE token_hash=?", (digest,))
                self._event(db, now, row[0], "session_expired", row[6]); return None
            db.execute("UPDATE app_sessions SET last_seen_at=? WHERE token_hash=?", (now.isoformat(), digest))
        return AuthSession(row[0], row[1], bool(row[4]), _role(row[5]), row[6])

    def change_password(self, username: str, current: str, new: str) -> None:
        if len(new)<12 or len(new)>256 or new.lower()==username.lower() or new=="admin":
            raise ValueError("Use 12–256 characters and do not reuse the username or default password.")
        with self._connect() as db:
            row=db.execute("SELECT password_hash FROM app_users WHERE username=?",(username,)).fetchone()
            if not row or not _verify_password(current,row[0]): raise ValueError("Current password is incorrect.")
            now=self._utc_now(); db.execute("UPDATE app_users SET password_hash=?,must_change_password=0,updated_at=? WHERE username=?",
              (_hash_password(new),now.isoformat(),username)); self._event(db,now,username,"password_changed")

    def verify_password(self, username: str, password: str) -> bool:
        with self._connect() as db:
            row = db.execute("SELECT password_hash FROM app_users WHERE username=?", (username,)).fetchone()
        candidate = row[0] if row else _hash_password("not-the-password")
        return row is not None and _verify_password(password, candidate)

    def logout(self, token: str | None) -> None:
        if not token: return
        with self._connect() as db:
            row=db.execute("SELECT username,session_id FROM app_sessions WHERE token_hash=?",(_token_hash(token),)).fetchone()
            db.execute("DELETE FROM app_sessions WHERE token_hash=?",(_token_hash(token),))
            if row: self._event(db,self._utc_now(),row[0],"logout",row[1])

    def sessions(self, username: str, current_id: str) -> list[dict[str, object]]:
        now=self._utc_now()
        with self._connect() as db:
            db.execute("DELETE FROM app_sessions WHERE username=? AND (expires_at<=? OR last_seen_at<=?)",
                       (username,now.isoformat(),(now-IDLE_TIMEOUT).isoformat()))
            rows=db.execute("SELECT session_id,client_label,created_at,last_seen_at,expires_at FROM app_sessions WHERE username=? ORDER BY last_seen_at DESC LIMIT 100",(username,)).fetchall()
        return [{"session_id":r[0],"client_label":r[1],"created_at":r[2],"last_seen_at":r[3],
                 "expires_at":r[4],"current":hmac.compare_digest(r[0],current_id)} for r in rows]

    def revoke_session(self, username: str, session_id: str) -> bool:
        with self._connect() as db:
            cursor=db.execute("DELETE FROM app_sessions WHERE username=? AND session_id=?",(username,session_id))
            if cursor.rowcount: self._event(db,self._utc_now(),username,"session_revoked",session_id)
            return bool(cursor.rowcount)

    def events(self, username: str, limit: int=50) -> list[dict[str, object]]:
        with self._connect() as db:
            rows=db.execute("SELECT id,occurred_at,event_type,session_id FROM auth_events WHERE username=? ORDER BY id DESC LIMIT ?",
                            (username,min(max(limit,1),100))).fetchall()
        return [{"id":r[0],"occurred_at":r[1],"event_type":r[2],"session_id":r[3]} for r in rows]

    @staticmethod
    def _add_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        if column not in {r[1] for r in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @staticmethod
    def _event(db: sqlite3.Connection, when: datetime, username: str | None,
               kind: str, session_id: str | None=None) -> None:
        db.execute("INSERT INTO auth_events(occurred_at,username,event_type,session_id) VALUES (?,?,?,?)",
                   (when.isoformat(),username,kind,session_id))

    def _utc_now(self) -> datetime:
        value=self._now(); return value if value.tzinfo else value.replace(tzinfo=UTC)

    def _connect(self) -> sqlite3.Connection:
        db=sqlite3.connect(self.path,timeout=5); db.execute("PRAGMA foreign_keys=ON"); db.execute("PRAGMA busy_timeout=5000"); return db


def _hash_password(password: str) -> str:
    salt=secrets.token_bytes(16); digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"

def _verify_password(password: str, encoded: str) -> bool:
    try:
        _,n,r,p,salt,expected=encoded.split("$"); actual=hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=int(n),r=int(r),p=int(p))
        return hmac.compare_digest(actual.hex(),expected)
    except (ValueError,TypeError): return False

def _token_hash(token: str) -> str: return hashlib.sha256(token.encode()).hexdigest()
def _client_key(username: str, client_ip: str) -> str: return hashlib.sha256(f"{username}\0{client_ip}".encode()).hexdigest()
def _role(value: str) -> str: return value if value in ROLES else "viewer"
def _client_label(agent: str) -> str:
    value=agent[:256].lower(); browser="Firefox" if "firefox" in value else "Edge" if "edg/" in value else "Chrome" if "chrome" in value else "Browser"
    platform="Windows" if "windows" in value else "Linux" if "linux" in value else "macOS" if "macintosh" in value else ""
    return f"{browser} on {platform}" if platform else browser
