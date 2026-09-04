"""Bounded SQLite persistence for local operator conversations."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

MAX_CHAT_MESSAGES = 1_000
MAX_CONTENT_CHARS = 32_000

CHAT_SCHEMA = """
CREATE TABLE IF NOT EXISTS chat_sessions (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    host TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('openai', 'gemini'))
);
CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES chat_sessions(id),
    created_at TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS chat_messages_session_id
ON chat_messages(session_id, id);
"""


@dataclass(frozen=True)
class ChatMessage:
    id: int
    session_id: str
    created_at: str
    role: str
    content: str
    metadata: str


class SQLiteChatStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(CHAT_SCHEMA)

    def ensure_session(self, session_id: str, host: str, provider: str) -> None:
        _validate_session_id(session_id)
        timestamp = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO chat_sessions (id, created_at, updated_at, host, provider)
                VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
                updated_at = excluded.updated_at, host = excluded.host,
                provider = excluded.provider""",
                (session_id, timestamp, timestamp, host, provider),
            )

    def append(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        _validate_session_id(session_id)
        if role not in {"user", "assistant"}:
            raise ValueError("invalid chat role")
        if not isinstance(content, str) or not content or len(content) > MAX_CONTENT_CHARS:
            raise ValueError("chat content is empty or exceeds its limit")
        encoded_metadata = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
        timestamp = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO chat_messages
                (session_id, created_at, role, content, metadata)
                VALUES (?, ?, ?, ?, ?)""",
                (session_id, timestamp, role, content, encoded_metadata),
            )

    def messages(self, session_id: str, limit: int = 200) -> list[dict[str, object]]:
        _validate_session_id(session_id)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_CHAT_MESSAGES
        ):
            raise ValueError("chat limit must be between 1 and 1000")
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT * FROM (
                    SELECT * FROM chat_messages WHERE session_id = ?
                    ORDER BY id DESC LIMIT ?
                ) ORDER BY id""",
                (session_id, limit),
            ).fetchall()
        return [asdict(ChatMessage(**dict(row))) for row in rows]

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection


def _validate_session_id(session_id: str) -> None:
    try:
        parsed = UUID(session_id)
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("invalid chat session id") from error
    if str(parsed) != session_id.lower():
        raise ValueError("invalid chat session id")
