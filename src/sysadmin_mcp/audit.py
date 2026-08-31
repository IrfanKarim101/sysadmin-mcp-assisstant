"""Durable, append-only SQLite audit events for executor actions."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

MAX_EXCERPT_BYTES = 4_096
MAX_PARAMETERS_BYTES = 8_192
MAX_RECENT_ROWS = 1_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS action_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    request_id TEXT NOT NULL,
    session_id TEXT,
    target_host TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    parameters TEXT NOT NULL,
    command_executed TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('attempted', 'success', 'error', 'denied')),
    output_excerpt TEXT,
    output_sha256 TEXT,
    duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0)
);
CREATE INDEX IF NOT EXISTS action_log_request_id ON action_log(request_id);
CREATE TRIGGER IF NOT EXISTS action_log_no_update
BEFORE UPDATE ON action_log
BEGIN
    SELECT RAISE(ABORT, 'action_log is append-only');
END;
CREATE TRIGGER IF NOT EXISTS action_log_no_delete
BEFORE DELETE ON action_log
BEGIN
    SELECT RAISE(ABORT, 'action_log is append-only');
END;
"""


class AuditError(RuntimeError):
    """An audit event could not be persisted safely."""


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    session_id: str | None
    target_host: str
    tool_name: str
    parameters: Mapping[str, object]
    command: Sequence[str]
    status: str
    output: str | None = None
    duration_ms: int | None = None


@dataclass(frozen=True)
class AuditRow:
    id: int
    timestamp: str
    request_id: str
    session_id: str | None
    target_host: str
    tool_name: str
    parameters: str
    command_executed: str
    status: str
    output_excerpt: str | None
    output_sha256: str | None
    duration_ms: int | None


class AuditSink(Protocol):
    """Minimal boundary consumed by the executor."""

    def append(self, event: AuditEvent) -> None: ...


class SQLiteAuditLog:
    """SQLite event store which commits each event in its own transaction."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.executescript(SCHEMA)
            os.chmod(self.path, 0o600)
        except sqlite3.Error as error:
            raise AuditError("could not initialize audit database") from error

    def append(self, event: AuditEvent) -> None:
        if event.status not in {"attempted", "success", "error", "denied"}:
            raise AuditError(f"invalid audit status: {event.status}")
        parameters = self._parameters_json(event.parameters)
        excerpt, digest = self._summarize_output(event.output)
        timestamp = datetime.now(UTC).isoformat()
        command = shlex.join(tuple(event.command)) if event.command else ""
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO action_log (
                        timestamp, request_id, session_id, target_host, tool_name,
                        parameters, command_executed, status, output_excerpt,
                        output_sha256, duration_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        timestamp,
                        event.request_id,
                        event.session_id,
                        event.target_host,
                        event.tool_name,
                        parameters,
                        command,
                        event.status,
                        excerpt,
                        digest,
                        event.duration_ms,
                    ),
                )
        except sqlite3.Error as error:
            raise AuditError("could not append audit event") from error

    def recent(self, limit: int = 20) -> list[AuditRow]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_RECENT_ROWS
        ):
            raise ValueError(f"limit must be an integer between 1 and {MAX_RECENT_ROWS}")
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM action_log ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        except sqlite3.Error as error:
            raise AuditError("could not read audit events") from error
        return [AuditRow(**dict(row)) for row in rows]

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @staticmethod
    def _parameters_json(parameters: Mapping[str, object]) -> str:
        try:
            serialized = json.dumps(
                parameters, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            )
        except (TypeError, ValueError) as error:
            raise AuditError("audit parameters are not JSON serializable") from error
        encoded = serialized.encode("utf-8")
        if len(encoded) <= MAX_PARAMETERS_BYTES:
            return serialized
        return json.dumps(
            {
                "_truncated": True,
                "sha256": hashlib.sha256(encoded).hexdigest(),
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _summarize_output(output: str | None) -> tuple[str | None, str | None]:
        if output is None:
            return None, None
        encoded = output.encode("utf-8")
        excerpt = encoded[:MAX_EXCERPT_BYTES].decode("utf-8", errors="ignore")
        return excerpt, hashlib.sha256(encoded).hexdigest()
