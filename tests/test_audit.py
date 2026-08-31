from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest

from sysadmin_mcp.audit import (
    MAX_EXCERPT_BYTES,
    MAX_PARAMETERS_BYTES,
    AuditError,
    AuditEvent,
    SQLiteAuditLog,
)
from sysadmin_mcp.config import HostConfig
from sysadmin_mcp.executor import CommandResult, PolicyError, ReadOnlyExecutor


def event(**changes) -> AuditEvent:
    base = AuditEvent(
        request_id="request-1",
        session_id="session-1",
        target_host="test",
        tool_name="grep_log",
        parameters={"pattern": "error"},
        command=("grep", "-n", "-m", "10", "--", "error", "/var/log/syslog"),
        status="success",
        output="one line\n",
        duration_ms=12,
    )
    return replace(base, **changes)


def test_sqlite_audit_round_trips_parameterized_untrusted_values(tmp_path: Path) -> None:
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    injection = "x'); DELETE FROM action_log; --"
    audit.append(event(parameters={"pattern": injection}, output=injection))

    rows = audit.recent()
    assert len(rows) == 1
    assert json.loads(rows[0].parameters) == {"pattern": injection}
    assert rows[0].output_excerpt == injection
    assert rows[0].command_executed.startswith("grep -n -m 10 --")


def test_database_triggers_reject_update_and_delete(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    audit = SQLiteAuditLog(path)
    audit.append(event())

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE action_log SET status = 'error'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM action_log")
    assert len(audit.recent()) == 1


def test_output_excerpt_is_bounded_and_full_output_is_hashed(tmp_path: Path) -> None:
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    output = "é" * (MAX_EXCERPT_BYTES + 100)
    audit.append(event(output=output))

    row = audit.recent(1)[0]
    assert len(row.output_excerpt.encode("utf-8")) <= MAX_EXCERPT_BYTES
    assert row.output_sha256 == hashlib.sha256(output.encode()).hexdigest()


def test_oversized_parameters_are_replaced_by_a_digest(tmp_path: Path) -> None:
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    audit.append(event(parameters={"pattern": "x" * (MAX_PARAMETERS_BYTES + 1)}))
    stored = json.loads(audit.recent(1)[0].parameters)
    assert stored["_truncated"] is True
    assert len(stored["sha256"]) == 64


def test_invalid_status_and_recent_limit_are_rejected(tmp_path: Path) -> None:
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    with pytest.raises(AuditError, match="invalid audit status"):
        audit.append(event(status="pending"))
    for limit in (0, 1_001, True, "10"):
        with pytest.raises(ValueError, match="limit"):
            audit.recent(limit)


class FakeTransport:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.commands: list[tuple[str, ...]] = []

    async def run(self, host, argv) -> CommandResult:
        command = tuple(argv)
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return CommandResult(command, "healthy\n", "", 0)


def make_executor(path: Path, transport: FakeTransport) -> tuple[ReadOnlyExecutor, SQLiteAuditLog]:
    host = HostConfig(
        name="test",
        hostname="localhost",
        username="reader",
        known_hosts=None,
        client_keys=(),
        allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
    )
    audit = SQLiteAuditLog(path)
    executor = ReadOnlyExecutor({"test": host}, transport, audit, session_id="chat-42")
    return executor, audit


@pytest.mark.asyncio
async def test_executor_appends_attempted_then_success(tmp_path: Path) -> None:
    executor, audit = make_executor(tmp_path / "audit.db", FakeTransport())
    await executor.check_services("test", "active")

    rows = list(reversed(audit.recent()))
    assert [row.status for row in rows] == ["attempted", "success"]
    assert rows[0].request_id == rows[1].request_id
    assert rows[1].session_id == "chat-42"
    assert rows[1].command_executed.endswith("--state=active")
    assert rows[1].output_sha256 is not None
    assert rows[1].duration_ms is not None


@pytest.mark.asyncio
async def test_executor_appends_error_when_transport_raises(tmp_path: Path) -> None:
    transport = FakeTransport(RuntimeError("connection failed"))
    executor, audit = make_executor(tmp_path / "audit.db", transport)
    with pytest.raises(RuntimeError, match="connection failed"):
        await executor.check_ports("test")

    rows = list(reversed(audit.recent()))
    assert [row.status for row in rows] == ["attempted", "error"]
    assert rows[1].output_excerpt == "RuntimeError: connection failed"


@pytest.mark.asyncio
async def test_policy_rejection_is_audited_without_transport(tmp_path: Path) -> None:
    transport = FakeTransport()
    executor, audit = make_executor(tmp_path / "audit.db", transport)
    with pytest.raises(PolicyError):
        await executor.read_log("test", "/etc/shadow", "tail")

    row = audit.recent(1)[0]
    assert row.status == "denied"
    assert row.command_executed == ""
    assert json.loads(row.parameters)["logfile"] == "/etc/shadow"
    assert transport.commands == []


@pytest.mark.asyncio
async def test_audit_failure_prevents_transport_execution() -> None:
    class BrokenAudit:
        def append(self, event) -> None:
            raise AuditError("disk unavailable")

    transport = FakeTransport()
    host = HostConfig("test", "localhost", "reader", None, (), frozenset())
    executor = ReadOnlyExecutor({"test": host}, transport, BrokenAudit())
    with pytest.raises(AuditError, match="disk unavailable"):
        await executor.check_ports("test")
    assert transport.commands == []
