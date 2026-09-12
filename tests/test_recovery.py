import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

import sysadmin_mcp.recovery as recovery_module
from sysadmin_mcp.audit import SQLiteAuditLog
from sysadmin_mcp.recovery import RecoveryDenied, RecoveryStore


def store(tmp_path: Path, now=None):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    return audit, RecoveryStore(audit.path, audit, now=now)


def actions():
    return [
        {"action": "write_managed_file", "host": "lab", "target": "/etc/app.conf", "value": "x=1"},
        {"action": "update_package", "host": "lab", "target": "nginx"},
        {"action": "restart_service", "host": "lab", "target": "nginx.service"},
    ]


def test_typed_snapshots_are_verified_opaque_and_idempotently_restored(tmp_path):
    _, recovery = store(tmp_path)
    transaction_id = str(uuid4())
    captured = recovery.capture(transaction_id, actions(), "admin", "session-a")
    assert [item["snapshot_type"] for item in captured] == [
        "managed_file", "package_state", "service_state"
    ]
    assert all(item["reference"].startswith("recovery://") for item in captured)
    assert all(item["verified"] and item["remote_mutation"] is False for item in captured)
    assert "prior_content_sha256" in captured[0]["metadata"]
    first = recovery.restore(transaction_id, "admin", "session-a")
    second = recovery.restore(transaction_id, "admin", "session-a")
    assert [item["restored_at"] for item in first] == [item["restored_at"] for item in second]


def test_missing_tampered_and_expired_snapshots_fail_closed(tmp_path):
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    audit, recovery = store(tmp_path, lambda: current[0])
    transaction_id = str(uuid4())
    recovery.capture(transaction_id, actions(), "admin", "session-a")
    with sqlite3.connect(audit.path) as db:
        db.execute("UPDATE recovery_snapshots SET metadata='{}' WHERE action_index=0")
    with pytest.raises(RecoveryDenied, match="integrity"):
        recovery.verify_required(transaction_id, actions())
    with sqlite3.connect(audit.path) as db:
        db.execute("DELETE FROM recovery_snapshots WHERE action_index=1")
    with pytest.raises(RecoveryDenied, match="missing"):
        recovery.verify_required(transaction_id, actions())
    current[0] += timedelta(hours=25)
    assert recovery.cleanup() == 2


def test_retention_capacity_and_estimated_size_are_bounded(tmp_path, monkeypatch):
    _, recovery = store(tmp_path)
    monkeypatch.setattr(recovery_module, "MAX_SNAPSHOTS", 1)
    recovery.capture(str(uuid4()), [actions()[0]], "admin", "session-a")
    with pytest.raises(RecoveryDenied, match="capacity"):
        recovery.capture(str(uuid4()), [actions()[1]], "admin", "session-a")
    monkeypatch.setattr(recovery_module, "MAX_SNAPSHOTS", 1_000)
    huge = [{"action": "write_managed_file", "host": "lab", "target": f"/etc/{i}",
             "value": "x" * 32_000} for i in range(30)]
    with pytest.raises(RecoveryDenied, match="estimate"):
        recovery.capture(str(uuid4()), huge, "admin", "session-a")
