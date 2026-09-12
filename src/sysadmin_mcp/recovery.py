"""Typed, bounded recovery snapshots; Phase 17 is deliberately simulation-only."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from .audit import AuditEvent, AuditSink

SNAPSHOT_TTL = timedelta(hours=24)
MAX_SNAPSHOTS = 1_000
MAX_TRANSACTION_BYTES = 1_000_000
REVERSIBLE_ACTIONS = {
    "write_managed_file": "managed_file",
    "install_package": "package_state",
    "update_package": "package_state",
    "enable_service": "service_state",
    "disable_service": "service_state",
    "reload_service": "service_state",
    "restart_service": "service_state",
}


class RecoveryDenied(ValueError):
    """A snapshot or restoration operation failed closed."""


class RecoveryStore:
    def __init__(self, path: Path, audit: AuditSink,
                 *, now: Callable[[], datetime] | None = None) -> None:
        self.path, self.audit = path, audit
        self._now = now or (lambda: datetime.now(UTC))
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS recovery_snapshots (
              id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL, action_index INTEGER NOT NULL,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL, snapshot_type TEXT NOT NULL,
              host TEXT NOT NULL, target TEXT NOT NULL, metadata TEXT NOT NULL,
              checksum TEXT NOT NULL, estimated_bytes INTEGER NOT NULL,
              verified INTEGER NOT NULL DEFAULT 1, restored_at TEXT,
              UNIQUE(transaction_id, action_index)
            );
            CREATE INDEX IF NOT EXISTS idx_recovery_expiry ON recovery_snapshots(expires_at);
            """)

    def capture(self, transaction_id: str, actions: Sequence[Mapping[str, object]],
                username: str, session_id: str) -> list[dict[str, object]]:
        self._transaction_id(transaction_id)
        self.cleanup()
        reversible = [(index, action) for index, action in enumerate(actions)
                      if str(action["action"]) in REVERSIBLE_ACTIONS]
        if self._count() + len(reversible) > MAX_SNAPSHOTS:
            raise RecoveryDenied("Recovery snapshot capacity is exhausted")
        estimates = sum(_estimate(action) for _, action in reversible)
        if estimates > MAX_TRANSACTION_BYTES:
            raise RecoveryDenied("Recovery snapshot estimate exceeds the transaction limit")
        now, expires = self._utc_now(), self._utc_now() + SNAPSHOT_TTL
        with self._connect() as db:
            for index, action in reversible:
                metadata = _metadata(action)
                encoded = _canonical(metadata)
                db.execute("""INSERT OR IGNORE INTO recovery_snapshots
                  (id,transaction_id,action_index,created_at,expires_at,snapshot_type,host,target,
                   metadata,checksum,estimated_bytes,verified)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?,1)""", (
                    str(uuid4()), transaction_id, index, now.isoformat(), expires.isoformat(),
                    REVERSIBLE_ACTIONS[str(action["action"])], action["host"], action["target"],
                    encoded, _digest(encoded), _estimate(action),
                ))
        snapshots = self.for_transaction(transaction_id)
        self._audit("recovery_snapshots_captured", transaction_id, username, session_id,
                    {"count": len(snapshots), "estimated_bytes": estimates})
        return snapshots

    def verify_required(self, transaction_id: str,
                        actions: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
        required = {index for index, action in enumerate(actions)
                    if str(action["action"]) in REVERSIBLE_ACTIONS}
        snapshots = self.for_transaction(transaction_id)
        found = {int(item["action_index"]) for item in snapshots}
        if found != required:
            raise RecoveryDenied("A required recovery snapshot is missing")
        self._verify_snapshots(snapshots)
        return snapshots

    def _verify_snapshots(self, snapshots: Sequence[Mapping[str, object]]) -> None:
        now = self._utc_now()
        for item in snapshots:
            if not item["verified"] or now >= datetime.fromisoformat(str(item["expires_at"])):
                raise RecoveryDenied("A required recovery snapshot is stale or unverified")
            if _digest(_canonical(item["metadata"])) != item["checksum"]:
                raise RecoveryDenied("Recovery snapshot integrity verification failed")

    def restore(self, transaction_id: str, username: str,
                session_id: str) -> list[dict[str, object]]:
        snapshots = self.for_transaction(transaction_id)
        if not snapshots:
            return []
        self._verify_snapshots(snapshots)
        restored_at = self._utc_now().isoformat()
        with self._connect() as db:
            db.execute("""UPDATE recovery_snapshots SET restored_at=COALESCE(restored_at, ?)
                          WHERE transaction_id=?""", (restored_at, transaction_id))
        result = self.for_transaction(transaction_id)
        self._audit("recovery_restore_simulated", transaction_id, username, session_id,
                    {"count": len(result), "remote_mutation": False})
        return result

    def for_transaction(self, transaction_id: str) -> list[dict[str, object]]:
        normalized = self._transaction_id(transaction_id)
        with self._connect() as db:
            rows = db.execute("""SELECT * FROM recovery_snapshots WHERE transaction_id=?
                               ORDER BY action_index""", (normalized,)).fetchall()
        return [_public(row) for row in rows]

    def cleanup(self) -> int:
        with self._connect() as db:
            cursor = db.execute("DELETE FROM recovery_snapshots WHERE expires_at <= ?",
                                (self._utc_now().isoformat(),))
        return cursor.rowcount

    def _count(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM recovery_snapshots").fetchone()[0])

    @staticmethod
    def _transaction_id(value: str) -> str:
        try:
            return str(UUID(value))
        except (ValueError, TypeError, AttributeError) as error:
            raise RecoveryDenied("Invalid recovery transaction ID") from error

    def _audit(self, tool: str, transaction_id: str, username: str, session_id: str,
               parameters: Mapping[str, object]) -> None:
        self.audit.append(AuditEvent(
            request_id=str(uuid4()), session_id=session_id, target_host="recovery-store",
            tool_name=tool, parameters={"transaction_id": transaction_id,
                                        "operator": username, **parameters},
            command=(), status="success",
        ))

    def _utc_now(self) -> datetime:
        value = self._now()
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db


def _metadata(action: Mapping[str, object]) -> dict[str, object]:
    kind = str(action["action"])
    common = {"schema": 1, "simulated": True, "owner": "root", "group": "root"}
    if kind == "write_managed_file":
        return {**common, "mode": "0644", "prior_content_sha256": _digest("simulated-prior-content")}
    if kind in {"install_package", "update_package"}:
        return {**common, "installed": True, "version": "simulated-current"}
    return {**common, "enabled": True, "active": True, "sub_state": "running"}


def _estimate(action: Mapping[str, object]) -> int:
    return 4096 + min(len(str(action.get("value") or "").encode()), 32_000)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _public(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "reference": f"recovery://{row['id']}", "action_index": row["action_index"],
        "snapshot_type": row["snapshot_type"], "host": row["host"], "target": row["target"],
        "created_at": row["created_at"], "expires_at": row["expires_at"],
        "metadata": json.loads(str(row["metadata"])), "checksum": row["checksum"],
        "estimated_bytes": row["estimated_bytes"], "verified": bool(row["verified"]),
        "restored_at": row["restored_at"], "remote_mutation": False,
    }
