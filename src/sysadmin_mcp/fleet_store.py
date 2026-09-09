"""Bounded SQLite history for fleet health snapshots."""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

MAX_HISTORY_ROWS = 500


class FleetSnapshotStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        with sqlite3.connect(path) as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS fleet_snapshots (
              id INTEGER PRIMARY KEY, captured_at TEXT NOT NULL, host TEXT NOT NULL,
              status TEXT NOT NULL, cpu_percent REAL, memory_percent REAL,
              disk_percent REAL, message TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_fleet_snapshots_host_time
              ON fleet_snapshots(host, captured_at DESC);
            """)
            db.execute("PRAGMA optimize")

    def append_many(self, snapshots: list[dict[str, object]]) -> None:
        stamp = datetime.now(UTC).isoformat()
        with sqlite3.connect(self.path) as db:
            db.executemany("""INSERT INTO fleet_snapshots
              (captured_at,host,status,cpu_percent,memory_percent,disk_percent,message,payload)
              VALUES (?,?,?,?,?,?,?,?)""", [
                (stamp, row["name"], row["status"], row.get("cpu_percent"),
                 row.get("memory_percent"), row.get("disk_percent"), row["message"],
                 json.dumps(row, separators=(",", ":"))) for row in snapshots
            ])

    def history(self, host: str, limit: int = 100) -> list[dict[str, object]]:
        bounded = min(max(limit, 1), MAX_HISTORY_ROWS)
        with sqlite3.connect(self.path) as db:
            rows = db.execute("""SELECT captured_at,status,cpu_percent,memory_percent,
              disk_percent,message FROM fleet_snapshots WHERE host=? ORDER BY id DESC LIMIT ?""",
              (host, bounded)).fetchall()
        return [{"captured_at": r[0], "status": r[1], "cpu_percent": r[2],
                 "memory_percent": r[3], "disk_percent": r[4], "message": r[5]}
                for r in rows]

    def latest(self, host: str) -> dict[str, object] | None:
        rows = self.history(host, 1)
        return rows[0] if rows else None
