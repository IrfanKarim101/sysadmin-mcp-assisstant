"""Small local report command for recent audit events."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from .audit import MAX_RECENT_ROWS, SQLiteAuditLog


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show recent sysadmin audit events")
    parser.add_argument("database", type=Path, help="path to the SQLite audit database")
    parser.add_argument(
        "--limit", type=int, default=20, help=f"rows to show (1-{MAX_RECENT_ROWS})"
    )
    args = parser.parse_args(argv)

    rows = SQLiteAuditLog(args.database).recent(args.limit)
    print("ID  TIMESTAMP                         STATUS     HOST              TOOL")
    for row in rows:
        print(
            f"{row.id:<3} {row.timestamp:<33} {row.status:<10} "
            f"{row.target_host:<17} {row.tool_name}"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
