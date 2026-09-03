"""Local MVP preflight checks which do not connect to remote hosts."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from pathlib import Path

from .config import ConfigError, load_hosts


def check_local_prerequisites(config_path: Path, audit_path: Path) -> list[str]:
    """Return actionable configuration/filesystem problems without exposing secrets."""
    problems: list[str] = []
    try:
        hosts = load_hosts(config_path)
    except ConfigError as error:
        return [str(error)]
    if not hosts:
        problems.append("No hosts are configured")
    for name, host in hosts.items():
        known_hosts = Path(host.known_hosts)
        if not known_hosts.is_file():
            problems.append(f"Host {name!r}: known_hosts file does not exist")
        for key in host.client_keys:
            if not key.is_file():
                problems.append(f"Host {name!r}: a configured client key does not exist")
            elif os.name == "posix" and key.stat().st_mode & 0o077:
                problems.append(f"Host {name!r}: a client key is accessible by group/others")
    audit_parent = audit_path.parent
    if not audit_parent.exists():
        problems.append(f"Audit directory does not exist: {audit_parent}")
    elif not os.access(audit_parent, os.W_OK):
        problems.append(f"Audit directory is not writable: {audit_parent}")
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check local MVP prerequisites")
    parser.add_argument("--config", type=Path, default=Path("config/hosts.toml"))
    parser.add_argument("--audit-db", type=Path, default=Path("data/audit.db"))
    args = parser.parse_args(argv)
    problems = check_local_prerequisites(args.config, args.audit_db)
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}")
        return 1
    print("Preflight passed: host configuration, SSH files, and audit directory are ready")
    return 0
