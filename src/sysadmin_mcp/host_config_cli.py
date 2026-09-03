"""Administrative CLI for atomic host configuration changes."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from .config import (
    ConfigError,
    HostConfig,
    ResourceThresholds,
    load_hosts,
    save_hosts,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage approved sysadmin MCP hosts")
    parser.add_argument("--config", type=Path, default=Path("config/hosts.toml"))
    commands = parser.add_subparsers(dest="operation", required=True)

    commands.add_parser("list", help="list configured targets without key material")

    add = commands.add_parser("add", help="add one explicitly configured target")
    add.add_argument("name")
    add.add_argument("--hostname", required=True)
    add.add_argument("--username", required=True)
    add.add_argument("--known-hosts", required=True)
    add.add_argument("--client-key", action="append", required=True)
    add.add_argument("--allowed-log", action="append", required=True)
    add.add_argument("--cpu-threshold", type=float, default=90.0)
    add.add_argument("--memory-threshold", type=float, default=90.0)
    add.add_argument("--replace", action="store_true")

    remove = commands.add_parser("remove", help="remove one target by its exact name")
    remove.add_argument("name")

    args = parser.parse_args(argv)
    try:
        hosts = load_hosts(args.config) if args.config.exists() else {}
        if args.operation == "list":
            for name in sorted(hosts):
                host = hosts[name]
                print(
                    f"{name}\t{host.username}@{host.hostname}\t"
                    f"{len(host.allowed_logs)} allowed log(s)"
                )
            return 0
        if args.operation == "add":
            if args.name in hosts and not args.replace:
                raise ConfigError(
                    f"Host {args.name!r} already exists; pass --replace to overwrite it"
                )
            host = HostConfig(
                name=args.name,
                hostname=args.hostname,
                username=args.username,
                known_hosts=str(Path(args.known_hosts).expanduser()),
                client_keys=tuple(Path(item).expanduser() for item in args.client_key),
                allowed_logs=frozenset(PurePosixPath(item) for item in args.allowed_log),
                thresholds=ResourceThresholds(
                    cpu_percent=args.cpu_threshold,
                    memory_percent=args.memory_threshold,
                ),
            )
            updated = dict(hosts)
            updated[host.name] = host
            save_hosts(args.config, updated)
            print(f"Added host {host.name!r}")
            return 0
        if args.name not in hosts:
            raise ConfigError(f"Unknown host: {args.name}")
        updated = dict(hosts)
        del updated[args.name]
        save_hosts(args.config, updated)
        print(f"Removed host {args.name!r}")
        return 0
    except ConfigError as error:
        parser.error(str(error))
    return 2
