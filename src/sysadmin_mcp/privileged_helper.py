"""Root-side helper for narrowly allowlisted maintenance actions.

This program is intended to be the sole sudo target. It accepts one typed action,
revalidates the root-owned policy, and replaces itself with a fixed executable.
"""
from __future__ import annotations

import os
import sys
import tomllib
from collections.abc import Sequence

from .forced_command import (
    DEFAULT_POLICY_PATH,
    SAFE_ENVIRONMENT,
    CommandDenied,
    load_restart_services,
    validate_policy_file,
)

SYSTEMCTL = "/usr/bin/systemctl"


def authorize_action(argv: Sequence[str], policy_path: str = DEFAULT_POLICY_PATH) -> tuple[str, ...]:
    if len(argv) != 2 or argv[0] != "restart-service":
        raise CommandDenied("maintenance action is outside policy")
    validate_policy_file(policy_path)
    service = argv[1]
    if service not in load_restart_services(policy_path):
        raise CommandDenied("service restart is not approved")
    return (SYSTEMCTL, "restart", service)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        command = authorize_action(arguments)
    except (CommandDenied, OSError, tomllib.TOMLDecodeError) as error:
        print(f"remediation policy denied request: {error}", file=sys.stderr)
        return 126
    os.execve(command[0], command, SAFE_ENVIRONMENT)
    return 127  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
