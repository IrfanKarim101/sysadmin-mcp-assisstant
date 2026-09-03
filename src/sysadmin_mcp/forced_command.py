"""OpenSSH forced-command gate for the dedicated read-only account.

The gate is intentionally standalone from the executor and never invokes a
shell. OpenSSH supplies the requested command in ``SSH_ORIGINAL_COMMAND``;
this module parses it, validates one exact argv shape, and replaces itself with
an approved absolute executable via ``execve``.
"""

from __future__ import annotations

import os
import shlex
import stat
import sys
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath

DEFAULT_POLICY_PATH = "/etc/sysadmin-readonly-policy.toml"
MAX_COMMAND_LENGTH = 4_096
MAX_ARGUMENTS = 16
MAX_LINES = 500
MAX_PATTERN_LENGTH = 256

DEFAULT_BINARIES = {
    "free": "/usr/bin/free",
    "grep": "/usr/bin/grep",
    "head": "/usr/bin/head",
    "netstat": "/usr/bin/netstat",
    "sed": "/usr/bin/sed",
    "ss": "/usr/bin/ss",
    "systemctl": "/usr/bin/systemctl",
    "tail": "/usr/bin/tail",
    "top": "/usr/bin/top",
    "vmstat": "/usr/bin/vmstat",
    "w": "/usr/bin/w",
    "who": "/usr/bin/who",
}

SAFE_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}

SERVICE_BASE = ("systemctl", "list-units", "--type=service", "--no-pager", "--no-legend")
SERVICE_STATES = frozenset({"active", "inactive", "failed"})
FIXED_COMMANDS = frozenset(
    {
        ("ss", "-tulnp"),
        ("netstat", "-tulnp"),
        ("top", "-bn1"),
        ("free", "-h"),
        ("vmstat", "1", "2"),
        ("w", "-h"),
        ("who",),
        SERVICE_BASE,
    }
)


class CommandDenied(ValueError):
    """The SSH request does not match the read-only OS policy."""


def load_allowed_logs(path: str = DEFAULT_POLICY_PATH) -> frozenset[PurePosixPath]:
    """Load exact absolute log paths from the root-owned policy file."""
    with open(path, "rb") as policy_file:
        values = tomllib.load(policy_file)
    raw_logs = values.get("policy", {}).get("allowed_logs")
    if not isinstance(raw_logs, list) or not raw_logs:
        raise CommandDenied("policy must define at least one allowed log")

    logs: set[PurePosixPath] = set()
    for value in raw_logs:
        if not isinstance(value, str) or any(char in value for char in ("\x00", "\n", "\r")):
            raise CommandDenied("policy contains an unsafe log path")
        log = PurePosixPath(value)
        if not log.is_absolute() or ".." in log.parts:
            raise CommandDenied("policy contains an unsafe log path")
        logs.add(log)
    return frozenset(logs)


def validate_policy_file(path: str = DEFAULT_POLICY_PATH) -> None:
    """Require a regular, root-owned policy which no non-root user can modify."""
    metadata = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise CommandDenied("policy must be a regular file")
    if metadata.st_uid != 0:
        raise CommandDenied("policy must be owned by root")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise CommandDenied("policy must not be group/world writable")


def authorize_command(
    original_command: str | None,
    allowed_logs: frozenset[PurePosixPath],
    binaries: Mapping[str, str] = DEFAULT_BINARIES,
) -> tuple[str, ...]:
    """Return an absolute argv only when the request matches an approved form."""
    if not original_command:
        raise CommandDenied("interactive sessions are disabled")
    if len(original_command) > MAX_COMMAND_LENGTH:
        raise CommandDenied("command is too long")
    try:
        argv = tuple(shlex.split(original_command, posix=True))
    except ValueError as error:
        raise CommandDenied("command quoting is invalid") from error
    if not argv or len(argv) > MAX_ARGUMENTS:
        raise CommandDenied("invalid argument count")

    _validate_argv(argv, allowed_logs)
    binary = binaries.get(argv[0])
    if binary is None or not PurePosixPath(binary).is_absolute():
        raise CommandDenied("approved binary is not configured safely")
    return (binary, *argv[1:])


def _validate_argv(argv: tuple[str, ...], allowed_logs: frozenset[PurePosixPath]) -> None:
    if argv in FIXED_COMMANDS:
        return
    if len(argv) == len(SERVICE_BASE) + 1 and argv[: len(SERVICE_BASE)] == SERVICE_BASE:
        state_option = argv[-1]
        if state_option.startswith("--state=") and state_option[8:] in SERVICE_STATES:
            return
        raise CommandDenied("service state is not approved")
    if argv[0] in {"head", "tail"}:
        if len(argv) == 4 and argv[1] == "-n":
            _validate_lines(argv[2])
            _validate_log(argv[3], allowed_logs)
            return
    elif argv[0] == "sed":
        if len(argv) == 4 and argv[1] == "-n" and argv[2].startswith("1,"):
            expression = argv[2]
            if expression.endswith("p"):
                _validate_lines(expression[2:-1])
                _validate_log(argv[3], allowed_logs)
                return
    elif (
        argv[0] == "grep"
        and len(argv) == 7
        and argv[1:3] == ("-n", "-m")
        and argv[4] == "--"
    ):
        _validate_lines(argv[3])
        pattern = argv[5]
        if not pattern or len(pattern) > MAX_PATTERN_LENGTH:
            raise CommandDenied("grep pattern length is outside policy")
        if any(char in pattern for char in ("\x00", "\n", "\r")):
            raise CommandDenied("grep pattern contains a control character")
        _validate_log(argv[6], allowed_logs)
        return
    raise CommandDenied("command is outside the read-only policy")


def _validate_lines(value: str) -> None:
    if not value.isascii() or not value.isdecimal() or str(int(value)) != value:
        raise CommandDenied("line count is invalid")
    if not 1 <= int(value) <= MAX_LINES:
        raise CommandDenied("line count is outside policy")


def _validate_log(value: str, allowed_logs: frozenset[PurePosixPath]) -> None:
    if any(char in value for char in ("\x00", "\n", "\r")):
        raise CommandDenied("log path contains a control character")
    log = PurePosixPath(value)
    if not log.is_absolute() or ".." in log.parts or log not in allowed_logs:
        raise CommandDenied("log path is not allowlisted")


def main(argv: Sequence[str] | None = None) -> int:
    """Authorize the OpenSSH request and replace this process with the binary."""
    del argv  # There is deliberately no caller-controlled CLI surface.
    try:
        validate_policy_file()
        allowed_logs = load_allowed_logs()
        command = authorize_command(os.environ.get("SSH_ORIGINAL_COMMAND"), allowed_logs)
    except (CommandDenied, OSError, tomllib.TOMLDecodeError) as error:
        print(f"read-only policy denied request: {error}", file=sys.stderr)
        return 126
    os.execve(command[0], command, SAFE_ENVIRONMENT)
    return 127  # pragma: no cover - execve only returns by raising an error


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
