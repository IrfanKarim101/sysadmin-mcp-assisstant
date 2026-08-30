"""Pure command policy for the read-only diagnostic capabilities.

This module deliberately knows nothing about SSH.  It turns typed requests into
fixed argument vectors, making the security boundary cheap to test locally.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath

from .config import HostConfig

MAX_LINES = 500
MAX_GREP_PATTERN_LENGTH = 256
SERVICE_STATES = frozenset({"active", "inactive", "failed"})
LOG_MODES = frozenset({"head", "tail", "cat"})

Command = tuple[str, ...]


class PolicyError(ValueError):
    """A caller asked for an operation outside the read-only policy."""


class ReadOnlyCommandPolicy:
    """Build only the fixed argv forms approved by the application policy."""

    def __init__(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def host(self, name: str) -> HostConfig:
        try:
            return self._hosts[name]
        except KeyError as error:
            raise PolicyError(f"Unknown target host: {name}") from error

    def ports(self, *, fallback: bool = False) -> Command:
        return ("netstat" if fallback else "ss", "-tulnp")

    def services(self, state_filter: str | None = None) -> Command:
        argv = ["systemctl", "list-units", "--type=service", "--no-pager", "--no-legend"]
        if state_filter is not None:
            if state_filter not in SERVICE_STATES:
                raise PolicyError("state_filter must be active, inactive, or failed")
            argv.append(f"--state={state_filter}")
        return tuple(argv)

    def resources(self) -> tuple[Command, Command, Command]:
        return (("top", "-bn1"), ("free", "-h"), ("vmstat", "1", "2"))

    def read_log(self, host: str, logfile: str, mode: str, lines: int = 100) -> Command:
        log_path = self._allowed_log(host, logfile)
        if mode not in LOG_MODES:
            raise PolicyError("mode must be head, tail, or cat")
        self._line_count(lines, "lines")
        if mode == "cat":
            # There is intentionally no unbounded cat command in the policy.
            return ("sed", "-n", f"1,{lines}p", str(log_path))
        return (mode, "-n", str(lines), str(log_path))

    def grep_log(
        self, host: str, logfile: str, pattern: str, max_lines: int = 100
    ) -> Command:
        log_path = self._allowed_log(host, logfile)
        if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_GREP_PATTERN_LENGTH:
            raise PolicyError(f"pattern must contain 1-{MAX_GREP_PATTERN_LENGTH} characters")
        if any(character in pattern for character in ("\x00", "\n", "\r")):
            raise PolicyError("pattern contains a prohibited control character")
        self._line_count(max_lines, "max_lines")
        # -- terminates grep options. The pattern and path remain discrete argv.
        return ("grep", "-n", "-m", str(max_lines), "--", pattern, str(log_path))

    def active_users(self) -> tuple[Command, Command]:
        return (("w", "-h"), ("who",))

    def _allowed_log(self, host: str, logfile: str) -> PurePosixPath:
        target = self.host(host)
        if not isinstance(logfile, str) or any(
            character in logfile for character in ("\x00", "\n", "\r")
        ):
            raise PolicyError("Log file is not allowlisted for this host")
        path = PurePosixPath(logfile)
        if not path.is_absolute() or ".." in path.parts or path not in target.allowed_logs:
            raise PolicyError("Log file is not allowlisted for this host")
        return path

    @staticmethod
    def _line_count(value: int, parameter: str) -> None:
        # bool is an int subclass, but accepting it as a line count is surprising.
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_LINES:
            raise PolicyError(f"{parameter} must be an integer between 1 and {MAX_LINES}")
