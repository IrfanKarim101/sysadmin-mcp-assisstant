"""Transport-neutral result models."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    stdout: str
    stderr: str
    exit_status: int
    truncated: bool = False
